//! A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
//! resolution directly from untrusted lightning nodes, providing privacy through onion routing.

use std::boxed::Box;
use std::collections::HashMap;
use std::future::Future;
use std::ops::Deref;
use std::pin::Pin;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::task::{Context, Poll, Waker};
use std::vec::Vec;

use bitcoin::secp256k1::PublicKey;
use lightning::blinded_path::message::{DNSResolverContext, MessageContext};
use lightning::ln::channelmanager::PaymentId;
use lightning::onion_message::dns_resolution::{
	DNSResolverMessage, DNSResolverMessageHandler, DNSSECProof, DNSSECQuery, OMNameResolver,
};
use lightning::onion_message::messenger::{
	Destination, MessageSendInstructions, Responder, ResponseInstruction,
};
use lightning::routing::gossip::NetworkGraph;
use lightning::sign::EntropySource;
use lightning::util::logger::Logger;

use crate::hrn_resolution::{
	HrnResolution, HrnResolutionFuture, HrnResolver, HumanReadableName, LNURLResolutionFuture,
};
use crate::Amount;

struct OsRng;
impl EntropySource for OsRng {
	fn get_secure_random_bytes(&self) -> [u8; 32] {
		let mut res = [0; 32];
		getrandom::fill(&mut res).expect("Fetching system randomness should always succeed");
		res
	}
}

struct ChannelState {
	waker: Option<Waker>,
	result: Option<HrnResolution>,
}

struct ChannelSend(Arc<Mutex<ChannelState>>);

impl ChannelSend {
	fn complete(self, result: HrnResolution) {
		let mut state = self.0.lock().unwrap();
		state.result = Some(result);
		if let Some(waker) = state.waker.take() {
			waker.wake();
		}
	}

	fn receiver_alive(&self) -> bool {
		Arc::strong_count(&self.0) > 1
	}
}

struct ChannelRecv(Arc<Mutex<ChannelState>>);

impl Future for ChannelRecv {
	type Output = HrnResolution;
	fn poll(self: Pin<&mut Self>, context: &mut Context) -> Poll<HrnResolution> {
		let mut state = self.0.lock().unwrap();
		if let Some(res) = state.result.take() {
			debug_assert!(state.waker.is_none());
			Poll::Ready(res)
		} else {
			state.waker = Some(context.waker().clone());
			Poll::Pending
		}
	}
}

fn channel() -> (ChannelSend, ChannelRecv) {
	let state = Arc::new(Mutex::new(ChannelState { waker: None, result: None }));
	(ChannelSend(Arc::clone(&state)), ChannelRecv(state))
}

/// A [`HrnResolver`] which uses lightning onion messages and DNSSEC proofs to request DNS
/// resolution directly from untrusted lightning nodes, providing privacy through onion routing.
///
/// This implements LDK's [`DNSResolverMessageHandler`], which it uses to send onion messages and
/// process response messages.
///
/// Note that because this implementation does not assume an async runtime, queries which are not
/// responded to *may hang forever*. You must always wrap resolution futures to ensure they time
/// out properly, eg via `tokio::time::timeout`.
///
/// Note that after a query begines, [`PeerManager::process_events`] should be called to ensure the
/// query message goes out in a timely manner. You can call [`Self::register_post_queue_action`] to
/// have this happen automatically.
///
/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
pub struct LDKOnionMessageDNSSECHrnResolver<N: Deref<Target = NetworkGraph<L>>, L: Deref>
where
	L::Target: Logger,
{
	network_graph: N,
	resolver_nodes: Vec<PublicKey>,
	resolver: OMNameResolver,
	next_id: AtomicUsize,
	pending_resolutions: Mutex<HashMap<HumanReadableName, Vec<(PaymentId, ChannelSend)>>>,
	message_queue: Mutex<Vec<(DNSResolverMessage, MessageSendInstructions)>>,
	pm_event_poker: RwLock<Option<Box<dyn Fn() + Send + Sync>>>,
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	/// Constructs a new [`LDKOnionMessageDNSSECHrnResolver`].
	///
	/// If `resolver_nodes` is non-empty, all DNS resolution queries are sent to the given
	/// nodes, otherwise nodes which advertise support for DNS resolution in the network graph
	/// are queried.
	///
	/// See the struct-level documentation for more info.
	pub fn new(network_graph: N, resolver_nodes: Vec<PublicKey>) -> Self {
		Self {
			network_graph,
			resolver_nodes,
			next_id: AtomicUsize::new(0),
			resolver: OMNameResolver::new_without_no_std_expiry_validation(),
			pending_resolutions: Mutex::new(HashMap::new()),
			message_queue: Mutex::new(Vec::new()),
			pm_event_poker: RwLock::new(None),
		}
	}

	/// Sets a callback which is called any time a new resolution begins and a message is available
	/// to be sent. This should generally call [`PeerManager::process_events`].
	///
	/// [`PeerManager::process_events`]: lightning::ln::peer_handler::PeerManager::process_events
	pub fn register_post_queue_action(&self, callback: Box<dyn Fn() + Send + Sync>) {
		*self.pm_event_poker.write().unwrap() = Some(callback);
	}

	fn init_resolve_hrn<'a>(
		&'a self, hrn: &HumanReadableName,
	) -> Result<ChannelRecv, &'static str> {
		#[cfg(feature = "std")]
		{
			use std::time::SystemTime;
			let clock_err =
				"DNSSEC validation relies on having a correct system clock. It is currently set before 1970.";
			let now =
				SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).map_err(|_| clock_err)?;
			// Use `now / 60` as the block height to expire pending requests after 1-2 minutes.
			self.resolver.new_best_block((now.as_secs() / 60) as u32, now.as_secs() as u32);
		}

		let dns_resolvers = if !self.resolver_nodes.is_empty() {
			self.resolver_nodes.iter().map(|node| Destination::Node(*node)).collect()
		} else {
			let mut dns_resolvers = Vec::new();
			for (node_id, node) in self.network_graph.read_only().nodes().unordered_iter() {
				if let Some(info) = &node.announcement_info {
					// Sadly, 31 nodes currently squat on the DNS Resolver feature bit
					// without speaking it.
					// Its unclear why they're doing so, but none of them currently
					// also have the onion messaging feature bit set, so here we check
					// for both.
					let supports_dns = info.features().supports_dns_resolution();
					let supports_om = info.features().supports_onion_messages();
					if supports_dns && supports_om {
						if let Ok(pubkey) = node_id.as_pubkey() {
							dns_resolvers.push(Destination::Node(pubkey));
						}
					}
				}
				if dns_resolvers.len() > 5 {
					break;
				}
			}
			if dns_resolvers.is_empty() {
				return Err(
					"Failed to find any DNS resolving nodes, check your network graph is synced",
				);
			}
			dns_resolvers
		};

		let counter = self.next_id.fetch_add(1, Ordering::Relaxed) as u64;
		let mut payment_id = [0; 32];
		payment_id[..8].copy_from_slice(&counter.to_ne_bytes());
		let payment_id = PaymentId(payment_id);

		let err = "The provided HRN did not fit in a DNS request";
		// TODO: Once LDK ships a response context authentication method which doesn't require
		// client-side entropy, we shouldn't need the RNG here and can stop depending on std.
		let (query, dns_context) =
			self.resolver.resolve_name(payment_id, *hrn, &OsRng).map_err(|_| err)?;
		let context = MessageContext::DNSResolver(dns_context);

		let (send, recv) = channel();
		{
			let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
			let senders = pending_resolutions.entry(*hrn).or_insert_with(Vec::new);
			senders.push((payment_id, send));

			// If we're running in no-std, we won't expire lookups with the time updates above, so walk
			// the pending resolution list and expire them here.
			pending_resolutions.retain(|name, resolutions| {
				resolutions.retain(|(payment_id, resolution)| {
					let has_receiver = resolution.receiver_alive();
					if !has_receiver {
						self.resolver.expire_pending_resolution(name, *payment_id);
					}
					has_receiver
				});
				!resolutions.is_empty()
			});
		}

		{
			let mut queue = self.message_queue.lock().unwrap();
			for destination in dns_resolvers {
				let instructions = MessageSendInstructions::WithReplyPath {
					destination,
					context: context.clone(),
				};
				queue.push((DNSResolverMessage::DNSSECQuery(query.clone()), instructions));
			}
		}

		let callback = self.pm_event_poker.read().unwrap();
		if let Some(callback) = &*callback {
			callback();
		}

		Ok(recv)
	}
}

impl<N: Deref<Target = NetworkGraph<L>>, L: Deref> DNSResolverMessageHandler
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn handle_dnssec_query(
		&self, _: DNSSECQuery, _: Option<Responder>,
	) -> Option<(DNSResolverMessage, ResponseInstruction)> {
		None
	}

	fn handle_dnssec_proof(&self, msg: DNSSECProof, context: DNSResolverContext) {
		let results = self.resolver.handle_dnssec_proof_for_uri(msg.clone(), context);
		if let Some((resolved, res)) = results {
			let mut pending_resolutions = self.pending_resolutions.lock().unwrap();
			for (name, _payment_id) in resolved {
				if let Some(requests) = pending_resolutions.remove(&name) {
					for (_id, send) in requests {
						send.complete(HrnResolution::DNSSEC {
							proof: Some(msg.proof.clone()),
							result: res.clone(),
						});
					}
				}
			}
		}
	}

	fn release_pending_messages(&self) -> Vec<(DNSResolverMessage, MessageSendInstructions)> {
		std::mem::take(&mut self.message_queue.lock().unwrap())
	}
}

impl<N: Deref<Target = NetworkGraph<L>> + Sync, L: Deref> HrnResolver
	for LDKOnionMessageDNSSECHrnResolver<N, L>
where
	L::Target: Logger,
{
	fn resolve_hrn<'a>(&'a self, hrn: &'a HumanReadableName) -> HrnResolutionFuture<'a> {
		match self.init_resolve_hrn(hrn) {
			Err(e) => Box::pin(async move { Err(e) }),
			Ok(recv) => Box::pin(async move { Ok(recv.await) }),
		}
	}

	fn resolve_lnurl<'a>(&'a self, _url: &'a str) -> HrnResolutionFuture<'a> {
		let err = "DNS resolver does not support LNURL resolution";
		Box::pin(async move { Err(err) })
	}

	fn resolve_lnurl_to_invoice<'a>(
		&'a self, _: String, _: Amount, _: [u8; 32],
	) -> LNURLResolutionFuture<'a> {
		let err = "resolve_lnurl_to_invoice shouldn't be called when we don't resolve LNURL";
		debug_assert!(false, "{err}");
		Box::pin(async move { Err(err) })
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::*;

	use std::net::ToSocketAddrs;

	use bitcoin::hex::FromHex;
	use bitcoin::secp256k1::PublicKey;

	use std::sync::atomic::AtomicBool;

	use lightning::blinded_path::NodeIdLookUp;
	use lightning::events::{Event, EventsProvider};
	use lightning::ln::peer_handler::{
		ErroringMessageHandler, IgnoringMessageHandler, MessageHandler, PeerManager,
	};
	use lightning::onion_message::messenger::{DefaultMessageRouter, OnionMessenger};
	use lightning::routing::gossip::P2PGossipSync;
	use lightning::routing::utxo::UtxoLookup;
	use lightning::sign::KeysManager;
	use lightning::util::logger::Record;

	struct TestLogger;
	impl Logger for TestLogger {
		fn log(&self, r: Record) {
			eprintln!("{}", r.args);
		}
	}

	struct NoPeers;
	impl NodeIdLookUp for NoPeers {
		fn next_node_id(&self, _scid: u64) -> Option<PublicKey> {
			None
		}
	}

	#[tokio::test]
	async fn test_dns_om_hrn_resolver() {
		do_test().await;
	}

	async fn do_test() {
		// Resolution against the live network can be slow or fail transiently regardless, so
		// retry a couple of times before giving up. Each attempt syncs a fresh network graph.
		for _ in 0..5 {
			if do_test_attempt().await {
				return;
			}
		}
		panic!("Failed to resolve payment instructions over the network");
	}

	async fn do_test_attempt() -> bool {
		// Set once the attempt is done, however it ends, so that the background loops spawned
		// below stop hammering the resolver node during any retry.
		let shutdown = Arc::new(AtomicBool::new(false));
		let attempt = async {
			let graph = Arc::new(NetworkGraph::new(Network::Bitcoin, &TestLogger));
			let their_id_hex = "03db10aa09ff04d3568b0621750794063df401e6853c79a21a83e1a3f3b5bfb0c8";
			let their_id =
				PublicKey::from_slice(&Vec::<u8>::from_hex(their_id_hex).unwrap()).unwrap();
			// A transient DNS failure shouldn't panic the test, just fail this attempt.
			let Ok(mut addrs) = "ldk-ln-node.bitcoin.ninja:9735".to_socket_addrs() else {
				return false;
			};
			let Some(addr) = addrs.next() else { return false };

			let resolver =
				Arc::new(LDKOnionMessageDNSSECHrnResolver::new(Arc::clone(&graph), vec![their_id]));
			let signer = Arc::new(KeysManager::new(&OsRng.get_secure_random_bytes(), 0, 0, true));
			let message_router = Arc::new(DefaultMessageRouter::new(Arc::clone(&graph), &OsRng));
			let messenger = Arc::new(OnionMessenger::new(
				&OsRng,
				Arc::clone(&signer),
				&TestLogger,
				&NoPeers,
				message_router,
				&IgnoringMessageHandler {},
				&IgnoringMessageHandler {},
				Arc::clone(&resolver),
				&IgnoringMessageHandler {},
			));
			let no_utxos = None::<&(dyn UtxoLookup + Sync + Send)>;
			let handlers = MessageHandler {
				chan_handler: Arc::new(ErroringMessageHandler::new()),
				route_handler: Arc::new(P2PGossipSync::new(
					Arc::clone(&graph),
					no_utxos,
					&TestLogger,
				)),
				onion_message_handler: Arc::clone(&messenger),
				custom_message_handler: &IgnoringMessageHandler {},
				send_only_message_handler: &IgnoringMessageHandler {},
			};
			let rand = OsRng.get_secure_random_bytes();
			let peer_manager =
				Arc::new(PeerManager::new(handlers, 0, &rand, &TestLogger, Arc::clone(&signer)));

			// Maintain a connection to a static LDK node which we know will do DNS resolutions for us.
			let connect_pm = Arc::clone(&peer_manager);
			let connect_shutdown = Arc::clone(&shutdown);
			tokio::spawn(async move {
				loop {
					if connect_shutdown.load(Ordering::Relaxed) {
						return;
					}
					match lightning_net_tokio::connect_outbound(
						Arc::clone(&connect_pm),
						their_id,
						addr,
					)
					.await
					{
						Some(fut) => {
							fut.await;
							tokio::time::sleep(Duration::from_millis(100)).await;
						},
						// A failed TCP connection shouldn't kill the reconnect loop.
						None => tokio::time::sleep(Duration::from_secs(1)).await,
					}
				}
			});

			// Connect to any node the onion messenger needs a connection to in order to send its
			// queries.
			let events_messenger = Arc::clone(&messenger);
			let events_pm = Arc::clone(&peer_manager);
			let events_shutdown = Arc::clone(&shutdown);
			tokio::spawn(async move {
				loop {
					if events_shutdown.load(Ordering::Relaxed) {
						return;
					}
					events_messenger.process_pending_events(&|event| {
						if let Event::ConnectionNeeded { node_id, addresses } = event {
							// Skip nodes whose addresses we can't resolve rather than panicking;
							// the attempt will fail via its timeouts if none are reachable.
							let resolved = match addresses.into_iter().next() {
								Some(addr) => {
									addr.to_socket_addrs().ok().and_then(|mut addrs| addrs.next())
								},
								None => {
									assert_eq!(node_id, their_id);
									Some(addr)
								},
							};
							let Some(addr) = resolved else { return Ok(()) };
							let connect_pm = Arc::clone(&events_pm);
							tokio::spawn(async move {
								lightning_net_tokio::connect_outbound(connect_pm, node_id, addr)
									.await
									.unwrap()
									.await;
							});
						}
						Ok(())
					});
					tokio::time::sleep(Duration::from_millis(10)).await;
				}
			});

			let pm_reference = Arc::clone(&peer_manager);
			let poller_shutdown = Arc::clone(&shutdown);
			tokio::spawn(async move {
				loop {
					if poller_shutdown.load(Ordering::Relaxed) {
						return;
					}
					pm_reference.process_events();
					tokio::time::sleep(Duration::from_micros(10)).await;
				}
			});

			let parsed = tokio::time::timeout(
				Duration::from_secs(30),
				PaymentInstructions::parse(
					"send.some@satsto.me",
					bitcoin::Network::Bitcoin,
					&*resolver,
					true,
				),
			)
			.await;
			let instructions = match parsed {
				Ok(Ok(instructions)) => instructions,
				_ => return false,
			};

			let resolved = if let PaymentInstructions::ConfigurableAmount(instr) = instructions {
				assert_eq!(instr.min_amt(), None);
				assert_eq!(instr.max_amt(), None);

				assert_eq!(instr.pop_callback(), None);
				assert!(instr.bip_353_dnssec_proof().is_some());

				let hrn = instr.human_readable_name().as_ref().unwrap();
				assert_eq!(hrn.user(), "send.some");
				assert_eq!(hrn.domain(), "satsto.me");

				instr.set_amount(Amount::from_sats(100_000).unwrap(), &*resolver).await.unwrap()
			} else {
				panic!();
			};

			assert_eq!(resolved.pop_callback(), None);
			assert!(resolved.bip_353_dnssec_proof().is_some());

			let hrn = resolved.human_readable_name().as_ref().unwrap();
			assert_eq!(hrn.user(), "send.some");
			assert_eq!(hrn.domain(), "satsto.me");

			for method in resolved.methods() {
				match method {
					PaymentMethod::LightningBolt11(_) => {
						panic!("Should only have static payment instructions");
					},
					PaymentMethod::LightningBolt12(_) => {},
					PaymentMethod::OnChain { .. } => {},
					PaymentMethod::Bark(_) => {},
					PaymentMethod::Cashu(_) => {},
				}
			}
			true
		};
		// Bound the whole attempt so that a stuck connection or graph sync can't hang the test
		// forever.
		let res = tokio::time::timeout(Duration::from_secs(2 * 60), attempt).await.unwrap_or(false);
		shutdown.store(true, Ordering::Relaxed);
		res
	}
}
