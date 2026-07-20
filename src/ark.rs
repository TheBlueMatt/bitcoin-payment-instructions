//! Bark address parsing.
//!
//! Bark addresses are Bech32m strings with `ark`/`tark` HRPs, a policy-address version byte, and
//! an opaque Bark payload. This module validates the address envelope while preserving the payload
//! for wallets that understand Bark payments.

use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;

use bitcoin::bech32::primitives::decode::CheckedHrpstring;
use bitcoin::bech32::{Bech32m, ByteIterExt, Fe32, Fe32IterExt, Hrp};
use bitcoin::Network;

const HRP_MAINNET: Hrp = Hrp::parse_unchecked("ark");
const HRP_TESTNET: Hrp = Hrp::parse_unchecked("tark");
const VERSION_POLICY: Fe32 = Fe32::P;

/// A Bark policy address.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct BarkAddress {
	testnet: bool,
	payload: Vec<u8>,
}

impl BarkAddress {
	/// Whether this address uses Bark's test-network HRP (`tark`).
	pub fn is_testnet(&self) -> bool {
		self.testnet
	}

	/// The raw address payload after the Bark address version field.
	pub fn payload(&self) -> &[u8] {
		&self.payload
	}

	/// Requires that this address matches the given Bitcoin network.
	pub fn require_network(self, network: Network) -> Result<Self, NetworkValidationError> {
		if self.testnet == (network != Network::Bitcoin) {
			Ok(self)
		} else {
			Err(NetworkValidationError)
		}
	}
}

impl FromStr for BarkAddress {
	type Err = ParseAddressError;

	fn from_str(s: &str) -> Result<Self, Self::Err> {
		let mut checked =
			CheckedHrpstring::new::<Bech32m>(s).map_err(|_| ParseAddressError::Bech32)?;
		let testnet = hrp_is_testnet(checked.hrp())?;

		let version = checked.remove_witness_version().ok_or(ParseAddressError::Empty)?;
		if version != VERSION_POLICY {
			return Err(ParseAddressError::UnknownVersion);
		}

		let payload: Vec<_> = checked.byte_iter().collect();
		if payload.is_empty() {
			return Err(ParseAddressError::Invalid("empty Bark address payload"));
		}
		Ok(BarkAddress { testnet, payload })
	}
}

impl fmt::Display for BarkAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		let hrp = hrp_for_testnet(self.testnet);
		let chars = [VERSION_POLICY]
			.into_iter()
			.chain(self.payload.iter().copied().bytes_to_fes())
			.with_checksum::<Bech32m>(&hrp)
			.chars();
		for c in chars {
			let mut buf = [0; 4];
			f.write_str(c.encode_utf8(&mut buf))?;
		}
		Ok(())
	}
}

impl fmt::Debug for BarkAddress {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		fmt::Display::fmt(self, f)
	}
}

/// Error parsing a Bark address.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParseAddressError {
	/// The address was not a valid Bech32m string.
	Bech32,
	/// The address HRP was not `ark` or `tark`.
	Hrp,
	/// The address had no version field.
	Empty,
	/// The address version was not supported.
	UnknownVersion,
	/// The address payload was malformed.
	Invalid(&'static str),
}

impl fmt::Display for ParseAddressError {
	fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
		match self {
			Self::Bech32 => f.write_str("bech32m decoding error"),
			Self::Hrp => f.write_str("invalid Bark address HRP"),
			Self::Empty => f.write_str("empty Bark address"),
			Self::UnknownVersion => f.write_str("unknown Bark address version"),
			Self::Invalid(msg) => f.write_str(msg),
		}
	}
}

/// Error returned when an address does not match the requested network.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NetworkValidationError;

fn hrp_is_testnet(hrp: Hrp) -> Result<bool, ParseAddressError> {
	if hrp == HRP_MAINNET {
		Ok(false)
	} else if hrp == HRP_TESTNET {
		Ok(true)
	} else {
		Err(ParseAddressError::Hrp)
	}
}

fn hrp_for_testnet(testnet: bool) -> Hrp {
	if testnet {
		HRP_TESTNET
	} else {
		HRP_MAINNET
	}
}

#[cfg(test)]
mod tests {
	use alloc::string::ToString;

	use super::*;

	const BARK_MAINNET: &str = "ark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mqkr4cf5";
	const BARK_TESTNET: &str = "tark1pwh9vsmezqqpharv69q4z8m6x364d5m5prnmcalcalq9pdmzw0y7mpveck4pcfhezqypczkrrj3lkx5ue4qrf4jc7ztpt9htdttmh2judhqnu7aue8p0y9mq47jn9z";

	#[test]
	fn parse_bark_address() {
		let address = BarkAddress::from_str(BARK_MAINNET).unwrap();
		assert!(!address.is_testnet());
		assert_eq!(address.to_string(), BARK_MAINNET);
		assert_eq!(BarkAddress::from_str(&BARK_MAINNET.to_ascii_uppercase()).unwrap(), address);
		assert!(address.payload().len() > 4);
		assert!(address.clone().require_network(Network::Bitcoin).is_ok());
		assert!(address.require_network(Network::Signet).is_err());
	}

	#[test]
	fn parse_testnet_bark_address() {
		let address = BarkAddress::from_str(BARK_TESTNET).unwrap();
		assert!(address.is_testnet());
		assert_eq!(address.to_string(), BARK_TESTNET);
		assert_eq!(BarkAddress::from_str(&BARK_TESTNET.to_ascii_uppercase()).unwrap(), address);
		assert!(address.clone().require_network(Network::Signet).is_ok());
		assert!(address.require_network(Network::Bitcoin).is_err());
	}

	#[test]
	fn reject_empty_bark_payload() {
		let address = BarkAddress { testnet: false, payload: Vec::new() }.to_string();

		assert_eq!(
			BarkAddress::from_str(&address),
			Err(ParseAddressError::Invalid("empty Bark address payload"))
		);
	}
}
