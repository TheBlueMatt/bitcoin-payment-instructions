#!/bin/bash
set -e
set -x

pushd src/bin
rm *_target.rs
./gen_target.sh
[ "$(git diff)" != "" ] && exit 1
popd

cargo install --color always --force honggfuzz --version 0.5.59 --no-default-features
sed -i 's/lto = true//' Cargo.toml

export RUSTFLAGS="--cfg=secp256k1_fuzz --cfg=hashes_fuzz"
export HFUZZ_BUILD_ARGS="--features honggfuzz_fuzz"

cargo --color always hfuzz build
for TARGET in src/bin/*.rs; do
	FILENAME=$(basename $TARGET)
	FILE="${FILENAME%.*}"
	HFUZZ_RUN_ARGS="--exit_upon_crash -v -n2 -N10000000"
	export HFUZZ_RUN_ARGS
	cargo --color always hfuzz run $FILE
	if [ -f hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT ]; then
		cat hfuzz_workspace/$FILE/HONGGFUZZ.REPORT.TXT
		for CASE in hfuzz_workspace/$FILE/SIG*; do
			cat $CASE | xxd -p
		done
		exit 1
	fi
done
