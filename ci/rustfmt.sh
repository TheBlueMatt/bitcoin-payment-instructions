#!/bin/bash
set -eox pipefail

# The +rustversion syntax only works with rustup-installed rust toolchains,
# not with any distro-provided ones. Thus, we check for a rustup install and
# only pass +1.85.0 if we find one.
VERS=""
[ "$(which rustup)" != "" ] && VERS="+1.85.0"

# Run fmt
for file in $(git ls-files | grep '.rs$'); do
	echo "Checking formatting of $file"
	rustfmt $VERS --edition 2021 --check "$file"
done
