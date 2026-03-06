#!/usr/bin/env bash
# Build and set up dstack-guest-agent simulator for local development.
#
# The simulator provides the same GetKey/GetQuote APIs as production TEE,
# using Unix domain sockets (dstack.sock, tappd.sock).
#
# How it works:
#   The dstack-sdk dependency (in key-manager/Cargo.toml) points to the dstack
#   monorepo. Cargo caches the full monorepo source in ~/.cargo/git/checkouts/.
#   This script reuses that checkout to build the guest-agent binary as a
#   simulator. If the source isn't cached yet, the script fetches it via cargo.
#
# Usage:
#   ./scripts/setup-dstack-simulator.sh          # build
#   ./scripts/setup-dstack-simulator.sh run       # build + start

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

# Resolve the dstack monorepo checkout from cargo's git cache.
# cargo clones https://github.com/Dstack-TEE/dstack.git into
# ~/.cargo/git/checkouts/dstack-<hash>/<rev>/ when building key-manager
# We reuse that checkout to build the simulator.
DSTACK_REV="d3275d1"

# Find checkout dir dynamically (the hash before rev varies by machine)
DSTACK_CHECKOUT="$(find "$HOME/.cargo/git/checkouts" -maxdepth 2 -type d -name "$DSTACK_REV" -path "*/dstack-*" 2>/dev/null | head -1)"

if [ -z "$DSTACK_CHECKOUT" ] || [ ! -d "$DSTACK_CHECKOUT/guest-agent" ]; then
    echo "dstack source (rev $DSTACK_REV) not found in cargo cache. Fetching..."
    cd "$REPO_ROOT"
    cargo build -p key-manager
    DSTACK_CHECKOUT="$(find "$HOME/.cargo/git/checkouts" -maxdepth 2 -type d -name "$DSTACK_REV" -path "*/dstack-*" 2>/dev/null | head -1)"
    if [ -z "$DSTACK_CHECKOUT" ]; then
        echo "Failed to fetch dstack source."
        exit 1
    fi
fi

SIMULATOR_DIR="$DSTACK_CHECKOUT/sdk/simulator"
BINARY="$DSTACK_CHECKOUT/target/release/dstack-guest-agent"

# --- Build ---
echo "Building dstack-guest-agent (release)..."
cd "$DSTACK_CHECKOUT"
cargo build --release -p dstack-guest-agent

echo "Binary: $BINARY"
echo "Size: $(du -h "$BINARY" | cut -f1)"

if [ "${1:-}" = "run" ]; then
    echo ""
    echo "Starting simulator in $SIMULATOR_DIR ..."
    echo "Sockets: dstack.sock, tappd.sock, external.sock, guest.sock"
    echo "Press Ctrl+C to stop."
    echo ""
    cd "$SIMULATOR_DIR"
    exec "$BINARY" -c dstack.toml
else
    echo ""
    echo "To start the simulator:"
    echo "  cd $SIMULATOR_DIR"
    echo "  $BINARY -c dstack.toml"
    echo ""
    echo "To run dstack integration tests:"
    echo "  DSTACK_SIMULATOR_ENDPOINT=$SIMULATOR_DIR/dstack.sock \\"
    echo "    cargo test -p key-manager -- --ignored"
    echo "  DSTACK_SIMULATOR_ENDPOINT=$SIMULATOR_DIR/dstack.sock \\"
    echo "    cargo test -p cced -- --ignored"
fi
