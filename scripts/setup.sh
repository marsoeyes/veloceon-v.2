#!/usr/bin/env bash
# Build spr on a fresh cloud box (Google Colab, Kaggle, vast.ai, RunPod, Lambda...).
#
#   bash scripts/setup.sh            # install toolchain (if needed) + release build + self-check
#   bash scripts/setup.sh --no-check # skip the self-check
#
# Safe to re-run: it only adds the Rust toolchain to $HOME/.cargo and writes into target/.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$here"

run_check=1
for arg in "$@"; do
  case "$arg" in
    --no-check) run_check=0 ;;
    *) echo "unknown option: $arg" >&2; exit 2 ;;
  esac
done

# 1. system prerequisites -----------------------------------------------------
if ! command -v cc >/dev/null 2>&1 && ! command -v gcc >/dev/null 2>&1; then
  echo "==> installing C toolchain"
  if command -v apt-get >/dev/null 2>&1; then
    (sudo apt-get update -qq && sudo apt-get install -y -qq build-essential) || \
      (apt-get update -qq && apt-get install -y -qq build-essential)
  elif command -v dnf >/dev/null 2>&1; then
    sudo dnf install -y gcc gcc-c++ make
  else
    echo "!! please install gcc/make, then re-run" >&2
    exit 1
  fi
fi

# 2. Rust toolchain -----------------------------------------------------------
export CARGO_TERM_COLOR=never
export PATH="$HOME/.cargo/bin:$PATH"
if ! command -v cargo >/dev/null 2>&1; then
  echo "==> installing Rust (rustup, minimal profile)"
  curl -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
  sh /tmp/rustup-init.sh -y --profile minimal --default-toolchain stable >/tmp/rustup.log 2>&1 || {
    tail -20 /tmp/rustup.log; exit 1; }
fi
echo "==> $(cargo --version)"

# 3. build --------------------------------------------------------------------
echo "==> building release binary (this takes a few minutes on a fresh box)"
cargo build --release

bin="$here/target/release/spr"
[ -x "$bin" ] || { echo "!! build produced no binary" >&2; exit 1; }
echo "==> binary: $bin"

# 4. verify -------------------------------------------------------------------
if [ "$run_check" = "1" ]; then
  echo "==> verifying derivation vectors"
  "$bin" selfcheck
  echo "==> measuring this machine"
  "$bin" bench --seconds 3
fi

cat <<EOF

Done. Try:

  # recover one missing word, verified against your own EVM address
  $bin recover --phrase "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon ?" \\
      --target evm:0x9858EfFD232B4033E47d90003D41EC34EcaEda94

  # see the plan (space size, derivations) without spending CPU
  $bin recover --dry-run --phrase "word1 ? ? word4 ..." --target btc:1LqBG...

  # web dashboard
  $bin serve --port 8080

  # scale out over processes / machines (each gets its own slice)
  $bin recover --shard 1/8 ...      # and 2/8, 3/8 ... on other boxes

  # make sure target/release/spr is on PATH for convenience
  export PATH="$here/target/release:\$PATH"
EOF
