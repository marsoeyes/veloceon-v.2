#!/usr/bin/env bash
# Run one search over N processes, each with its own slice of the candidate space.
#
#   bash scripts/run_shards.sh 8 --phrase "a ? ? d ..." --target evm:0x...
#
# The first argument is the process count (default: CPU cores / 2); everything
# after it is passed to `spr recover` unchanged. Results are written to
# shard-<i>.json and the first shard that finds a phrase prints it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
bin="${SPR_BIN:-$here/target/release/spr}"
[ -x "$bin" ] || { echo "build first: cargo build --release" >&2; exit 1; }

shards="${1:-$(( $(nproc) / 2 > 0 ? $(nproc) / 2 : 1 ))}"
shift || true
[ "$shards" -ge 1 ] || { echo "shard count must be >= 1" >&2; exit 2; }

outdir="spr-shards-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$outdir"
echo "==> $shards shards -> $outdir"

pids=()
for i in $(seq 1 "$shards"); do
  "$bin" recover --shard "$i/$shards" --json "$outdir/shard-$i.json" "$@" \
    > "$outdir/shard-$i.log" 2>&1 &
  pids+=($!)
done

status=1
for pid in "${pids[@]}"; do
  if wait "$pid"; then status=0; fi
done

echo "==> done"
grep -h -A3 "MATCH" "$outdir"/*.log 2>/dev/null || echo "no match in this run"
for f in "$outdir"/shard-*.json; do
  [ -f "$f" ] || continue
  python3 - "$f" <<'PY' 2>/dev/null || true
import json,sys
d=json.load(open(sys.argv[1]))
if d.get("found"):
    for h in d["hits"]:
        print(f"  {h['network']:8} {h['path']:20} {h['address']}  {h['phrase']}")
PY
done
exit $status
