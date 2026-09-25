#!/usr/bin/env bash
# Performance baselines for netRo (CLI + TUI).
#
# Records startup, memory and idle CPU so regressions are visible. Numbers are
# environment-dependent; compare runs on the same machine.
set -euo pipefail

cd "$(dirname "$0")/.."

BIN="./target/release/netro"
if [[ ! -x "$BIN" ]]; then
  echo "building release binary..."
  cargo build --release
fi

BENCH_DIR="$(mktemp -d)"
export XDG_CONFIG_HOME="$BENCH_DIR/config"
export XDG_DATA_HOME="$BENCH_DIR/data"
export XDG_CACHE_HOME="$BENCH_DIR/cache"
trap 'rm -rf "$BENCH_DIR"' EXIT

hr() { printf '%s\n' "------------------------------------------------------------"; }

hr
echo "CLI startup (30 runs of 'version')"
python3 - "$BIN" <<'PY'
import subprocess, sys, time
binary = sys.argv[1]
started = time.time()
for _ in range(30):
    subprocess.run([binary, "version"], stdout=subprocess.DEVNULL, check=True)
print(f"  average: {(time.time() - started) / 30 * 1000:.1f} ms")
PY

hr
echo "CLI command wall time / peak RSS"
for args in "system --json" "doctor --json --no-internet" "security audit --json" "network interfaces --json"; do
  printf '  %-34s' "$args"
  /usr/bin/time -f "wall %es  maxrss %MkB" $BIN $args > /dev/null 2>"$BENCH_DIR/time.txt" || true
  tail -1 "$BENCH_DIR/time.txt" | sed 's/^/  /'
done

hr
echo "10k-port localhost scan (512 workers)"
/usr/bin/time -f "  wall %es  maxrss %MkB" $BIN network scan 127.0.0.1 \
  --ports 1-10000 --concurrency 512 --timeout-ms 100 --no-banner --no-tls \
  --open-only --json > /dev/null 2>"$BENCH_DIR/time.txt" || true
tail -1 "$BENCH_DIR/time.txt"

hr
echo "TUI (needs util-linux 'script' for a PTY)"
if command -v script > /dev/null 2>&1; then
  for seconds in 6 18; do
    printf '  idle %-3ss: ' "$seconds"
    /usr/bin/time -f "user %Us  sys %Ss  wall %es  maxrss %MkB" \
      script -qec "timeout $seconds $BIN" /dev/null > /dev/null 2>"$BENCH_DIR/time.txt" || true
    tail -1 "$BENCH_DIR/time.txt" | sed 's/^/  /'
  done
  echo "  (the difference between the 6s and 18s runs is the steady-state cost;"
  echo "   the first seconds include real startup diagnostics)"
else
  echo "  skipped: 'script' not available"
fi

hr
echo "done"
