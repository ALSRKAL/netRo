#!/usr/bin/env bash
# Full local verification: formatting, linting, tests, CLI smoke tests and
# machine-readable output validation. Mirrors the CI pipeline.
set -euo pipefail

cd "$(dirname "$0")/.."

echo "== cargo fmt =="
cargo fmt --all -- --check

echo "== cargo clippy =="
cargo clippy --all-targets --all-features -- -D warnings

echo "== cargo test =="
cargo test --all-features

echo "== TUI tests (render snapshots, interaction, PTY) =="
cargo test --test tui_render --test tui_interaction --test tui_pty
if find tests/snapshots -name '*.snap.new' | grep -q .; then
  echo "ERROR: pending snapshot files found; review and accept them intentionally"
  exit 1
fi

echo "== release build =="
cargo build --release --all-features

BIN="./target/release/netro"

echo "== CLI smoke tests =="
"$BIN" version
"$BIN" --help > /dev/null
"$BIN" doctor --json --no-internet > /tmp/netro-doctor.json
"$BIN" system --json > /tmp/netro-system.json
"$BIN" network interfaces --json > /tmp/netro-interfaces.json
"$BIN" security audit --json > /tmp/netro-security.json
"$BIN" dependencies --json > /tmp/netro-deps.json

echo "== TUI smoke test (no terminal: prints help) =="
"$BIN" | grep -q "Usage: netro" && echo "  non-interactive launch prints help"

echo "== JSON validation =="
if command -v python3 > /dev/null 2>&1; then
  python3 - <<'PY'
import json
for name in ["doctor", "system", "interfaces", "security", "deps"]:
    with open(f"/tmp/netro-{name}.json") as fh:
        data = json.load(fh)
    assert "command" in data, name
    assert "schema_version" in data, name
    print(f"  {name}: valid JSON ({data['command']})")
PY
else
  echo "python3 not found; skipping JSON validation"
fi

echo "== all checks passed =="
