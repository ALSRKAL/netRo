# netRo

Cross-platform system, network, diagnostics, monitoring and security-audit CLI
for Linux, Windows and macOS. Every result comes from a real check; anything a
platform cannot do is reported as `UNSUPPORTED`, `DEPENDENCY_MISSING` or
`PERMISSION_DENIED` instead of being faked.

> **Status:** 5.0.0 — Rust rewrite of the original Bash dashboard
> (`legacy/netRo.sh`). See [`docs/AUDIT.md`](docs/AUDIT.md) for what the old
> script did and why it was replaced.

## Two ways to use it

* **Interactive TUI** — run `netro` (or `netro tui`) for a dashboard with
  System, Network, Discovery, Scanner, Security, Monitor, Doctor, Reports,
  Snapshots and Settings screens, a command palette (`Ctrl+P`), search (`/`)
  and contextual help (`?`). See [`docs/TUI.md`](docs/TUI.md).
* **Scriptable CLI** — every command below works non-interactively with
  `--json`/`--csv` for automation.

Both modes call the same diagnostic engine; the TUI never shells out.

## What it does

* **System** — OS/kernel/arch/uptime/virtualization, CPU (usage, cores, load,
  frequency, temperatures), memory/swap, every mounted filesystem, GPUs
  (NVIDIA/AMD/Intel/Apple) with live metrics where the driver exposes them.
* **Network** — interfaces with type/state/MAC/IPv4/IPv6/MTU/DHCP, routing
  tables, resolver configuration and real DNS queries (built-in client), IPv4
  and IPv6 connectivity, latency and packet loss, traceroute.
* **Discovery and scanning** — neighbor-table/ICMP/TCP discovery with MAC vendor
  lookup, TCP connect scanning with banner and TLS certificate detection,
  optional UDP probes. Public targets require explicit authorization.
* **Connections and processes** — live TCP/UDP connections mapped to processes,
  listening sockets with exposure classification, process inventory.
* **Security audit** — platform-aware firewall state, exposed services,
  account/password policy review, SSH configuration, file-integrity baselines
  (SHA-256) with added/removed/modified detection.
* **Doctor** — one command that runs all of the above and reports findings with
  severity, evidence, impact, recommendation and a transparent score.
* **Monitoring and reports** — live sampling (text or JSON Lines), and reports
  as text, JSON, CSV or self-contained HTML.

netRo is **local-first**: no telemetry, no external requests unless you
configure a speed-test server or explicitly run a scan.

## Supported platforms

| Platform | Status | Notes |
|----------|--------|-------|
| Linux (x64, arm64) | Primary, fully tested | Ubuntu/Debian/Fedora/Arch families; systemd and SysV; ufw/firewalld/nftables/iptables |
| Windows 10/11 (x64) | Implemented | PowerShell/CIM providers, Windows Defender Firewall, native elevation check; validate on your fleet before relying on it |
| macOS 12+ (Intel, Apple Silicon) | Implemented | BSD tools, Application Firewall/pf, `system_profiler`; validate on your fleet before relying on it |

CI builds and tests Linux, Windows x64, macOS x64 and macOS arm64. See
[`docs/FINAL_AUDIT.md`](docs/FINAL_AUDIT.md) for exactly what was executed
where.

## Install

### From a release binary

Download the archive for your platform from the releases page, unpack and put
`netro` on your `PATH`:

```sh
# Linux / macOS
tar -xzf netro-linux-x64.tar.gz
sudo install -m 0755 netro-linux-x64 /usr/local/bin/netro
netro version
```

```powershell
# Windows
Expand-Archive netro-windows-x64.exe.zip -DestinationPath .
.\netro-windows-x64.exe version
```

### From source

Requires a Rust toolchain (1.83+):

```sh
git clone https://github.com/ALSRKAL/netRo
cd netRo
cargo build --release
./target/release/netro version
```

To build without TLS probing (avoids the `ring` C dependency, useful for
cross-compiling without a target C toolchain):

```sh
cargo build --release --no-default-features
```

## Quick start

```sh
netro                            # interactive TUI (on a terminal)
netro doctor                     # full health check with evidence
netro doctor --json | jq         # machine-readable
netro system                     # OS/CPU/memory/storage/GPU
netro network interfaces
netro network dns example.com
netro network scan 127.0.0.1 --ports common
netro network scan 10.0.0.5 --authorized --ports 22,80,443
netro network discover --method auto
netro network speedtest --provider iperf3 --server speed.internal.example
netro connections --state ESTABLISHED
netro processes --sort memory --limit 10
netro security audit
netro firewall status
netro integrity baseline create && netro integrity scan
netro monitor --interval 2
netro report --html report.html
```

## Permissions

netRO never escalates privileges by itself. Commands that need it fail with:

```
error: PERMISSION_DENIED: blocking traffic requires root on Linux (hint: run the command with sudo, or as root)
```

Typical privilege requirements:

| Operation | Requirement |
|-----------|-------------|
| System/network/process inventory | Normal user |
| Process list of other users, TCP connections of other users | root/Administrator |
| Full `/etc/shadow` password status | root |
| ICMP ping | normal (stock `ping` is unprivileged on modern systems) |
| Firewall block/unblock | root/Administrator |
| `firewall block --dry-run` | normal user |
| macOS pf state | root |

## Optional dependencies

netRO detects tools instead of requiring them (`netro dependencies`):

| Tool | Used for |
|------|----------|
| `ping` | ICMP latency and sweeps (TCP fallback exists) |
| `traceroute` / `tracert` | hop addresses (built-in TCP tracer otherwise) |
| `nmap` | advanced discovery only; never required |
| `arp-scan` | layer-2 discovery (Linux) |
| `iperf3` | speed tests against your server |
| `lsof` | process↔connection mapping on macOS |
| `nvidia-smi` / `rocm-smi` | live GPU metrics |
| `rkhunter` / `chkrootkit` / `lynis` | opt-in external scans (`security audit --run-external`) |
| PowerShell | Windows network/firewall/account/service data |

## Security limitations

Read [`docs/SECURITY.md`](docs/SECURITY.md). In short: netRO is integrity
monitoring, not antivirus; findings are configuration evidence, not proof of
compromise; the built-in TCP tracer cannot see intermediate IPs; SYN and
reliable UDP scanning are not implemented and are reported as such.

## JSON and automation

Every command supports `--json` (or `--format csv`). JSON is one valid document
with no ANSI escapes:

```sh
netro doctor --json | jq '.data.summary'
netro monitor --json --count 5 | jq -c '.data | {cpu: .cpu_usage_percent, mem: .memory_utilization_percent}'
```

Example (abridged):

```json
{
  "command": "doctor",
  "schema_version": 1,
  "netro_version": "5.0.0",
  "data": {
    "checks": [
      { "id": "system", "status": "PASS", "summary": "Linux (Ubuntu 24.04) ..." },
      { "id": "security", "status": "FAIL", "summary": "score 82/100 (grade C), 5 finding(s)" }
    ],
    "summary": {
      "passed": 8, "warnings": 2, "failed": 1,
      "score": { "total": 82, "max": 100, "grade": "C",
                 "categories": [ { "category": "firewall", "score": 13, "max": 25 } ] }
    }
  }
}
```

Errors follow the same envelope:

```json
{"command":"error","error":{"code":"UNAUTHORIZED_SCAN","message":"...","hint":"..."}}
```

## Performance

Measured on Linux x86_64 with the release build (see `docs/FINAL_AUDIT.md`):

| Metric | Result |
|--------|--------|
| Startup (`netro version`) | ~12 ms |
| `netro system --json` | ~1.0 s, ~21 MB RSS |
| `netro doctor --json --no-internet` | ~4.7 s, ~22 MB RSS |
| `netro security audit --json` | ~0.7 s |
| 10,000-port localhost scan (512 workers) | ~0.37 s |
| Monitoring steady-state | ~16 ms per sample, near-idle CPU |
| TUI time-to-first-frame | immediate (checks stream in) |
| TUI idle CPU | ~0% (redraws throttled to 1 Hz when idle) |

CPU and memory sampling intentionally includes a short measuring window
(sysinfo requirement), which is why latency/CPU commands take a few hundred
milliseconds more than pure inventory commands.

## Development

```sh
cargo fmt --all -- --check          # formatting
cargo clippy --all-targets -- -D warnings
cargo test                          # 239 unit, CLI and TUI tests
cargo build --release
bash scripts/verify.sh              # full local gate (fmt, clippy, tests, JSON)
bash scripts/bench.sh               # performance baselines (CLI + TUI)
```

Cross-compile checks used in CI:

```sh
cargo check --target x86_64-pc-windows-gnu  --no-default-features
cargo check --target x86_64-apple-darwin    --no-default-features
cargo check --target aarch64-apple-darwin   --no-default-features
```

Layout:

```
src/cli.rs          clap definitions
src/commands/       one module per command group
src/core/           diagnostics logic (dns, scan, security, doctor, ...)
src/platform/       Linux/Windows/macOS providers implementing the traits
src/tui/            ratatui/crossterm UI (components, tasks, theme, state)
src/model.rs        serializable domain types (JSON contract)
tests/cli.rs        end-to-end CLI contract tests
docs/               architecture, CLI, security, audit, final audit
legacy/             original netRo.sh (reference only)
```

## Contributing

* Keep OS-specific code inside `src/platform/<os>/`; core must stay portable.
* Never add a shell invocation or a fabricated result. Unsupported features must
  return a structured error and be covered by a test.
* Add tests for parsers and new checks (`cargo test` must stay green).
* Run `cargo fmt` and `cargo clippy --all-targets -- -D warnings` before a PR.
* Document new commands in `docs/CLI.md` and update the README command list.

## License

MIT
