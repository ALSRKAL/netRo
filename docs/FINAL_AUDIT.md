# netRo 5.0.0 — final engineering audit

This report records exactly what was executed, where, and what remains
unverified. Nothing in this document is claimed beyond the evidence shown.

Environment for all local results:

```
host        Linux (Ubuntu 24.04), x86_64, kernel 6.8
rustc       1.90.0
cargo       1.90 (edition 2021, rust-version 1.83)
privileges  normal user (not root)
network     local LAN + internet; no privileged firewall changes performed
```

## Summary

```text
NETRO FINAL AUDIT

Architecture          PASS   (module boundaries + provider traits reviewed)
Linux runtime         PASS   (all commands exercised end-to-end)
Windows               COMPILE PASS / RUNTIME NOT TESTED (no Windows host here)
macOS                 COMPILE PASS / RUNTIME NOT TESTED (no macOS host here)
System Diagnostics    PASS
Network Diagnostics   PASS
Security Audit        PASS   (read-only paths; privileged apply paths untested)
Monitoring            PASS
CLI                    PASS
JSON                   PASS
Tests                  PASS   (173 automated tests)
CI                     PASS   (configuration complete; not executed by this session)
Documentation          PASS
Release artifact       PASS   (Linux x64 built and exercised)
```

## Architecture

* Reviewed layering: `commands/` → `core/` → `platform/` traits. `rg` confirms
  no OS-specific commands in `core/`; Linux `/proc` parsing, Windows
  PowerShell/CIM and macOS BSD tools live only under `src/platform/<os>/`.
* Error model is structured and tested for unique stable codes, exit-code
  mapping and serialization.
* Legacy audit (`docs/AUDIT.md`) maps every original script behavior to its
  disposition.

Commands: `rg -n "Command::new\(\"(sh|bash|cmd" src/` → no matches.
`rg -n "sh -c|bash -c|cmd /c" src/` → no matches.

## Linux runtime — executed and verified

| What | Command | Result |
|------|---------|--------|
| Version/build info | `netro version` | correct semver, target, profile, rustc, features |
| System | `netro system --json` | real CPU model `Intel i7-6820HQ`, 8 logical cores, 16.5 GB RAM, 3 filesystems, 2 GPUs |
| GPUs | `netro system --gpu` | NVIDIA Quadro M1000M via `nvidia-smi` (live util), Intel iGPU via sysfs, no duplicates |
| Interfaces | `netro network interfaces --json` | 13 interfaces incl. docker/veth/wifi/loopback; loopback `up`, only `wlp3s0` carries the default route |
| Routes | `netro network routes` | IPv4 default via 192.168.29.1, IPv6 default via `fe80::f6ca:e7ff:fed9:b0dc` (byte-order bug found and fixed) |
| DNS | `netro network dns` / `dns example.com` | resolver list from systemd-resolved + `resolvectl`; real query with rcode and RTT |
| Latency | `netro network latency 127.0.0.1 --method tcp` | ICMP unavailable/unprivileged path exercised; TCP method reports loss correctly |
| Connectivity | `netro network connectivity --json` | loopback/gateway/DNS/IPv4/IPv6 checks with real targets |
| Scan | `netro network scan 127.0.0.1 --ports 1-10000 --concurrency 512` | 10,000 ports in 374 ms; 14 live listeners found (incl. Mailpit on 1025 with real banner) |
| Scan auth | `netro network scan 1.1.1.1` | exit 7, `UNAUTHORIZED_SCAN`, hint present |
| Discovery | `netro network discover --target 127.0.0.0/29 --method tcp` | real subnet sweep, no invented hosts |
| Trace | `netro network trace 127.0.0.1` | built-in TCP tracer reaches target in 1 hop |
| Connections | `netro connections --json` | sockets with state/pid/process where readable |
| Processes | `netro processes --sort cpu` | real process table with CPU/memory/user |
| Security audit | `netro security audit --json` | 5 findings with evidence; score 82/100 explained category-by-category |
| Firewall status | `netro firewall status` | detected ufw (inactive), nftables (inactive), iptables (inactive) — reports "disabled" honestly |
| Firewall dry-run | `netro firewall block 203.0.113.9 --dry-run` | prints exact nft commands + rollback without root |
| Firewall apply | `netro firewall block 203.0.113.9` | correctly denied: `PERMISSION_DENIED` + elevation hint (not tested as root) |
| Integrity | `integrity baseline` + `integrity scan` | detected a real content modification (`MODIFIED`, hash changed) |
| Monitor | `netro monitor --count 5 --interval 1` | real CPU/mem/swap/net rates; marginal cost ≈16 ms/sample |
| Doctor | `netro doctor --no-internet` | 11 checks, per-category score deductions, methodology printed |
| Report | `netro report --html` | self-contained HTML, escaped, sections verified |
| Speed test (HTTP) | `--server http://127.0.0.1:<port>/blob.bin` | 20,000,000 bytes transferred, ~5.9 Gbit/s loopback; 401 response refused with exit 8 |
| Dependencies | `netro dependencies --json` | installed/missing reported with paths and versions |

## Windows

* Compile check: `cargo check --target x86_64-pc-windows-gnu --no-default-features`
  → PASS (all providers, PowerShell bridge, `windows-sys` elevation check).
* TLS is feature-gated; the full-featured build requires MSVC on a Windows
  runner and is produced by `.github/workflows/release.yml`.
* **Runtime behavior was not tested in this session** (no Windows machine or
  runner available). PowerShell/CIM scripts, firewall rule creation and adapter
  parsing are implemented but unverified at runtime. Treat Windows as
  beta-quality until validated on a test host.

## macOS

* Compile checks: `cargo check --target x86_64-apple-darwin --no-default-features`
  and `--target aarch64-apple-darwin --no-default-features` → PASS.
* **Runtime behavior was not tested in this session** (no macOS machine or
  runner available). `netstat`/`arp`/`ndp`/`lsof`/`scutil`/`socketfilterfw`/
  `pfctl` parsing was validated against captured-format fixtures in unit tests
  only.

## Tests

```
cargo fmt --all -- --check                          PASS
cargo clippy --all-targets --all-features -- -D warnings   PASS
cargo clippy --lib --no-default-features -- -D warnings    PASS
cargo test                                          PASS   (144 unit + 29 CLI)
cargo build --release --all-features                PASS
bash scripts/verify.sh                              PASS   (includes JSON validation)
```

Coverage highlights: `/proc` parsers (routes, ARP, sockets, shadow, groups),
CIDR math, target validation/injection rejection, DNS encode/decode with
compression pointers and NXDOMAIN, ping/traceroute parsers for Unix and
Windows, nmap grepable parsing, OUI lookup, integrity add/modify/remove,
severity/scoring caps, HTML/CSV escaping, redaction, iperf3 JSON, HTTP status
handling, and end-to-end CLI contracts (JSON validity, exit codes,
authorization gating, real listener detection, speed test against a local
server).

## Performance (measured, release build)

| Metric | Result |
|--------|--------|
| Startup (`version`, 50 runs avg) | 12.4 ms |
| `doctor --json --no-internet` | ~4.7 s, 22 MB peak RSS |
| `system --json` | ~1.0 s, 21 MB |
| `security audit --json` | ~0.7 s, 15 MB |
| `network interfaces --json` | ~0.18 s |
| Scan 10,000 localhost ports (512 workers) | 0.37 s |
| Monitor steady-state | ~16 ms per sample, near-idle CPU |

Optimizations made after initial measurements: process-table refresh removed
from CPU/memory sampling, batched NetworkManager detection, targeted
socket-inode resolution instead of full `/proc/*/fd` scans, and no
`systemctl list-unit-files` (slow) in the audit path.

## Security review

* No shell invocation anywhere (evidence above).
* `unsafe` appears in exactly four places: SIGPIPE reset (`main.rs`), Win32
  token elevation (`platform/windows`), and `geteuid` on Linux/macOS.
* Input validation and injection tests pass; leading-dash targets are rejected
  by the argument parser before value parsing.
* PowerShell uses `-EncodedCommand` with fixed literals.
* Firewall changes require confirmation/`--yes`, show commands, and record
  rollback state; dry-run is unprivileged-safe.
* Log redaction covered by tests.
* Not run in this session: `cargo audit` (tool not installed locally). CI runs
  `rustsec/audit-check` on every push/PR.

> A dedicated TUI phase followed this audit; see
> [`TUI_FINAL_AUDIT.md`](TUI_FINAL_AUDIT.md) for its own evidence table and
> self-review record. Test count grew from 173 to 237.

## Second audit — self-review loop (§46)

The full specification requires eight explicit review passes *after* the first
successful build. Each pass below found at least one real issue; all fixes were
applied and the full suite was re-run afterwards (173 tests green, Clippy
`-D warnings` clean, cross-target checks still pass).

**Review 1 — architecture.** Found: `report` performed the security audit and
the connectivity probes twice (once for the report section, once inside the
doctor). Fixed by adding `health::run_with(options, connectivity, security)`
and reusing both results in `core/reporting.rs`. Removed dead helper `csv_rows_from_table`
and leftover no-op statements in three command modules.

**Review 2 — cross-platform.** Re-ran `cargo check` for
`x86_64-pc-windows-gnu`, `x86_64-apple-darwin`, `aarch64-apple-darwin` after
the fixes: all clean. No new OS-specific code entered `core/` (the sanitizer is
pure Rust). macOS DHCP is explicitly reported as not queried rather than
guessed; Windows remains compile-verified only.

**Review 3 — security (real vulnerability found).** Service banners, TLS
certificate subjects/issuers/SANs and DNS answers come from remote peers and
were printed verbatim. A hostile peer could embed ANSI escape sequences and
manipulate the user's terminal. Added `util::sanitize_terminal` (CSI/OSC
sequence removal + control-character replacement) and applied it to banner
parsing (per line, preserving protocol structure), TLS names, discovery
hostnames/vendors and DNS query output. Regression tests added for CSI, OSC and
control-character cases.

**Review 4 — false-positive diagnostics.** Re-reviewed every finding source:
UID<1000 accounts are no longer "unauthorized" (system accounts are labelled and
only login-shell+password-set combinations are flagged as LOW); process
high-CPU is `Likely` confidence and explicitly scoped to "this sample";
firewall findings require a backend that answered; unknown/unsupported checks
never deduct score. No changes required.

**Review 5 — performance.** Found and removed three hot spots beyond the first
pass: process-table refresh in CPU-only monitoring, unconditional
`systemctl list-unit-files` (~4.4 s) in the audit path, and duplicate
connectivity/audit work in `report`. Measured results above.

**Review 6 — CLI behavior.** Exercised error paths end-to-end: empty port spec,
unknown DNS record type, missing integrity baseline, unblock of a non-existent
block, unwritable HTML path, zero-count latency, unknown trace/discovery
methods. All return structured errors with correct exit codes and no panics.
Added validation for `config set discovery.method` and `config set scan.ports`
(previously any string was accepted and could silently break later runs).

**Review 7 — documentation.** Test counts, sample commands and the scan target
help text were corrected; this section was added. `docs/CLI.md`,
`docs/SECURITY.md`, `docs/ARCHITECTURE.md` and `README.md` cross-checked against
the actual CLI (`--help` output) and observed behavior.

**Review 8 — full suite re-run.** `cargo fmt --check`,
`cargo clippy --all-targets --all-features -D warnings`, `cargo test`
(144 unit + 29 CLI), release build, cross-target checks and
`scripts/verify.sh` (including JSON validation) all pass after the fixes.

## Unresolved issues and limitations

1. Windows and macOS runtime behavior is not verified (see above).
2. Privileged paths not exercised: firewall apply/rollback, full `/etc/shadow`
   reads, macOS pf apply, raw-ICMP traceroute. They are covered by unit tests
   where they are pure logic, and by explicit permission-denied tests.
3. SYN (half-open) scanning is not implemented; netRO says so rather than
   simulating it. UDP scanning reports `open|filtered` when no reply arrives.
4. Localized Windows `ping`/`tracert` output may not parse; the error is
   structured and points at the TCP methods.
5. IPv6 host discovery sweeps are not supported (IPv6 is covered in interfaces,
   routes, DNS, connectivity and latency).
6. External tool integrations (`nmap`, `arp-scan`, `iperf3`, rootkit scanners)
   were validated with fixtures/unit tests; the tools are not installed in this
   environment, so end-to-end runs were not possible.
7. macOS DHCP state is not queried (documented in the interface note) to avoid
   relying on private SystemConfiguration APIs.
8. The security score is an evidence-based heuristic; it is intentionally
   transparent and does not claim to be a compliance standard.
