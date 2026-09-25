# Architecture

## Goals

* One code base for Linux, Windows and macOS.
* No fake data: every result is a real measurement or an explicit
  `UNSUPPORTED`/`SKIPPED`/`PERMISSION_DENIED` outcome.
* Scriptable: a stable CLI and JSON contract, valid without a TTY.
* Safe: no shell, validated inputs, explicit confirmations, no automatic
  privilege escalation.

## Language decision

Rust was selected over Go and Python:

| Criterion | Rust | Go | Python |
|-----------|------|----|--------|
| Windows APIs / FFI | First-class, no runtime | First-class | Needs C extensions |
| Linux/macOS system access | First-class | First-class | First-class |
| Single static binary, no runtime | Yes | Yes | No |
| Memory/concurrency safety | Compile-time | Runtime GC | Interpreter |
| Startup time / footprint | Very low | Low | High |
| Dependency management | Cargo + lockfile | Modules | pip/venv |
| Distribution without toolchain | Yes | Yes | No |

Python would have required shipping an interpreter or a bundler, and Go was not
available in the development environment. Rust also lets the same source compile
for Windows/macOS with only the platform module differing.

## Layering

```
CLI (clap) ──► commands/ ──┐
                           ├──► core/ ──► platform/ (trait) ──► OS APIs, /proc, sysctl, CIM
TUI (ratatui/crossterm) ──►┘         └──► util, model, output, config, logging
   │
   └── tui/tasks.rs: worker threads, typed TaskResult, cooperative cancel
```

The TUI is a second presentation layer over the same core APIs; it contains no
diagnostics of its own and never constructs shell commands. See
[`TUI.md`](TUI.md).

* `src/cli.rs` — clap definitions only; no logic.
* `src/commands/` — presentation and argument handling; formats output through
  `output.rs`; never touches OS-specific APIs directly.
* `src/core/` — diagnostics logic: dns, diagnostics (ping/trace/connectivity),
  discovery, scan, security, integrity, health, monitoring, reporting,
  speedtest, oui.
* `src/platform/` — the only place with OS knowledge.
  * `platform/mod.rs` defines the provider traits and selects the compile-time
    implementation.
  * `platform/shared.rs` contains cross-platform helpers built on `sysinfo`
    (CPU, memory, processes, disks, temperatures).
  * `platform/linux/` — `/proc` and `/sys` parsers, ufw/firewalld/nft/iptables,
    nvidia-smi/rocm-smi/sysfs GPU detection, systemd services.
  * `platform/windows/` — PowerShell/CIM providers (invoked with
    `-EncodedCommand`, never string interpolation), Win32 token elevation check,
    Windows Defender Firewall control.
  * `platform/macos/` — netstat/arp/ndp/lsof/scutil/socketfilterfw/pfctl/
    `system_profiler`, `launchctl`, `dscacheutil`.
* `src/model.rs` — serializable domain types; the JSON contract.
* `src/util.rs` — process execution without a shell, PATH lookup, target
  validation, CIDR math, formatting, redaction, escaping.
* `src/error.rs` — structured error codes and exit-code mapping.
* `src/config.rs`, `src/logging.rs`, `src/output.rs` — configuration
  directories, structured logs, text/JSON/CSV emission.

## The provider traits

```rust
pub trait SystemProvider    { os_info, cpu_info, memory_info, disks, gpu_info, temperatures }
pub trait NetworkProvider   { interfaces, routes, dns_config, neighbors, listening_ports }
pub trait ProcessProvider   { processes, connections, process_connections }
pub trait SecurityProvider  { accounts, password_policy, firewall_status, firewall_rules, services }
pub trait FirewallControl   { block_ip, unblock_ip }
pub trait Platform: SystemProvider + NetworkProvider + ProcessProvider
                  + SecurityProvider + FirewallControl {
    fn id(&self) -> PlatformId;
    fn is_elevated(&self) -> bool;
    fn elevation_hint(&self) -> &'static str;
    fn dependencies(&self) -> Vec<Dependency>;
}
```

`platform()` returns `&'static dyn Platform` selected by `#[cfg(target_os)]`.
Adding a platform means implementing the traits — no changes to `core/`.

## Error model

Every failure returns `NetroError { code, message, hint, source }` with a stable
code:

`PERMISSION_DENIED`, `OPERATION_NOT_PERMITTED`, `DEPENDENCY_MISSING`,
`PLATFORM_UNSUPPORTED`, `TIMEOUT`, `INVALID_TARGET`, `UNAUTHORIZED_SCAN`,
`NETWORK_DNS_UNAVAILABLE`, `NETWORK_UNREACHABLE`, `NOT_FOUND`, `IO_ERROR`,
`PARSE_ERROR`, `CONFIG_ERROR`, `CANCELLED`, `CONFIRMATION_REQUIRED`,
`NOT_A_TERMINAL`, `ERROR`.

Exit codes: 1 generic, 2 clap usage, 3 permission, 4 dependency, 5 unsupported,
6 timeout, 7 invalid/unauthorized target, 8 network/DNS.

## Security posture

* No `sh -c`/`cmd /c`: all external programs run with explicit argument vectors.
* PowerShell scripts are fixed literals passed via UTF-16LE base64; user data
  (IP addresses, paths) is validated before use and never concatenated into
  script text except as validated IP literals in firewall rules.
* Targets reject leading `-` and shell metacharacters even though no shell is
  used.
* Firewall changes: elevation required (except `--dry-run`), exact commands
  displayed, confirmation/`--yes`, rollback recorded.
* Log values matching secret-like keys are redacted.
* Privacy: no telemetry, no external requests unless the user configures a
  speed-test server or performs a scan.

## Scaling and limits

* Port scans use a scoped thread pool bounded by `--concurrency`.
* Discovery caps hosts (`--max-hosts`) and probes with bounded concurrency.
* Integrity baselines cap file count/depth and skip files over the configured
  size with a stated reason.
* JSON output is streamed for monitoring (`JSON Lines`).
