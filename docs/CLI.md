# CLI reference

Global options (available before or after the subcommand):

```
--format <text|json|csv>   output format (default text)
--json                     shorthand for --format json
--color <auto|always|never>  color policy (default auto; NO_COLOR respected)
-v, --verbose...           increase log verbosity (-v, -vv)
--quiet                    suppress informational stderr messages
--log-level <debug|info|warn|error>
--log-file <PATH>          write logs to PATH (default: per-user data dir)
--yes                      assume "yes" for confirmation prompts (non-interactive)
```

Exit codes: `0` success, `1` generic/config, `2` usage error, `3` permission,
`4` dependency missing, `5` platform unsupported, `6` timeout, `7`
invalid/unauthorized target, `8` network/DNS.

---

## `netro` / `netro tui [--no-mouse] [--theme auto|dark|light|contrast|none]`
With no subcommand on an interactive terminal, netRo launches the TUI. Without a
terminal it prints help and exits (never hangs in scripts). `netro tui` is the
explicit form. See [`TUI.md`](TUI.md) for screens and key bindings.

## `netro version`
Prints name, semantic version, target triple, build profile, commit, rustc
version and enabled features. `--json` emits the same data as an object.

## `netro system [--cpu] [--memory] [--storage] [--gpu]`
OS, kernel, hostname, uptime, virtualization; CPU model/cores/usage/frequency/
load/temperatures; memory and swap; every mounted filesystem (size, usage,
read-only, removable); GPU vendor/model/VRAM/driver/utilization/temperature/
power when the driver exposes them. Without flags all sections are shown.

## `netro network interfaces`
Interface inventory: name, kind (loopback/ethernet/wifi/vpn/bridge/virtual/
docker/tunnel/bond), state, MAC, IPv4/IPv6 with prefix, link speed, MTU,
DHCP (when readable), and the interface carrying the default route.

## `netro network routes`
IPv4/IPv6 routing table with destination, gateway, interface, metric, flags and
default-route markers.

## `netro network dns [NAME] [--server IP[:PORT]] [--type TYPE] [--reverse]`
Without a name, shows resolver configuration and its source. With a name,
performs a real DNS query using the built-in resolver client (`A`, `AAAA`,
`CNAME`, `MX`, `TXT`, `NS`, `SOA`, `PTR`, `SRV`), reporting rcode, TTLs,
answers and response latency. `--reverse` performs a PTR lookup.

## `netro network discover [--method auto|neighbors|icmp|tcp|nmap] [--target CIDR] [--interface IF] [--max-hosts N] [--ports ...] [--no-dns] [--no-vendor]`
Discovers hosts on the machine's own subnets using the OS neighbor table,
optional ICMP sweep, optional TCP probes, or `nmap -sn` when installed.
Reports IP, hostname (reverse DNS), MAC, vendor (OUI), response time, open
ports probed and the evidence source for each host.

## `netro network scan <TARGET> [--ports common|all|LIST|RANGE] [--timeout-ms N] [--concurrency N] [--no-banner] [--no-tls] [--udp] [--open-only] [--authorized]`
TCP connect scan with bounded concurrency. For open ports it attempts banner
grabs and TLS handshakes (built with `--features tls`, default) and reports
service, product, version, certificate details and a confidence level.
UDP probing is available for DNS/NTP and reports `open|filtered` when no reply
is received. Public targets require `--authorized`.

## `netro network latency <TARGET> [--count N] [--method auto|icmp|tcp] [--port P] [--timeout-ms N]`
Latency and packet loss. `auto` uses the system `ping` when available and falls
back to TCP connect latency. The probe method is reported in the result.

## `netro network connectivity [--no-ipv6] [--timeout-ms N]`
Real checks for loopback, default gateway, DNS resolution, IPv4 and IPv6
internet reachability (TCP to anycast addresses). Every check includes target,
method, result and error/note.

## `netro network trace <TARGET> [--max-hops N] [--method auto|icmp|tcp] [--port P]`
Hop-by-hop path tracing. `icmp` uses the system `traceroute`/`tracert` and
reports hop addresses; the built-in `tcp` method reports hop distance and
latency (intermediate addresses appear as `*` because that requires raw ICMP).

## `netro network speedtest [--provider iperf3|http] [--server HOST|URL] [--port P] [--duration S] [--direction download|upload|both] [--udp]`
Throughput measurement against a user-specified server only. `iperf3` captures
throughput, jitter and packet loss from iperf3 JSON. `http` performs streamed
downloads and chunked uploads against an http(s) URL. No third-party service is
contacted implicitly.

## `netro connections [--state S] [--process P] [--port N] [--remote ADDR] [--protocol tcp|udp] [--listen] [--limit N]`
Active TCP/UDP connections with local/remote endpoints, state, PID and process
name where permissions allow. `--listen` lists listening sockets with exposure
scope (`local`, `interface`, `all`).

## `netro processes [--sort cpu|memory|pid|recent|name] [--limit N] [--pid P] [--name SUBSTR] [--network]`
Process inventory with CPU, memory, user, runtime, status and executable path.
`--network` restricts to processes with active network connections.

## `netro security audit [--run-external]`
Evidence-based audit: firewall state, exposed listeners (telephone/FTP/r-services,
unauthenticated Docker API, databases, VNC, RDP, WinRM, SSH/HTTP informationally),
account analysis (empty passwords, privileged accounts, system accounts with
login shells), password policy, and SSH server configuration on Unix. Findings
carry severity, evidence, impact, recommendation, confidence, source and an
explicit score impact. `--run-external` optionally runs rkhunter/chkrootkit/
lynis and labels the output as external.

## `netro security accounts` / `netro security listening`
Focused views of the account inventory and listening sockets.

## `netro firewall status|rules [--limit N]`
Shows detected backends (ufw, firewalld, nftables, iptables, Windows Defender
Firewall profiles, macOS Application Firewall/pf) with state and the command
used to check it.

## `netro firewall block <IP> [--dry-run]` / `netro firewall unblock <IP> [--dry-run]`
Manages a rule **on this host** for the given IP. Requires elevation to apply
(dry-run does not). Shows the exact commands and the rollback, and records state
so `unblock` removes only netRO-created rules. Confirmation is required in
interactive mode; `--yes` is required when not attached to a terminal.

## `netro integrity baseline [--paths p1,p2] [--max-size-mb N]`
Creates a SHA-256 baseline (size, mtime, mode, uid/gid) for the given paths
(defaults: platform-critical configuration files).

## `netro integrity scan [--max-size-mb N] [--all]`
Compares the current state against the baseline and reports ADDED, REMOVED and
MODIFIED entries with details. Unreadable or oversized files are listed with the
reason. This is integrity monitoring, not malware detection.

## `netro integrity show`
Baseline metadata (creation time, host, paths, entry count).

## `netro doctor [--run-external] [--no-internet] [--dependencies]`
Unified health check. Sections: System, CPU, Memory, Storage, GPU, Network,
Routes, DNS, Internet, Firewall, Processes, Security. Each check reports status
(`PASS`/`WARNING`/`FAIL`/`UNSUPPORTED`/`SKIPPED`), a summary and evidence.
Findings are listed with severity and recommendations, and the security score is
shown with per-category deductions and the methodology. `--dependencies` lists
optional external tools.

## `netro monitor [--interval S] [--count N] [--duration S] [--top N] [--no-processes] [--active-net]`
Live sampling of CPU (global and per-core), load, memory, swap, network rates
per interface, temperatures and top processes. `--json` emits one JSON object
per line (JSON Lines) for pipelines. Ctrl-C stops cleanly.

## `netro tui`
Alias of `netro monitor` with the interactive text display.

## `netro report [--html PATH] [--out PATH] [--no-internet] [--no-security] [--no-system]`
Builds a full report. Default output is text; `--json`/`--format csv` select
other formats; `--out` writes it to a file; `--html` writes a self-contained
HTML report with escaped values, findings and limitations.

## `netro config show|path|init|set <key> <value>`
Configuration lives at the platform config directory (`~/.config/netro/`,
`~/Library/Application Support/netro/`, `%APPDATA%\netro`). `set` validates
dotted keys such as `scan.timeout_ms`, `monitor.interval_secs`,
`integrations.oui_file` or `privacy.reverse_dns`.

## `netro dependencies [--missing]`
Optional external tools relevant to the current platform with installed state,
version, path and purpose.

---

## JSON contract

Every command emits an envelope when `--json` is used:

```json
{
  "command": "doctor",
  "schema_version": 1,
  "netro_version": "5.0.0",
  "generated_at_epoch": 1790000000,
  "data": { }
}
```

Errors emit `{"command":"error","error":{"code","message","hint"}}` and use the
exit codes above. Monitoring emits the same envelope once per line (JSON Lines).
