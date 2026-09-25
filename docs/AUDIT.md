# Audit of the legacy `netRo.sh` (v4.2)

This document records what the pre-rewrite shell script actually did, what was
incorrect or unsafe, and how the current Rust implementation addresses each
item. The legacy script is preserved unmodified at [`legacy/netRo.sh`](../legacy/netRo.sh);
it is not maintained and should not be used.

## Executive summary

The legacy script was a Linux-only, interactive Bash dashboard that mixed real
checks with placeholders and false-positive-prone heuristics. Its security
checks could not be trusted (`rootkit check` always said "skipped", all system
accounts were labelled "unauthorized", legitimate administration tools were
labelled "suspicious processes"), and its "block device" feature wrote
permanent firewall rules without confirmation or rollback. There were no tests,
no CI, no machine-readable output, and no Windows/macOS support.

## Findings and disposition

| # | Legacy behavior | Problem | Disposition in netRo 5.x |
|---|-----------------|---------|--------------------------|
| 1 | Single 733-line Bash script with hardcoded Linux commands (`ip`, `ss`, `free`, `top`, `stat`, `df`) | Linux-only; no abstraction | `platform/` trait layer with Linux/Windows/macOS providers; core has no OS commands |
| 2 | `update_system_info() { sleep 2; }` | Fake work presented as a background update | Removed; every displayed value comes from a real refresh |
| 3 | `check_suspicious_processes` greps for `nmap`, `wireshark`, `tcpdump`, `nc`, `john`… | Labels legitimate tools as "suspicious"; leaks other users' command lines | Removed. netRo never claims a process is malicious. Security findings are configuration-evidence based |
| 4 | `check_unauthorized_users` flags every UID < 1000 | All system accounts on Linux are UID < 1000 → guaranteed false positives | Replaced by an account inventory that distinguishes system accounts, login-capable accounts, privileged accounts (`admin`/`sudo`/`wheel`) and locked/empty passwords |
| 5 | `check_file_integrity` required mode exactly `644` for `/etc/passwd`, `/etc/shadow`, `/etc/sudoers` | `/etc/shadow` is normally `640`/`600`; strict equality flags correct systems and misses content changes | Replaced by SHA-256 baselines with added/removed/modified detection, permission/ownership deltas, and per-file skip reasons (`integrity`) |
| 6 | `check_rootkits` always prints "skipped" | Fake capability; no attempt to detect the tool | `security audit` detects rkhunter/chkrootkit/ClamAV/lynis and reports them as installed/missing; running them is opt-in (`--run-external`) and results are labelled `ExternalTool` |
| 7 | `check_cpu_usage` parses `top -bn1` with `grep/sed/awk/bc` | Breaks on locales/distros without `bc`; numeric comparison with `bc -l` | Uses sysinfo (native OS APIs); no text parsing of `top` |
| 8 | `detect_network_range` returns `gateway/24` by truncating the gateway's last octet | Wrong for any non-/24 network; scans the wrong range | CIDR math driven by the interface's real prefix; `/16`/`/12` etc. handled; bounded host enumeration |
| 9 | `block_device` runs `sudo iptables -A INPUT … && sudo iptables-save > /etc/iptables/rules.v4` | Silent privilege escalation, unconditional persistence, path may not exist, no rollback, no confirmation, and it cannot block a remote device (only local traffic) | `firewall block/unblock`: elevation required and reported, exact commands shown, `--dry-run`, explicit confirmation/`--yes`, per-backend rollback, state file for unblock; documentation states it blocks traffic **on this host** only |
| 10 | `nmap $custom_args "$target"` | Unquoted expansion → argument injection; arbitrary nmap flags | No shell, no user-supplied argument strings; explicit argument arrays and validated targets. netRo's own scanner is default; nmap is an optional, detected integration |
| 11 | `save_scan_results` writes to any user-supplied filename | Path traversal; clobbers arbitrary files | Reports go to explicit paths chosen by the user via `--html`/`--out`; no hidden redirection |
| 12 | Log file `/tmp/system_info.log`, `chmod 644`, truncate on start | Predictable path, world-readable, symlink attack surface | Logs under the per-user data dir with `0600`, append-only with rotation, no secrets (redaction) |
| 13 | `cleanup() { jobs -p | xargs kill; }` | Can kill unrelated jobs; `tput` errors without a TTY | No global job killing; `ctrlc` handler only stops the monitor loop |
| 14 | `tput colors` gate; exits if terminal unsupported | Fails in CI/dumb terminals | Color is optional (`--color auto/never`), output never requires a TTY |
| 15 | Public IP via `curl ifconfig.me` | External data leak by default, no timeout, dependency | No external calls at startup or by default. There is no public-IP fetch; speed tests require an explicit `--server` |
| 16 | Interactive menu only (`read -p`) | Not scriptable, hangs in non-interactive contexts | Subcommand CLI (`system`, `network`, `security`, `doctor`, …); no prompts unless action is destructive; `--json` everywhere |
| 17 | `ss -tuln` with no process attribution | No way to know what is exposed and by which process | Listening sockets map to processes where permissions allow; exposure scope is classified (`local`/`interface`/`all`) |
| 18 | `ping -c 4` only | Linux flags; macOS/Windows differ | Per-OS ping argument handling plus a native TCP latency fallback; method is reported in results |
| 19 | `nslookup` only | No configurable server, no record types, no latency | Built-in DNS client: UDP+TCP fallback, A/AAAA/CNAME/MX/TXT/NS/SOA/PTR/SRV, RTT, custom server, reverse lookups |
| 20 | No IPv6 support | Modern networks are dual-stack | IPv6 interfaces, routes, connectivity and neighbor handling throughout |
| 21 | No error model; `set -e` aborts | Missing tool or permission kills the whole dashboard | Structured error codes (`DEPENDENCY_MISSING`, `PERMISSION_DENIED`, …), per-check degradation, matching exit codes |
| 22 | No tests, no CI, no linting | Unknown correctness; regressions invisible | 173 automated tests (unit + CLI), Rustfmt/Clippy gates, CI on Ubuntu/Windows/macOS x64+arm64, release workflow |
| 23 | Version string `4.2` with no build info | No reproducibility | Semantic version `5.0.0` plus target, profile, commit, rustc and feature info in `netro version` |

## Behaviors intentionally preserved

* Quick, single-command inspection of system, network, storage and security.
* Interactive convenience: `netro tui` (live monitor) and confirmation prompts
  for destructive actions when running in a terminal.
* The original script is kept under `legacy/` for reference.

## Behavior changes users will notice

* No public-IP lookup by default (privacy).
* No automatic `sudo`: privileged operations fail with `PERMISSION_DENIED` and
  an elevation hint unless you run them elevated.
* "Blocking a device on the network" is no longer implied: netRo manages the
  local host firewall only.
* Findings are accompanied by evidence, impact, recommendation and a documented
  score impact; informational items never lower the score.
