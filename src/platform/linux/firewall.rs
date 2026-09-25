//! Linux firewall inspection and controlled block/unblock.
//!
//! Backends are detected, never assumed: ufw, firewalld, nftables, iptables
//! (and ip6tables for IPv6). Destructive operations require root, only accept
//! validated IP literals, always show the exact commands, and record enough
//! state to roll back.

use crate::error::{permission_denied, ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::platform;
use crate::util::{self, which};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use std::path::PathBuf;
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum LinuxBackend {
    Ufw,
    Firewalld,
    Nftables,
    Iptables,
}

impl LinuxBackend {
    pub fn name(self) -> &'static str {
        match self {
            LinuxBackend::Ufw => "ufw",
            LinuxBackend::Firewalld => "firewalld",
            LinuxBackend::Nftables => "nftables",
            LinuxBackend::Iptables => "iptables",
        }
    }
}

#[derive(Debug, Default, Serialize, Deserialize)]
struct BlockState {
    rules: Vec<BlockRecord>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct BlockRecord {
    ip: String,
    backend: String,
    handle: Option<String>,
    family: String,
}

fn state_path() -> PathBuf {
    crate::config::data_dir().join("firewall-blocks.json")
}

fn load_state() -> BlockState {
    std::fs::read_to_string(state_path())
        .ok()
        .and_then(|s| serde_json::from_str(&s).ok())
        .unwrap_or_default()
}

fn save_state(state: &BlockState) -> Result<()> {
    crate::config::ensure_dirs()?;
    let path = state_path();
    std::fs::write(&path, serde_json::to_string_pretty(state)?)?;
    crate::config::restrict_permissions(&path);
    Ok(())
}

fn backend_binary(backend: LinuxBackend) -> Option<PathBuf> {
    let program = match backend {
        LinuxBackend::Ufw => "ufw",
        LinuxBackend::Firewalld => "firewall-cmd",
        LinuxBackend::Nftables => "nft",
        LinuxBackend::Iptables => "iptables",
    };
    which(program)
}

/// Detect all known firewall backends present on the system and their state.
pub fn detect() -> FirewallStatus {
    let mut status = FirewallStatus::default();
    let mut any_active = false;
    let mut any_readable = false;

    if let Some(path) = which("ufw") {
        let out = util::run_command(&path.to_string_lossy(), &["status", "verbose"], CMD_TIMEOUT);
        match out {
            Ok(o) => {
                any_readable = true;
                let active = o.stdout.contains("Status: active");
                any_active |= active;
                status.backends.push(FirewallBackend {
                    name: "ufw".into(),
                    active: Some(active),
                    detail: o
                        .stdout
                        .lines()
                        .find(|l| l.starts_with("Default:"))
                        .map(|s| s.trim().to_string()),
                    via: "ufw status verbose".into(),
                });
            }
            Err(e) => status.backends.push(FirewallBackend {
                name: "ufw".into(),
                active: None,
                detail: Some(e.message().to_string()),
                via: "ufw status verbose".into(),
            }),
        }
    }

    if let Some(path) = which("firewall-cmd") {
        let out = util::run_command(&path.to_string_lossy(), &["--state"], CMD_TIMEOUT);
        match out {
            Ok(o) => {
                any_readable = true;
                let running = o.stdout.trim() == "running";
                any_active |= running;
                status.backends.push(FirewallBackend {
                    name: "firewalld".into(),
                    active: Some(running),
                    detail: (!running)
                        .then(|| o.stdout.trim().to_string())
                        .filter(|s| !s.is_empty()),
                    via: "firewall-cmd --state".into(),
                });
            }
            Err(e) => status.backends.push(FirewallBackend {
                name: "firewalld".into(),
                active: None,
                detail: Some(e.message().to_string()),
                via: "firewall-cmd --state".into(),
            }),
        }
    }

    if let Some(path) = which("nft") {
        let out = util::run_command(&path.to_string_lossy(), &["list", "ruleset"], CMD_TIMEOUT);
        match out {
            Ok(o) => {
                any_readable = true;
                let rule_count = o.stdout.lines().filter(|l| !l.trim().is_empty()).count();
                let active = rule_count > 0;
                any_active |= active;
                status.backends.push(FirewallBackend {
                    name: "nftables".into(),
                    active: Some(active),
                    detail: Some(format!("{rule_count} ruleset lines")),
                    via: "nft list ruleset".into(),
                });
            }
            Err(e) => status.backends.push(FirewallBackend {
                name: "nftables".into(),
                active: None,
                detail: Some(e.message().to_string()),
                via: "nft list ruleset".into(),
            }),
        }
    }

    if let Some(path) = which("iptables") {
        let out = util::run_command(&path.to_string_lossy(), &["-S"], CMD_TIMEOUT);
        match out {
            Ok(o) => {
                any_readable = true;
                // Built-in chains alone are not an active policy.
                let custom = o
                    .stdout
                    .lines()
                    .filter(|l| l.starts_with("-A") || l.starts_with("-I"))
                    .count();
                let active = custom > 0;
                any_active |= active;
                status.backends.push(FirewallBackend {
                    name: "iptables".into(),
                    active: Some(active),
                    detail: Some(format!("{custom} rules")),
                    via: "iptables -S".into(),
                });
            }
            Err(e) => status.backends.push(FirewallBackend {
                name: "iptables".into(),
                active: None,
                detail: Some(e.message().to_string()),
                via: "iptables -S".into(),
            }),
        }
    }

    if status.backends.is_empty() {
        status.notes.push(
            "no supported firewall backend found (checked ufw, firewalld, nftables, iptables)"
                .into(),
        );
        status.enabled = None;
    } else if any_readable {
        status.enabled = Some(any_active);
    } else {
        status.enabled = None;
        status.notes.push(
            "firewall state could not be fully determined (permission or service unavailable)"
                .into(),
        );
    }
    if !platform().is_elevated() {
        status
            .notes
            .push("rule inspection may be incomplete without root privileges".into());
    }
    status
}

/// Read a preview of loaded rules.
pub fn rules(limit: usize) -> Result<Vec<FirewallRule>> {
    let mut out = Vec::new();
    if let Some(path) = which("ufw") {
        if let Ok(o) = util::run_command(
            &path.to_string_lossy(),
            &["status", "numbered"],
            CMD_TIMEOUT,
        ) {
            for line in o.stdout.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with("To") || trimmed.starts_with("--") {
                    continue;
                }
                out.push(FirewallRule {
                    backend: "ufw".into(),
                    chain: None,
                    action: trimmed
                        .split_whitespace()
                        .last()
                        .unwrap_or("UNKNOWN")
                        .to_string(),
                    source: None,
                    destination: None,
                    ports: trimmed.split_whitespace().next().map(|s| s.to_string()),
                    protocol: None,
                    raw: trimmed.to_string(),
                });
                if out.len() >= limit {
                    return Ok(out);
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(path) = which("nft") {
            if let Ok(o) = util::run_command(
                &path.to_string_lossy(),
                &["-a", "list", "ruleset"],
                CMD_TIMEOUT,
            ) {
                for line in o.stdout.lines() {
                    let trimmed = line.trim();
                    if !trimmed.contains("rule") && !trimmed.is_empty() {
                        continue;
                    }
                    if trimmed.is_empty() {
                        continue;
                    }
                    out.push(FirewallRule {
                        backend: "nftables".into(),
                        chain: None,
                        action: trimmed
                            .split_whitespace()
                            .last()
                            .unwrap_or("UNKNOWN")
                            .to_string(),
                        source: None,
                        destination: None,
                        ports: None,
                        protocol: None,
                        raw: trimmed.to_string(),
                    });
                    if out.len() >= limit {
                        return Ok(out);
                    }
                }
            }
        }
    }
    if out.is_empty() {
        if let Some(path) = which("iptables") {
            let o = util::run_command(&path.to_string_lossy(), &["-S"], CMD_TIMEOUT)?;
            for line in o.stdout.lines() {
                if !line.starts_with("-A") && !line.starts_with("-P") {
                    continue;
                }
                out.push(FirewallRule {
                    backend: "iptables".into(),
                    chain: None,
                    action: line
                        .split_whitespace()
                        .find(|t| t.starts_with("-j") || *t == "DROP" || *t == "ACCEPT")
                        .unwrap_or("UNKNOWN")
                        .to_string(),
                    source: None,
                    destination: None,
                    ports: None,
                    protocol: None,
                    raw: line.to_string(),
                });
                if out.len() >= limit {
                    break;
                }
            }
        }
    }
    if out.is_empty() {
        return Err(NetroError::new(
            ErrorCode::PlatformUnsupported,
            "no firewall backend is readable on this system",
        ));
    }
    Ok(out)
}

fn choose_backend() -> Option<(LinuxBackend, PathBuf)> {
    let status = detect();
    let active = |name: &str| {
        status
            .backends
            .iter()
            .find(|b| b.name == name)
            .and_then(|b| b.active)
            .unwrap_or(false)
    };
    if active("ufw") {
        if let Some(p) = which("ufw") {
            return Some((LinuxBackend::Ufw, p));
        }
    }
    if active("firewalld") {
        if let Some(p) = which("firewall-cmd") {
            return Some((LinuxBackend::Firewalld, p));
        }
    }
    if let Some(p) = which("nft") {
        return Some((LinuxBackend::Nftables, p));
    }
    if let Some(p) = which("iptables") {
        return Some((LinuxBackend::Iptables, p));
    }
    None
}

fn family_of(ip: &str) -> &'static str {
    match ip.parse::<IpAddr>() {
        Ok(IpAddr::V4(_)) => "ipv4",
        Ok(IpAddr::V6(_)) => "ipv6",
        Err(_) => "ipv4",
    }
}

pub fn block(ip: &str, dry_run: bool) -> Result<FirewallChange> {
    if ip.parse::<IpAddr>().is_err() {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{ip}' is not an IP address"),
        ));
    }
    if !dry_run && !platform().is_elevated() {
        return Err(permission_denied("blocking traffic requires root on Linux")
            .with_hint(platform().elevation_hint()));
    }
    let (backend, binary) = choose_backend().ok_or_else(|| {
        NetroError::new(
            ErrorCode::PlatformUnsupported,
            "no usable firewall backend (ufw/firewalld/nftables/iptables)",
        )
    })?;
    let binary = binary.to_string_lossy().to_string();
    let mut commands: Vec<Vec<String>> = Vec::new();
    let mut rollback: Vec<Vec<String>> = Vec::new();
    let mut handle = None;
    let family = family_of(ip);

    match backend {
        LinuxBackend::Ufw => {
            commands.push(vec!["deny".into(), "from".into(), ip.into()]);
            rollback.push(vec![
                "delete".into(),
                "deny".into(),
                "from".into(),
                ip.into(),
            ]);
        }
        LinuxBackend::Firewalld => {
            let rule = format!("rule family={family} source address={ip} drop",);
            commands.push(vec![
                "--permanent".into(),
                format!("--add-rich-rule={rule}"),
            ]);
            commands.push(vec!["--reload".into()]);
            rollback.push(vec![
                "--permanent".into(),
                format!("--remove-rich-rule={rule}"),
            ]);
            rollback.push(vec!["--reload".into()]);
        }
        LinuxBackend::Nftables => {
            // Self-contained table so netRO never edits unrelated rulesets.
            let table_exists =
                util::run_command(&binary, &["list", "table", "inet", "netro"], CMD_TIMEOUT)
                    .map(|o| o.success())
                    .unwrap_or(false);
            if !table_exists {
                commands.push(vec![
                    "add".into(),
                    "table".into(),
                    "inet".into(),
                    "netro".into(),
                ]);
                commands.push(vec![
                    "add".into(),
                    "chain".into(),
                    "inet".into(),
                    "netro".into(),
                    "input".into(),
                    "{ type filter hook input priority filter; policy accept; }".into(),
                ]);
            }
            let addr_family = if family == "ipv6" { "ip6" } else { "ip" };
            commands.push(vec![
                "add".into(),
                "rule".into(),
                "inet".into(),
                "netro".into(),
                "input".into(),
                addr_family.into(),
                "saddr".into(),
                ip.into(),
                "drop".into(),
            ]);
            rollback.push(vec![
                "delete".into(),
                "table".into(),
                "inet".into(),
                "netro".into(),
            ]);
        }
        LinuxBackend::Iptables => {
            let tool = if family == "ipv6" {
                "ip6tables"
            } else {
                "iptables"
            };
            let tool = which(tool)
                .map(|p| p.to_string_lossy().to_string())
                .unwrap_or_else(|| "iptables".into());
            commands.push(vec![
                "-w".into(),
                "-I".into(),
                "INPUT".into(),
                "-s".into(),
                ip.into(),
                "-j".into(),
                "DROP".into(),
            ]);
            rollback.push(vec![
                "-w".into(),
                "-D".into(),
                "INPUT".into(),
                "-s".into(),
                ip.into(),
                "-j".into(),
                "DROP".into(),
            ]);
            let mut change = FirewallChange {
                action: "block".into(),
                ip: ip.to_string(),
                backend: backend.name().into(),
                commands: vec![format_command(
                    &tool,
                    commands.first().map(|c| c.as_slice()).unwrap_or(&[]),
                )],
                applied: false,
                output: None,
                rollback: vec![format_command(
                    &tool,
                    rollback.first().map(|c| c.as_slice()).unwrap_or(&[]),
                )],
                note: Some(
                    "iptables rules are not persisted across reboot unless a saving tool is used"
                        .into(),
                ),
            };
            if dry_run {
                return Ok(change);
            }
            let output = run_sequence(&tool, &commands)?;
            change.applied = true;
            change.output = Some(output);
            let mut state = load_state();
            state.rules.push(BlockRecord {
                ip: ip.to_string(),
                backend: backend.name().into(),
                handle: None,
                family: family.into(),
            });
            save_state(&state)?;
            return Ok(change);
        }
    }

    let mut change = FirewallChange {
        action: "block".into(),
        ip: ip.to_string(),
        backend: backend.name().into(),
        commands: commands
            .iter()
            .map(|c| format_command(&binary, c))
            .collect(),
        applied: false,
        output: None,
        rollback: rollback
            .iter()
            .map(|c| format_command(&binary, c))
            .collect(),
        note: None,
    };
    if dry_run {
        return Ok(change);
    }
    let output = run_sequence(&binary, &commands)?;
    change.applied = true;
    change.output = Some(output.clone());
    if backend == LinuxBackend::Nftables {
        handle = find_nft_handle(ip);
    }
    let mut state = load_state();
    state.rules.push(BlockRecord {
        ip: ip.to_string(),
        backend: backend.name().into(),
        handle,
        family: family.into(),
    });
    save_state(&state)?;
    Ok(change)
}

pub fn unblock(ip: &str, dry_run: bool) -> Result<FirewallChange> {
    if ip.parse::<IpAddr>().is_err() {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{ip}' is not an IP address"),
        ));
    }
    if !dry_run && !platform().is_elevated() {
        return Err(
            permission_denied("changing firewall rules requires root on Linux")
                .with_hint(platform().elevation_hint()),
        );
    }
    let state = load_state();
    let record = state
        .rules
        .iter()
        .rev()
        .find(|r| r.ip == ip)
        .cloned()
        .ok_or_else(|| {
            NetroError::new(
                ErrorCode::NotFound,
                format!("netro has no recorded block for {ip}"),
            )
            .with_hint("only rules created by 'netro firewall block' can be removed by netro")
        })?;

    let backend = match record.backend.as_str() {
        "ufw" => LinuxBackend::Ufw,
        "firewalld" => LinuxBackend::Firewalld,
        "nftables" => LinuxBackend::Nftables,
        _ => LinuxBackend::Iptables,
    };
    let binary = if backend == LinuxBackend::Iptables {
        let tool = if record.family == "ipv6" {
            "ip6tables"
        } else {
            "iptables"
        };
        which(tool)
            .or_else(|| backend_binary(backend))
            .ok_or_else(|| {
                NetroError::new(
                    ErrorCode::DependencyMissing,
                    format!("{} is no longer installed", record.backend),
                )
            })?
    } else {
        backend_binary(backend).ok_or_else(|| {
            NetroError::new(
                ErrorCode::DependencyMissing,
                format!("{} is no longer installed", record.backend),
            )
        })?
    };
    let binary = binary.to_string_lossy().to_string();

    let (commands, rollback): (Vec<Vec<String>>, Vec<Vec<String>>) = match backend {
        LinuxBackend::Ufw => (
            vec![vec![
                "delete".into(),
                "deny".into(),
                "from".into(),
                ip.into(),
            ]],
            vec![],
        ),
        LinuxBackend::Firewalld => {
            let rule = format!("rule family={} source address={ip} drop", record.family);
            (
                vec![
                    vec!["--permanent".into(), format!("--remove-rich-rule={rule}")],
                    vec!["--reload".into()],
                ],
                vec![],
            )
        }
        LinuxBackend::Nftables => match &record.handle {
            Some(handle) => (
                vec![vec![
                    "delete".into(),
                    "rule".into(),
                    "inet".into(),
                    "netro".into(),
                    "input".into(),
                    "handle".into(),
                    handle.clone(),
                ]],
                vec![],
            ),
            None => (
                vec![vec![
                    "delete".into(),
                    "table".into(),
                    "inet".into(),
                    "netro".into(),
                ]],
                vec![],
            ),
        },
        LinuxBackend::Iptables => (
            vec![vec![
                "-w".into(),
                "-D".into(),
                "INPUT".into(),
                "-s".into(),
                ip.into(),
                "-j".into(),
                "DROP".into(),
            ]],
            vec![],
        ),
    };

    let mut change = FirewallChange {
        action: "unblock".into(),
        ip: ip.to_string(),
        backend: backend.name().into(),
        commands: commands
            .iter()
            .map(|c| format_command(&binary, c))
            .collect(),
        applied: false,
        output: None,
        rollback: rollback
            .iter()
            .map(|c| format_command(&binary, c))
            .collect(),
        note: None,
    };
    if dry_run {
        return Ok(change);
    }
    let output = run_sequence(&binary, &commands)?;
    change.applied = true;
    change.output = Some(output);
    let mut state = load_state();
    state.rules.retain(|r| r.ip != ip);
    save_state(&state)?;
    Ok(change)
}

fn find_nft_handle(ip: &str) -> Option<String> {
    let path = which("nft")?;
    let out = util::run_command(
        &path.to_string_lossy(),
        &["-a", "list", "chain", "inet", "netro", "input"],
        CMD_TIMEOUT,
    )
    .ok()?;
    for line in out.stdout.lines() {
        if line.contains(ip) {
            // `... # handle 42`
            if let Some(pos) = line.rfind("handle") {
                let handle = line[pos + "handle".len()..].trim();
                if !handle.is_empty() {
                    return Some(handle.to_string());
                }
            }
        }
    }
    None
}

fn run_sequence(binary: &str, sequences: &[Vec<String>]) -> Result<String> {
    let mut output = String::new();
    for args in sequences {
        let out = util::run_command(binary, args, CMD_TIMEOUT)?;
        output.push_str(&format!(
            "$ {}\n{}",
            format_command(binary, args),
            out.combined()
        ));
        if !out.success() {
            return Err(NetroError::new(
                ErrorCode::Io,
                format!(
                    "command failed with status {:?}: {}",
                    out.status,
                    out.stderr.trim()
                ),
            ));
        }
    }
    Ok(output)
}

fn format_command(binary: &str, args: &[String]) -> String {
    let mut cmd = binary.to_string();
    for a in args {
        cmd.push(' ');
        if a.contains(char::is_whitespace) {
            cmd.push('\'');
            cmd.push_str(a);
            cmd.push('\'');
        } else {
            cmd.push_str(a);
        }
    }
    cmd
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn family_detection() {
        assert_eq!(family_of("1.2.3.4"), "ipv4");
        assert_eq!(family_of("::1"), "ipv6");
    }

    #[test]
    fn block_rejects_non_ip() {
        let err = block("not-an-ip", true).unwrap_err();
        assert_eq!(err.code(), ErrorCode::InvalidTarget);
    }

    #[test]
    fn block_dry_run_shows_commands_without_requiring_root() {
        // Dry-run must be safe and informative for unprivileged users.
        match block("203.0.113.7", true) {
            Ok(change) => {
                assert!(!change.applied);
                assert!(
                    change.commands.iter().any(|c| c.contains("203.0.113.7")),
                    "the rule command must reference the target IP: {:?}",
                    change.commands
                );
            }
            Err(e) => {
                // Only acceptable when no backend exists at all.
                assert_eq!(e.code(), ErrorCode::PlatformUnsupported);
            }
        }
    }

    #[test]
    fn block_without_root_and_without_dry_run_is_denied() {
        if crate::platform::platform().is_elevated() {
            return; // running as root: nothing to assert here
        }
        match block("203.0.113.7", false) {
            Err(e) => assert!(matches!(
                e.code(),
                ErrorCode::PermissionDenied | ErrorCode::PlatformUnsupported
            )),
            Ok(change) => panic!("must not apply firewall changes unprivileged: {change:?}"),
        }
    }

    #[test]
    fn command_formatting_quotes_spaces() {
        let cmd = format_command("/usr/sbin/nft", &["add".into(), "a b".into()]);
        assert_eq!(cmd, "/usr/sbin/nft add 'a b'");
    }
}
