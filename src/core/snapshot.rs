//! Session snapshots: point-in-time captures of stable diagnostic state with a
//! real structured diff.
//!
//! A snapshot intentionally records only data that is stable between sessions
//! (interfaces, routes, listening ports, privileged accounts, firewall state,
//! findings). Volatile data such as per-process CPU is excluded so comparisons
//! stay meaningful. Diffs are computed from the structured models, not text.

use crate::config;
use crate::error::{ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::platform;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Snapshot {
    pub schema_version: u32,
    pub created_epoch: i64,
    pub hostname: Option<String>,
    pub platform: PlatformId,
    pub label: Option<String>,
    pub os_summary: String,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub listening: Vec<ListeningPort>,
    pub privileged_accounts: Vec<String>,
    pub firewall_enabled: Option<bool>,
    pub findings: Vec<SnapshotFinding>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct SnapshotFinding {
    pub id: String,
    pub severity: Severity,
    pub title: String,
}

#[derive(Debug, Clone, Default, serde::Serialize, serde::Deserialize)]
pub struct SnapshotDiff {
    pub from: String,
    pub to: String,
    pub added_ports: Vec<String>,
    pub removed_ports: Vec<String>,
    pub added_interfaces: Vec<String>,
    pub removed_interfaces: Vec<String>,
    pub route_changes: Vec<String>,
    pub firewall_change: Option<String>,
    pub new_findings: Vec<String>,
    pub resolved_findings: Vec<String>,
    pub account_changes: Vec<String>,
    pub note: Option<String>,
}

impl SnapshotDiff {
    pub fn is_empty(&self) -> bool {
        self.added_ports.is_empty()
            && self.removed_ports.is_empty()
            && self.added_interfaces.is_empty()
            && self.removed_interfaces.is_empty()
            && self.route_changes.is_empty()
            && self.firewall_change.is_none()
            && self.new_findings.is_empty()
            && self.resolved_findings.is_empty()
            && self.account_changes.is_empty()
    }
}

fn now_epoch() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0)
}

/// Capture the current state. Errors from individual providers are recorded in
/// the snapshot note rather than aborting the capture.
pub fn capture(label: Option<String>) -> Result<Snapshot> {
    let mut note_parts: Vec<String> = Vec::new();
    let os = platform().os_info()?;
    let interfaces = platform().interfaces().unwrap_or_else(|e| {
        note_parts.push(format!("interfaces unavailable: {e}"));
        Vec::new()
    });
    let routes = platform().routes().unwrap_or_else(|e| {
        note_parts.push(format!("routes unavailable: {e}"));
        Vec::new()
    });
    let listening = platform().listening_ports().unwrap_or_else(|e| {
        note_parts.push(format!("listening sockets unavailable: {e}"));
        Vec::new()
    });
    let privileged_accounts = match platform().accounts() {
        Ok(accounts) => accounts
            .into_iter()
            .filter(|a| a.privileged)
            .map(|a| a.name)
            .collect(),
        Err(e) => {
            note_parts.push(format!("accounts unavailable: {e}"));
            Vec::new()
        }
    };
    let firewall_enabled = platform()
        .firewall_status()
        .ok()
        .and_then(|status| status.enabled);
    let findings = crate::core::security::audit(false)
        .findings
        .into_iter()
        .map(|f| SnapshotFinding {
            id: f.id,
            severity: f.severity,
            title: f.title,
        })
        .collect();

    Ok(Snapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        created_epoch: now_epoch(),
        hostname: os.hostname.clone(),
        platform: platform().id(),
        label: label.map(|l| crate::util::sanitize_terminal(&l)),
        os_summary: format!(
            "{} {} ({})",
            os.long_name.clone().or(os.name.clone()).unwrap_or_default(),
            os.version.clone().unwrap_or_default(),
            os.arch
        ),
        interfaces,
        routes,
        listening,
        privileged_accounts,
        firewall_enabled,
        findings,
        note: (!note_parts.is_empty()).then(|| note_parts.join("; ")),
    })
}

pub fn snapshots_dir() -> PathBuf {
    config::data_dir().join("snapshots")
}

fn file_name(snapshot: &Snapshot) -> String {
    let label = snapshot
        .label
        .as_deref()
        .map(|l| {
            l.chars()
                .map(|c| {
                    if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                        c
                    } else {
                        '-'
                    }
                })
                .collect::<String>()
        })
        .filter(|l| !l.is_empty())
        .unwrap_or_else(|| "snapshot".into());
    format!("{}-{label}.json", snapshot.created_epoch)
}

/// Save into an explicit directory (used by tests and `save`).
pub fn save_to(dir: &Path, snapshot: &Snapshot) -> Result<PathBuf> {
    std::fs::create_dir_all(dir)?;
    let path = dir.join(file_name(snapshot));
    let text = serde_json::to_string_pretty(snapshot)?;
    std::fs::write(&path, text)?;
    config::restrict_permissions(&path);
    Ok(path)
}

pub fn save(snapshot: &Snapshot) -> Result<PathBuf> {
    save_to(&snapshots_dir(), snapshot)
}

pub fn load_file(path: &Path) -> Result<Snapshot> {
    let text = std::fs::read_to_string(path).map_err(|e| {
        NetroError::new(
            ErrorCode::NotFound,
            format!("cannot read snapshot {}: {e}", path.display()),
        )
    })?;
    let snapshot: Snapshot = serde_json::from_str(&text)?;
    if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
        return Err(NetroError::new(
            ErrorCode::ParseError,
            format!(
                "snapshot {} has schema {} but this netro supports {}",
                path.display(),
                snapshot.schema_version,
                SNAPSHOT_SCHEMA_VERSION
            ),
        ));
    }
    Ok(snapshot)
}

/// List snapshots in a directory, newest first. Unreadable files are skipped
/// silently (they may be mid-write); callers see only valid snapshots.
pub fn list_in(dir: &Path) -> Vec<(PathBuf, Snapshot)> {
    let mut out = Vec::new();
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return out,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) != Some("json") {
            continue;
        }
        if let Ok(snapshot) = load_file(&path) {
            out.push((path, snapshot));
        }
    }
    out.sort_by(|a, b| b.1.created_epoch.cmp(&a.1.created_epoch));
    out
}

pub fn list() -> Vec<(PathBuf, Snapshot)> {
    list_in(&snapshots_dir())
}

pub fn delete_file(path: &Path) -> Result<()> {
    std::fs::remove_file(path).map_err(|e| {
        NetroError::new(
            ErrorCode::Io,
            format!("cannot delete snapshot {}: {e}", path.display()),
        )
    })
}

// ---------------------------------------------------------------------------
// Diff
// ---------------------------------------------------------------------------

fn port_key(port: &ListeningPort) -> String {
    format!("{} {}:{}", port.protocol, port.address, port.port)
}

fn interface_key(iface: &Interface) -> String {
    iface.name.clone()
}

fn route_key(route: &Route) -> String {
    format!(
        "{} {}/{} via {} dev {}",
        route.family,
        route.destination,
        route.prefix,
        route.gateway.clone().unwrap_or_else(|| "-".into()),
        route.interface.clone().unwrap_or_else(|| "-".into())
    )
}

fn set_of<T, F: Fn(&T) -> String>(items: &[T], key: F) -> BTreeSet<String> {
    items.iter().map(key).collect()
}

/// Compare two snapshots, producing a human-readable structured diff.
pub fn compare(from: &Snapshot, to: &Snapshot) -> SnapshotDiff {
    let from_ports = set_of(&from.listening, port_key);
    let to_ports = set_of(&to.listening, port_key);
    let from_ifaces = set_of(&from.interfaces, interface_key);
    let to_ifaces = set_of(&to.interfaces, interface_key);
    let from_routes = set_of(&from.routes, route_key);
    let to_routes = set_of(&to.routes, route_key);
    let from_findings: BTreeSet<String> = from.findings.iter().map(|f| f.id.clone()).collect();
    let to_findings: BTreeSet<String> = to.findings.iter().map(|f| f.id.clone()).collect();
    let from_accounts = set_of(&from.privileged_accounts, |a| a.clone());
    let to_accounts = set_of(&to.privileged_accounts, |a| a.clone());

    let mut diff = SnapshotDiff {
        from: format!(
            "{} {}",
            from.label.clone().unwrap_or_else(|| "snapshot".into()),
            crate::core::reporting::format_epoch(from.created_epoch)
        ),
        to: format!(
            "{} {}",
            to.label.clone().unwrap_or_else(|| "snapshot".into()),
            crate::core::reporting::format_epoch(to.created_epoch)
        ),
        added_ports: to_ports.difference(&from_ports).cloned().collect(),
        removed_ports: from_ports.difference(&to_ports).cloned().collect(),
        added_interfaces: to_ifaces.difference(&from_ifaces).cloned().collect(),
        removed_interfaces: from_ifaces.difference(&to_ifaces).cloned().collect(),
        route_changes: from_routes
            .symmetric_difference(&to_routes)
            .cloned()
            .collect(),
        firewall_change: match (from.firewall_enabled, to.firewall_enabled) {
            (Some(a), Some(b)) if a != b => Some(format!(
                "firewall enabled changed: {} -> {}",
                if a { "yes" } else { "no" },
                if b { "yes" } else { "no" }
            )),
            (None, Some(b)) => Some(format!(
                "firewall state now known: {}",
                if b { "enabled" } else { "disabled" }
            )),
            _ => None,
        },
        new_findings: to_findings.difference(&from_findings).cloned().collect(),
        resolved_findings: from_findings.difference(&to_findings).cloned().collect(),
        account_changes: from_accounts
            .symmetric_difference(&to_accounts)
            .cloned()
            .collect(),
        note: None,
    };
    if diff.is_empty() {
        diff.note = Some("no stable differences detected".into());
    }
    diff
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, addr: &str) -> Interface {
        Interface {
            name: name.into(),
            kind: InterfaceKind::Ethernet,
            mac: None,
            ipv4: vec![IpWithPrefix {
                addr: addr.into(),
                prefix: 24,
            }],
            ipv6: Vec::new(),
            up: true,
            oper_state: Some("up".into()),
            speed_mbps: None,
            mtu: Some(1500),
            dhcp: Some(true),
            dhcp_source: None,
            default_route: None,
            note: None,
        }
    }

    fn port(port: u16, addr: &str) -> ListeningPort {
        ListeningPort {
            protocol: "tcp".into(),
            address: addr.into(),
            port,
            scope: if addr == "0.0.0.0" {
                ExposureScope::All
            } else {
                ExposureScope::Local
            },
            state: "LISTEN".into(),
            pid: None,
            process: None,
        }
    }

    fn base_snapshot() -> Snapshot {
        Snapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            created_epoch: 1_700_000_000,
            hostname: Some("host".into()),
            platform: PlatformId::Linux,
            label: Some("base".into()),
            os_summary: "Linux".into(),
            interfaces: vec![iface("eth0", "192.168.1.10")],
            routes: vec![Route {
                family: "ipv4".into(),
                destination: "0.0.0.0".into(),
                prefix: 0,
                gateway: Some("192.168.1.1".into()),
                interface: Some("eth0".into()),
                metric: Some(100),
                flags: vec!["UP".into()],
                is_default: true,
            }],
            listening: vec![port(22, "0.0.0.0")],
            privileged_accounts: vec!["root".into()],
            firewall_enabled: Some(true),
            findings: vec![SnapshotFinding {
                id: "policy.min-length".into(),
                severity: Severity::Low,
                title: "short".into(),
            }],
            note: None,
        }
    }

    #[test]
    fn diff_detects_new_and_removed_ports() {
        let from = base_snapshot();
        let mut to = base_snapshot();
        to.created_epoch += 3600;
        to.listening.push(port(8080, "0.0.0.0"));
        to.listening.retain(|p| p.port != 22);

        let diff = compare(&from, &to);
        assert_eq!(diff.added_ports, vec!["tcp 0.0.0.0:8080"]);
        assert_eq!(diff.removed_ports, vec!["tcp 0.0.0.0:22"]);
        assert!(!diff.is_empty());
        assert!(diff.note.is_none());
    }

    #[test]
    fn diff_detects_route_interface_firewall_and_findings() {
        let from = base_snapshot();
        let mut to = base_snapshot();
        to.created_epoch += 60;
        to.routes[0].gateway = Some("192.168.1.254".into());
        to.interfaces.push(iface("wlan0", "192.168.1.20"));
        to.firewall_enabled = Some(false);
        to.findings.push(SnapshotFinding {
            id: "firewall.disabled".into(),
            severity: Severity::High,
            title: "disabled".into(),
        });
        to.privileged_accounts.push("admin".into());

        let diff = compare(&from, &to);
        assert!(diff
            .route_changes
            .iter()
            .any(|c| c.contains("192.168.1.254")));
        assert!(diff.added_interfaces.contains(&"wlan0".to_string()));
        assert_eq!(
            diff.firewall_change.as_deref(),
            Some("firewall enabled changed: yes -> no")
        );
        assert_eq!(diff.new_findings, vec!["firewall.disabled"]);
        assert!(diff.account_changes.iter().any(|c| c == "admin"));
    }

    #[test]
    fn identical_snapshots_report_no_differences() {
        let from = base_snapshot();
        let to = base_snapshot();
        let diff = compare(&from, &to);
        assert!(diff.is_empty());
        assert_eq!(diff.note.as_deref(), Some("no stable differences detected"));
    }

    #[test]
    fn save_list_load_delete_round_trip() {
        let dir = std::env::temp_dir().join(format!(
            "netro-snapshot-test-{}-{}",
            std::process::id(),
            now_epoch()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let snapshot = base_snapshot();
        let path = save_to(&dir, &snapshot).unwrap();
        assert!(path.exists());

        let listed = list_in(&dir);
        assert_eq!(listed.len(), 1);
        assert_eq!(listed[0].1.label.as_deref(), Some("base"));

        let loaded = load_file(&path).unwrap();
        assert_eq!(loaded.listening.len(), 1);

        delete_file(&path).unwrap();
        assert!(list_in(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn labels_are_sanitized_and_filename_safe() {
        let mut snapshot = base_snapshot();
        snapshot.label = Some("before\x1b[31m update/1".into());
        let name = file_name(&snapshot);
        assert!(!name.contains('\x1b'));
        assert!(!name.contains('/'));
        assert!(name.ends_with(".json"));
    }
}
