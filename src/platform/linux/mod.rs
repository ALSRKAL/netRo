//! Linux platform provider.
//!
//! All Linux-specific access lives here and in the sibling modules:
//! `proc.rs` (parsers), `firewall.rs`, `gpu.rs`, `services.rs`.

mod firewall;
mod gpu;
mod proc;
mod services;

use crate::config;
use crate::error::{unsupported, Result};
use crate::model::*;
use crate::platform::shared;
use crate::platform::{
    probe_dependency, FirewallControl, NetworkProvider, Platform, ProcessProvider,
    SecurityProvider, SystemProvider,
};
use crate::util::{self, which};
use std::collections::BTreeMap;
use std::time::Duration;
use sysinfo::Networks;

const CMD_TIMEOUT: Duration = Duration::from_secs(5);

pub struct LinuxPlatform;

impl SystemProvider for LinuxPlatform {
    fn os_info(&self) -> Result<OsInfo> {
        Ok(shared::os_info())
    }

    fn cpu_info(&self) -> Result<CpuInfo> {
        let (cpu, _) = shared::sample_cpu_memory();
        Ok(cpu)
    }

    fn memory_info(&self) -> Result<MemoryInfo> {
        let (_, memory) = shared::sample_cpu_memory();
        Ok(memory)
    }

    fn disks(&self) -> Result<Vec<DiskInfo>> {
        Ok(shared::disks())
    }

    fn gpu_info(&self) -> Result<Vec<GpuInfo>> {
        Ok(gpu::gpus())
    }

    fn temperatures(&self) -> Result<Vec<Temperature>> {
        Ok(shared::temperatures())
    }

    fn virtualization(&self) -> Option<String> {
        shared::detect_virtualization()
    }
}

impl NetworkProvider for LinuxPlatform {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        let networks = Networks::new_with_refreshed_list();
        let routes = self.routes().unwrap_or_default();
        let gw4 = shared::default_gateway(&routes, "ipv4");
        let gw6 = shared::default_gateway(&routes, "ipv6");
        let dhcp_methods = detect_dhcp_methods();
        let default_iface4 = routes
            .iter()
            .find(|r| r.is_default && r.family == "ipv4")
            .and_then(|r| r.interface.clone());
        let default_iface6 = routes
            .iter()
            .find(|r| r.is_default && r.family == "ipv6")
            .and_then(|r| r.interface.clone());

        let mut names: BTreeMap<String, ()> = BTreeMap::new();
        if let Ok(dir) = std::fs::read_dir("/sys/class/net") {
            for entry in dir.flatten() {
                names.insert(entry.file_name().to_string_lossy().to_string(), ());
            }
        }

        let mut out = Vec::new();
        for name in names.keys() {
            let data = networks.list().get(name);
            let sys = format!("/sys/class/net/{name}");
            let mac = data
                .map(|d| d.mac_address().to_string())
                .filter(|m| m != "00:00:00:00:00:00")
                .or_else(|| read_trim(&format!("{sys}/address")));
            let ipv4 = data
                .map(|d| {
                    d.ip_networks()
                        .iter()
                        .filter(|n| n.addr.is_ipv4())
                        .map(|n| IpWithPrefix {
                            addr: n.addr.to_string(),
                            prefix: n.prefix,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let ipv6 = data
                .map(|d| {
                    d.ip_networks()
                        .iter()
                        .filter(|n| n.addr.is_ipv6())
                        .map(|n| IpWithPrefix {
                            addr: n.addr.to_string(),
                            prefix: n.prefix,
                        })
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            let oper_state = read_trim(&format!("{sys}/operstate"));
            let up = oper_state.as_deref() == Some("up")
                || (oper_state.as_deref() != Some("down")
                    && (!ipv4.is_empty() || !ipv6.is_empty()));
            let speed_mbps = read_trim(&format!("{sys}/speed"))
                .and_then(|s| s.parse::<i64>().ok())
                .filter(|v| *v > 0)
                .map(|v| v as u64);
            let mtu = read_trim(&format!("{sys}/mtu"))
                .and_then(|s| s.parse::<u64>().ok())
                .or_else(|| data.map(|d| d.mtu()));
            let kind = classify_linux_interface(name);
            let has_default = default_iface4.as_deref() == Some(name.as_str())
                || default_iface6.as_deref() == Some(name.as_str());
            let (dhcp, dhcp_source) = match dhcp_methods.get(name) {
                Some((value, source)) => (Some(*value), Some(source.clone())),
                None => (
                    None,
                    Some(
                        "no readable DHCP client state (install nmcli or check manually)"
                            .to_string(),
                    ),
                ),
            };
            out.push(Interface {
                name: name.clone(),
                kind,
                mac,
                ipv4,
                ipv6,
                up,
                oper_state,
                speed_mbps,
                mtu,
                dhcp,
                dhcp_source,
                default_route: if has_default {
                    gw4.clone().or(gw6.clone())
                } else {
                    None
                },
                note: None,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn routes(&self) -> Result<Vec<Route>> {
        let mut routes = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/proc/net/route") {
            routes.extend(proc::parse_proc_route(&content));
        }
        if let Ok(content) = std::fs::read_to_string("/proc/net/ipv6_route") {
            routes.extend(proc::parse_proc_ipv6_route(&content));
        }
        if routes.is_empty() {
            return Err(unsupported(
                "/proc/net routes are unavailable (unusual for Linux)",
            ));
        }
        routes.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.family.cmp(&b.family))
                .then_with(|| a.destination.cmp(&b.destination))
        });
        Ok(routes)
    }

    fn dns_config(&self) -> Result<DnsConfig> {
        let mut servers = Vec::new();
        let mut search = Vec::new();
        let mut source = "/etc/resolv.conf".to_string();
        let mut note = None;
        let mut stub = false;
        if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
                    continue;
                }
                let mut parts = line.split_whitespace();
                match parts.next() {
                    Some("nameserver") => {
                        if let Some(server) = parts.next() {
                            if server == "127.0.0.53" || server == "127.0.0.54" {
                                stub = true;
                            }
                            servers.push(server.to_string());
                        }
                    }
                    Some("search") => {
                        for domain in parts {
                            search.push(domain.to_string());
                        }
                    }
                    Some("domain") => {
                        if let Some(domain) = parts.next() {
                            search.push(domain.to_string());
                        }
                    }
                    _ => {}
                }
            }
        } else {
            note = Some("cannot read /etc/resolv.conf".into());
        }

        if stub {
            if let Some(path) = which("resolvectl") {
                if let Ok(out) =
                    util::run_command(&path.to_string_lossy(), &["status"], CMD_TIMEOUT)
                {
                    let mut real: Vec<String> = Vec::new();
                    for line in out.stdout.lines() {
                        let trimmed = line.trim();
                        if let Some(rest) = trimmed.strip_prefix("DNS Servers:") {
                            real.extend(rest.split_whitespace().map(|s| s.to_string()));
                        } else if let Some(rest) = trimmed.strip_prefix("Current DNS Server:") {
                            real.push(rest.trim().to_string());
                        }
                    }
                    if !real.is_empty() {
                        source = "/etc/resolv.conf (systemd-resolved stub) + resolvectl".into();
                        servers = real;
                    }
                }
            }
            if note.is_none() {
                note = Some(
                    "resolv.conf points at the systemd-resolved stub; effective servers shown when resolvectl is available"
                        .into(),
                );
            }
        }

        if servers.is_empty() {
            return Err(crate::error::NetroError::new(
                crate::error::ErrorCode::NetworkDnsUnavailable,
                "no DNS servers configured",
            )
            .with_hint("check /etc/resolv.conf or your network manager"));
        }
        Ok(DnsConfig {
            servers,
            search_domains: search,
            source,
            systemd_resolved_stub: stub,
            note,
        })
    }

    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        let mut out = Vec::new();
        if let Ok(content) = std::fs::read_to_string("/proc/net/arp") {
            out.extend(proc::parse_proc_arp(&content));
        }
        if let Some(path) = which("ip") {
            if let Ok(o) = util::run_command(
                &path.to_string_lossy(),
                &["-6", "neigh", "show"],
                CMD_TIMEOUT,
            ) {
                for line in o.stdout.lines() {
                    if let Some(n) = parse_ip_neigh_line(line) {
                        out.push(n);
                    }
                }
            }
        }
        out.sort_by_key(|n| {
            n.ip.parse::<std::net::IpAddr>()
                .ok()
                .map(|ip| util::ip_sort_key(&ip))
        });
        Ok(out)
    }

    fn listening_ports(&self) -> Result<Vec<ListeningPort>> {
        let sockets = read_all_sockets();
        let inodes: Vec<u64> = sockets.iter().map(|s| s.inode).collect();
        let inode_map = proc::inode_process_map_for(&inodes);
        let mut out = Vec::new();
        for s in sockets {
            let is_tcp = s.protocol == "tcp";
            if is_tcp && s.state != "LISTEN" {
                continue;
            }
            let (pid, process) = inode_map
                .get(&s.inode)
                .map(|(pid, name)| (Some(*pid), Some(name.clone())))
                .unwrap_or((None, None));
            out.push(ListeningPort {
                protocol: s.protocol.to_string(),
                address: s.local_addr.clone(),
                port: s.local_port,
                scope: scope_of(&s.local_addr),
                state: s.state.clone(),
                pid,
                process,
            });
        }
        out.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
        out.dedup_by(|a, b| {
            a.port == b.port && a.protocol == b.protocol && a.address == b.address && a.pid == b.pid
        });
        Ok(out)
    }
}

impl ProcessProvider for LinuxPlatform {
    fn processes(&self) -> Result<Vec<ProcessInfo>> {
        let system = shared::sample_processes();
        Ok(shared::processes(&system, shared::ProcessSort::Cpu))
    }

    fn connections(&self) -> Result<Vec<Connection>> {
        let sockets = read_all_sockets();
        let inodes: Vec<u64> = sockets.iter().map(|s| s.inode).collect();
        let inode_map = proc::inode_process_map_for(&inodes);
        let mut out = Vec::new();
        for s in sockets {
            if s.protocol == "udp" && s.remote_addr.is_none() {
                continue; // bound but unconnected UDP socket
            }
            let (pid, process) = inode_map
                .get(&s.inode)
                .map(|(pid, name)| (Some(*pid), Some(name.clone())))
                .unwrap_or((None, None));
            out.push(Connection {
                protocol: s.protocol.to_string(),
                local_addr: s.local_addr.clone(),
                local_port: s.local_port,
                remote_addr: s.remote_addr.clone(),
                remote_port: s.remote_port,
                state: s.state.clone(),
                pid,
                process,
            });
        }
        out.sort_by(|a, b| {
            a.remote_addr
                .cmp(&b.remote_addr)
                .then_with(|| a.local_port.cmp(&b.local_port))
        });
        Ok(out)
    }
}

impl SecurityProvider for LinuxPlatform {
    fn accounts(&self) -> Result<Vec<Account>> {
        let passwd_content = std::fs::read_to_string("/etc/passwd").map_err(|e| {
            crate::error::NetroError::new(
                crate::error::ErrorCode::Io,
                format!("cannot read /etc/passwd: {e}"),
            )
        })?;
        let shadow_content = std::fs::read_to_string("/etc/shadow").ok();
        let groups_content = std::fs::read_to_string("/etc/group").unwrap_or_default();

        let entries = proc::parse_passwd(&passwd_content);
        let shadows: BTreeMap<String, proc::ShadowEntry> = shadow_content
            .as_deref()
            .map(proc::parse_shadow)
            .unwrap_or_default()
            .into_iter()
            .map(|s| (s.name.clone(), s))
            .collect();
        let groups = proc::parse_groups(&groups_content);

        let mut out = Vec::new();
        for entry in entries {
            let privileged = proc::is_privileged_account(&entry, &groups);
            let login_shell = proc::is_login_shell(&entry.shell);
            let is_system = entry.uid < 1000 && entry.uid != 0;
            let password = match shadows.get(&entry.name) {
                Some(shadow) => proc::classify_password_hash(&shadow.hash),
                None => {
                    if shadow_content.is_none() {
                        PasswordStatus::Unknown
                    } else {
                        PasswordStatus::NoShadowEntry
                    }
                }
            };
            let mut member_of: Vec<String> = groups
                .iter()
                .filter(|(_, members)| members.iter().any(|m| m == &entry.name))
                .map(|(name, _)| name.clone())
                .collect();
            member_of.sort();
            let note = if shadow_content.is_none() {
                Some("password status unknown: /etc/shadow not readable (needs root)".into())
            } else {
                shadows
                    .get(&entry.name)
                    .map(password_aging_note)
                    .filter(|s| !s.is_empty())
            };
            out.push(Account {
                name: entry.name,
                uid: Some(entry.uid),
                gid: Some(entry.gid),
                home: Some(entry.home),
                shell: Some(entry.shell),
                privileged,
                is_system,
                login_shell,
                password,
                groups: member_of,
                note,
            });
        }
        out.sort_by_key(|a| a.uid);
        Ok(out)
    }

    fn password_policy(&self) -> Result<Option<PasswordPolicy>> {
        let mut policy = PasswordPolicy {
            min_length: None,
            max_age_days: None,
            min_age_days: None,
            warn_days: None,
            remember: None,
            lockout_threshold: None,
            lockout_duration_secs: None,
            source: "system policy files".into(),
        };
        let mut found = false;

        if let Ok(content) = std::fs::read_to_string("/etc/login.defs") {
            let map = proc::parse_login_defs(&content);
            policy.max_age_days = map.get("PASS_MAX_DAYS").copied();
            policy.min_age_days = map.get("PASS_MIN_DAYS").copied();
            policy.warn_days = map.get("PASS_WARN_AGE").copied();
            found = true;
        }
        if let Ok(content) = std::fs::read_to_string("/etc/security/pwquality.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    let key = key.trim();
                    let value = value.trim();
                    if key == "minlen" {
                        policy.min_length = value.parse().ok();
                        found = true;
                    }
                }
            }
        }
        if let Ok(content) = std::fs::read_to_string("/etc/security/faillock.conf") {
            for line in content.lines() {
                let line = line.trim();
                if line.starts_with('#') || line.is_empty() {
                    continue;
                }
                if let Some((key, value)) = line.split_once('=') {
                    match key.trim() {
                        "deny" => {
                            policy.lockout_threshold = value.trim().parse().ok();
                            found = true;
                        }
                        "unlock_time" => {
                            policy.lockout_duration_secs = value.trim().parse().ok();
                            found = true;
                        }
                        _ => {}
                    }
                }
            }
        }
        if !found {
            return Ok(None);
        }
        Ok(Some(policy))
    }

    fn firewall_status(&self) -> Result<FirewallStatus> {
        Ok(firewall::detect())
    }

    fn firewall_rules(&self, limit: usize) -> Result<Vec<FirewallRule>> {
        firewall::rules(limit)
    }

    fn services(&self) -> Result<Vec<ServiceInfo>> {
        services::services()
    }
}

impl FirewallControl for LinuxPlatform {
    fn block_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        firewall::block(ip, dry_run)
    }

    fn unblock_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        firewall::unblock(ip, dry_run)
    }
}

impl Platform for LinuxPlatform {
    fn id(&self) -> PlatformId {
        PlatformId::Linux
    }

    fn display_name(&self) -> &'static str {
        "Linux"
    }

    fn is_elevated(&self) -> bool {
        #[cfg(unix)]
        unsafe {
            libc::geteuid() == 0
        }
        #[cfg(not(unix))]
        {
            false
        }
    }

    fn elevation_hint(&self) -> &'static str {
        "run the command with sudo, or as root"
    }

    fn dependencies(&self) -> Vec<Dependency> {
        vec![
            probe_dependency(
                "iproute2 (ip)",
                "ip",
                &["-V"],
                "routes, neighbors, link state",
                false,
            ),
            probe_dependency(
                "iproute2 (ss)",
                "ss",
                &["-V"],
                "socket listing fallback",
                false,
            ),
            probe_dependency(
                "iputils ping",
                "ping",
                &["-V"],
                "ICMP latency and connectivity",
                false,
            ),
            probe_dependency(
                "traceroute",
                "traceroute",
                &["--version"],
                "hop-by-hop path tracing",
                false,
            ),
            probe_dependency(
                "nmap",
                "nmap",
                &["--version"],
                "advanced discovery and scanning",
                false,
            ),
            probe_dependency(
                "arp-scan",
                "arp-scan",
                &["--version"],
                "layer-2 LAN discovery",
                false,
            ),
            probe_dependency(
                "iperf3",
                "iperf3",
                &["--version"],
                "throughput testing",
                false,
            ),
            probe_dependency(
                "lsof",
                "lsof",
                &["-v"],
                "connection-to-process mapping",
                false,
            ),
            probe_dependency("ethtool", "ethtool", &["--version"], "link details", false),
            probe_dependency(
                "nvidia-smi",
                "nvidia-smi",
                &["--version"],
                "NVIDIA GPU metrics",
                false,
            ),
            probe_dependency(
                "rocm-smi",
                "rocm-smi",
                &["--version"],
                "AMD GPU metrics",
                false,
            ),
            probe_dependency("lspci", "lspci", &["-v"], "hardware model names", false),
            probe_dependency(
                "rkhunter",
                "rkhunter",
                &["--version"],
                "optional rootkit scan (external)",
                false,
            ),
            probe_dependency(
                "chkrootkit",
                "chkrootkit",
                &["-V"],
                "optional rootkit scan (external)",
                false,
            ),
            probe_dependency(
                "ClamAV",
                "clamscan",
                &["--version"],
                "optional malware scan (external)",
                false,
            ),
            probe_dependency(
                "lynis",
                "lynis",
                &["--version"],
                "optional hardening audit (external)",
                false,
            ),
        ]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Describe password aging from a shadow entry, using only recorded values.
fn password_aging_note(shadow: &proc::ShadowEntry) -> String {
    let mut parts = Vec::new();
    if let Some(last_change) = shadow.last_change {
        if last_change > 0 {
            let now_days = (chrono::Utc::now().timestamp() / 86_400) as u64;
            if now_days >= last_change {
                parts.push(format!(
                    "password last changed {} day(s) ago",
                    now_days - last_change
                ));
            }
        }
    }
    if let Some(max_days) = shadow.max_days {
        parts.push(if max_days == 0 || max_days >= 99_999 {
            "password aging disabled".to_string()
        } else {
            format!("password expires every {max_days} day(s)")
        });
    }
    if let Some(min_days) = shadow.min_days {
        if min_days > 0 {
            parts.push(format!("minimum password age {min_days} day(s)"));
        }
    }
    if let Some(warn_days) = shadow.warn_days {
        if warn_days > 0 {
            parts.push(format!("expiry warning {warn_days} day(s) before"));
        }
    }
    if shadow.inactive_days == Some(0) && shadow.expire_days.is_some() {
        parts.push("account expiry configured".to_string());
    }
    parts.join("; ")
}

fn read_trim(path: &str) -> Option<String> {
    std::fs::read_to_string(path)
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn classify_linux_interface(name: &str) -> InterfaceKind {
    let base = shared::classify_interface(name);
    if base == InterfaceKind::Unknown {
        // Under systemd predictable names, en* is Ethernet; anything else stays
        // unknown rather than guessing.
        if name.starts_with("en") || name.starts_with("eth") {
            return InterfaceKind::Ethernet;
        }
    }
    base
}

/// Detect DHCP from NetworkManager / systemd-networkd, when readable.
/// Returns `(None, reason)` when there is no reliable local evidence.
fn detect_dhcp_methods() -> std::collections::HashMap<String, (bool, String)> {
    let mut map = std::collections::HashMap::new();

    if let Some(nmcli) = which("nmcli") {
        let out = util::run_command(
            &nmcli.to_string_lossy(),
            &["-t", "-f", "GENERAL.DEVICE,IP4.METHOD", "device", "show"],
            Duration::from_secs(3),
        );
        if let Ok(out) = out {
            let mut current: Option<String> = None;
            for line in out.stdout.lines() {
                if let Some(device) = line.strip_prefix("GENERAL.DEVICE:") {
                    current = Some(device.trim().to_string());
                } else if let Some(method) = line.strip_prefix("IP4.METHOD:") {
                    if let Some(device) = current.take() {
                        let method = method.trim().to_ascii_lowercase();
                        let dhcp = method.contains("auto") || method.contains("shared");
                        map.insert(device, (dhcp, "NetworkManager (nmcli)".into()));
                    }
                }
            }
        }
    }

    // systemd-networkd writes leases named by interface index; map them back to
    // interface names via sysfs.
    if let Ok(entries) = std::fs::read_dir("/run/systemd/netif/leases") {
        for entry in entries.flatten() {
            let ifindex = entry.file_name().to_string_lossy().to_string();
            let content = std::fs::read_to_string(entry.path()).unwrap_or_default();
            let has_lease = content.contains("SERVER_ADDRESS") || content.contains("ADDRESS=");
            if !has_lease {
                continue;
            }
            for name in std::fs::read_dir("/sys/class/net")
                .into_iter()
                .flatten()
                .flatten()
            {
                let name_str = name.file_name().to_string_lossy().to_string();
                if read_trim(&format!("/sys/class/net/{name_str}/ifindex")).as_deref()
                    == Some(ifindex.as_str())
                {
                    map.entry(name_str)
                        .or_insert((true, "systemd-networkd lease".into()));
                    break;
                }
            }
        }
    }

    map
}

fn parse_ip_neigh_line(line: &str) -> Option<Neighbor> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.is_empty() {
        return None;
    }
    let ip = cols[0].to_string();
    let mut mac = None;
    let mut iface = None;
    let mut state = None;
    let mut i = 1;
    while i < cols.len() {
        match cols[i] {
            "dev" => {
                iface = cols.get(i + 1).map(|s| s.to_string());
                i += 2;
            }
            "lladdr" => {
                mac = cols.get(i + 1).map(|s| s.to_ascii_lowercase());
                i += 2;
            }
            other => {
                if other.chars().all(|c| c.is_ascii_uppercase()) && other.len() > 2 {
                    state = Some(other.to_string());
                    i += 1;
                } else {
                    i += 1;
                }
            }
        }
    }
    Some(Neighbor {
        ip,
        mac,
        interface: iface,
        state,
        vendor: None,
        hostname: None,
    })
}

struct RawSocket {
    protocol: &'static str,
    local_addr: String,
    local_port: u16,
    remote_addr: Option<String>,
    remote_port: Option<u16>,
    state: String,
    inode: u64,
}

fn read_socket_file(path: &str, protocol: &'static str, udp: bool) -> Vec<RawSocket> {
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };
    proc::parse_proc_sockets(&content, udp)
        .into_iter()
        .map(|s| RawSocket {
            protocol,
            local_addr: s.local_addr,
            local_port: s.local_port,
            remote_addr: s.remote_addr,
            remote_port: s.remote_port,
            state: s.state,
            inode: s.inode,
        })
        .collect()
}

fn read_all_sockets() -> Vec<RawSocket> {
    let mut out = Vec::new();
    out.extend(read_socket_file("/proc/net/tcp", "tcp", false));
    out.extend(read_socket_file("/proc/net/tcp6", "tcp", false));
    out.extend(read_socket_file("/proc/net/udp", "udp", true));
    out.extend(read_socket_file("/proc/net/udp6", "udp", true));
    out
}

fn scope_of(addr: &str) -> ExposureScope {
    match addr.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                ExposureScope::Local
            } else if v4.is_unspecified() {
                ExposureScope::All
            } else {
                ExposureScope::Interface
            }
        }
        Ok(std::net::IpAddr::V6(v6)) => {
            if v6.is_loopback() {
                ExposureScope::Local
            } else if v6.is_unspecified() {
                ExposureScope::All
            } else {
                ExposureScope::Interface
            }
        }
        Err(_) => ExposureScope::Unknown,
    }
}

#[allow(dead_code)]
fn default_integrity_paths() -> Vec<String> {
    config::default_integrity_paths()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ip_neigh_line_parsing() {
        let n =
            parse_ip_neigh_line("192.168.1.1 dev eth0 lladdr aa:bb:cc:dd:ee:ff REACHABLE").unwrap();
        assert_eq!(n.ip, "192.168.1.1");
        assert_eq!(n.mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(n.interface.as_deref(), Some("eth0"));
        assert_eq!(n.state.as_deref(), Some("REACHABLE"));
    }

    #[test]
    fn scope_classification() {
        assert_eq!(scope_of("0.0.0.0"), ExposureScope::All);
        assert_eq!(scope_of("127.0.0.1"), ExposureScope::Local);
        assert_eq!(scope_of("192.168.1.5"), ExposureScope::Interface);
        assert_eq!(scope_of("::"), ExposureScope::All);
        assert_eq!(scope_of("::1"), ExposureScope::Local);
    }

    #[test]
    fn interfaces_are_real_on_linux() {
        let ifaces = LinuxPlatform.interfaces().unwrap();
        assert!(!ifaces.is_empty(), "Linux must report at least loopback");
        assert!(ifaces.iter().any(|i| i.kind == InterfaceKind::Loopback));
    }

    #[test]
    fn routes_or_unsupported() {
        match LinuxPlatform.routes() {
            Ok(routes) => {
                for r in routes {
                    assert!(!r.family.is_empty());
                }
            }
            Err(e) => assert!(e.code().is_unavailable()),
        }
    }

    #[test]
    fn listening_ports_or_unsupported() {
        match LinuxPlatform.listening_ports() {
            Ok(ports) => {
                for p in ports {
                    assert!(p.port > 0 || p.protocol == "udp");
                }
            }
            Err(e) => assert!(e.code().is_unavailable()),
        }
    }
}
