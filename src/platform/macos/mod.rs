//! macOS platform provider (Intel and Apple Silicon).
//!
//! Uses the BSD/macOS userland (netstat, arp, ndp, lsof, launchctl,
//! socketfilterfw, pfctl, system_profiler) and `sysinfo` for native system
//! data. `/proc` is never assumed. Commands that need root report
//! `PERMISSION_DENIED` instead of partial guesses where the data would be
//! misleading.

use crate::error::{dependency_missing, unsupported, ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::shared;
use crate::platform::{
    probe_dependency, FirewallControl, NetworkProvider, Platform, ProcessProvider,
    SecurityProvider, SystemProvider,
};
use crate::util::{self, which};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Duration;
use sysinfo::Networks;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

pub struct MacosPlatform;

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

impl SystemProvider for MacosPlatform {
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
        let path = which("system_profiler")
            .ok_or_else(|| dependency_missing("system_profiler", "GPU information"))?;
        let out = util::run_command(
            &path.to_string_lossy(),
            &["SPDisplaysDataType", "-json"],
            Duration::from_secs(30),
        )?;
        if !out.success() {
            return Err(NetroError::new(
                ErrorCode::Other,
                "system_profiler failed to report displays",
            ));
        }
        let value: serde_json::Value = serde_json::from_str(&out.stdout)?;
        let mut gpus = Vec::new();
        if let Some(items) = value.get("SPDisplaysDataType").and_then(|v| v.as_array()) {
            for item in items {
                let model = item.get("sppci_model").and_then(|v| v.as_str());
                let vendor = item.get("spdisplays_vendor").and_then(|v| v.as_str());
                let vram = item
                    .get("spdisplays_vram")
                    .or_else(|| item.get("spdisplays_vram_shared"))
                    .and_then(|v| v.as_str());
                let metal = item.get("spdisplays_metal").and_then(|v| v.as_str());
                let mut gpu = GpuInfo {
                    vendor: vendor.map(|s| s.to_string()),
                    model: model.map(|s| s.to_string()),
                    vram_bytes: vram.and_then(parse_vram),
                    driver: None,
                    utilization_percent: None,
                    temperature_c: None,
                    power_watts: None,
                    compute_backend: metal.map(|m| format!("Metal: {m}")),
                    source: "system_profiler SPDisplaysDataType".into(),
                    note: None,
                };
                if gpu.vendor.is_none() {
                    if let Some(model) = &gpu.model {
                        let lower = model.to_ascii_lowercase();
                        if lower.contains("apple") {
                            gpu.vendor = Some("Apple".into());
                        } else if lower.contains("amd") || lower.contains("radeon") {
                            gpu.vendor = Some("AMD".into());
                        } else if lower.contains("intel") {
                            gpu.vendor = Some("Intel".into());
                        }
                    }
                }
                if gpu.utilization_percent.is_none() {
                    gpu.note = Some(
                        "macOS does not expose live GPU utilization through system_profiler".into(),
                    );
                }
                gpus.push(gpu);
            }
        }
        Ok(gpus)
    }

    fn temperatures(&self) -> Result<Vec<Temperature>> {
        // sysinfo reads SMC-backed sensors where available on macOS.
        Ok(shared::temperatures())
    }

    fn virtualization(&self) -> Option<String> {
        let path = which("sysctl")?;
        let out = util::run_command(
            &path.to_string_lossy(),
            &["-n", "kern.hv_vmm_present"],
            Duration::from_secs(3),
        )
        .ok()?;
        if out.stdout.trim() == "1" {
            Some("virtual machine hypervisor".into())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

impl NetworkProvider for MacosPlatform {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        let networks = Networks::new_with_refreshed_list();
        let routes = self.routes().unwrap_or_default();
        let gw4 = shared::default_gateway(&routes, "ipv4");
        let hardware_ports = macos_hardware_ports();

        let mut out = Vec::new();
        for (name, data) in networks.list() {
            let mac = data
                .mac_address()
                .to_string()
                .trim()
                .to_string()
                .to_ascii_lowercase();
            let mac = if mac.is_empty() || mac == "00:00:00:00:00:00" || mac == "0:0:0:0:0:0" {
                None
            } else {
                Some(mac)
            };
            let ipv4: Vec<IpWithPrefix> = data
                .ip_networks()
                .iter()
                .filter(|n| n.addr.is_ipv4())
                .map(|n| IpWithPrefix {
                    addr: n.addr.to_string(),
                    prefix: n.prefix,
                })
                .collect();
            let ipv6: Vec<IpWithPrefix> = data
                .ip_networks()
                .iter()
                .filter(|n| n.addr.is_ipv6())
                .map(|n| IpWithPrefix {
                    addr: n.addr.to_string(),
                    prefix: n.prefix,
                })
                .collect();
            let up = !ipv4.is_empty() || !ipv6.is_empty() || name == "lo0";
            let kind = hardware_ports
                .get(name)
                .map(|port| classify_macos_port(port))
                .unwrap_or_else(|| shared::classify_interface(name));
            let has_default = kind != InterfaceKind::Loopback
                && ((gw4.is_some() && !ipv4.is_empty())
                    || (shared::default_gateway(&routes, "ipv6").is_some() && !ipv6.is_empty()));
            out.push(Interface {
                name: name.clone(),
                kind,
                mac,
                ipv4,
                ipv6,
                up,
                oper_state: None,
                speed_mbps: None,
                mtu: Some(data.mtu()),
                dhcp: None,
                dhcp_source: Some(
                    "not queried (per-interface DHCP state requires ipconfig/SystemConfiguration)"
                        .into(),
                ),
                default_route: has_default.then(|| gw4.clone()).flatten(),
                note: hardware_ports.get(name).cloned(),
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn routes(&self) -> Result<Vec<Route>> {
        let mut out = Vec::new();
        let netstat =
            which("netstat").ok_or_else(|| dependency_missing("netstat", "routing table"))?;
        for (family, flag) in [("ipv4", "inet"), ("ipv6", "inet6")] {
            let o = util::run_command(
                &netstat.to_string_lossy(),
                &["-rn", "-f", flag],
                CMD_TIMEOUT,
            )?;
            out.extend(parse_netstat_routes(&o.stdout, family));
        }
        if out.is_empty() {
            return Err(unsupported("netstat returned no routes"));
        }
        out.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.family.cmp(&b.family))
        });
        Ok(out)
    }

    fn dns_config(&self) -> Result<DnsConfig> {
        let mut servers = Vec::new();
        let mut search = Vec::new();
        let mut source = "scutil --dns".to_string();
        let mut note = None;
        if let Some(scutil) = which("scutil") {
            if let Ok(o) = util::run_command(&scutil.to_string_lossy(), &["--dns"], CMD_TIMEOUT) {
                for line in o.stdout.lines() {
                    let trimmed = line.trim();
                    if let Some(rest) = trimmed.strip_prefix("nameserver[") {
                        if let Some((_, addr)) = rest.split_once(':') {
                            let addr = addr.trim();
                            if !addr.is_empty() && !servers.contains(&addr.to_string()) {
                                servers.push(addr.to_string());
                            }
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("search domain[") {
                        if let Some((_, domain)) = rest.split_once(':') {
                            let domain = domain.trim();
                            if !domain.is_empty() && !search.contains(&domain.to_string()) {
                                search.push(domain.to_string());
                            }
                        }
                    } else if let Some(rest) = trimmed.strip_prefix("domain :") {
                        let domain = rest.trim();
                        if !domain.is_empty() && !search.contains(&domain.to_string()) {
                            search.push(domain.to_string());
                        }
                    }
                }
            }
        }
        if servers.is_empty() {
            if let Ok(content) = std::fs::read_to_string("/etc/resolv.conf") {
                for line in content.lines() {
                    if let Some(rest) = line.trim().strip_prefix("nameserver") {
                        let addr = rest.trim();
                        if !addr.is_empty() {
                            servers.push(addr.to_string());
                        }
                    }
                }
                source = "scutil --dns + /etc/resolv.conf".into();
            }
        }
        if servers.is_empty() {
            return Err(NetroError::new(
                ErrorCode::NetworkDnsUnavailable,
                "no DNS servers found via scutil or resolv.conf",
            ));
        }
        if note.is_none() && servers.iter().any(|s| s.starts_with("127.")) {
            note = Some(
                "resolver is a local stub (mDNSResponder); effective upstream servers may differ"
                    .into(),
            );
        }
        Ok(DnsConfig {
            servers,
            search_domains: search,
            source,
            systemd_resolved_stub: false,
            note,
        })
    }

    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        let mut out = Vec::new();
        if let Some(arp) = which("arp") {
            if let Ok(o) = util::run_command(&arp.to_string_lossy(), &["-an"], CMD_TIMEOUT) {
                out.extend(parse_arp_output(&o.stdout));
            }
        }
        if let Some(ndp) = which("ndp") {
            if let Ok(o) = util::run_command(&ndp.to_string_lossy(), &["-an"], CMD_TIMEOUT) {
                out.extend(parse_ndp_output(&o.stdout));
            }
        }
        if out.is_empty() {
            return Err(unsupported("no neighbor table entries could be read"));
        }
        out.sort_by_key(|n| {
            n.ip.split('%')
                .next()
                .and_then(|s| s.parse::<IpAddr>().ok())
                .map(|ip| util::ip_sort_key(&ip))
        });
        Ok(out)
    }

    fn listening_ports(&self) -> Result<Vec<ListeningPort>> {
        let connections = macos_lsof_connections()?;
        let mut out: Vec<ListeningPort> = connections
            .into_iter()
            .filter(|c| c.state == "LISTEN" && c.remote_addr.is_none())
            .map(|c| ListeningPort {
                protocol: c.protocol.clone(),
                address: c.local_addr.clone(),
                port: c.local_port,
                scope: scope_of(&c.local_addr),
                state: c.state.clone(),
                pid: c.pid,
                process: c.process.clone(),
            })
            .collect();
        out.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
        out.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol && a.pid == b.pid);
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "no listening sockets reported by lsof",
            ));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

impl ProcessProvider for MacosPlatform {
    fn processes(&self) -> Result<Vec<ProcessInfo>> {
        let system = shared::sample_processes();
        Ok(shared::processes(&system, shared::ProcessSort::Cpu))
    }

    fn connections(&self) -> Result<Vec<Connection>> {
        macos_lsof_connections()
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

impl SecurityProvider for MacosPlatform {
    fn accounts(&self) -> Result<Vec<Account>> {
        let dscacheutil = which("dscacheutil")
            .ok_or_else(|| dependency_missing("dscacheutil", "local account listing"))?;
        let users_out =
            util::run_command(&dscacheutil.to_string_lossy(), &["-q", "user"], CMD_TIMEOUT)?;
        if !users_out.success() {
            return Err(NetroError::new(
                ErrorCode::Other,
                "dscacheutil -q user failed",
            ));
        }
        let admin_group = macos_admin_members();
        let groups = macos_groups();
        let mut out = Vec::new();
        for record in split_dscache_blocks(&users_out.stdout) {
            let name = record.get("name").cloned().unwrap_or_default();
            if name.is_empty() {
                continue;
            }
            let uid = record.get("uid").and_then(|s| s.parse::<u32>().ok());
            let gid = record.get("gid").and_then(|s| s.parse::<u32>().ok());
            let shell = record.get("shell").cloned();
            let home = record.get("dir").cloned();
            let privileged = uid == Some(0) || admin_group.iter().any(|a| a == &name);
            let mut member_of: Vec<String> = groups
                .iter()
                .filter(|(_, members)| members.iter().any(|m| m == &name))
                .map(|(g, _)| g.clone())
                .collect();
            member_of.sort();
            let login_shell = shell
                .as_deref()
                .map(|s| !s.ends_with("/false") && !s.ends_with("/uucico") && !s.is_empty())
                .unwrap_or(true);
            out.push(Account {
                name,
                uid,
                gid,
                home,
                shell,
                privileged,
                is_system: uid.map(|u| u < 500 && u != 0).unwrap_or(false),
                login_shell,
                password: PasswordStatus::Unknown,
                groups: member_of,
                note: Some(
                    "macOS does not expose password hashes without root; status is unknown here"
                        .into(),
                ),
            });
        }
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::NotFound,
                "no local accounts returned by dscacheutil",
            ));
        }
        out.sort_by_key(|a| a.uid);
        Ok(out)
    }

    fn password_policy(&self) -> Result<Option<PasswordPolicy>> {
        // pwpolicy output is a binary/XML plist that varies by OS version and
        // requires root; parsing it unreliably would risk misleading results.
        Ok(None)
    }

    fn firewall_status(&self) -> Result<FirewallStatus> {
        let mut status = FirewallStatus::default();
        let socketfilterfw = which("socketfilterfw")
            .map(|p| p.to_string_lossy().to_string())
            .or_else(|| {
                let candidate = "/usr/libexec/ApplicationFirewall/socketfilterfw";
                std::path::Path::new(candidate)
                    .exists()
                    .then(|| candidate.to_string())
            });
        if let Some(binary) = socketfilterfw {
            let state = util::run_command(&binary, &["--getglobalstate"], CMD_TIMEOUT);
            match state {
                Ok(o) => {
                    let enabled = o.stdout.to_ascii_lowercase().contains("enabled");
                    let stealth = util::run_command(&binary, &["--getstealthmode"], CMD_TIMEOUT)
                        .ok()
                        .map(|s| s.stdout.trim().to_string());
                    status.backends.push(FirewallBackend {
                        name: "macOS Application Firewall".into(),
                        active: Some(enabled),
                        detail: stealth.map(|s| format!("stealth mode: {s}")),
                        via: "socketfilterfw --getglobalstate".into(),
                    });
                    status.enabled = Some(enabled);
                }
                Err(e) => status.backends.push(FirewallBackend {
                    name: "macOS Application Firewall".into(),
                    active: None,
                    detail: Some(e.message().to_string()),
                    via: "socketfilterfw --getglobalstate".into(),
                }),
            }
        } else {
            status
                .notes
                .push("socketfilterfw not found at the standard location".into());
        }

        if let Some(pfctl) = which("pfctl") {
            match util::run_command(&pfctl.to_string_lossy(), &["-s", "info"], CMD_TIMEOUT) {
                Ok(o) => {
                    let enabled = o.stdout.contains("Status: Enabled");
                    let detail = o
                        .stdout
                        .lines()
                        .find(|l| l.trim_start().starts_with("Status:"))
                        .map(|s| s.trim().to_string());
                    status.backends.push(FirewallBackend {
                        name: "pf (packet filter)".into(),
                        active: Some(enabled),
                        detail,
                        via: "pfctl -s info".into(),
                    });
                    if status.enabled.is_none() {
                        status.enabled = Some(enabled);
                    }
                }
                Err(e) => {
                    let note = if e.code() == ErrorCode::PermissionDenied {
                        "pf state needs root (pfctl requires privileges)".to_string()
                    } else {
                        e.message().to_string()
                    };
                    status.notes.push(note);
                }
            }
        }
        if let Some(appfw) = status
            .backends
            .iter()
            .find(|b| b.name.contains("Application Firewall"))
        {
            if appfw.active == Some(false) {
                status.notes.push("Application Firewall is disabled".into());
            }
        }
        if status.backends.is_empty() {
            return Err(unsupported("no macOS firewall interface is available"));
        }
        Ok(status)
    }

    fn firewall_rules(&self, limit: usize) -> Result<Vec<FirewallRule>> {
        let socketfilterfw = "/usr/libexec/ApplicationFirewall/socketfilterfw";
        if !std::path::Path::new(socketfilterfw).exists() {
            return Err(unsupported(
                "macOS Application Firewall rule listing is not available",
            ));
        }
        let out = util::run_command(socketfilterfw, &["--listapps"], CMD_TIMEOUT)?;
        let mut rules = Vec::new();
        for line in out.stdout.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            rules.push(FirewallRule {
                backend: "macos-appfw".into(),
                chain: None,
                action: if trimmed.to_ascii_lowercase().contains("allow") {
                    "allow".into()
                } else {
                    "unknown".into()
                },
                source: None,
                destination: None,
                ports: None,
                protocol: None,
                raw: trimmed.to_string(),
            });
            if rules.len() >= limit {
                break;
            }
        }
        if rules.is_empty() {
            return Err(NetroError::new(
                ErrorCode::NotFound,
                "no application firewall entries returned",
            ));
        }
        Ok(rules)
    }

    fn services(&self) -> Result<Vec<ServiceInfo>> {
        let launchctl =
            which("launchctl").ok_or_else(|| dependency_missing("launchctl", "service listing"))?;
        let out = util::run_command(&launchctl.to_string_lossy(), &["list"], CMD_TIMEOUT)?;
        if !out.success() {
            return Err(NetroError::new(ErrorCode::Other, "launchctl list failed"));
        }
        let mut services = Vec::new();
        for line in out.stdout.lines().skip(1) {
            let cols: Vec<&str> = line.split('\t').collect();
            if cols.len() < 3 {
                continue;
            }
            let pid = cols[0].trim();
            let status = cols[1].trim();
            let label = cols[2].trim();
            if label.is_empty() {
                continue;
            }
            services.push(ServiceInfo {
                name: label.to_string(),
                display_name: None,
                status: if pid != "-" {
                    format!("running (pid {pid})")
                } else if status != "0" {
                    format!("loaded (last exit {status})")
                } else {
                    "loaded".into()
                },
                startup: None,
                description: None,
            });
        }
        services.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(services)
    }
}

// ---------------------------------------------------------------------------
// Firewall control (pf anchor)
// ---------------------------------------------------------------------------

impl FirewallControl for MacosPlatform {
    fn block_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        let ip: IpAddr = ip.parse().map_err(|_| {
            NetroError::new(
                ErrorCode::InvalidTarget,
                format!("'{ip}' is not an IP address"),
            )
        })?;
        if !dry_run && !self.is_elevated() {
            return Err(NetroError::new(
                ErrorCode::PermissionDenied,
                "pf firewall changes require root on macOS",
            )
            .with_hint(self.elevation_hint()));
        }
        let mut ips = read_pf_state();
        if !ips.contains(&ip.to_string()) {
            ips.push(ip.to_string());
        }
        let rules_file = pf_rules_path();
        let commands = vec![
            format!("write pf anchor rules to {}", rules_file.display()),
            format!("pfctl -a netro -f {}", rules_file.display()),
            "pfctl -e  # enable pf if currently disabled".to_string(),
        ];
        if dry_run {
            return Ok(FirewallChange {
                action: "block".into(),
                ip: ip.to_string(),
                backend: "pf (anchor netro)".into(),
                commands,
                applied: false,
                output: None,
                rollback: vec!["pfctl -a netro -F rules".into()],
                note: Some(
                    "netro manages only its own pf anchor; other pf rules are untouched".into(),
                ),
            });
        }
        write_pf_state(&ips)?;
        let pfctl = which("pfctl")
            .ok_or_else(|| dependency_missing("pfctl", "macOS packet filter control"))?;
        let mut output = util::run_command(
            &pfctl.to_string_lossy(),
            &["-a", "netro", "-f", &rules_file.to_string_lossy()],
            CMD_TIMEOUT,
        )?
        .combined();
        {
            let info = util::run_command(&pfctl.to_string_lossy(), &["-s", "info"], CMD_TIMEOUT)?;
            if !info.stdout.contains("Status: Enabled") {
                output.push_str(
                    &util::run_command(&pfctl.to_string_lossy(), &["-e"], CMD_TIMEOUT)?.combined(),
                );
            }
        }
        Ok(FirewallChange {
            action: "block".into(),
            ip: ip.to_string(),
            backend: "pf (anchor netro)".into(),
            commands,
            applied: true,
            output: Some(output.trim().to_string()),
            rollback: vec!["pfctl -a netro -F rules".into()],
            note: Some("netro manages only its own pf anchor; other pf rules are untouched".into()),
        })
    }

    fn unblock_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        let ip: IpAddr = ip.parse().map_err(|_| {
            NetroError::new(
                ErrorCode::InvalidTarget,
                format!("'{ip}' is not an IP address"),
            )
        })?;
        if !dry_run && !self.is_elevated() {
            return Err(NetroError::new(
                ErrorCode::PermissionDenied,
                "pf firewall changes require root on macOS",
            )
            .with_hint(self.elevation_hint()));
        }
        let mut ips = read_pf_state();
        if !ips.contains(&ip.to_string()) {
            return Err(NetroError::new(
                ErrorCode::NotFound,
                format!("netro has no recorded pf block for {ip}"),
            ));
        }
        ips.retain(|s| s != &ip.to_string());
        let rules_file = pf_rules_path();
        let commands = vec![
            format!("rewrite pf anchor rules to {}", rules_file.display()),
            format!("pfctl -a netro -f {}", rules_file.display()),
        ];
        if dry_run {
            return Ok(FirewallChange {
                action: "unblock".into(),
                ip: ip.to_string(),
                backend: "pf (anchor netro)".into(),
                commands,
                applied: false,
                output: None,
                rollback: vec![],
                note: None,
            });
        }
        write_pf_state(&ips)?;
        let pfctl = which("pfctl")
            .ok_or_else(|| dependency_missing("pfctl", "macOS packet filter control"))?;
        let output = util::run_command(
            &pfctl.to_string_lossy(),
            &["-a", "netro", "-f", &rules_file.to_string_lossy()],
            CMD_TIMEOUT,
        )?
        .combined();
        Ok(FirewallChange {
            action: "unblock".into(),
            ip: ip.to_string(),
            backend: "pf (anchor netro)".into(),
            commands,
            applied: true,
            output: Some(output.trim().to_string()),
            rollback: vec![],
            note: None,
        })
    }
}

impl Platform for MacosPlatform {
    fn id(&self) -> PlatformId {
        PlatformId::Macos
    }

    fn display_name(&self) -> &'static str {
        "macOS"
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
        "run the command with sudo"
    }

    fn dependencies(&self) -> Vec<Dependency> {
        vec![
            probe_dependency(
                "netstat",
                "netstat",
                &["-h"],
                "routing table and sockets",
                true,
            ),
            probe_dependency("arp", "arp", &["-a"], "IPv4 neighbor table", false),
            probe_dependency("ndp", "ndp", &["-h"], "IPv6 neighbor table", false),
            probe_dependency(
                "lsof",
                "lsof",
                &["-v"],
                "connection-to-process mapping",
                true,
            ),
            probe_dependency(
                "scutil",
                "scutil",
                &["--help"],
                "resolver configuration",
                false,
            ),
            probe_dependency(
                "socketfilterfw",
                "socketfilterfw",
                &["--help"],
                "Application Firewall state",
                false,
            ),
            probe_dependency(
                "pfctl",
                "pfctl",
                &["-h"],
                "packet filter state and control",
                false,
            ),
            probe_dependency(
                "system_profiler",
                "system_profiler",
                &["-h"],
                "GPU and hardware details",
                false,
            ),
            probe_dependency(
                "launchctl",
                "launchctl",
                &["help"],
                "service (launchd) listing",
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
                "iperf3",
                "iperf3",
                &["--version"],
                "throughput testing",
                false,
            ),
            probe_dependency(
                "ping",
                "ping",
                &["-h"],
                "ICMP latency and connectivity",
                false,
            ),
            probe_dependency(
                "traceroute",
                "traceroute",
                &["--help"],
                "hop-by-hop path tracing",
                false,
            ),
        ]
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn macos_hardware_ports() -> HashMap<String, String> {
    let mut map = HashMap::new();
    let Some(path) = which("networksetup") else {
        return map;
    };
    let Ok(out) = util::run_command(
        &path.to_string_lossy(),
        &["-listallhardwareports"],
        CMD_TIMEOUT,
    ) else {
        return map;
    };
    let mut current_port: Option<String> = None;
    for line in out.stdout.lines() {
        let trimmed = line.trim();
        if let Some(port) = trimmed.strip_prefix("Hardware Port:") {
            current_port = Some(port.trim().to_string());
        } else if let Some(device) = trimmed.strip_prefix("Device:") {
            if let Some(port) = &current_port {
                map.insert(device.trim().to_string(), port.clone());
            }
        }
    }
    map
}

fn classify_macos_port(port: &str) -> InterfaceKind {
    let lower = port.to_ascii_lowercase();
    if lower.contains("wi-fi") || lower.contains("airport") {
        InterfaceKind::Wifi
    } else if lower.contains("ethernet") || lower.contains("thunderbolt") {
        InterfaceKind::Ethernet
    } else if lower.contains("bridge") {
        InterfaceKind::Bridge
    } else if lower.contains("vpn") || lower.contains("tunnel") {
        InterfaceKind::Vpn
    } else if lower.contains("firewire") {
        InterfaceKind::Virtual
    } else {
        InterfaceKind::Unknown
    }
}

fn parse_netstat_routes(content: &str, family: &str) -> Vec<Route> {
    let mut out = Vec::new();
    for line in content.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Routing tables")
            || trimmed.starts_with("Internet")
            || trimmed.starts_with("Destination")
            || trimmed.starts_with("Gateway")
        {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.len() < 2 {
            continue;
        }
        let destination_raw = cols[0];
        let gateway_raw = cols[1];
        if destination_raw.eq_ignore_ascii_case("default") {
            out.push(Route {
                family: family.into(),
                destination: if family == "ipv6" { "::" } else { "0.0.0.0" }.into(),
                prefix: 0,
                gateway: (!gateway_raw.starts_with("link#")).then(|| gateway_raw.to_string()),
                interface: cols.get(3).map(|s| s.to_string()),
                metric: None,
                flags: cols.get(2).map(|f| vec![f.to_string()]).unwrap_or_default(),
                is_default: true,
            });
            continue;
        }
        let (destination, prefix) = match destination_raw.split_once('/') {
            Some((d, p)) => (d.to_string(), p.parse::<u8>().unwrap_or(0)),
            None => {
                let inferred = if family == "ipv6" {
                    if destination_raw.contains("::") && !destination_raw.contains(':') {
                        0
                    } else {
                        128
                    }
                } else {
                    match destination_raw.matches('.').count() {
                        3 => 32,
                        2 => 24,
                        1 => 16,
                        _ => 0,
                    }
                };
                (destination_raw.to_string(), inferred)
            }
        };
        out.push(Route {
            family: family.into(),
            destination,
            prefix,
            gateway: (!gateway_raw.starts_with("link#")).then(|| gateway_raw.to_string()),
            interface: cols.get(3).map(|s| s.to_string()),
            metric: None,
            flags: cols.get(2).map(|f| vec![f.to_string()]).unwrap_or_default(),
            is_default: false,
        });
    }
    out
}

fn parse_arp_output(content: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in content.lines() {
        let Some(open) = line.find('(') else { continue };
        let Some(close) = line[open..].find(')') else {
            continue;
        };
        let ip = line[open + 1..open + close].trim().to_string();
        let rest = &line[open + close + 1..];
        if !rest.contains(" at ") {
            continue;
        }
        let after_at = rest.split(" at ").nth(1).unwrap_or("");
        let mut parts = after_at.split_whitespace();
        let mac = parts.next().unwrap_or("").to_ascii_lowercase();
        if mac == "(incomplete)" || mac.is_empty() {
            continue;
        }
        let interface = after_at
            .split(" on ")
            .nth(1)
            .and_then(|s| s.split_whitespace().next())
            .map(|s| s.to_string());
        out.push(Neighbor {
            ip,
            mac: Some(mac),
            interface,
            state: Some("reachable".into()),
            vendor: None,
            hostname: None,
        });
    }
    out
}

fn parse_ndp_output(content: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 3 || cols[0] == "Neighbor" {
            continue;
        }
        let ip = cols[0].split('%').next().unwrap_or("").to_string();
        let mac = cols[1].to_ascii_lowercase();
        if mac.is_empty() || mac == "(incomplete)" {
            continue;
        }
        out.push(Neighbor {
            ip,
            mac: Some(mac),
            interface: Some(cols[2].to_string()),
            state: None,
            vendor: None,
            hostname: None,
        });
    }
    out
}

fn split_dscache_blocks(content: &str) -> Vec<HashMap<String, String>> {
    let mut records = Vec::new();
    let mut current: HashMap<String, String> = HashMap::new();
    for line in content.lines() {
        if line.trim().is_empty() {
            if !current.is_empty() {
                records.push(std::mem::take(&mut current));
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            current.insert(key.trim().to_string(), value.trim().to_string());
        }
    }
    if !current.is_empty() {
        records.push(current);
    }
    records
}

fn macos_groups() -> HashMap<String, Vec<String>> {
    let mut map = HashMap::new();
    let Some(path) = which("dscacheutil") else {
        return map;
    };
    let Ok(out) = util::run_command(&path.to_string_lossy(), &["-q", "group"], CMD_TIMEOUT) else {
        return map;
    };
    for record in split_dscache_blocks(&out.stdout) {
        let name = record.get("name").cloned().unwrap_or_default();
        let users = record
            .get("users")
            .map(|u| {
                u.split_whitespace()
                    .map(|s| s.to_string())
                    .collect::<Vec<_>>()
            })
            .unwrap_or_default();
        if !name.is_empty() {
            map.insert(name, users);
        }
    }
    map
}

fn macos_admin_members() -> Vec<String> {
    let Some(path) = which("dscl") else {
        return Vec::new();
    };
    let Ok(out) = util::run_command(
        &path.to_string_lossy(),
        &[".", "-read", "/Groups/admin", "GroupMembership"],
        CMD_TIMEOUT,
    ) else {
        return Vec::new();
    };
    out.stdout
        .split_once(':')
        .map(|(_, rest)| rest.split_whitespace().map(|s| s.to_string()).collect())
        .unwrap_or_default()
}

fn macos_lsof_connections() -> Result<Vec<Connection>> {
    let lsof =
        which("lsof").ok_or_else(|| dependency_missing("lsof", "connection listing on macOS"))?;
    let out = util::run_command(&lsof.to_string_lossy(), &["-nP", "-i"], CMD_TIMEOUT)?;
    if !out.success() && out.stdout.trim().is_empty() {
        return Err(NetroError::new(
            ErrorCode::Other,
            "lsof failed to list network connections",
        ));
    }
    let mut connections = Vec::new();
    for line in out.stdout.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 9 {
            continue;
        }
        let command = cols[0].to_string();
        let pid = cols[1].parse::<u32>().ok();
        let protocol = cols[7].to_ascii_lowercase();
        if protocol != "tcp" && protocol != "udp" {
            continue;
        }
        let name = cols[8..].join(" ");
        let (local_part, state, remote_part) = split_lsof_name(&name);
        let (local_addr, local_port) = match parse_lsof_addr(&local_part) {
            Some(v) => v,
            None => continue,
        };
        let (remote_addr, remote_port) = remote_part
            .as_deref()
            .and_then(parse_lsof_addr)
            .map(|(a, p)| (Some(a), Some(p)))
            .unwrap_or((None, None));
        connections.push(Connection {
            protocol,
            local_addr,
            local_port,
            remote_addr,
            remote_port,
            state,
            pid,
            process: Some(command),
        });
    }
    Ok(connections)
}

fn split_lsof_name(name: &str) -> (String, String, Option<String>) {
    // Examples:
    //   127.0.0.1:8080 (LISTEN)
    //   192.168.1.5:52344->93.184.216.34:443 (ESTABLISHED)
    //   [::1]:8080 (LISTEN)
    let (body, state) = match name.rsplit_once('(') {
        Some((b, s)) => (b.trim(), s.trim_end_matches(')').trim().to_string()),
        None => (name.trim(), String::new()),
    };
    match body.split_once("->") {
        Some((local, remote)) => (
            local.trim().to_string(),
            state,
            Some(remote.trim().to_string()),
        ),
        None => (body.to_string(), state, None),
    }
}

fn parse_lsof_addr(text: &str) -> Option<(String, u16)> {
    let text = text.trim();
    if text.is_empty() || text == "*" {
        return None;
    }
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let (host, after) = rest.split_once(']')?;
        let port = after.strip_prefix(':')?;
        (host.to_string(), port)
    } else {
        let (host, port) = text.rsplit_once(':')?;
        (host.to_string(), port)
    };
    let port: u16 = port.parse().ok()?;
    let host = if host == "*" {
        "0.0.0.0".to_string()
    } else {
        host
    };
    Some((host, port))
}

fn pf_rules_path() -> std::path::PathBuf {
    crate::config::data_dir().join("pf-netro.conf")
}

fn read_pf_state() -> Vec<String> {
    let path = pf_rules_path();
    let content = std::fs::read_to_string(path).unwrap_or_default();
    content
        .lines()
        .filter_map(|l| {
            let l = l.trim();
            l.strip_prefix("block drop quick from ")
                .and_then(|rest| rest.split_whitespace().next())
                .map(|s| s.to_string())
        })
        .collect()
}

fn write_pf_state(ips: &[String]) -> Result<()> {
    crate::config::ensure_dirs()?;
    let mut content = String::from("# managed by netro - do not edit while netro is running\n");
    for ip in ips {
        content.push_str(&format!("block drop quick from {ip} to any\n"));
    }
    let path = pf_rules_path();
    std::fs::write(&path, content)?;
    crate::config::restrict_permissions(&path);
    Ok(())
}

fn scope_of(addr: &str) -> ExposureScope {
    match addr.parse::<IpAddr>() {
        Ok(IpAddr::V4(v4)) => {
            if v4.is_loopback() {
                ExposureScope::Local
            } else if v4.is_unspecified() {
                ExposureScope::All
            } else {
                ExposureScope::Interface
            }
        }
        Ok(IpAddr::V6(v6)) => {
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

fn parse_vram(value: &str) -> Option<u64> {
    let number: String = value
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let n: f64 = number.parse().ok()?;
    let lower = value.to_ascii_lowercase();
    if lower.contains("gb") {
        Some((n * 1024.0 * 1024.0 * 1024.0) as u64)
    } else if lower.contains("mb") {
        Some((n * 1024.0 * 1024.0) as u64)
    } else {
        Some(n as u64)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn netstat_route_parsing() {
        let content = "Routing tables\n\nInternet:\nDestination        Gateway            Flags        Netif Expire\ndefault            192.168.1.1        UGSc           en0\n127.0.0.1          127.0.0.1          UH             lo0\n192.168.1          link#4             UCS            en0\n192.168.1.1/32     link#4             UCS            en0\n";
        let routes = parse_netstat_routes(content, "ipv4");
        assert_eq!(routes.len(), 4);
        let default = routes.iter().find(|r| r.is_default).unwrap();
        assert_eq!(default.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(default.interface.as_deref(), Some("en0"));
        assert!(routes
            .iter()
            .any(|r| r.destination == "192.168.1" && r.prefix == 24));
    }

    #[test]
    fn arp_parsing() {
        let content = "? (192.168.1.1) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n? (192.168.1.9) at (incomplete) on en0 ifscope [ethernet]\n";
        let neighbors = parse_arp_output(content);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].ip, "192.168.1.1");
        assert_eq!(neighbors[0].interface.as_deref(), Some("en0"));
    }

    #[test]
    fn ndp_parsing() {
        let content = "Neighbor                             Linklayer Address  Netif Expire    St Flgs Prbs\nfe80::1%en0                          aa:bb:cc:dd:ee:ff  en0   23h59m59s S  R\n";
        let neighbors = parse_ndp_output(content);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].ip, "fe80::1");
    }

    #[test]
    fn lsof_name_parsing() {
        let (local, state, remote) =
            split_lsof_name("192.168.1.5:52344->93.184.216.34:443 (ESTABLISHED)");
        assert_eq!(local, "192.168.1.5:52344");
        assert_eq!(state, "ESTABLISHED");
        assert_eq!(remote.as_deref(), Some("93.184.216.34:443"));
        assert_eq!(parse_lsof_addr("[::1]:8080"), Some(("::1".into(), 8080)));
        assert_eq!(parse_lsof_addr("*:22"), Some(("0.0.0.0".into(), 22)));
    }

    #[test]
    fn vram_parsing() {
        assert_eq!(parse_vram("8 GB"), Some(8 * 1024 * 1024 * 1024));
        assert_eq!(parse_vram("1536 MB"), Some(1536 * 1024 * 1024));
    }

    #[test]
    fn dscache_blocks() {
        let content = "name: root\nuid: 0\ngid: 0\ndir: /var/root\nshell: /bin/sh\n\nname: alice\nuid: 501\ngid: 20\ndir: /Users/alice\nshell: /bin/zsh\n";
        let records = split_dscache_blocks(content);
        assert_eq!(records.len(), 2);
        assert_eq!(records[1].get("name").map(|s| s.as_str()), Some("alice"));
    }
}
