//! Windows platform provider.
//!
//! Uses Windows-native facilities: PowerShell/CIM cmdlets for network, firewall,
//! accounts and services; Win32 security APIs for elevation detection; and
//! `sysinfo` (native FFI) for CPU/memory/process/disk data. No Linux-style
//! shell commands are used.

mod ps;

use crate::error::{ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::shared;
use crate::platform::{
    probe_dependency, FirewallControl, NetworkProvider, Platform, ProcessProvider,
    SecurityProvider, SystemProvider,
};
use crate::util;
use serde_json::Value;
use std::collections::HashMap;
use std::net::IpAddr;

pub struct WindowsPlatform;

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

impl SystemProvider for WindowsPlatform {
    fn os_info(&self) -> Result<OsInfo> {
        let mut info = shared::os_info();
        let script = "Get-CimInstance Win32_OperatingSystem | Select-Object Caption,Version,BuildNumber,OSArchitecture | ConvertTo-Json";
        if let Ok(value) = ps::run_json(script) {
            if let Some(item) = ps::as_array(&value).first() {
                if let Some(caption) = ps::str_field(item, &["Caption"]) {
                    info.long_name = Some(caption);
                }
                if let Some(build) = ps::str_field(item, &["BuildNumber"]) {
                    info.note = Some(format!("Windows build {build}"));
                }
            }
        }
        Ok(info)
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
        let script = "Get-CimInstance Win32_VideoController | Select-Object Name,AdapterRAM,DriverVersion,VideoProcessor | ConvertTo-Json";
        let value = ps::run_json(script)?;
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            let name = ps::str_field(item, &["Name"]);
            let mut gpu = GpuInfo {
                vendor: None,
                model: name.clone(),
                vram_bytes: ps::u64_field(item, &["AdapterRAM"]),
                driver: ps::str_field(item, &["DriverVersion"]),
                utilization_percent: None,
                temperature_c: None,
                power_watts: None,
                compute_backend: None,
                source: "Win32_VideoController (CIM)".into(),
                note: Some(
                    "live GPU utilization/temperature is not exposed by Win32_VideoController; vendor tooling is required"
                        .into(),
                ),
            };
            if let Some(name) = &name {
                let lower = name.to_ascii_lowercase();
                gpu.vendor = if lower.contains("nvidia") {
                    Some("NVIDIA".into())
                } else if lower.contains("amd") || lower.contains("radeon") {
                    Some("AMD".into())
                } else if lower.contains("intel") {
                    Some("Intel".into())
                } else {
                    None
                };
            }
            out.push(gpu);
        }
        Ok(out)
    }

    fn temperatures(&self) -> Result<Vec<Temperature>> {
        Ok(shared::temperatures())
    }

    fn virtualization(&self) -> Option<String> {
        let script = "(Get-CimInstance Win32_ComputerSystem).Manufacturer + '|' + (Get-CimInstance Win32_ComputerSystem).Model | ConvertTo-Json";
        let value = ps::run_json(script).ok()?;
        let text = value.as_str()?.to_ascii_lowercase();
        if text.contains("vmware") {
            Some("VMware".into())
        } else if text.contains("virtualbox") {
            Some("VirtualBox".into())
        } else if text.contains("microsoft corporation") && text.contains("virtual") {
            Some("Hyper-V".into())
        } else if text.contains("qemu") || text.contains("kvm") {
            Some("KVM/QEMU".into())
        } else {
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

impl NetworkProvider for WindowsPlatform {
    fn interfaces(&self) -> Result<Vec<Interface>> {
        let adapter_script = "Get-NetAdapter | Select-Object Name,InterfaceIndex,InterfaceDescription,Status,LinkSpeed,MacAddress,mtu | ConvertTo-Json -Depth 3";
        let adapters = ps::run_json(adapter_script)?;

        let ip_script = "Get-NetIPConfiguration | Select-Object InterfaceAlias,InterfaceIndex,@{n='IPv4';e={@($_.IPv4Address | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength })}},@{n='IPv6';e={@($_.IPv6Address | ForEach-Object { $_.IPAddress + '/' + $_.PrefixLength })}},@{n='Gateway';e={($_.IPv4DefaultGateway | Select-Object -First 1).NextHop}},@{n='Dhcp';e={$_.NetIPv4Interface.Dhcp}},@{n='Dns';e={@($_.DNSServer | ForEach-Object { $_.ServerAddresses })}} | ConvertTo-Json -Depth 4";
        let ip_configs = ps::run_json(ip_script).unwrap_or(Value::Null);

        let config_by_index: HashMap<String, &Value> = ps::as_array(&ip_configs)
            .into_iter()
            .filter_map(|v| {
                let idx = ps::str_field(v, &["InterfaceIndex"])?;
                Some((idx, v))
            })
            .collect();

        let mut out = Vec::new();
        for adapter in ps::as_array(&adapters) {
            let name = ps::str_field(adapter, &["Name"]).unwrap_or_else(|| "unknown".into());
            let index = ps::str_field(adapter, &["InterfaceIndex"]).unwrap_or_default();
            let description = ps::str_field(adapter, &["InterfaceDescription"]);
            let status = ps::str_field(adapter, &["Status"]).unwrap_or_else(|| "Unknown".into());
            let mac = ps::str_field(adapter, &["MacAddress"])
                .map(|m| m.replace('-', ":").to_ascii_lowercase())
                .filter(|m| m != "00:00:00:00:00:00");
            let speed_mbps =
                ps::str_field(adapter, &["LinkSpeed"]).and_then(|s| parse_link_speed_mbps(&s));
            let mtu = ps::u64_field(adapter, &["mtu"]);
            let config = config_by_index.get(&index);
            let ipv4 = config
                .and_then(|c| c.get("IPv4"))
                .map(parse_ip_list)
                .unwrap_or_default();
            let ipv6 = config
                .and_then(|c| c.get("IPv6"))
                .map(parse_ip_list)
                .unwrap_or_default();
            let dhcp = config.and_then(|c| ps::bool_field(c, &["Dhcp"]));
            let default_route = config
                .and_then(|c| ps::str_field(c, &["Gateway"]))
                .filter(|g| !g.is_empty() && g != "0.0.0.0");
            let kind = classify_windows_interface(&name, description.as_deref());
            out.push(Interface {
                name,
                kind,
                mac,
                ipv4,
                ipv6,
                up: status.eq_ignore_ascii_case("up"),
                oper_state: Some(status),
                speed_mbps,
                mtu,
                dhcp,
                dhcp_source: dhcp
                    .map(|_| "Get-NetIPConfiguration NetIPv4Interface.Dhcp".to_string()),
                default_route,
                note: description,
            });
        }
        out.sort_by(|a, b| a.name.cmp(&b.name));
        Ok(out)
    }

    fn routes(&self) -> Result<Vec<Route>> {
        let script = "Get-NetRoute | Select-Object AddressFamily,DestinationPrefix,NextHop,InterfaceAlias,RouteMetric,Protocol | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script)?;
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            let family_raw = ps::str_field(item, &["AddressFamily"]).unwrap_or_default();
            let family = if family_raw.contains("2") || family_raw.eq_ignore_ascii_case("IPv6") {
                "ipv6"
            } else {
                "ipv4"
            };
            let destination_prefix =
                ps::str_field(item, &["DestinationPrefix"]).unwrap_or_default();
            let (destination, prefix) = split_prefix(&destination_prefix, family);
            let next_hop = ps::str_field(item, &["NextHop"]).filter(|s| !s.is_empty());
            let is_default = destination_prefix == "0.0.0.0/0" || destination_prefix == "::/0";
            out.push(Route {
                family: family.into(),
                destination,
                prefix,
                gateway: next_hop,
                interface: ps::str_field(item, &["InterfaceAlias"]),
                metric: ps::u64_field(item, &["RouteMetric"]).map(|m| m as u32),
                flags: ps::str_field(item, &["Protocol"])
                    .map(|p| vec![p])
                    .unwrap_or_default(),
                is_default,
            });
        }
        out.sort_by(|a, b| {
            b.is_default
                .cmp(&a.is_default)
                .then_with(|| a.family.cmp(&b.family))
        });
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "Get-NetRoute returned no routes",
            ));
        }
        Ok(out)
    }

    fn dns_config(&self) -> Result<DnsConfig> {
        let script = "Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 } | Select-Object InterfaceAlias,AddressFamily,ServerAddresses | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script)?;
        let mut servers: Vec<String> = Vec::new();
        for item in ps::as_array(&value) {
            if let Some(list) = item.get("ServerAddresses").and_then(|v| v.as_array()) {
                for s in list {
                    if let Some(s) = s.as_str() {
                        if !servers.contains(&s.to_string()) {
                            servers.push(s.to_string());
                        }
                    }
                }
            } else if let Some(s) = ps::str_field(item, &["ServerAddresses"]) {
                servers.push(s);
            }
        }
        if servers.is_empty() {
            return Err(NetroError::new(
                ErrorCode::NetworkDnsUnavailable,
                "no DNS servers configured on any interface",
            ));
        }
        Ok(DnsConfig {
            servers,
            search_domains: Vec::new(),
            source: "Get-DnsClientServerAddress".into(),
            systemd_resolved_stub: false,
            note: None,
        })
    }

    fn neighbors(&self) -> Result<Vec<Neighbor>> {
        let script = "Get-NetNeighbor | Where-Object { $_.LinkLayerAddress -and $_.LinkLayerAddress -ne '' } | Select-Object IPAddress,LinkLayerAddress,InterfaceAlias,State | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script)?;
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            let ip = match ps::str_field(item, &["IPAddress"]) {
                Some(ip) => ip,
                None => continue,
            };
            let mac = ps::str_field(item, &["LinkLayerAddress"])
                .map(|m| m.replace('-', ":").to_ascii_lowercase())
                .filter(|m| m != "ff:ff:ff:ff:ff:ff");
            out.push(Neighbor {
                ip,
                mac,
                interface: ps::str_field(item, &["InterfaceAlias"]),
                state: ps::str_field(item, &["State"]),
                vendor: None,
                hostname: None,
            });
        }
        out.sort_by_key(|n| n.ip.parse::<IpAddr>().ok().map(|ip| util::ip_sort_key(&ip)));
        Ok(out)
    }

    fn listening_ports(&self) -> Result<Vec<ListeningPort>> {
        let script = "$tcp = @(Get-NetTCPConnection -State Listen | Select-Object LocalAddress,LocalPort,OwningProcess,State); $udp = @(Get-NetUDPEndpoint | Select-Object LocalAddress,LocalPort,OwningProcess); [pscustomobject]@{tcp=$tcp;udp=$udp} | ConvertTo-Json -Depth 4";
        let value = ps::run_json(script)?;
        let pid_names = process_name_map();
        let mut out = Vec::new();
        if let Some(tcp) = value.get("tcp") {
            for item in ps::as_array(tcp) {
                let address = ps::str_field(item, &["LocalAddress"]).unwrap_or_default();
                let port = ps::u64_field(item, &["LocalPort"]).unwrap_or(0) as u16;
                let pid = ps::u64_field(item, &["OwningProcess"]).map(|p| p as u32);
                out.push(ListeningPort {
                    protocol: "tcp".into(),
                    scope: scope_of(&address),
                    address,
                    port,
                    state: ps::str_field(item, &["State"]).unwrap_or_else(|| "Listen".into()),
                    pid,
                    process: pid.and_then(|p| pid_names.get(&p).cloned()),
                });
            }
        }
        if let Some(udp) = value.get("udp") {
            for item in ps::as_array(udp) {
                let address = ps::str_field(item, &["LocalAddress"]).unwrap_or_default();
                let port = ps::u64_field(item, &["LocalPort"]).unwrap_or(0) as u16;
                let pid = ps::u64_field(item, &["OwningProcess"]).map(|p| p as u32);
                out.push(ListeningPort {
                    protocol: "udp".into(),
                    scope: scope_of(&address),
                    address,
                    port,
                    state: "UNCONNECTED".into(),
                    pid,
                    process: pid.and_then(|p| pid_names.get(&p).cloned()),
                });
            }
        }
        out.sort_by(|a, b| {
            a.port
                .cmp(&b.port)
                .then_with(|| a.protocol.cmp(&b.protocol))
        });
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

impl ProcessProvider for WindowsPlatform {
    fn processes(&self) -> Result<Vec<ProcessInfo>> {
        let system = shared::sample_processes();
        Ok(shared::processes(&system, shared::ProcessSort::Cpu))
    }

    fn connections(&self) -> Result<Vec<Connection>> {
        let script = "Get-NetTCPConnection | Where-Object { $_.RemoteAddress -and $_.RemoteAddress -ne '0.0.0.0' -and $_.RemoteAddress -ne '::' } | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script).unwrap_or(Value::Null);
        let pid_names = process_name_map();
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            let pid = ps::u64_field(item, &["OwningProcess"]).map(|p| p as u32);
            out.push(Connection {
                protocol: "tcp".into(),
                local_addr: ps::str_field(item, &["LocalAddress"]).unwrap_or_default(),
                local_port: ps::u64_field(item, &["LocalPort"]).unwrap_or(0) as u16,
                remote_addr: ps::str_field(item, &["RemoteAddress"]),
                remote_port: ps::u64_field(item, &["RemotePort"]).map(|p| p as u16),
                state: ps::str_field(item, &["State"]).unwrap_or_else(|| "Unknown".into()),
                pid,
                process: pid.and_then(|p| pid_names.get(&p).cloned()),
            });
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Security
// ---------------------------------------------------------------------------

impl SecurityProvider for WindowsPlatform {
    fn accounts(&self) -> Result<Vec<Account>> {
        let script = "$users = @(Get-LocalUser | Select-Object Name,Enabled,PasswordRequired,PasswordLastSet,LastLogon,Description); $admins = @(Get-LocalGroupMember -Group Administrators | Select-Object -ExpandProperty Name); [pscustomobject]@{users=$users;admins=$admins} | ConvertTo-Json -Depth 4";
        let value = ps::run_json(script)?;
        let admins: Vec<String> = value
            .get("admins")
            .map(ps::as_array)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|v| v.as_str().map(|s| s.to_string()))
            .map(|s| s.split('\\').last().unwrap_or(&s).to_string())
            .collect();
        let mut out = Vec::new();
        if let Some(users) = value.get("users") {
            for item in ps::as_array(users) {
                let name = match ps::str_field(item, &["Name"]) {
                    Some(n) => n,
                    None => continue,
                };
                let enabled = ps::bool_field(item, &["Enabled"]).unwrap_or(true);
                let password_required = ps::bool_field(item, &["PasswordRequired"]);
                let password = if !enabled {
                    PasswordStatus::Locked
                } else if password_required == Some(false) {
                    PasswordStatus::Empty
                } else {
                    PasswordStatus::Set
                };
                let privileged = admins.iter().any(|a| a.eq_ignore_ascii_case(&name));
                out.push(Account {
                    name: name.clone(),
                    uid: None,
                    gid: None,
                    home: None,
                    shell: None,
                    privileged,
                    is_system: false,
                    login_shell: true,
                    password,
                    groups: if privileged {
                        vec!["Administrators".into()]
                    } else {
                        Vec::new()
                    },
                    note: Some(
                        "Windows does not expose password hashes; status derives from account flags"
                            .into(),
                    ),
                });
            }
        }
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::DependencyMissing,
                "Get-LocalUser returned no accounts",
            )
            .with_hint("requires PowerShell with the LocalAccounts module"));
        }
        out.sort_by(|a, b| a.name.to_lowercase().cmp(&b.name.to_lowercase()));
        Ok(out)
    }

    fn password_policy(&self) -> Result<Option<PasswordPolicy>> {
        let out = ps::run_text("net accounts")?;
        let mut policy = PasswordPolicy {
            min_length: None,
            max_age_days: None,
            min_age_days: None,
            warn_days: None,
            remember: None,
            lockout_threshold: None,
            lockout_duration_secs: None,
            source: "net accounts".into(),
        };
        let mut found = false;
        for line in out.lines() {
            let Some((key, value)) = line.split_once(':') else {
                continue;
            };
            let key = key.trim().to_ascii_lowercase();
            let value = value.trim();
            let num = || {
                value
                    .split_whitespace()
                    .next()
                    .and_then(|v| v.parse::<u32>().ok())
            };
            if key.contains("minimum password length") {
                policy.min_length = num();
                found = true;
            } else if key.contains("maximum password age") {
                policy.max_age_days = num();
                found = true;
            } else if key.contains("minimum password age") {
                policy.min_age_days = num();
                found = true;
            } else if key.contains("lockout threshold") {
                policy.lockout_threshold = num();
                found = true;
            } else if key.contains("lockout duration") {
                policy.lockout_duration_secs = num().map(|m| m * 60);
                found = true;
            }
        }
        Ok(found.then_some(policy))
    }

    fn firewall_status(&self) -> Result<FirewallStatus> {
        let script = "Get-NetFirewallProfile | Select-Object Name,Enabled,DefaultInboundAction,DefaultOutboundAction | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script)?;
        let mut status = FirewallStatus::default();
        let mut all_enabled = true;
        let mut any = false;
        for item in ps::as_array(&value) {
            let name = ps::str_field(item, &["Name"]).unwrap_or_else(|| "Unknown".into());
            let enabled = ps::bool_field(item, &["Enabled"]);
            any = true;
            if enabled != Some(true) {
                all_enabled = false;
            }
            let inbound = ps::str_field(item, &["DefaultInboundAction"]);
            let outbound = ps::str_field(item, &["DefaultOutboundAction"]);
            status.backends.push(FirewallBackend {
                name: format!("Windows Defender Firewall ({name} profile)"),
                active: enabled,
                detail: Some(format!(
                    "default inbound={}, default outbound={}",
                    inbound.unwrap_or_else(|| "unknown".into()),
                    outbound.unwrap_or_else(|| "unknown".into())
                )),
                via: "Get-NetFirewallProfile".into(),
            });
        }
        if !any {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "Get-NetFirewallProfile returned no profiles",
            ));
        }
        status.enabled = Some(all_enabled);
        if !all_enabled {
            status
                .notes
                .push("at least one firewall profile is disabled".into());
        }
        Ok(status)
    }

    fn firewall_rules(&self, limit: usize) -> Result<Vec<FirewallRule>> {
        let script = format!(
            "Get-NetFirewallRule -Enabled True -Direction Inbound | Select-Object -First {limit} DisplayName,Action,Profile | ConvertTo-Json -Depth 3"
        );
        let value = ps::run_json(&script)?;
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            let display = ps::str_field(item, &["DisplayName"]).unwrap_or_else(|| "?".into());
            out.push(FirewallRule {
                backend: "windows-defender".into(),
                chain: ps::str_field(item, &["Profile"]),
                action: ps::str_field(item, &["Action"]).unwrap_or_else(|| "Unknown".into()),
                source: None,
                destination: None,
                ports: None,
                protocol: None,
                raw: display,
            });
        }
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "no enabled inbound firewall rules returned",
            ));
        }
        Ok(out)
    }

    fn services(&self) -> Result<Vec<ServiceInfo>> {
        let script = "Get-Service | Select-Object Name,DisplayName,Status,StartType | ConvertTo-Json -Depth 3";
        let value = ps::run_json(script)?;
        let mut out = Vec::new();
        for item in ps::as_array(&value) {
            out.push(ServiceInfo {
                name: ps::str_field(item, &["Name"]).unwrap_or_default(),
                display_name: ps::str_field(item, &["DisplayName"]),
                status: ps::str_field(item, &["Status"]).unwrap_or_else(|| "Unknown".into()),
                startup: ps::str_field(item, &["StartType"]),
                description: None,
            });
        }
        if out.is_empty() {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "Get-Service returned no services",
            ));
        }
        Ok(out)
    }
}

// ---------------------------------------------------------------------------
// Firewall control
// ---------------------------------------------------------------------------

impl FirewallControl for WindowsPlatform {
    fn block_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        let ip = validate_ip(ip)?;
        if !dry_run && !self.is_elevated() {
            return Err(NetroError::new(
                ErrorCode::PermissionDenied,
                "blocking traffic requires an elevated (Administrator) shell",
            )
            .with_hint(self.elevation_hint()));
        }
        let display_name = format!("netro-block-{ip}");
        let commands = vec![format!(
            "New-NetFirewallRule -DisplayName '{display_name}' -Direction Inbound -RemoteAddress {ip} -Action Block -Profile Any"
        )];
        let rollback = vec![format!(
            "Remove-NetFirewallRule -DisplayName '{display_name}'"
        )];
        if dry_run {
            return Ok(FirewallChange {
                action: "block".into(),
                ip: ip.to_string(),
                backend: "windows-defender".into(),
                commands,
                applied: false,
                output: None,
                rollback,
                note: None,
            });
        }
        let script = format!(
            "New-NetFirewallRule -DisplayName '{display_name}' -Direction Inbound -RemoteAddress {ip} -Action Block -Profile Any | Out-Null; 'ok'"
        );
        let output = ps::run_text(&script)?;
        Ok(FirewallChange {
            action: "block".into(),
            ip: ip.to_string(),
            backend: "windows-defender".into(),
            commands,
            applied: true,
            output: Some(output.trim().to_string()),
            rollback,
            note: None,
        })
    }

    fn unblock_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange> {
        let ip = validate_ip(ip)?;
        if !dry_run && !self.is_elevated() {
            return Err(NetroError::new(
                ErrorCode::PermissionDenied,
                "changing firewall rules requires an elevated (Administrator) shell",
            )
            .with_hint(self.elevation_hint()));
        }
        let display_name = format!("netro-block-{ip}");
        let commands = vec![format!(
            "Remove-NetFirewallRule -DisplayName '{display_name}'"
        )];
        if dry_run {
            return Ok(FirewallChange {
                action: "unblock".into(),
                ip: ip.to_string(),
                backend: "windows-defender".into(),
                commands,
                applied: false,
                output: None,
                rollback: vec![],
                note: None,
            });
        }
        let script = format!(
            "$r = Get-NetFirewallRule -DisplayName '{display_name}' -ErrorAction SilentlyContinue; if (-not $r) {{ throw 'no netro block rule for {ip}' }}; Remove-NetFirewallRule -DisplayName '{display_name}'; 'ok'"
        );
        let output = ps::run_text(&script)?;
        Ok(FirewallChange {
            action: "unblock".into(),
            ip: ip.to_string(),
            backend: "windows-defender".into(),
            commands,
            applied: true,
            output: Some(output.trim().to_string()),
            rollback: vec![],
            note: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Platform
// ---------------------------------------------------------------------------

impl Platform for WindowsPlatform {
    fn id(&self) -> PlatformId {
        PlatformId::Windows
    }

    fn display_name(&self) -> &'static str {
        "Windows"
    }

    fn is_elevated(&self) -> bool {
        #[cfg(windows)]
        {
            native_is_elevated()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }

    fn elevation_hint(&self) -> &'static str {
        "run netro from an Administrator terminal (or use 'Run as administrator')"
    }

    fn dependencies(&self) -> Vec<Dependency> {
        let mut deps = vec![
            probe_dependency(
                "PowerShell",
                "powershell",
                &[
                    "-NoProfile",
                    "-Command",
                    "$PSVersionTable.PSVersion.ToString()",
                ],
                "network, firewall, account and service data",
                true,
            ),
            probe_dependency(
                "ping",
                "ping",
                &["-?"],
                "ICMP latency and connectivity",
                false,
            ),
            probe_dependency(
                "tracert",
                "tracert",
                &["-?"],
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
            probe_dependency("ncat", "ncat", &["--version"], "connectivity checks", false),
            probe_dependency(
                "iperf3",
                "iperf3",
                &["--version"],
                "throughput testing",
                false,
            ),
            probe_dependency(
                "nvidia-smi",
                "nvidia-smi",
                &["--version"],
                "NVIDIA GPU metrics",
                false,
            ),
        ];
        if ps::powershell_path().is_none() {
            deps.push(Dependency {
                name: "PowerShell".into(),
                binary: "powershell".into(),
                installed: false,
                path: None,
                version: None,
                purpose: "network, firewall, account and service data".into(),
                required: true,
                platform: Some(PlatformId::Windows),
            });
        }
        deps
    }
}

#[cfg(windows)]
fn native_is_elevated() -> bool {
    use windows_sys::Win32::Foundation::{CloseHandle, HANDLE};
    use windows_sys::Win32::Security::{
        GetTokenInformation, TokenElevation, TOKEN_ELEVATION, TOKEN_QUERY,
    };
    use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
    unsafe {
        let mut token: HANDLE = std::ptr::null_mut();
        if OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) == 0 {
            return false;
        }
        let mut elevation = TOKEN_ELEVATION { TokenIsElevated: 0 };
        let mut returned = 0u32;
        let ok = GetTokenInformation(
            token,
            TokenElevation,
            &mut elevation as *mut _ as *mut core::ffi::c_void,
            std::mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        );
        CloseHandle(token);
        ok != 0 && elevation.TokenIsElevated != 0
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn process_name_map() -> HashMap<u32, String> {
    use sysinfo::System;
    let mut system = System::new();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system
        .processes()
        .iter()
        .map(|(pid, p)| (pid.as_u32(), p.name().to_string_lossy().to_string()))
        .collect()
}

fn validate_ip(ip: &str) -> Result<IpAddr> {
    ip.parse::<IpAddr>().map_err(|_| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{ip}' is not an IP address"),
        )
    })
}

fn parse_ip_list(value: &Value) -> Vec<IpWithPrefix> {
    let mut out = Vec::new();
    for item in ps::as_array(value) {
        if let Some(s) = item.as_str() {
            let (addr, prefix) = match s.split_once('/') {
                Some((a, p)) => (a.to_string(), p.parse::<u8>().unwrap_or(0)),
                None => (s.to_string(), 0),
            };
            if addr.parse::<IpAddr>().is_ok() {
                out.push(IpWithPrefix { addr, prefix });
            }
        }
    }
    out
}

fn split_prefix(prefix_str: &str, family: &str) -> (String, u8) {
    match prefix_str.split_once('/') {
        Some((addr, p)) => (addr.to_string(), p.parse().unwrap_or(0)),
        None => (
            prefix_str.to_string(),
            if family == "ipv6" { 128 } else { 32 },
        ),
    }
}

fn parse_link_speed_mbps(value: &str) -> Option<u64> {
    let cleaned = value.trim();
    let number: String = cleaned
        .chars()
        .take_while(|c| c.is_ascii_digit() || *c == '.')
        .collect();
    let n: f64 = number.parse().ok()?;
    let lower = cleaned.to_ascii_lowercase();
    if lower.contains("gbps") || lower.contains("gbit") {
        Some((n * 1000.0) as u64)
    } else if lower.contains("kbps") || lower.contains("kbit") {
        Some((n / 1000.0) as u64)
    } else {
        Some(n as u64)
    }
}

fn classify_windows_interface(name: &str, description: Option<&str>) -> InterfaceKind {
    let combined = format!(
        "{} {}",
        name.to_ascii_lowercase(),
        description.unwrap_or("").to_ascii_lowercase()
    );
    if combined.contains("wi-fi") || combined.contains("wifi") || combined.contains("wireless") {
        return InterfaceKind::Wifi;
    }
    if combined.contains("virtual")
        || combined.contains("vmware")
        || combined.contains("hyper-v")
        || combined.contains("vbox")
        || combined.contains("loopback")
    {
        return InterfaceKind::Virtual;
    }
    if combined.contains("vpn") || combined.contains("wireguard") || combined.contains("tap") {
        return InterfaceKind::Vpn;
    }
    if combined.contains("bluetooth") {
        return InterfaceKind::Virtual;
    }
    if combined.contains("ethernet") {
        return InterfaceKind::Ethernet;
    }
    InterfaceKind::Unknown
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn link_speed_parsing() {
        assert_eq!(parse_link_speed_mbps("1 Gbps"), Some(1000));
        assert_eq!(parse_link_speed_mbps("100 Mbps"), Some(100));
        assert_eq!(parse_link_speed_mbps("2.5 Gbps"), Some(2500));
        assert_eq!(parse_link_speed_mbps("unknown"), None);
    }

    #[test]
    fn prefix_splitting() {
        assert_eq!(
            split_prefix("192.168.1.5/24", "ipv4"),
            ("192.168.1.5".into(), 24)
        );
        assert_eq!(split_prefix("::1/128", "ipv6"), ("::1".into(), 128));
        assert_eq!(split_prefix("0.0.0.0/0", "ipv4"), ("0.0.0.0".into(), 0));
    }

    #[test]
    fn interface_classification() {
        assert_eq!(
            classify_windows_interface("Wi-Fi", None),
            InterfaceKind::Wifi
        );
        assert_eq!(
            classify_windows_interface("Ethernet", Some("Intel(R) Ethernet Connection")),
            InterfaceKind::Ethernet
        );
    }

    #[test]
    fn ip_validation() {
        assert!(validate_ip("10.0.0.1").is_ok());
        assert_eq!(
            validate_ip("evil; rm -rf /").unwrap_err().code(),
            ErrorCode::InvalidTarget
        );
    }
}
