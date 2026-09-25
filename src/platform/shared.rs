//! Cross-platform helpers built on `sysinfo` plus shared classification logic.
//!
//! Platform modules may call these, then add OS-specific detail. Anything that
//! only exists on one OS lives in the corresponding platform module.

use crate::model::*;
use std::time::Duration;
use sysinfo::{Components, Disks, System, Users};

/// Convert a sysinfo UID to a numeric id where the platform has one.
#[cfg(unix)]
pub fn uid_to_u32(uid: &sysinfo::Uid) -> Option<u32> {
    Some(**uid)
}

/// Windows user identities are SIDs, not numeric UIDs.
#[cfg(not(unix))]
pub fn uid_to_u32(_uid: &sysinfo::Uid) -> Option<u32> {
    None
}

/// Minimum delay needed for a meaningful CPU usage delta (sysinfo guidance).
pub const CPU_SAMPLE_INTERVAL: Duration = Duration::from_millis(250);

/// Build a `System` with CPU usage sampled over a short interval.
///
/// Deliberately does **not** refresh processes: enumerating the process table
/// costs proportionally to the number of running processes and is only needed
/// by [`sample_processes`].
pub fn sample_cpu_memory() -> (CpuInfo, MemoryInfo) {
    let mut system = System::new();
    system.refresh_memory();
    system.refresh_cpu_all();
    std::thread::sleep(CPU_SAMPLE_INTERVAL);
    system.refresh_cpu_usage();
    (cpu_info(&system), memory_info(&system))
}

/// Build a `System` with a process table refreshed twice (sysinfo needs two
/// refreshes with a short delay to compute per-process CPU percentages).
pub fn sample_processes() -> System {
    let mut system = System::new();
    system.refresh_cpu_all();
    system.refresh_memory();
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    std::thread::sleep(CPU_SAMPLE_INTERVAL);
    system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
    system.refresh_cpu_usage();
    system
}

pub fn os_info() -> OsInfo {
    let uptime = System::uptime();
    let boot = System::boot_time();
    OsInfo {
        name: System::name(),
        long_name: System::long_os_version(),
        version: System::os_version(),
        kernel: System::kernel_version(),
        arch: System::cpu_arch(),
        hostname: System::host_name(),
        distro_id: {
            let id = System::distribution_id();
            if id.is_empty() {
                None
            } else {
                Some(id)
            }
        },
        uptime_secs: uptime,
        boot_time_epoch: if boot > 0 { Some(boot) } else { None },
        virtualization: detect_virtualization(),
        platform: crate::platform::platform_id(),
        note: None,
    }
}

/// Best-effort virtualization detection (Linux DMI/container evidence).
///
/// macOS and Windows implement their own detection in their platform module.
pub fn detect_virtualization() -> Option<String> {
    if cfg!(target_os = "linux") {
        if let Ok(v) = std::fs::read_to_string("/sys/class/dmi/id/product_name") {
            let v = v.trim().to_lowercase();
            if v.contains("kvm") || v.contains("qemu") {
                return Some("KVM/QEMU".into());
            }
            if v.contains("vmware") {
                return Some("VMware".into());
            }
            if v.contains("virtualbox") || v.contains("vbox") {
                return Some("VirtualBox".into());
            }
            if v.contains("hyper-v") || v.contains("virtual machine") {
                return Some("Hyper-V".into());
            }
        }
        if std::path::Path::new("/.dockerenv").exists() {
            return Some("Docker container".into());
        }
        if let Ok(cgroup) = std::fs::read_to_string("/proc/1/cgroup") {
            if cgroup.contains("docker") || cgroup.contains("containerd") {
                return Some("Container".into());
            }
        }
    }
    None
}

pub fn cpu_info(system: &System) -> CpuInfo {
    let cpus = system.cpus();
    let logical = cpus.len();
    let model = cpus.first().map(|c| c.brand().trim().to_string());
    let vendor = cpus.first().map(|c| c.vendor_id().trim().to_string());
    let per_core: Vec<f32> = cpus.iter().map(|c| c.cpu_usage()).collect();
    let max_freq = cpus.iter().map(|c| c.frequency()).max().filter(|f| *f > 0);
    let load = System::load_average();
    let has_load = load.one > 0.0 || load.five > 0.0 || load.fifteen > 0.0;
    let temperatures = crate::platform::platform()
        .temperatures()
        .unwrap_or_default();
    CpuInfo {
        model: model.filter(|m| !m.is_empty()),
        vendor: vendor.filter(|v| !v.is_empty()),
        arch: System::cpu_arch(),
        logical_cores: logical,
        physical_cores: System::physical_core_count(),
        usage_percent: Some(system.global_cpu_usage()),
        per_core_usage: per_core,
        frequency_mhz: max_freq,
        load_average: has_load.then_some([load.one, load.five, load.fifteen]),
        temperatures_c: temperatures,
        note: None,
    }
}

pub fn memory_info(system: &System) -> MemoryInfo {
    let total = system.total_memory();
    let used = system.used_memory();
    let available = system.available_memory();
    let free = system.free_memory();
    let swap_total = system.total_swap();
    let swap_used = system.used_swap();
    MemoryInfo {
        total_bytes: total,
        used_bytes: used,
        available_bytes: available,
        free_bytes: free,
        utilization_percent: crate::util::percent(used, total),
        swap_total_bytes: swap_total,
        swap_used_bytes: swap_used,
        swap_free_bytes: swap_total.saturating_sub(swap_used),
        swap_utilization_percent: crate::util::percent(swap_used, swap_total),
    }
}

pub fn disks() -> Vec<DiskInfo> {
    let disks = Disks::new_with_refreshed_list();
    let mut out: Vec<DiskInfo> = disks
        .list()
        .iter()
        // Filesystems reporting zero total size (e.g. some container overlay
        // mounts) carry no usable capacity information.
        .filter(|d| d.total_space() > 0)
        .map(|d| {
            let total = d.total_space();
            let free = d.available_space();
            let used = total.saturating_sub(free);
            DiskInfo {
                device: d.name().to_string_lossy().to_string(),
                mount_point: d.mount_point().to_string_lossy().to_string(),
                file_system: d.file_system().to_string_lossy().to_string(),
                total_bytes: total,
                used_bytes: used,
                free_bytes: free,
                utilization_percent: crate::util::percent(used, total),
                read_only: d.is_read_only(),
                removable: d.is_removable(),
                kind: Some(d.kind().to_string()),
                note: None,
            }
        })
        .collect();
    out.sort_by(|a, b| a.mount_point.cmp(&b.mount_point));
    out
}

pub fn temperatures() -> Vec<Temperature> {
    let components = Components::new_with_refreshed_list();
    components
        .list()
        .iter()
        .filter_map(|c| {
            let current = c.temperature()?;
            Some(Temperature {
                label: c.label().to_string(),
                current_c: current,
                max_c: c.max(),
                critical_c: c.critical(),
            })
        })
        .collect()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessSort {
    Cpu,
    Memory,
    Pid,
    Recent,
    Name,
}

pub fn processes(system: &System, sort: ProcessSort) -> Vec<ProcessInfo> {
    let users: Vec<(sysinfo::Uid, String)> = Users::new_with_refreshed_list()
        .list()
        .iter()
        .map(|u| (u.id().clone(), u.name().to_string()))
        .collect();

    let mut list: Vec<ProcessInfo> = system
        .processes()
        .iter()
        .map(|(pid, p)| {
            let uid = p.user_id().and_then(uid_to_u32);
            let user = p.user_id().and_then(|id| {
                users
                    .iter()
                    .find(|(known, _)| known == id)
                    .map(|(_, name)| name.clone())
            });
            let cmdline = {
                let cmd: Vec<String> = p
                    .cmd()
                    .iter()
                    .map(|s| s.to_string_lossy().to_string())
                    .collect();
                if cmd.is_empty() {
                    None
                } else {
                    Some(cmd.join(" "))
                }
            };
            let exe = p.exe().map(|e| e.to_string_lossy().to_string());
            let note = if exe.is_none() {
                Some("executable path not readable (permissions)".to_string())
            } else {
                None
            };
            ProcessInfo {
                pid: pid.as_u32(),
                ppid: p.parent().map(|pp| pp.as_u32()),
                name: p.name().to_string_lossy().to_string(),
                exe,
                cmdline,
                user,
                uid,
                cpu_percent: p.cpu_usage(),
                memory_bytes: p.memory(),
                virtual_memory_bytes: p.virtual_memory(),
                start_time_epoch: p.start_time(),
                run_time_secs: p.run_time(),
                status: p.status().to_string(),
                note,
            }
        })
        .collect();

    match sort {
        ProcessSort::Cpu => list.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
                .then_with(|| b.memory_bytes.cmp(&a.memory_bytes))
        }),
        ProcessSort::Memory => list.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
        ProcessSort::Pid => list.sort_by_key(|p| p.pid),
        ProcessSort::Recent => list.sort_by(|a, b| b.start_time_epoch.cmp(&a.start_time_epoch)),
        ProcessSort::Name => list.sort_by(|a, b| a.name.cmp(&b.name)),
    }
    list
}

/// Classify an interface by name using conventional prefixes. This is a
/// heuristic on the *name only* and is labelled as such where it is surfaced.
pub fn classify_interface(name: &str) -> InterfaceKind {
    let n = name.to_ascii_lowercase();
    if n == "lo" || n == "lo0" || n.starts_with("loopback") {
        return InterfaceKind::Loopback;
    }
    if n.starts_with("wl") || n.starts_with("wlan") || n.starts_with("wifi") || n == "en0" {
        // en0 on macOS is usually Wi-Fi, but not always; refined by platform.
        if cfg!(target_os = "macos") {
            return InterfaceKind::Wifi;
        }
        if n.starts_with("wl") || n.starts_with("wlan") {
            return InterfaceKind::Wifi;
        }
    }
    if n.starts_with("docker") || n.starts_with("br-") || n.starts_with("veth") {
        return InterfaceKind::Docker;
    }
    if n.starts_with("tun")
        || n.starts_with("tap")
        || n.starts_with("wg")
        || n.starts_with("utun")
        || n.starts_with("ppp")
        || n.starts_with("ipsec")
        || n.starts_with("tailscale")
        || n.starts_with("zt")
    {
        return InterfaceKind::Vpn;
    }
    if n.starts_with("br") || n.starts_with("bridge") {
        return InterfaceKind::Bridge;
    }
    if n.starts_with("bond") || n.starts_with("lagg") {
        return InterfaceKind::Bond;
    }
    if n.starts_with("vnet")
        || n.starts_with("virbr")
        || n.starts_with("vmnet")
        || n.starts_with("vbox")
        || n.starts_with("dummy")
        || n.starts_with("sit")
        || n.starts_with("gif")
        || n.starts_with("stf")
    {
        return InterfaceKind::Virtual;
    }
    if n.starts_with("eth")
        || n.starts_with("en")
        || n.starts_with("eno")
        || n.starts_with("ens")
        || n.starts_with("enp")
        || n.starts_with("em")
    {
        return InterfaceKind::Ethernet;
    }
    InterfaceKind::Unknown
}

/// Find the default gateway from a route list.
pub fn default_gateway(routes: &[Route], family: &str) -> Option<String> {
    routes
        .iter()
        .find(|r| r.is_default && r.family == family)
        .and_then(|r| r.gateway.clone())
}

/// Helper: resolve the user name for a uid using the system user table.
pub fn username_for_uid(uid: u32) -> Option<String> {
    Users::new_with_refreshed_list()
        .list()
        .iter()
        .find(|u| uid_to_u32(u.id()) == Some(uid))
        .map(|u| u.name().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn interface_classification() {
        assert_eq!(classify_interface("lo"), InterfaceKind::Loopback);
        assert_eq!(classify_interface("wlan0"), InterfaceKind::Wifi);
        assert_eq!(classify_interface("docker0"), InterfaceKind::Docker);
        assert_eq!(classify_interface("tun0"), InterfaceKind::Vpn);
        assert_eq!(classify_interface("br-abc123"), InterfaceKind::Docker);
        assert_eq!(classify_interface("eth0"), InterfaceKind::Ethernet);
    }

    #[test]
    fn default_gateway_picks_correct_family() {
        let routes = vec![
            Route {
                family: "ipv4".into(),
                destination: "0.0.0.0".into(),
                prefix: 0,
                gateway: Some("192.168.1.1".into()),
                interface: Some("eth0".into()),
                metric: Some(100),
                flags: vec!["G".into()],
                is_default: true,
            },
            Route {
                family: "ipv6".into(),
                destination: "::".into(),
                prefix: 0,
                gateway: Some("fe80::1".into()),
                interface: Some("eth0".into()),
                metric: Some(100),
                flags: vec![],
                is_default: true,
            },
        ];
        assert_eq!(default_gateway(&routes, "ipv4"), Some("192.168.1.1".into()));
        assert_eq!(default_gateway(&routes, "ipv6"), Some("fe80::1".into()));
        assert_eq!(default_gateway(&routes, "ipx"), None);
    }

    #[test]
    fn os_info_reports_platform() {
        let info = os_info();
        assert_eq!(info.platform, crate::platform::platform_id());
        assert!(!info.arch.is_empty());
    }
}
