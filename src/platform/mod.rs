//! Platform abstraction layer.
//!
//! Core logic depends only on the traits in this module. Operating-system
//! specifics (reading `/proc`, `sysctl`, PowerShell/WMI calls, firewall
//! backends) live exclusively in the per-platform modules.

use crate::error::{unsupported, Result};
use crate::model::*;
use crate::util;

pub mod shared;

#[cfg(target_os = "linux")]
pub mod linux;
#[cfg(target_os = "macos")]
pub mod macos;
#[cfg(target_os = "windows")]
pub mod windows;

/// Host system facts and resources.
pub trait SystemProvider {
    fn os_info(&self) -> Result<OsInfo>;
    fn cpu_info(&self) -> Result<CpuInfo>;
    fn memory_info(&self) -> Result<MemoryInfo>;
    fn disks(&self) -> Result<Vec<DiskInfo>>;
    fn gpu_info(&self) -> Result<Vec<GpuInfo>>;
    fn temperatures(&self) -> Result<Vec<Temperature>> {
        Ok(Vec::new())
    }
    fn virtualization(&self) -> Option<String> {
        None
    }
}

/// Interfaces, routes, resolver configuration and neighbors.
pub trait NetworkProvider {
    fn interfaces(&self) -> Result<Vec<Interface>>;
    fn routes(&self) -> Result<Vec<Route>>;
    fn dns_config(&self) -> Result<DnsConfig>;
    fn neighbors(&self) -> Result<Vec<Neighbor>>;
    fn listening_ports(&self) -> Result<Vec<ListeningPort>>;
}

/// Process inventory and process-to-network mapping.
pub trait ProcessProvider {
    fn processes(&self) -> Result<Vec<ProcessInfo>>;
    fn connections(&self) -> Result<Vec<Connection>>;
    fn process_connections(&self, pid: u32) -> Result<Vec<Connection>> {
        let all = self.connections()?;
        Ok(all
            .into_iter()
            .filter(|c| c.pid == Some(pid))
            .collect::<Vec<_>>())
    }
}

/// Accounts, firewall state and system services.
pub trait SecurityProvider {
    fn accounts(&self) -> Result<Vec<Account>>;
    fn password_policy(&self) -> Result<Option<PasswordPolicy>> {
        Ok(None)
    }
    fn firewall_status(&self) -> Result<FirewallStatus>;
    fn firewall_rules(&self, limit: usize) -> Result<Vec<FirewallRule>> {
        let _ = limit;
        Err(unsupported(
            "firewall rule listing is not implemented on this platform",
        ))
    }
    fn services(&self) -> Result<Vec<ServiceInfo>> {
        Err(unsupported(
            "service listing is not implemented on this platform",
        ))
    }
}

/// Destructive firewall operations, separated from read-only status.
pub trait FirewallControl {
    fn block_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange>;
    fn unblock_ip(&self, ip: &str, dry_run: bool) -> Result<FirewallChange>;
}

/// The complete platform facade.
pub trait Platform:
    SystemProvider
    + NetworkProvider
    + ProcessProvider
    + SecurityProvider
    + FirewallControl
    + Send
    + Sync
{
    fn id(&self) -> PlatformId;
    fn display_name(&self) -> &'static str;
    /// True when running with administrative/root privileges.
    fn is_elevated(&self) -> bool;
    /// Human explanation of how to obtain privileges on this platform.
    fn elevation_hint(&self) -> &'static str;
    /// Optional external tools relevant on this platform.
    fn dependencies(&self) -> Vec<Dependency>;
    /// Paths monitored by integrity checks by default.
    fn default_integrity_paths(&self) -> Vec<String> {
        crate::config::default_integrity_paths()
    }
}

/// The current platform implementation.
pub fn platform() -> &'static dyn Platform {
    #[cfg(target_os = "linux")]
    {
        &linux::LinuxPlatform
    }
    #[cfg(target_os = "windows")]
    {
        &windows::WindowsPlatform
    }
    #[cfg(target_os = "macos")]
    {
        &macos::MacosPlatform
    }
    #[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
    {
        &UnsupportedPlatform
    }
}

pub fn platform_id() -> PlatformId {
    platform().id()
}

pub fn is_elevated() -> bool {
    platform().is_elevated()
}

/// Fallback for platforms netRo does not support. Every capability reports
/// `PLATFORM_UNSUPPORTED` rather than fabricating data.
#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
pub struct UnsupportedPlatform;

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
macro_rules! unsupported_impl {
    ($($name:ident($($arg:ident : $ty:ty),*) -> $ret:ty;)*) => {
        $(
            fn $name(&self $(, $arg: $ty)*) -> $ret {
                $(let _ = $arg;)*
                Err(unsupported("this operating system is not supported by netro"))
            }
        )*
    };
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl SystemProvider for UnsupportedPlatform {
    unsupported_impl! {
        os_info() -> Result<OsInfo>;
        cpu_info() -> Result<CpuInfo>;
        memory_info() -> Result<MemoryInfo>;
        disks() -> Result<Vec<DiskInfo>>;
        gpu_info() -> Result<Vec<GpuInfo>>;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl NetworkProvider for UnsupportedPlatform {
    unsupported_impl! {
        interfaces() -> Result<Vec<Interface>>;
        routes() -> Result<Vec<Route>>;
        dns_config() -> Result<DnsConfig>;
        neighbors() -> Result<Vec<Neighbor>>;
        listening_ports() -> Result<Vec<ListeningPort>>;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl ProcessProvider for UnsupportedPlatform {
    unsupported_impl! {
        processes() -> Result<Vec<ProcessInfo>>;
        connections() -> Result<Vec<Connection>>;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl SecurityProvider for UnsupportedPlatform {
    unsupported_impl! {
        accounts() -> Result<Vec<Account>>;
        firewall_status() -> Result<FirewallStatus>;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl FirewallControl for UnsupportedPlatform {
    unsupported_impl! {
        block_ip(ip: &str, dry_run: bool) -> Result<FirewallChange>;
        unblock_ip(ip: &str, dry_run: bool) -> Result<FirewallChange>;
    }
}

#[cfg(not(any(target_os = "linux", target_os = "windows", target_os = "macos")))]
impl Platform for UnsupportedPlatform {
    fn id(&self) -> PlatformId {
        PlatformId::Unknown
    }
    fn display_name(&self) -> &'static str {
        "unsupported"
    }
    fn is_elevated(&self) -> bool {
        false
    }
    fn elevation_hint(&self) -> &'static str {
        "platform not supported"
    }
    fn dependencies(&self) -> Vec<Dependency> {
        Vec::new()
    }
}

/// Helper shared by platform modules: probe a binary and its version.
pub fn probe_dependency(
    name: &str,
    binary: &str,
    version_args: &[&str],
    purpose: &str,
    required: bool,
) -> Dependency {
    match util::which(binary) {
        Some(path) => {
            let out = util::run_command(
                &path.to_string_lossy(),
                version_args,
                std::time::Duration::from_secs(3),
            )
            .ok();
            let version = out
                .as_ref()
                .map(|o| o.combined())
                .and_then(|s| {
                    s.lines()
                        .find(|l| !l.trim().is_empty())
                        .map(|l| l.trim().to_string())
                })
                .map(|l| l.chars().take(80).collect());
            Dependency {
                name: name.to_string(),
                binary: binary.to_string(),
                installed: true,
                path: Some(path.to_string_lossy().to_string()),
                version,
                purpose: purpose.to_string(),
                required,
                platform: Some(platform_id()),
            }
        }
        None => Dependency {
            name: name.to_string(),
            binary: binary.to_string(),
            installed: false,
            path: None,
            version: None,
            purpose: purpose.to_string(),
            required,
            platform: Some(platform_id()),
        },
    }
}
