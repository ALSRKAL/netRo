//! Platform-aware configuration directories and persistent settings.
//!
//! Defaults live in code; the user file is JSON at
//! `config_dir()/config.json`. Missing fields fall back to defaults. netRo is
//! local-first: no telemetry, no remote calls at startup.

use crate::error::{ErrorCode, NetroError, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

pub const CONFIG_SCHEMA_VERSION: u32 = 1;

/// `~/.config/netro` (Linux), `~/Library/Application Support/netro` (macOS),
/// `%APPDATA%\netro` (Windows).
pub fn config_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("netro")
    } else if cfg!(windows) {
        std::env::var_os("APPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Roaming"))
            .join("netro")
    } else {
        std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home_dir().join(".config"))
            .join("netro")
    }
}

/// Persistent data (integrity baselines).
pub fn data_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        home_dir()
            .join("Library")
            .join("Application Support")
            .join("netro")
            .join("data")
    } else if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Local"))
            .join("netro")
            .join("data")
    } else {
        std::env::var_os("XDG_DATA_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home_dir().join(".local").join("share"))
            .join("netro")
    }
}

/// Cache (scratch) directory.
pub fn cache_dir() -> PathBuf {
    if cfg!(target_os = "macos") {
        home_dir().join("Library").join("Caches").join("netro")
    } else if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA")
            .map(PathBuf::from)
            .unwrap_or_else(|| home_dir().join("AppData").join("Local"))
            .join("netro")
            .join("cache")
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .filter(|p| p.is_absolute())
            .unwrap_or_else(|| home_dir().join(".cache"))
            .join("netro")
    }
}

/// Log directory (under the data dir).
pub fn log_dir() -> PathBuf {
    data_dir().join("logs")
}

pub fn config_file() -> PathBuf {
    config_dir().join("config.json")
}

pub fn baseline_file() -> PathBuf {
    data_dir().join("integrity-baseline.json")
}

/// Render a path for display, replacing the home directory prefix with `~`.
/// Keeps UI text portable across machines and users.
pub fn display_path(path: &Path) -> String {
    let home = home_dir();
    if let Ok(stripped) = path.strip_prefix(&home) {
        let suffix = stripped.display().to_string();
        if suffix.is_empty() {
            return "~".to_string();
        }
        return format!("~{}{suffix}", std::path::MAIN_SEPARATOR);
    }
    path.display().to_string()
}

fn home_dir() -> PathBuf {
    std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("."))
}

/// Create config/data/cache/log directories if missing.
pub fn ensure_dirs() -> Result<()> {
    for dir in [config_dir(), data_dir(), cache_dir(), log_dir()] {
        std::fs::create_dir_all(&dir).map_err(|e| {
            NetroError::new(
                ErrorCode::Io,
                format!("cannot create {}: {e}", dir.display()),
            )
        })?;
    }
    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub schema_version: u32,
    pub scan: ScanDefaults,
    pub monitor: MonitorDefaults,
    pub output: OutputDefaults,
    pub integrity: IntegrityDefaults,
    pub discovery: DiscoveryDefaults,
    pub integrations: Integrations,
    pub privacy: Privacy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            schema_version: CONFIG_SCHEMA_VERSION,
            scan: ScanDefaults::default(),
            monitor: MonitorDefaults::default(),
            output: OutputDefaults::default(),
            integrity: IntegrityDefaults::default(),
            discovery: DiscoveryDefaults::default(),
            integrations: Integrations::default(),
            privacy: Privacy::default(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct ScanDefaults {
    pub ports: String,
    pub timeout_ms: u64,
    pub concurrency: usize,
    pub banner_grab: bool,
    pub tls_probe: bool,
    pub confirm_public_targets: bool,
}

impl Default for ScanDefaults {
    fn default() -> Self {
        Self {
            ports: "common".to_string(),
            timeout_ms: 1000,
            concurrency: 100,
            banner_grab: true,
            tls_probe: true,
            confirm_public_targets: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct MonitorDefaults {
    pub interval_secs: f64,
    pub top_n: usize,
    pub show_temperatures: bool,
}

impl Default for MonitorDefaults {
    fn default() -> Self {
        Self {
            interval_secs: 2.0,
            top_n: 5,
            show_temperatures: true,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct OutputDefaults {
    pub format: String,
    pub color: String,
    pub table_width: usize,
}

impl Default for OutputDefaults {
    fn default() -> Self {
        Self {
            format: "text".to_string(),
            color: "auto".to_string(),
            table_width: 0,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct IntegrityDefaults {
    /// Empty means "use the platform defaults".
    pub paths: Vec<String>,
    pub max_file_size_mb: u64,
}

impl Default for IntegrityDefaults {
    fn default() -> Self {
        Self {
            paths: Vec::new(),
            max_file_size_mb: 64,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DiscoveryDefaults {
    pub method: String,
    pub tcp_ports: Vec<u16>,
    pub max_hosts: usize,
    pub resolve_hostnames: bool,
}

impl Default for DiscoveryDefaults {
    fn default() -> Self {
        Self {
            method: "auto".to_string(),
            tcp_ports: vec![22, 80, 443, 445, 139, 8080],
            max_hosts: 256,
            resolve_hostnames: true,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(default)]
pub struct Integrations {
    /// Explicit path overrides for optional external tools.
    pub nmap_path: Option<String>,
    pub iperf3_path: Option<String>,
    pub traceroute_path: Option<String>,
    pub ping_path: Option<String>,
    /// Optional IEEE OUI database (CSV or `oui.txt`) for MAC vendor lookup.
    pub oui_file: Option<String>,
    /// Speed test provider: "iperf3" or "http".
    pub speedtest_provider: Option<String>,
    /// Speed test server (host for iperf3, URL for http).
    pub speedtest_server: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct Privacy {
    /// Reserved. netRo never sends telemetry; kept for forward compatibility.
    pub telemetry: bool,
    pub resolve_hostnames: bool,
    pub vendor_lookup: bool,
    /// Reverse DNS during scans/discovery.
    pub reverse_dns: bool,
}

impl Default for Privacy {
    fn default() -> Self {
        Self {
            telemetry: false,
            resolve_hostnames: true,
            vendor_lookup: true,
            reverse_dns: true,
        }
    }
}

impl Config {
    /// Load configuration from disk, falling back to defaults. Returns the
    /// config plus non-fatal warnings (e.g. malformed file).
    pub fn load() -> (Config, Vec<String>) {
        let path = config_file();
        let mut warnings = Vec::new();
        if !path.exists() {
            return (Config::default(), warnings);
        }
        match std::fs::read_to_string(&path) {
            Ok(text) => match serde_json::from_str::<Config>(&text) {
                Ok(cfg) => {
                    if cfg.privacy.telemetry {
                        warnings.push(
                            "privacy.telemetry is reserved and has no effect; netRo never sends telemetry"
                                .to_string(),
                        );
                    }
                    (cfg, warnings)
                }
                Err(e) => {
                    warnings.push(format!(
                        "config file {} is invalid ({e}); using defaults",
                        path.display()
                    ));
                    (Config::default(), warnings)
                }
            },
            Err(e) => {
                warnings.push(format!(
                    "cannot read config {}: {e}; using defaults",
                    path.display()
                ));
                (Config::default(), warnings)
            }
        }
    }

    pub fn load_strict() -> Result<(Config, Vec<String>)> {
        let (cfg, warnings) = Config::load();
        if warnings.iter().any(|w| w.contains("invalid")) {
            return Err(NetroError::new(ErrorCode::ConfigError, warnings.join("; ")));
        }
        Ok((cfg, warnings))
    }

    pub fn save(&self) -> Result<PathBuf> {
        ensure_dirs()?;
        let path = config_file();
        let text = serde_json::to_string_pretty(self)?;
        std::fs::write(&path, text)?;
        restrict_permissions(&path);
        Ok(path)
    }

    /// Written only if no config file exists yet.
    pub fn init_if_missing() -> Result<(PathBuf, bool)> {
        let path = config_file();
        if path.exists() {
            return Ok((path, false));
        }
        let path = Config::default().save()?;
        Ok((path, true))
    }

    pub fn config_path_string() -> String {
        config_file().display().to_string()
    }
}

/// Best-effort restrictive permissions (0600) on sensitive files.
pub fn restrict_permissions(path: &Path) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
}

/// Platform default paths for integrity monitoring.
pub fn default_integrity_paths() -> Vec<String> {
    if cfg!(windows) {
        let windir = std::env::var("SystemRoot").unwrap_or_else(|_| "C:\\Windows".to_string());
        vec![
            format!("{windir}\\System32\\drivers\\etc\\hosts"),
            format!("{windir}\\System32\\drivers\\etc\\services"),
            format!("{windir}\\System32\\drivers\\etc\\networks"),
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "/etc/passwd".into(),
            "/etc/group".into(),
            "/etc/hosts".into(),
            "/etc/resolv.conf".into(),
            "/etc/ssh/sshd_config".into(),
        ]
    } else {
        vec![
            "/etc/passwd".into(),
            "/etc/group".into(),
            "/etc/hosts".into(),
            "/etc/resolv.conf".into(),
            "/etc/ssh/sshd_config".into(),
            "/etc/sudoers".into(),
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_round_trip_through_json() {
        let cfg = Config::default();
        let text = serde_json::to_string(&cfg).unwrap();
        let parsed: Config = serde_json::from_str(&text).unwrap();
        assert_eq!(parsed.scan.timeout_ms, cfg.scan.timeout_ms);
        assert!(!parsed.privacy.telemetry);
    }

    #[test]
    fn partial_config_gets_defaults() {
        let parsed: Config = serde_json::from_str(r#"{"scan":{"timeout_ms":2500}}"#).unwrap();
        assert_eq!(parsed.scan.timeout_ms, 2500);
        assert_eq!(parsed.scan.concurrency, ScanDefaults::default().concurrency);
        assert_eq!(parsed.monitor.interval_secs, 2.0);
    }

    #[test]
    fn paths_are_absolute_and_named_netro() {
        assert!(config_dir().is_absolute());
        assert!(config_dir().to_string_lossy().contains("netro"));
        assert!(data_dir().is_absolute());
        assert!(cache_dir().is_absolute());
        assert!(log_dir().starts_with(data_dir()));
    }

    #[test]
    fn default_integrity_paths_not_empty() {
        assert!(!default_integrity_paths().is_empty());
    }
}
