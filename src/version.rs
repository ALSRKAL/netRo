//! Build and version information.

use serde::Serialize;
use std::fmt;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const BUILD_TARGET: &str = env!("NETRO_BUILD_TARGET");
pub const BUILD_PROFILE: &str = env!("NETRO_BUILD_PROFILE");
pub const BUILD_COMMIT: &str = env!("NETRO_BUILD_COMMIT");
pub const BUILD_DIRTY: &str = env!("NETRO_BUILD_DIRTY");
pub const BUILD_RUSTC: &str = env!("NETRO_BUILD_RUSTC");

#[derive(Debug, Clone, Serialize)]
pub struct VersionInfo {
    pub name: &'static str,
    pub version: &'static str,
    pub target: &'static str,
    pub profile: &'static str,
    pub commit: &'static str,
    pub working_tree: &'static str,
    pub rustc: &'static str,
    pub platform: &'static str,
    pub features: Vec<&'static str>,
}

pub fn version_info() -> VersionInfo {
    let mut features = Vec::new();
    if cfg!(feature = "tls") {
        features.push("tls");
    } else {
        features.push("no-tls");
    }
    VersionInfo {
        name: "netro",
        version: VERSION,
        target: BUILD_TARGET,
        profile: BUILD_PROFILE,
        commit: BUILD_COMMIT,
        working_tree: BUILD_DIRTY,
        rustc: BUILD_RUSTC,
        platform: std::env::consts::OS,
        features,
    }
}

impl fmt::Display for VersionInfo {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "{} {}", self.name, self.version)?;
        writeln!(f, "target:     {}", self.target)?;
        writeln!(f, "profile:    {}", self.profile)?;
        writeln!(f, "commit:     {} ({})", self.commit, self.working_tree)?;
        writeln!(f, "rustc:      {}", self.rustc)?;
        writeln!(f, "platform:   {}", self.platform)?;
        write!(f, "features:   {}", self.features.join(", "))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_semver() {
        let parts: Vec<&str> = VERSION.split('.').collect();
        assert_eq!(parts.len(), 3, "version must be MAJOR.MINOR.PATCH");
        for p in parts {
            assert!(p.parse::<u32>().is_ok(), "version part not numeric: {p}");
        }
    }

    #[test]
    fn version_info_serializes() {
        let info = version_info();
        let json = serde_json::to_value(&info).unwrap();
        assert_eq!(json["name"], "netro");
        assert_eq!(json["version"], VERSION);
        assert!(json["features"].is_array());
    }
}
