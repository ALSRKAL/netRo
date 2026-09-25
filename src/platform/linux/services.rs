//! Service inventory on Linux via systemd, with a SysV fallback.

use crate::error::{unsupported, Result};
use crate::model::ServiceInfo;
use crate::util::{self, which};
use std::time::Duration;

const CMD_TIMEOUT: Duration = Duration::from_secs(10);

pub fn services() -> Result<Vec<ServiceInfo>> {
    if let Some(systemctl) = which("systemctl") {
        if let Some(services) = systemd_services(&systemctl.to_string_lossy()) {
            return Ok(services);
        }
    }
    sysv_services()
}

fn systemd_services(systemctl: &str) -> Option<Vec<ServiceInfo>> {
    let running = util::run_command(
        systemctl,
        &[
            "list-units",
            "--type=service",
            "--state=running",
            "--no-pager",
            "--plain",
            "--no-legend",
        ],
        CMD_TIMEOUT,
    )
    .ok()?;
    if !running.success() {
        return None;
    }

    // Note: `systemctl list-unit-files` takes several seconds on typical
    // systems (it reads every unit file), so startup state is intentionally not
    // queried here. Running units are cheap and sufficient for diagnostics.
    let mut out = Vec::new();
    for line in running.stdout.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        let unit = cols[0];
        let status = cols.get(3).copied().unwrap_or("running").to_string();
        let description = if cols.len() > 4 {
            Some(cols[4..].join(" "))
        } else {
            None
        };
        out.push(ServiceInfo {
            name: unit.trim_end_matches(".service").to_string(),
            display_name: None,
            status,
            startup: None,
            description,
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Some(out)
}

fn sysv_services() -> Result<Vec<ServiceInfo>> {
    let initd = std::path::Path::new("/etc/init.d");
    if !initd.is_dir() {
        return Err(unsupported(
            "no systemd and no /etc/init.d: service listing is unavailable",
        ));
    }
    let mut out = Vec::new();
    for entry in std::fs::read_dir(initd)?.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with('.') {
            continue;
        }
        out.push(ServiceInfo {
            name,
            display_name: None,
            status: "unknown".into(),
            startup: None,
            description: Some("SysV init script (state not queried)".into()),
        });
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn services_call_returns_result_or_unsupported() {
        match services() {
            Ok(list) => {
                for s in list {
                    assert!(!s.name.is_empty());
                }
            }
            Err(e) => assert!(e.code().is_unavailable()),
        }
    }
}
