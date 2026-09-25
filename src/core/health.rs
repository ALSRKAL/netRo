//! `netro doctor`: unified diagnostics with explicit evidence.
//!
//! Every check performs a real measurement. Checks that cannot run on the
//! current platform or without a dependency return `UNSUPPORTED`/`SKIPPED` and
//! are excluded from scoring rather than being reported as passing.

use crate::config::Config;
use crate::core::{diagnostics, dns, security};
use crate::model::*;
use crate::platform::platform;
use crate::util;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct DoctorOptions {
    pub run_external: bool,
    pub internet_timeout: Duration,
    pub skip_internet: bool,
}

impl Default for DoctorOptions {
    fn default() -> Self {
        Self {
            run_external: false,
            internet_timeout: Duration::from_secs(3),
            skip_internet: false,
        }
    }
}

pub fn run(options: &DoctorOptions) -> DoctorReport {
    run_with(options, None, None)
}

/// Run the doctor, optionally reusing an already-computed connectivity report
/// and/or security audit. `netro report` builds both, so reusing them avoids
/// performing the same network probes and audit twice.
pub fn run_with(
    options: &DoctorOptions,
    precomputed_connectivity: Option<&ConnectivityReport>,
    precomputed_security: Option<&security::SecurityAudit>,
) -> DoctorReport {
    execute(
        options,
        precomputed_connectivity,
        precomputed_security,
        &mut |_| {},
    )
}

/// Like [`run`], but invokes `on_check` as each check completes. Used by the
/// TUI to show real per-check progress instead of an indeterminate spinner.
pub fn run_streaming(
    options: &DoctorOptions,
    on_check: &mut dyn FnMut(&CheckResult),
) -> DoctorReport {
    execute(options, None, None, on_check)
}

/// Streaming variant that reuses an existing connectivity report and/or
/// security audit instead of probing again (session cache reuse).
pub fn run_streaming_with(
    options: &DoctorOptions,
    precomputed_connectivity: Option<&ConnectivityReport>,
    precomputed_security: Option<&security::SecurityAudit>,
    on_check: &mut dyn FnMut(&CheckResult),
) -> DoctorReport {
    execute(
        options,
        precomputed_connectivity,
        precomputed_security,
        on_check,
    )
}

fn execute(
    options: &DoctorOptions,
    precomputed_connectivity: Option<&ConnectivityReport>,
    precomputed_security: Option<&security::SecurityAudit>,
    on_check: &mut dyn FnMut(&CheckResult),
) -> DoctorReport {
    let mut checks: Vec<CheckResult> = Vec::new();
    macro_rules! stream_check {
        ($check:expr) => {{
            let check = $check;
            on_check(&check);
            checks.push(check);
        }};
    }
    stream_check!(check_system());
    stream_check!(check_cpu());
    stream_check!(check_memory());
    stream_check!(check_storage());
    stream_check!(check_gpu());
    stream_check!(check_network());
    stream_check!(check_routes());
    stream_check!(check_dns());
    if options.skip_internet {
        stream_check!(
            CheckResult::new("internet", "Internet", CheckStatus::Skipped)
                .with_summary("internet checks skipped by request (--no-internet)")
        );
    } else {
        stream_check!(check_internet(
            options.internet_timeout,
            precomputed_connectivity
        ));
    }
    stream_check!(check_firewall());
    stream_check!(check_processes());

    let (security_check, owned_audit) = match precomputed_security {
        Some(audit) => (security_check_from(audit, 0), None),
        None => {
            let started = Instant::now();
            let audit = security::audit(options.run_external);
            let check = security_check_from(&audit, started.elapsed().as_millis() as u64);
            (check, Some(audit))
        }
    };
    stream_check!(security_check);
    let security_audit: &security::SecurityAudit = precomputed_security
        .or(owned_audit.as_ref())
        .expect("security audit is always available");

    let mut findings: Vec<Finding> = security_audit.findings.clone();
    let mut recommendations: Vec<String> = Vec::new();
    for finding in &findings {
        if !finding.recommendation.is_empty()
            && finding.severity >= Severity::Medium
            && !recommendations.contains(&finding.recommendation)
        {
            recommendations.push(finding.recommendation.clone());
        }
    }
    recommendations.truncate(10);

    let mut summary = DoctorSummary::default();
    for check in &checks {
        match check.status {
            CheckStatus::Pass => summary.passed += 1,
            CheckStatus::Warning => summary.warnings += 1,
            CheckStatus::Fail => summary.failed += 1,
            CheckStatus::Unsupported => summary.unsupported += 1,
            CheckStatus::Skipped => summary.skipped += 1,
        }
    }
    summary.recommendations = recommendations;
    summary.score = Some(security_audit.score.clone());

    // De-duplicate findings across checks (security findings also appear in
    // their own check).
    findings.sort_by(|a, b| b.severity.cmp(&a.severity).then_with(|| a.id.cmp(&b.id)));
    findings.dedup_by(|a, b| a.id == b.id);

    let hostname = sysinfo::System::host_name();
    let dependencies = platform().dependencies();

    let notes = {
        let mut notes = Vec::new();
        if checks.iter().any(|c| c.id == "cpu" || c.id == "memory") {
            notes.push(
                "CPU/memory values are point-in-time samples; re-run or use `netro monitor` for trends"
                    .to_string(),
            );
        }
        if security_audit.limitations.is_empty() {
            notes
        } else {
            notes.extend(security_audit.limitations.iter().cloned());
            notes
        }
    };

    DoctorReport {
        generated_at_epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        platform: platform().id(),
        hostname,
        checks,
        findings,
        summary,
        dependencies,
        note: Some(notes.join("; ")),
    }
}

fn timed<F: FnOnce() -> CheckResult>(id: &str, label: &str, f: F) -> CheckResult {
    let started = Instant::now();
    let mut result = f();
    result.id = id.to_string();
    result.label = label.to_string();
    result.duration_ms = started.elapsed().as_millis() as u64;
    result
}

fn check_system() -> CheckResult {
    timed("system", "System", || match platform().os_info() {
        Ok(os) => {
            let mut check = CheckResult::new("system", "System", CheckStatus::Pass);
            check.summary = format!(
                "{} {} ({})",
                os.long_name
                    .or(os.name.clone())
                    .unwrap_or_else(|| "unknown OS".into()),
                os.version.clone().unwrap_or_default(),
                os.arch
            );
            check.evidence.push(format!(
                "hostname: {}",
                os.hostname.clone().unwrap_or_else(|| "unknown".into())
            ));
            if let Some(kernel) = &os.kernel {
                check.evidence.push(format!("kernel: {kernel}"));
            }
            check
                .evidence
                .push(format!("uptime: {}", util::human_uptime(os.uptime_secs)));
            if let Some(virt) = &os.virtualization {
                check.evidence.push(format!("virtualization: {virt}"));
            }
            check
        }
        Err(e) => CheckResult::new("system", "System", CheckStatus::Fail)
            .with_summary(format!("cannot read OS information: {e}")),
    })
}

fn check_cpu() -> CheckResult {
    timed("cpu", "CPU", || match platform().cpu_info() {
        Ok(cpu) => {
            let usage = cpu.usage_percent.unwrap_or(0.0);
            let status = if usage >= 95.0 {
                CheckStatus::Fail
            } else if usage >= 85.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Pass
            };
            let mut check = CheckResult::new("cpu", "CPU", status);
            check.summary = format!(
                "{:.1}% used across {} logical core(s)",
                usage, cpu.logical_cores
            );
            if let Some(model) = &cpu.model {
                check.evidence.push(format!("model: {model}"));
            }
            if let Some(load) = cpu.load_average {
                let per_core = if cpu.logical_cores > 0 {
                    load[0] / cpu.logical_cores as f64
                } else {
                    load[0]
                };
                check.evidence.push(format!(
                    "load average: {:.2} {:.2} {:.2} ({:.2}/core)",
                    load[0], load[1], load[2], per_core
                ));
                if per_core >= 2.0 && status == CheckStatus::Pass {
                    check.status = CheckStatus::Warning;
                    check.summary = format!(
                        "load average {:.2}/core is high although instantaneous CPU is {:.1}%",
                        per_core, usage
                    );
                }
            }
            if usage >= 85.0 {
                check.findings.push(
                    Finding::new(
                        "health.cpu.high",
                        if usage >= 95.0 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        "configuration",
                        "Sustained CPU utilization is high",
                    )
                    .with_evidence(format!("global CPU usage sample: {usage:.1}%"))
                    .with_impact("Application latency increases and timeouts may occur.")
                    .with_recommendation(
                        "Identify the top CPU consumers with `netro processes --sort cpu`.",
                    )
                    .with_confidence(Confidence::Likely)
                    .with_source(EvidenceSource::Heuristic),
                );
            }
            check
        }
        Err(e) => CheckResult::new("cpu", "CPU", CheckStatus::Unsupported)
            .with_summary(format!("CPU information unavailable: {e}")),
    })
}

fn check_memory() -> CheckResult {
    timed("memory", "Memory", || match platform().memory_info() {
        Ok(mem) => {
            let usage = mem.utilization_percent;
            let status = if usage >= 95.0 {
                CheckStatus::Fail
            } else if usage >= 85.0 {
                CheckStatus::Warning
            } else {
                CheckStatus::Pass
            };
            let mut check = CheckResult::new("memory", "Memory", status);
            check.summary = format!(
                "{:.1}% used ({} of {})",
                usage,
                util::human_bytes(mem.used_bytes),
                util::human_bytes(mem.total_bytes)
            );
            check.evidence.push(format!(
                "available: {}, free: {}",
                util::human_bytes(mem.available_bytes),
                util::human_bytes(mem.free_bytes)
            ));
            if mem.swap_total_bytes > 0 {
                check.evidence.push(format!(
                    "swap/pagefile: {:.1}% used ({} of {})",
                    mem.swap_utilization_percent,
                    util::human_bytes(mem.swap_used_bytes),
                    util::human_bytes(mem.swap_total_bytes)
                ));
                if mem.swap_utilization_percent >= 50.0 && status == CheckStatus::Pass {
                    check.status = CheckStatus::Warning;
                    check.summary = format!(
                        "{:.0}% of swap/pagefile in use",
                        mem.swap_utilization_percent
                    );
                }
            } else {
                check.evidence.push("swap/pagefile: not configured".into());
            }
            if usage >= 85.0 {
                check.findings.push(
                    Finding::new(
                        "health.memory.high",
                        if usage >= 95.0 {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        "configuration",
                        "Memory utilization is high",
                    )
                    .with_evidence(format!(
                        "{:.1}% of {} used",
                        usage,
                        util::human_bytes(mem.total_bytes)
                    ))
                    .with_impact("The system may swap/thrash and kill processes under pressure.")
                    .with_recommendation(
                        "Identify large consumers with `netro processes --sort memory`.",
                    )
                    .with_confidence(Confidence::Likely)
                    .with_source(EvidenceSource::Heuristic),
                );
            }
            check
        }
        Err(e) => CheckResult::new("memory", "Memory", CheckStatus::Unsupported)
            .with_summary(format!("memory information unavailable: {e}")),
    })
}

fn check_storage() -> CheckResult {
    timed("storage", "Storage", || match platform().disks() {
        Ok(disks) => {
            if disks.is_empty() {
                return CheckResult::new("storage", "Storage", CheckStatus::Unsupported)
                    .with_summary("no mounted filesystems reported");
            }
            let mut worst: Option<&DiskInfo> = None;
            for disk in &disks {
                if worst
                    .map(|w| disk.utilization_percent > w.utilization_percent)
                    .unwrap_or(true)
                {
                    worst = Some(disk);
                }
            }
            let worst = worst.unwrap();
            let status = if worst.utilization_percent >= 95.0
                || (worst.free_bytes < 500 * 1024 * 1024 && worst.total_bytes > 0)
            {
                CheckStatus::Fail
            } else if worst.utilization_percent >= 85.0
                || (worst.free_bytes < 2 * 1024 * 1024 * 1024 && worst.total_bytes > 0)
            {
                CheckStatus::Warning
            } else {
                CheckStatus::Pass
            };
            let mut check = CheckResult::new("storage", "Storage", status);
            check.summary = format!(
                "{} filesystem(s); fullest is {} at {:.1}% ({} free)",
                disks.len(),
                worst.mount_point,
                worst.utilization_percent,
                util::human_bytes(worst.free_bytes)
            );
            for disk in disks.iter().take(8) {
                check.evidence.push(format!(
                    "{} [{}] {:.1}% used, {} free{}{}",
                    disk.mount_point,
                    disk.file_system,
                    disk.utilization_percent,
                    util::human_bytes(disk.free_bytes),
                    if disk.read_only { ", read-only" } else { "" },
                    if disk.removable { ", removable" } else { "" }
                ));
            }
            if status != CheckStatus::Pass {
                check.findings.push(
                    Finding::new(
                        "health.storage.low-space",
                        if status == CheckStatus::Fail {
                            Severity::High
                        } else {
                            Severity::Medium
                        },
                        "configuration",
                        "Low disk space on a mounted filesystem",
                    )
                    .with_evidence(format!(
                        "{} is {:.1}% full ({} free of {})",
                        worst.mount_point,
                        worst.utilization_percent,
                        util::human_bytes(worst.free_bytes),
                        util::human_bytes(worst.total_bytes)
                    ))
                    .with_impact("Services can fail to write data; databases may stop.")
                    .with_recommendation("Free space or extend the filesystem."),
                );
            }
            check
        }
        Err(e) => CheckResult::new("storage", "Storage", CheckStatus::Unsupported)
            .with_summary(format!("disk information unavailable: {e}")),
    })
}

fn check_gpu() -> CheckResult {
    timed("gpu", "GPU", || match platform().gpu_info() {
        Ok(gpus) if gpus.is_empty() => CheckResult::new("gpu", "GPU", CheckStatus::Unsupported)
            .with_summary("no GPU detected (headless server or unsupported detection path)"),
        Ok(gpus) => {
            let live = gpus
                .iter()
                .filter(|g| g.utilization_percent.is_some() || g.temperature_c.is_some())
                .count();
            let mut check = CheckResult::new("gpu", "GPU", CheckStatus::Pass);
            check.summary = format!("{} GPU(s) detected, {} with live metrics", gpus.len(), live);
            for gpu in &gpus {
                check.evidence.push(format!(
                    "{} {} (source: {})",
                    gpu.vendor
                        .clone()
                        .unwrap_or_else(|| "unknown vendor".into()),
                    gpu.model.clone().unwrap_or_else(|| "unknown model".into()),
                    gpu.source
                ));
                if gpu.utilization_percent.is_none() && gpu.note.is_some() {
                    check.evidence.push(format!(
                        "metrics limited: {}",
                        gpu.note.clone().unwrap_or_default()
                    ));
                }
            }
            check
        }
        Err(e) => CheckResult::new("gpu", "GPU", CheckStatus::Unsupported)
            .with_summary(format!("GPU detection unavailable: {e}")),
    })
}

fn check_network() -> CheckResult {
    timed("network", "Network", || match platform().interfaces() {
        Ok(interfaces) => {
            let up: Vec<&Interface> = interfaces
                .iter()
                .filter(|i| i.up && i.kind != InterfaceKind::Loopback)
                .collect();
            let with_v4: Vec<&&Interface> = up.iter().filter(|i| !i.ipv4.is_empty()).collect();
            let status = if up.is_empty() {
                CheckStatus::Fail
            } else if with_v4.is_empty() {
                CheckStatus::Warning
            } else {
                CheckStatus::Pass
            };
            let mut check = CheckResult::new("network", "Network", status);
            check.summary = format!("{} interface(s) up, {} with IPv4", up.len(), with_v4.len());
            for iface in interfaces.iter().take(12) {
                let mut line = format!(
                    "{} [{}] {}",
                    iface.name,
                    match iface.kind {
                        InterfaceKind::Loopback => "loopback",
                        InterfaceKind::Ethernet => "ethernet",
                        InterfaceKind::Wifi => "wifi",
                        InterfaceKind::Vpn => "vpn",
                        InterfaceKind::Bridge => "bridge",
                        InterfaceKind::Virtual => "virtual",
                        InterfaceKind::Docker => "docker",
                        InterfaceKind::Tunnel => "tunnel",
                        InterfaceKind::Bond => "bond",
                        InterfaceKind::Unknown => "unknown",
                    },
                    if iface.up { "up" } else { "down" }
                );
                if let Some(mac) = &iface.mac {
                    line.push_str(&format!(" mac={mac}"));
                }
                for ip in &iface.ipv4 {
                    line.push_str(&format!(" ipv4={}/{}", ip.addr, ip.prefix));
                }
                for ip in &iface.ipv6 {
                    line.push_str(&format!(" ipv6={}/{}", ip.addr, ip.prefix));
                }
                check.evidence.push(line);
            }
            if status == CheckStatus::Fail {
                check.findings.push(
                    Finding::new(
                        "health.network.no-link",
                        Severity::High,
                        "configuration",
                        "No active network interface",
                    )
                    .with_evidence("all non-loopback interfaces are down or absent")
                    .with_impact("No network connectivity is possible.")
                    .with_recommendation("Check cabling/Wi-Fi/adapter state."),
                );
            } else if status == CheckStatus::Warning {
                check.findings.push(
                    Finding::new(
                        "health.network.no-ipv4",
                        Severity::Medium,
                        "configuration",
                        "Interfaces are up but no IPv4 address is configured",
                    )
                    .with_evidence("at least one interface is up without an IPv4 address")
                    .with_impact("IPv4 connectivity and many services will not work.")
                    .with_recommendation("Check DHCP/static configuration."),
                );
            }
            check
        }
        Err(e) => CheckResult::new("network", "Network", CheckStatus::Unsupported)
            .with_summary(format!("interface enumeration unavailable: {e}")),
    })
}

fn check_routes() -> CheckResult {
    timed("routes", "Routes", || match platform().routes() {
        Ok(routes) => {
            let has_v4_default = routes.iter().any(|r| r.is_default && r.family == "ipv4");
            let has_v6_default = routes.iter().any(|r| r.is_default && r.family == "ipv6");
            let status = if has_v4_default || has_v6_default {
                CheckStatus::Pass
            } else {
                CheckStatus::Fail
            };
            let mut check = CheckResult::new("routes", "Routes", status);
            check.summary = format!(
                "{} route(s); default IPv4: {}, default IPv6: {}",
                routes.len(),
                if has_v4_default { "yes" } else { "no" },
                if has_v6_default { "yes" } else { "no" }
            );
            for route in routes.iter().take(10) {
                check.evidence.push(format!(
                    "{} {}/{} via {} dev {} metric {}{}",
                    route.family,
                    route.destination,
                    route.prefix,
                    route.gateway.clone().unwrap_or_else(|| "-".into()),
                    route.interface.clone().unwrap_or_else(|| "-".into()),
                    route
                        .metric
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "-".into()),
                    if route.is_default { " (default)" } else { "" }
                ));
            }
            if status == CheckStatus::Fail {
                check.findings.push(
                    Finding::new(
                        "health.routes.no-default",
                        Severity::High,
                        "configuration",
                        "No default route is configured",
                    )
                    .with_evidence("routing table contains no default IPv4 or IPv6 route")
                    .with_impact("Traffic to networks outside local subnets cannot be routed.")
                    .with_recommendation("Check the default gateway configuration."),
                );
            }
            check
        }
        Err(e) => CheckResult::new("routes", "Routes", CheckStatus::Unsupported)
            .with_summary(format!("routing table unavailable: {e}")),
    })
}

fn check_dns() -> CheckResult {
    timed("dns", "DNS", || match platform().dns_config() {
        Ok(config) => {
            let query =
                dns::resolve_via_system("example.com", dns::RecordType::A, Duration::from_secs(3));
            match query {
                Ok(response) => {
                    let mut check = CheckResult::new("dns", "DNS", CheckStatus::Pass);
                    check.summary = format!(
                        "resolution via {} in {:.0} ms",
                        response.server, response.rtt_ms
                    );
                    check.evidence.push(format!(
                        "configured servers: {} (source: {})",
                        config.servers.join(", "),
                        config.source
                    ));
                    if !response.answers.is_empty() {
                        check.evidence.push(format!(
                            "example.com A -> {}",
                            response
                                .answers
                                .iter()
                                .map(|a| a.value.clone())
                                .collect::<Vec<_>>()
                                .join(", ")
                        ));
                    }
                    if response.rtt_ms > 1000.0 {
                        check.status = CheckStatus::Warning;
                        check.summary =
                            format!("DNS resolution is slow ({:.0} ms)", response.rtt_ms);
                    }
                    check
                }
                Err(e) => {
                    let mut check = CheckResult::new("dns", "DNS", CheckStatus::Fail);
                    check.summary =
                        format!("configured DNS servers: {}", config.servers.join(", "));
                    check.evidence.push(format!("resolution failed: {e}"));
                    check.findings.push(
                        Finding::new(
                            "health.dns.resolution-failed",
                            Severity::High,
                            "configuration",
                            "DNS resolution is failing",
                        )
                        .with_evidence(format!("test query for example.com failed: {e}"))
                        .with_impact("Name-based connectivity (web, updates, APIs) will fail.")
                        .with_recommendation(
                            "Verify resolver configuration and reachability of the DNS server.",
                        ),
                    );
                    check
                }
            }
        }
        Err(e) => {
            let mut check = CheckResult::new("dns", "DNS", CheckStatus::Fail);
            check.summary = "no usable DNS configuration".into();
            check.evidence.push(e.to_string());
            check
        }
    })
}

fn check_internet(timeout: Duration, precomputed: Option<&ConnectivityReport>) -> CheckResult {
    timed("internet", "Internet", || {
        let options = diagnostics::ConnectivityOptions {
            timeout,
            ..diagnostics::ConnectivityOptions::default()
        };
        let report = match precomputed {
            Some(report) => report.clone(),
            None => diagnostics::connectivity(&options),
        };
        let gateway_ok = report.gateway_reachable.unwrap_or(false);
        let status = if report.internet_reachable {
            CheckStatus::Pass
        } else if gateway_ok {
            CheckStatus::Warning
        } else {
            CheckStatus::Fail
        };
        let mut check = CheckResult::new("internet", "Internet", status);
        check.summary = if report.internet_reachable {
            "internet reachable".to_string()
        } else if gateway_ok {
            "gateway reachable but no external connectivity".to_string()
        } else {
            "no connectivity beyond the local machine".to_string()
        };
        for item in &report.checks {
            check.evidence.push(format!(
                "{}: {} ({}){}",
                item.name,
                if item.ok { "ok" } else { "failed" },
                item.target,
                item.error
                    .as_ref()
                    .map(|e| format!(" - {e}"))
                    .or_else(|| item.note.as_ref().map(|n| format!(" - {n}")))
                    .unwrap_or_default()
            ));
        }
        if !report.dns_working {
            // DNS is reported by the DNS check; avoid duplicate failure here.
            check
                .evidence
                .push("DNS resolution failed; see DNS check for the dedicated finding".into());
        }
        if !report.internet_reachable && gateway_ok {
            check.findings.push(
                Finding::new(
                    "health.internet.no-external",
                    Severity::Medium,
                    "configuration",
                    "No external connectivity while the gateway responds",
                )
                .with_evidence("gateway ping/TCP succeeded; external TCP probes failed")
                .with_impact("Cloud services, updates and remote APIs are unreachable.")
                .with_recommendation(
                    "Check upstream connectivity, ISP link, firewall egress rules or proxy \
                     requirements.",
                ),
            );
        } else if !report.internet_reachable {
            check.findings.push(
                Finding::new(
                    "health.internet.none",
                    Severity::High,
                    "configuration",
                    "No network connectivity",
                )
                .with_evidence("gateway and external probes both failed")
                .with_impact("The host is effectively offline.")
                .with_recommendation("Check link state, IP configuration and the default gateway."),
            );
        }
        check
    })
}

fn check_firewall() -> CheckResult {
    timed("firewall", "Firewall", || {
        match platform().firewall_status() {
            Ok(status) => {
                let (check_status, summary) = match status.enabled {
                    Some(true) => (CheckStatus::Pass, "host firewall is active".to_string()),
                    Some(false) => (
                        CheckStatus::Warning,
                        "host firewall appears disabled".to_string(),
                    ),
                    None => (
                        CheckStatus::Unsupported,
                        "firewall state could not be determined".to_string(),
                    ),
                };
                let mut check = CheckResult::new("firewall", "Firewall", check_status);
                check.summary = summary;
                for backend in &status.backends {
                    check.evidence.push(format!(
                        "{}: {}{}",
                        backend.name,
                        match backend.active {
                            Some(true) => "active",
                            Some(false) => "inactive",
                            None => "unknown",
                        },
                        backend
                            .detail
                            .as_ref()
                            .map(|d| format!(" ({d})"))
                            .unwrap_or_default()
                    ));
                }
                for note in &status.notes {
                    check.evidence.push(format!("note: {note}"));
                }
                if status.enabled == Some(false) {
                    check.findings.push(
                        Finding::new(
                            "health.firewall.disabled",
                            Severity::High,
                            "firewall",
                            "Host firewall is disabled",
                        )
                        .with_evidence("all detected firewall backends reported inactive")
                        .with_impact("Inbound connections are not filtered at the host level.")
                        .with_recommendation(
                            "Enable the platform firewall and allow only required ports.",
                        ),
                    );
                }
                check
            }
            Err(e) => CheckResult::new("firewall", "Firewall", CheckStatus::Unsupported)
                .with_summary(format!("firewall inspection unavailable: {e}")),
        }
    })
}

fn check_processes() -> CheckResult {
    timed("processes", "Processes", || match platform().processes() {
        Ok(processes) => {
            let zombies = processes.iter().filter(|p| p.status == "Zombie").count();
            let hot: Vec<&ProcessInfo> = processes
                .iter()
                .filter(|p| p.cpu_percent >= 90.0)
                .take(5)
                .collect();
            let mut check = CheckResult::new("processes", "Processes", CheckStatus::Pass);
            check.summary = format!("{} running process(es)", processes.len());
            if let Some(top) = processes.first() {
                check.evidence.push(format!(
                    "highest CPU: {} (pid {}) at {:.1}%",
                    top.name, top.pid, top.cpu_percent
                ));
            }
            if zombies > 0 {
                check
                    .evidence
                    .push(format!("{zombies} zombie process(es) present"));
                check.status = CheckStatus::Warning;
                check.findings.push(
                    Finding::new(
                        "health.processes.zombies",
                        Severity::Low,
                        "configuration",
                        "Zombie processes detected",
                    )
                    .with_evidence(format!("{zombies} process(es) in Zombie state"))
                    .with_impact(
                        "Zombies consume process-table entries and usually indicate a parent \
                         process that is not reaping children.",
                    )
                    .with_recommendation("Investigate the parent processes of the zombies."),
                );
            }
            if !hot.is_empty() {
                check.status = CheckStatus::Warning;
                check.summary = format!("{} process(es) above 90% CPU in this sample", hot.len());
                for process in &hot {
                    check.evidence.push(format!(
                        "{} (pid {}) CPU {:.1}%",
                        process.name, process.pid, process.cpu_percent
                    ));
                }
            }
            check
        }
        Err(e) => CheckResult::new("processes", "Processes", CheckStatus::Unsupported)
            .with_summary(format!("process listing unavailable: {e}")),
    })
}

fn security_check_from(audit: &security::SecurityAudit, duration_ms: u64) -> CheckResult {
    let worst = audit
        .findings
        .iter()
        .map(|f| f.severity)
        .max()
        .unwrap_or(Severity::Info);
    let status = match worst {
        Severity::Critical | Severity::High => CheckStatus::Fail,
        Severity::Medium => CheckStatus::Warning,
        _ => CheckStatus::Pass,
    };
    let mut check = CheckResult::new("security", "Security", status);
    check.summary = format!(
        "score {}/{} (grade {}), {} finding(s), {} exposed port(s)",
        audit.score.total,
        audit.score.max,
        audit.score.grade,
        audit.findings.len(),
        audit.exposed_ports
    );
    for finding in audit.findings.iter().take(20) {
        check.evidence.push(format!(
            "{} [{}] {}",
            finding.severity, finding.id, finding.title
        ));
    }
    for limitation in &audit.limitations {
        check.evidence.push(format!("limitation: {limitation}"));
    }
    check.findings = audit.findings.clone();
    check.duration_ms = duration_ms;
    check.id = "security".into();
    check.label = "Security".into();
    check
}

/// Used by `netro report`: expose the same findings used by doctor.
pub fn findings_only(options: &DoctorOptions) -> Vec<Finding> {
    run(options).findings
}

/// Apply doctor-relevant configuration defaults.
pub fn options_from_config(_config: &Config) -> DoctorOptions {
    DoctorOptions::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn doctor_runs_and_reports_real_sections() {
        let report = run(&DoctorOptions {
            skip_internet: true,
            ..DoctorOptions::default()
        });
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id.as_str()).collect();
        for expected in [
            "system",
            "cpu",
            "memory",
            "storage",
            "gpu",
            "network",
            "routes",
            "dns",
            "firewall",
            "processes",
            "security",
        ] {
            assert!(ids.contains(&expected), "missing check {expected}");
        }
        assert!(
            report.summary.passed
                + report.summary.warnings
                + report.summary.failed
                + report.summary.unsupported
                + report.summary.skipped
                == report.checks.len()
        );
        assert!(report.summary.score.is_some());
    }

    #[test]
    fn skipped_internet_is_reported_as_skipped_not_passed() {
        let report = run(&DoctorOptions {
            skip_internet: true,
            ..DoctorOptions::default()
        });
        let internet = report.checks.iter().find(|c| c.id == "internet").unwrap();
        assert_eq!(internet.status, CheckStatus::Skipped);
    }

    #[test]
    fn checks_have_evidence() {
        let report = run(&DoctorOptions {
            skip_internet: true,
            ..DoctorOptions::default()
        });
        let system = report.checks.iter().find(|c| c.id == "system").unwrap();
        assert!(!system.evidence.is_empty());
    }
}
