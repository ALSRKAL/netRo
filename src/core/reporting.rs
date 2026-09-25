//! Report generation: text, JSON, CSV and self-contained HTML.
//!
//! A report is a point-in-time capture; every section either contains real
//! measured data or a stated limitation.

use crate::core::{diagnostics, health, security};
use crate::error::Result;
use crate::model::*;
use crate::platform::platform;
use crate::util;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ReportOptions {
    pub include_system: bool,
    pub include_network: bool,
    pub include_connectivity: bool,
    pub include_security: bool,
    pub include_doctor: bool,
    pub internet_timeout: std::time::Duration,
}

impl Default for ReportOptions {
    fn default() -> Self {
        Self {
            include_system: true,
            include_network: true,
            include_connectivity: true,
            include_security: true,
            include_doctor: true,
            internet_timeout: std::time::Duration::from_secs(3),
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct Report {
    pub generated_at_epoch: i64,
    pub netro_version: String,
    pub hostname: Option<String>,
    pub platform: PlatformId,
    pub system: Option<SystemSnapshot>,
    pub interfaces: Vec<Interface>,
    pub routes: Vec<Route>,
    pub dns: Option<DnsConfig>,
    pub connectivity: Option<ConnectivityReport>,
    pub security: Option<security::SecurityAudit>,
    pub doctor: Option<DoctorReport>,
    pub limitations: Vec<String>,
}

pub fn build(options: &ReportOptions) -> Report {
    let mut limitations = Vec::new();

    let system = if options.include_system {
        match system_snapshot() {
            Ok(snapshot) => Some(snapshot),
            Err(e) => {
                limitations.push(format!("system section unavailable: {e}"));
                None
            }
        }
    } else {
        None
    };

    let interfaces = if options.include_network {
        match platform().interfaces() {
            Ok(i) => i,
            Err(e) => {
                limitations.push(format!("interface section unavailable: {e}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let routes = if options.include_network {
        match platform().routes() {
            Ok(r) => r,
            Err(e) => {
                limitations.push(format!("routing section unavailable: {e}"));
                Vec::new()
            }
        }
    } else {
        Vec::new()
    };
    let dns = if options.include_network {
        match platform().dns_config() {
            Ok(d) => Some(d),
            Err(e) => {
                limitations.push(format!("DNS configuration unavailable: {e}"));
                None
            }
        }
    } else {
        None
    };

    let connectivity = if options.include_connectivity {
        Some(diagnostics::connectivity(
            &diagnostics::ConnectivityOptions {
                timeout: options.internet_timeout,
                ..diagnostics::ConnectivityOptions::default()
            },
        ))
    } else {
        None
    };

    let security_audit = if options.include_security {
        Some(security::audit(false))
    } else {
        None
    };

    let doctor = if options.include_doctor {
        // Reuse the connectivity report and security audit already computed for
        // the report sections instead of probing the network twice.
        Some(health::run_with(
            &health::DoctorOptions {
                internet_timeout: options.internet_timeout,
                skip_internet: !options.include_connectivity,
                ..health::DoctorOptions::default()
            },
            connectivity.as_ref(),
            security_audit.as_ref(),
        ))
    } else {
        None
    };

    Report {
        generated_at_epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        netro_version: crate::version::VERSION.to_string(),
        hostname: sysinfo::System::host_name(),
        platform: platform().id(),
        system,
        interfaces,
        routes,
        dns,
        connectivity,
        security: security_audit,
        doctor,
        limitations,
    }
}

pub fn system_snapshot() -> Result<SystemSnapshot> {
    let mut warnings = Vec::new();
    let os = platform().os_info()?;
    let cpu = platform().cpu_info()?;
    let memory = platform().memory_info()?;
    let disks = platform()
        .disks()
        .map_err(|e| {
            warnings.push(format!("disks: {e}"));
            e
        })
        .unwrap_or_default();
    let gpus = platform()
        .gpu_info()
        .map_err(|e| {
            warnings.push(format!("gpu: {e}"));
            e
        })
        .unwrap_or_default();
    Ok(SystemSnapshot {
        generated_at_epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        platform: platform().id(),
        os,
        cpu,
        memory,
        disks,
        gpus,
        warnings,
    })
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

pub fn render_text(report: &Report) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "netro report  v{}\nhost: {}\nplatform: {}\ngenerated: {}\n",
        report.netro_version,
        report.hostname.clone().unwrap_or_else(|| "unknown".into()),
        report.platform,
        format_epoch(report.generated_at_epoch)
    ));

    if let Some(doctor) = &report.doctor {
        out.push_str("\n== Health ==\n");
        for check in &doctor.checks {
            out.push_str(&format!(
                "{:<12} {:<12} {}\n",
                check.label,
                check.status.as_str(),
                check.summary
            ));
        }
        if let Some(score) = &doctor.summary.score {
            out.push_str(&format!(
                "\nscore: {}/{} (grade {})\n",
                score.total, score.max, score.grade
            ));
        }
        if !doctor.summary.recommendations.is_empty() {
            out.push_str("\nrecommendations:\n");
            for rec in &doctor.summary.recommendations {
                out.push_str(&format!("  - {rec}\n"));
            }
        }
    }

    if let Some(system) = &report.system {
        out.push_str("\n== System ==\n");
        out.push_str(&format!(
            "os:      {} {}\nkernel:  {}\narch:    {}\nuptime:  {}\n",
            system
                .os
                .long_name
                .clone()
                .or(system.os.name.clone())
                .unwrap_or_default(),
            system.os.version.clone().unwrap_or_default(),
            system.os.kernel.clone().unwrap_or_else(|| "unknown".into()),
            system.os.arch,
            util::human_uptime(system.os.uptime_secs)
        ));
        out.push_str(&format!(
            "cpu:     {} ({} cores, {:.1}% used)\n",
            system.cpu.model.clone().unwrap_or_else(|| "unknown".into()),
            system.cpu.logical_cores,
            system.cpu.usage_percent.unwrap_or(0.0)
        ));
        out.push_str(&format!(
            "memory:  {:.1}% of {} used\n",
            system.memory.utilization_percent,
            util::human_bytes(system.memory.total_bytes)
        ));
        for disk in &system.disks {
            out.push_str(&format!(
                "disk:    {} {:.1}% used ({} free)\n",
                disk.mount_point,
                disk.utilization_percent,
                util::human_bytes(disk.free_bytes)
            ));
        }
        for gpu in &system.gpus {
            out.push_str(&format!(
                "gpu:     {} {} (source: {})\n",
                gpu.vendor.clone().unwrap_or_default(),
                gpu.model.clone().unwrap_or_else(|| "unknown".into()),
                gpu.source
            ));
        }
    }

    if !report.interfaces.is_empty() || !report.routes.is_empty() {
        out.push_str("\n== Network ==\n");
        for iface in &report.interfaces {
            let addrs: Vec<String> = iface
                .ipv4
                .iter()
                .map(|a| format!("{}/{}", a.addr, a.prefix))
                .chain(
                    iface
                        .ipv6
                        .iter()
                        .map(|a| format!("{}/{}", a.addr, a.prefix)),
                )
                .collect();
            out.push_str(&format!(
                "{:<16} {:<10} {}\n",
                iface.name,
                if iface.up { "up" } else { "down" },
                addrs.join(" ")
            ));
        }
        if let Some(dns) = &report.dns {
            out.push_str(&format!(
                "dns: {} ({})\n",
                dns.servers.join(", "),
                dns.source
            ));
        }
        let defaults: Vec<&Route> = report.routes.iter().filter(|r| r.is_default).collect();
        for route in defaults {
            out.push_str(&format!(
                "default route: {} via {} dev {}\n",
                route.family,
                route.gateway.clone().unwrap_or_else(|| "-".into()),
                route.interface.clone().unwrap_or_else(|| "-".into())
            ));
        }
    }

    if let Some(connectivity) = &report.connectivity {
        out.push_str("\n== Connectivity ==\n");
        for check in &connectivity.checks {
            out.push_str(&format!(
                "{:<16} {:<6} {} {}\n",
                check.name,
                if check.ok { "ok" } else { "fail" },
                check.target,
                check
                    .latency_ms
                    .map(|l| format!("{l:.0} ms"))
                    .or_else(|| check.error.clone())
                    .or_else(|| check.note.clone())
                    .unwrap_or_default()
            ));
        }
    }

    if let Some(security) = &report.security {
        out.push_str("\n== Security findings ==\n");
        if security.findings.is_empty() {
            out.push_str("no findings\n");
        }
        for finding in &security.findings {
            out.push_str(&format!(
                "{} [{}] {} ({})\n",
                finding.severity, finding.id, finding.title, finding.category
            ));
            for evidence in &finding.evidence {
                out.push_str(&format!("    evidence: {evidence}\n"));
            }
            if !finding.recommendation.is_empty() {
                out.push_str(&format!("    recommendation: {}\n", finding.recommendation));
            }
        }
    }

    if !report.limitations.is_empty() {
        out.push_str("\n== Limitations ==\n");
        for limitation in &report.limitations {
            out.push_str(&format!("  - {limitation}\n"));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// CSV
// ---------------------------------------------------------------------------

/// Flatten the report into `section,item,key,value` rows.
pub fn render_csv(report: &Report) -> String {
    let mut rows: Vec<Vec<String>> = Vec::new();
    let mut push = |section: &str, item: &str, key: &str, value: &str| {
        rows.push(vec![
            section.to_string(),
            item.to_string(),
            key.to_string(),
            value.to_string(),
        ]);
    };

    push("report", "meta", "version", &report.netro_version);
    push(
        "report",
        "meta",
        "hostname",
        report.hostname.as_deref().unwrap_or(""),
    );
    push("report", "meta", "platform", &report.platform.to_string());
    push(
        "report",
        "meta",
        "generated",
        &format_epoch(report.generated_at_epoch),
    );

    if let Some(system) = &report.system {
        push(
            "system",
            "os",
            "name",
            &system.os.name.clone().unwrap_or_default(),
        );
        push(
            "system",
            "os",
            "version",
            &system.os.version.clone().unwrap_or_default(),
        );
        push(
            "system",
            "os",
            "kernel",
            &system.os.kernel.clone().unwrap_or_default(),
        );
        push("system", "os", "arch", &system.os.arch);
        push(
            "system",
            "cpu",
            "model",
            &system.cpu.model.clone().unwrap_or_default(),
        );
        push(
            "system",
            "cpu",
            "usage_percent",
            &format!("{:.1}", system.cpu.usage_percent.unwrap_or(0.0)),
        );
        push(
            "system",
            "memory",
            "utilization_percent",
            &format!("{:.1}", system.memory.utilization_percent),
        );
        push(
            "system",
            "memory",
            "total_bytes",
            &system.memory.total_bytes.to_string(),
        );
        for disk in &system.disks {
            push(
                "storage",
                &disk.mount_point,
                "utilization_percent",
                &format!("{:.1}", disk.utilization_percent),
            );
            push(
                "storage",
                &disk.mount_point,
                "free_bytes",
                &disk.free_bytes.to_string(),
            );
        }
    }

    for iface in &report.interfaces {
        push(
            "network",
            &iface.name,
            "state",
            if iface.up { "up" } else { "down" },
        );
        push(
            "network",
            &iface.name,
            "mac",
            iface.mac.as_deref().unwrap_or(""),
        );
        push(
            "network",
            &iface.name,
            "ipv4",
            &iface
                .ipv4
                .iter()
                .map(|a| format!("{}/{}", a.addr, a.prefix))
                .collect::<Vec<_>>()
                .join(" "),
        );
    }

    if let Some(connectivity) = &report.connectivity {
        for check in &connectivity.checks {
            push(
                "connectivity",
                &check.name,
                "ok",
                if check.ok { "true" } else { "false" },
            );
            push(
                "connectivity",
                &check.name,
                "latency_ms",
                &check
                    .latency_ms
                    .map(|l| format!("{l:.1}"))
                    .unwrap_or_default(),
            );
        }
    }

    if let Some(doctor) = &report.doctor {
        for check in &doctor.checks {
            push("health", &check.id, "status", check.status.as_str());
            push("health", &check.id, "summary", &check.summary);
        }
        if let Some(score) = &doctor.summary.score {
            push("health", "score", "total", &score.total.to_string());
            push("health", "score", "max", &score.max.to_string());
            push("health", "score", "grade", &score.grade);
        }
    }

    if let Some(security) = &report.security {
        for finding in &security.findings {
            push(
                "finding",
                &finding.id,
                "severity",
                finding.severity.as_str(),
            );
            push("finding", &finding.id, "title", &finding.title);
            push("finding", &finding.id, "category", &finding.category);
            push(
                "finding",
                &finding.id,
                "score_impact",
                &finding.score_impact.to_string(),
            );
        }
    }

    let header = vec![
        "section".to_string(),
        "item".to_string(),
        "key".to_string(),
        "value".to_string(),
    ];
    let mut all = vec![header];
    all.extend(rows);
    let header_refs: Vec<&str> = vec!["section", "item", "key", "value"];
    crate::output::render_csv(&header_refs, &all[1..])
}

// ---------------------------------------------------------------------------
// HTML
// ---------------------------------------------------------------------------

pub fn render_html(report: &Report) -> String {
    let mut html = String::new();
    html.push_str("<!DOCTYPE html>\n<html lang=\"en\">\n<head>\n<meta charset=\"utf-8\">\n");
    html.push_str("<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n");
    html.push_str("<title>netro report</title>\n<style>\n");
    html.push_str(
        ":root{color-scheme:light dark}body{font-family:system-ui,-apple-system,Segoe UI,\
         Roboto,sans-serif;margin:0;padding:2rem;background:#0e1116;color:#e6e6e6}\
         h1,h2{font-weight:600}h1{margin-top:0}h2{margin-top:2rem;border-bottom:1px solid #2a2f3a;\
         padding-bottom:.3rem}table{border-collapse:collapse;width:100%;margin:.5rem 0}\
         th,td{text-align:left;padding:.45rem .6rem;border-bottom:1px solid #232833;font-size:.92rem;\
         vertical-align:top}th{color:#9aa4b2;font-weight:500}.muted{color:#9aa4b2}\
         .badge{display:inline-block;padding:.1rem .5rem;border-radius:999px;font-size:.78rem;\
         font-weight:600}.INFO{background:#1d4ed8;color:#fff}.LOW{background:#0e7490;color:#fff}\
         .MEDIUM{background:#b45309;color:#fff}.HIGH{background:#b91c1c;color:#fff}\
         .CRITICAL{background:#7e22ce;color:#fff}.PASS{background:#15803d;color:#fff}\
         .WARNING{background:#b45309;color:#fff}.FAIL{background:#b91c1c;color:#fff}\
         .UNSUPPORTED{background:#374151;color:#e5e7eb}.SKIPPED{background:#374151;color:#e5e7eb}\
         code{background:#1b2028;padding:.1rem .35rem;border-radius:4px}\
         .score{font-size:2rem;font-weight:700}footer{margin-top:3rem;color:#9aa4b2;font-size:.85rem}",
    );
    html.push_str("</style>\n</head>\n<body>\n");

    html.push_str("<h1>netro report</h1>\n");
    html.push_str(&format!(
        "<p class=\"muted\">Generated {} &middot; host <code>{}</code> &middot; platform {} &middot; netro v{}</p>\n",
        html_escape(&format_epoch(report.generated_at_epoch)),
        html_escape(report.hostname.as_deref().unwrap_or("unknown")),
        html_escape(&report.platform.to_string()),
        html_escape(&report.netro_version)
    ));

    if let Some(doctor) = &report.doctor {
        html.push_str("<h2>Overall health</h2>\n");
        if let Some(score) = &doctor.summary.score {
            html.push_str(&format!(
                "<p class=\"score\">{} / {} <span class=\"muted\">(grade {})</span></p>\n",
                score.total,
                score.max,
                html_escape(&score.grade)
            ));
            html.push_str(&format!(
                "<p class=\"muted\">{}</p>\n",
                html_escape(&score.methodology)
            ));
        }
        html.push_str(&format!(
            "<p>{} passed &middot; {} warnings &middot; {} failed &middot; {} unsupported &middot; {} skipped</p>\n",
            doctor.summary.passed,
            doctor.summary.warnings,
            doctor.summary.failed,
            doctor.summary.unsupported,
            doctor.summary.skipped
        ));
        html.push_str(
            "<table><thead><tr><th>Check</th><th>Status</th><th>Summary</th></tr></thead><tbody>\n",
        );
        for check in &doctor.checks {
            html.push_str(&format!(
                "<tr><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td></tr>\n",
                html_escape(&check.label),
                check.status.as_str(),
                check.status.as_str(),
                html_escape(&check.summary)
            ));
        }
        html.push_str("</tbody></table>\n");
        if !doctor.summary.recommendations.is_empty() {
            html.push_str("<h2>Recommendations</h2>\n<ul>\n");
            for rec in &doctor.summary.recommendations {
                html.push_str(&format!("<li>{}</li>\n", html_escape(rec)));
            }
            html.push_str("</ul>\n");
        }
    }

    if let Some(system) = &report.system {
        html.push_str("<h2>System</h2>\n<table><tbody>\n");
        let rows = [
            (
                "OS",
                format!(
                    "{} {}",
                    system
                        .os
                        .long_name
                        .clone()
                        .or(system.os.name.clone())
                        .unwrap_or_default(),
                    system.os.version.clone().unwrap_or_default()
                ),
            ),
            (
                "Kernel",
                system.os.kernel.clone().unwrap_or_else(|| "unknown".into()),
            ),
            ("Architecture", system.os.arch.clone()),
            ("Uptime", util::human_uptime(system.os.uptime_secs)),
            (
                "CPU",
                format!(
                    "{} ({} cores, {:.1}% used)",
                    system.cpu.model.clone().unwrap_or_else(|| "unknown".into()),
                    system.cpu.logical_cores,
                    system.cpu.usage_percent.unwrap_or(0.0)
                ),
            ),
            (
                "Memory",
                format!(
                    "{:.1}% of {} used",
                    system.memory.utilization_percent,
                    util::human_bytes(system.memory.total_bytes)
                ),
            ),
        ];
        for (key, value) in rows {
            html.push_str(&format!(
                "<tr><th>{}</th><td>{}</td></tr>\n",
                html_escape(key),
                html_escape(&value)
            ));
        }
        html.push_str("</tbody></table>\n");

        if !system.disks.is_empty() {
            html.push_str("<h3>Storage</h3>\n<table><thead><tr><th>Mount</th><th>Filesystem</th><th>Used</th><th>Free</th></tr></thead><tbody>\n");
            for disk in &system.disks {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{:.1}%</td><td>{}</td></tr>\n",
                    html_escape(&disk.mount_point),
                    html_escape(&disk.file_system),
                    disk.utilization_percent,
                    util::human_bytes(disk.free_bytes)
                ));
            }
            html.push_str("</tbody></table>\n");
        }
        if !system.gpus.is_empty() {
            html.push_str("<h3>GPU</h3>\n<table><thead><tr><th>Vendor</th><th>Model</th><th>Source</th></tr></thead><tbody>\n");
            for gpu in &system.gpus {
                html.push_str(&format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                    html_escape(gpu.vendor.as_deref().unwrap_or("")),
                    html_escape(gpu.model.as_deref().unwrap_or("")),
                    html_escape(&gpu.source)
                ));
            }
            html.push_str("</tbody></table>\n");
        }
    }

    if !report.interfaces.is_empty() {
        html.push_str("<h2>Network interfaces</h2>\n");
        html.push_str("<table><thead><tr><th>Interface</th><th>Kind</th><th>State</th><th>IPv4</th><th>IPv6</th><th>MAC</th></tr></thead><tbody>\n");
        for iface in &report.interfaces {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&iface.name),
                iface.kind,
                if iface.up { "up" } else { "down" },
                html_escape(
                    &iface
                        .ipv4
                        .iter()
                        .map(|a| format!("{}/{}", a.addr, a.prefix))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                html_escape(
                    &iface
                        .ipv6
                        .iter()
                        .map(|a| format!("{}/{}", a.addr, a.prefix))
                        .collect::<Vec<_>>()
                        .join(" ")
                ),
                html_escape(iface.mac.as_deref().unwrap_or(""))
            ));
        }
        html.push_str("</tbody></table>\n");
    }

    if let Some(connectivity) = &report.connectivity {
        html.push_str("<h2>Connectivity</h2>\n");
        html.push_str("<table><thead><tr><th>Check</th><th>Target</th><th>Result</th><th>Latency</th><th>Note</th></tr></thead><tbody>\n");
        for check in &connectivity.checks {
            html.push_str(&format!(
                "<tr><td>{}</td><td>{}</td><td><span class=\"badge {}\">{}</span></td><td>{}</td><td>{}</td></tr>\n",
                html_escape(&check.name),
                html_escape(&check.target),
                if check.ok { "PASS" } else { "FAIL" },
                if check.ok { "PASS" } else { "FAIL" },
                html_escape(
                    &check
                        .latency_ms
                        .map(|l| format!("{l:.0} ms"))
                        .unwrap_or_default()
                ),
                html_escape(
                    &check
                        .error
                        .clone()
                        .or_else(|| check.note.clone())
                        .unwrap_or_default()
                )
            ));
        }
        html.push_str("</tbody></table>\n");
    }

    if let Some(security) = &report.security {
        html.push_str("<h2>Security findings</h2>\n");
        if security.findings.is_empty() {
            html.push_str("<p class=\"muted\">No findings from the checks that ran.</p>\n");
        } else {
            for finding in &security.findings {
                html.push_str(&format!(
                    "<h3><span class=\"badge {}\">{}</span> {} <span class=\"muted\">({})</span></h3>\n",
                    finding.severity.as_str(),
                    finding.severity.as_str(),
                    html_escape(&finding.title),
                    html_escape(&finding.id)
                ));
                if !finding.evidence.is_empty() {
                    html.push_str("<p><strong>Evidence</strong></p><ul>\n");
                    for evidence in &finding.evidence {
                        html.push_str(&format!(
                            "<li><code>{}</code></li>\n",
                            html_escape(evidence)
                        ));
                    }
                    html.push_str("</ul>\n");
                }
                if !finding.impact.is_empty() {
                    html.push_str(&format!(
                        "<p><strong>Impact</strong><br>{}</p>\n",
                        html_escape(&finding.impact)
                    ));
                }
                if !finding.recommendation.is_empty() {
                    html.push_str(&format!(
                        "<p><strong>Recommendation</strong><br>{}</p>\n",
                        html_escape(&finding.recommendation)
                    ));
                }
                html.push_str(&format!(
                    "<p class=\"muted\">confidence: {} &middot; source: {:?} &middot; score impact: {}</p>\n",
                    match finding.confidence {
                        Confidence::Confirmed => "confirmed",
                        Confidence::Likely => "likely",
                        Confidence::Heuristic => "heuristic",
                    },
                    finding.source,
                    finding.score_impact
                ));
            }
        }
        if !security.limitations.is_empty() {
            html.push_str("<h3>Audit limitations</h3>\n<ul>\n");
            for limitation in &security.limitations {
                html.push_str(&format!("<li>{}</li>\n", html_escape(limitation)));
            }
            html.push_str("</ul>\n");
        }
    }

    if !report.limitations.is_empty() {
        html.push_str("<h2>Report limitations</h2>\n<ul>\n");
        for limitation in &report.limitations {
            html.push_str(&format!("<li>{}</li>\n", html_escape(limitation)));
        }
        html.push_str("</ul>\n");
    }

    html.push_str("<footer>Generated by netro. Integrity monitoring is not malware detection. Scores and findings are explained above; unsupported checks are reported as such.</footer>\n");
    html.push_str("</body>\n</html>\n");
    html
}

pub fn write_file(path: &std::path::Path, content: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)?;
        }
    }
    std::fs::write(path, content)?;
    Ok(())
}

fn html_escape(input: &str) -> String {
    util::html_escape(input)
}

pub fn format_epoch(epoch: i64) -> String {
    match chrono::DateTime::from_timestamp(epoch, 0) {
        Some(dt) => dt
            .with_timezone(&chrono::Local)
            .format("%Y-%m-%d %H:%M:%S %z")
            .to_string(),
        None => epoch.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn minimal_report() -> Report {
        Report {
            generated_at_epoch: 1_700_000_000,
            netro_version: crate::version::VERSION.to_string(),
            hostname: Some("<host>&\"'".to_string()),
            platform: PlatformId::Linux,
            system: None,
            interfaces: vec![],
            routes: vec![],
            dns: None,
            connectivity: None,
            security: None,
            doctor: None,
            limitations: vec![],
        }
    }

    #[test]
    fn html_escapes_hostile_values() {
        let report = minimal_report();
        let html = render_html(&report);
        assert!(!html.contains("<host>&\"'"));
        assert!(html.contains("&lt;host&gt;&amp;&quot;&#39;"));
    }

    #[test]
    fn html_is_self_contained_and_valid_enough() {
        let report = minimal_report();
        let html = render_html(&report);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.trim_end().ends_with("</html>"));
        assert!(html.contains("<style>"));
        assert!(!html.contains("http://"));
        assert!(!html.contains("https://"));
    }

    #[test]
    fn text_report_contains_metadata() {
        let report = minimal_report();
        let text = render_text(&report);
        assert!(text.contains("netro report"));
        assert!(text.contains("platform: linux"));
    }

    #[test]
    fn csv_report_has_header_and_meta() {
        let report = minimal_report();
        let csv = render_csv(&report);
        assert!(csv.starts_with("section,item,key,value\n"));
        assert!(csv.contains("report,meta,version,"));
    }
}
