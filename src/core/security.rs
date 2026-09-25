//! Evidence-based security audit and transparent scoring.
//!
//! Every finding carries: severity, category, evidence lines, impact,
//! recommendation, confidence and an explicit score impact. Nothing is labelled
//! malicious without defensible evidence. External tools (rkhunter, chkrootkit,
//! ClamAV, lynis) are only reported as `ExternalTool` results when the user
//! explicitly asks to run them.

use crate::error::Result;
use crate::model::*;
use crate::platform::platform;
use crate::util;
use serde::{Deserialize, Serialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Score categories with their maximum points. Total = 100.
pub const SCORE_CATEGORIES: &[(&str, i32)] = &[
    ("firewall", 25),
    ("exposure", 30),
    ("accounts", 25),
    ("policy", 10),
    ("configuration", 10),
];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExternalToolResult {
    pub tool: String,
    pub installed: bool,
    pub ran: bool,
    pub summary: Option<String>,
    pub error: Option<String>,
    pub source: EvidenceSource,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityAudit {
    pub generated_at_epoch: i64,
    pub platform: PlatformId,
    pub hostname: Option<String>,
    pub elevated: bool,
    pub findings: Vec<Finding>,
    pub score: HealthScore,
    pub listening: Vec<ListeningPort>,
    pub exposed_ports: usize,
    pub accounts: Vec<Account>,
    pub accounts_total: usize,
    pub privileged_accounts: Vec<String>,
    pub locked_accounts: usize,
    pub password_policy: Option<PasswordPolicy>,
    pub firewall: FirewallStatus,
    pub services: Vec<ServiceInfo>,
    pub external_tools: Vec<ExternalToolResult>,
    pub limitations: Vec<String>,
}

/// Run the audit. `run_external` explicitly opts into slow external scanners.
pub fn audit(run_external: bool) -> SecurityAudit {
    let mut findings: Vec<Finding> = Vec::new();
    let mut limitations: Vec<String> = Vec::new();

    // --- Firewall -----------------------------------------------------------
    let firewall = match platform().firewall_status() {
        Ok(status) => status,
        Err(e) => {
            limitations.push(format!("firewall status unavailable: {e}"));
            FirewallStatus {
                enabled: None,
                backends: Vec::new(),
                notes: vec![e.to_string()],
                error: Some(e.to_string()),
            }
        }
    };
    if firewall.enabled == Some(false) {
        let evidence: Vec<String> = firewall
            .backends
            .iter()
            .filter(|b| b.active == Some(false))
            .map(|b| format!("{} reported inactive ({})", b.name, b.via))
            .collect();
        findings.push(
            Finding::new(
                "firewall.disabled",
                Severity::High,
                "firewall",
                "Host firewall appears disabled",
            )
            .with_evidence(if evidence.is_empty() {
                "no active firewall backend detected".to_string()
            } else {
                evidence.join("; ")
            })
            .with_impact(
                "Inbound traffic is not filtered by the host; exposed services rely only on \
                 application-level controls.",
            )
            .with_recommendation(
                "Enable the platform firewall (ufw/firewalld/nftables on Linux, Windows \
                 Defender Firewall profiles, Application Firewall on macOS) and allow only \
                 required ports.",
            ),
        );
    } else if firewall.enabled.is_none() {
        limitations.push(
            "firewall state could not be determined (permissions or service unavailable)".into(),
        );
    }

    // --- Listening ports ----------------------------------------------------
    let (listening, port_findings, exposed_ports) = match platform().listening_ports() {
        Ok(ports) => analyze_listening_ports(&ports),
        Err(e) => {
            limitations.push(format!("listening socket enumeration unavailable: {e}"));
            (Vec::new(), Vec::new(), 0)
        }
    };
    findings.extend(port_findings);

    // --- Accounts -----------------------------------------------------------
    let mut accounts_total = 0;
    let mut privileged_accounts = Vec::new();
    let mut locked_accounts = 0;
    let mut password_policy = None;
    let mut account_list: Vec<Account> = Vec::new();
    match platform().accounts() {
        Ok(accounts) => {
            accounts_total = accounts.len();
            account_list = accounts.clone();
            for account in &accounts {
                if account.privileged {
                    privileged_accounts.push(account.name.clone());
                }
                if account.password == PasswordStatus::Locked {
                    locked_accounts += 1;
                }
            }
            findings.extend(analyze_accounts(&accounts));
        }
        Err(e) => {
            limitations.push(format!("account enumeration unavailable: {e}"));
        }
    }
    match platform().password_policy() {
        Ok(Some(policy)) => {
            findings.extend(analyze_password_policy(&policy));
            password_policy = Some(policy);
        }
        Ok(None) => limitations.push("password policy could not be read on this platform".into()),
        Err(e) => limitations.push(format!("password policy unavailable: {e}")),
    }

    // --- SSH configuration (Unix) ------------------------------------------
    findings.extend(analyze_sshd_config(&listening));

    // --- Services -----------------------------------------------------------
    let services = match platform().services() {
        Ok(services) => services,
        Err(e) => {
            limitations.push(format!("service listing unavailable: {e}"));
            Vec::new()
        }
    };

    // --- External tools (opt-in only) --------------------------------------
    let external_tools = external_tools(run_external);
    if !run_external && external_tools.iter().any(|t| t.installed && !t.ran) {
        limitations.push(
            "external scanners (rkhunter/chkrootkit) are installed but were not run; use \
             `netro security audit --run-external` to include them (slow)"
                .into(),
        );
    }

    findings.sort_by(|a, b| {
        b.severity
            .cmp(&a.severity)
            .then_with(|| a.category.cmp(&b.category))
            .then_with(|| a.id.cmp(&b.id))
    });

    let score = score_findings(&findings);

    SecurityAudit {
        generated_at_epoch: SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() as i64)
            .unwrap_or(0),
        platform: platform().id(),
        hostname: sysinfo::System::host_name(),
        elevated: platform().is_elevated(),
        findings,
        score,
        listening,
        exposed_ports,
        accounts: account_list,
        accounts_total,
        privileged_accounts,
        locked_accounts,
        password_policy,
        firewall,
        services,
        external_tools,
        limitations,
    }
}

/// Analyze listening sockets. Only wildcard (`0.0.0.0`/`::`) binds are counted
/// as network-exposed; loopback binds are informational.
fn analyze_listening_ports(ports: &[ListeningPort]) -> (Vec<ListeningPort>, Vec<Finding>, usize) {
    let mut findings = Vec::new();

    // Group wildcard binds by port+protocol.
    let mut wildcard: std::collections::BTreeMap<(u16, String), Vec<&ListeningPort>> =
        std::collections::BTreeMap::new();
    for port in ports {
        if port.scope == ExposureScope::All {
            wildcard
                .entry((port.port, port.protocol.clone()))
                .or_default()
                .push(port);
        }
    }
    let exposed = wildcard.len();

    for ((port, protocol), entries) in &wildcard {
        let process = entries
            .iter()
            .filter_map(|e| e.process.clone())
            .next()
            .unwrap_or_else(|| "unknown process".into());
        let evidence = format!(
            "{protocol} {}:{} LISTEN (process: {process})",
            entries
                .first()
                .map(|e| e.address.as_str())
                .unwrap_or("0.0.0.0"),
            port
        );
        let finding = match *port {
            23 => Some(
                Finding::new(
                    "exposure.telnet",
                    Severity::High,
                    "exposure",
                    "Telnet is listening on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact("Telnet transmits credentials and session data in cleartext.")
                .with_recommendation("Disable telnet and use SSH instead."),
            ),
            21 => Some(
                Finding::new(
                    "exposure.ftp",
                    Severity::Medium,
                    "exposure",
                    "FTP is listening on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact("FTP sends credentials in cleartext unless FTPS is enforced.")
                .with_recommendation(
                    "Disable FTP, require SFTP/FTPS, or restrict access with a firewall.",
                ),
            ),
            513 | 514 => Some(
                Finding::new(
                    "exposure.rservices",
                    Severity::High,
                    "exposure",
                    "Legacy r-services are listening",
                )
                .with_evidence(evidence.clone())
                .with_impact("rlogin/rsh historically trust host-based authentication and send data in cleartext.")
                .with_recommendation("Disable rlogin/rsh; use SSH."),
            ),
            2375 => Some(
                Finding::new(
                    "exposure.docker",
                    Severity::Critical,
                    "exposure",
                    "Unauthenticated Docker API is exposed",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Anyone who can reach port 2375 can start privileged containers and \
                     effectively take over the host.",
                )
                .with_recommendation(
                    "Bind the Docker API to loopback or a protected socket, or use TLS \
                     (port 2376) with client certificates.",
                ),
            ),
            9200 | 9300 => Some(
                Finding::new(
                    "exposure.elasticsearch",
                    Severity::High,
                    "exposure",
                    "Elasticsearch is exposed on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Elasticsearch historically has no authentication by default; data may be \
                     readable or writable by anyone who can reach it.",
                )
                .with_recommendation(
                    "Restrict Elasticsearch to localhost or an internal network and enable \
                     authentication.",
                ),
            ),
            11211 => Some(
                Finding::new(
                    "exposure.memcached",
                    Severity::High,
                    "exposure",
                    "Memcached is exposed on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Memcached has no authentication and can be abused for data leaks and \
                     amplification attacks.",
                )
                .with_recommendation(
                    "Bind memcached to loopback or a private interface and firewall the port.",
                ),
            ),
            6379 => Some(
                Finding::new(
                    "exposure.redis",
                    Severity::High,
                    "exposure",
                    "Redis is exposed on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Without requirepass/tls and a trusted network, Redis may allow arbitrary \
                     data access or configuration abuse.",
                )
                .with_recommendation(
                    "Bind Redis to loopback/private interfaces, require authentication and \
                     restrict with a firewall.",
                ),
            ),
            3306 | 5432 | 1433 | 1521 | 27017 | 5984 => Some(
                Finding::new(
                    format!("exposure.database.{port}"),
                    Severity::Medium,
                    "exposure",
                    format!("Database port {port} is exposed on all interfaces"),
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Database services reachable from other hosts expand the attack surface \
                     beyond application-mediated access.",
                )
                .with_recommendation(
                    "Bind the database to loopback or a private network and restrict access \
                     with firewall rules.",
                ),
            ),
            5900 | 5901 => Some(
                Finding::new(
                    "exposure.vnc",
                    Severity::Medium,
                    "exposure",
                    "VNC is listening on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "VNC often uses weak or no authentication and is not encrypted by default.",
                )
                .with_recommendation(
                    "Restrict VNC to localhost or a VPN, and use an SSH tunnel.",
                ),
            ),
            3389 => Some(
                Finding::new(
                    "exposure.rdp",
                    Severity::Medium,
                    "exposure",
                    "Remote Desktop is exposed on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact(
                    "Exposed RDP is a common target for credential brute force and \
                     pre-auth vulnerabilities.",
                )
                .with_recommendation(
                    "Restrict RDP to trusted networks/VPN, enable NLA and account lockout.",
                ),
            ),
            5985 => Some(
                Finding::new(
                    "exposure.winrm-http",
                    Severity::Medium,
                    "exposure",
                    "WinRM over HTTP is exposed",
                )
                .with_evidence(evidence.clone())
                .with_impact("WinRM on port 5985 is unencrypted and permits remote management.")
                .with_recommendation("Use WinRM over HTTPS (5986) or restrict access."),
            ),
            80 => Some(
                Finding::new(
                    "exposure.http",
                    Severity::Info,
                    "exposure",
                    "HTTP is listening on all interfaces",
                )
                .with_evidence(evidence.clone())
                .with_impact("Unencrypted HTTP traffic can be observed on the path.")
                .with_recommendation(
                    "Serve content over HTTPS where confidentiality or integrity matters.",
                ),
            ),
            22 => {
                // SSH is normal on servers; report as INFO with hardening advice.
                Some(
                    Finding::new(
                        "exposure.ssh",
                        Severity::Info,
                        "exposure",
                        "SSH is listening on all interfaces",
                    )
                    .with_evidence(evidence.clone())
                    .with_impact(
                        "Remote access is available from any reachable network; this is \
                         expected on servers but increases the attack surface.",
                    )
                    .with_recommendation(
                        "Restrict SSH with firewall rules or listen only on management \
                         networks when possible.",
                    ),
                )
            }
            _ => None,
        };
        if let Some(f) = finding {
            findings.push(f);
        }
    }

    (ports.to_vec(), findings, exposed)
}

fn analyze_accounts(accounts: &[Account]) -> Vec<Finding> {
    let mut findings = Vec::new();

    let empty_password_login: Vec<&Account> = accounts
        .iter()
        .filter(|a| a.password == PasswordStatus::Empty && a.login_shell)
        .collect();
    if !empty_password_login.is_empty() {
        let names: Vec<&str> = empty_password_login
            .iter()
            .map(|a| a.name.as_str())
            .collect();
        findings.push(
            Finding::new(
                "accounts.empty-password",
                Severity::Critical,
                "accounts",
                "Login-capable account(s) have empty password fields",
            )
            .with_evidence(format!("accounts: {}", names.join(", ")))
            .with_impact(
                "Anyone able to reach a login service can authenticate without a password.",
            )
            .with_recommendation("Lock these accounts or set a password immediately."),
        );
    }

    let root_empty = accounts
        .iter()
        .find(|a| a.uid == Some(0) && a.password == PasswordStatus::Empty);
    if root_empty.is_some() {
        findings.push(
            Finding::new(
                "accounts.root-empty-password",
                Severity::Critical,
                "accounts",
                "The root account has an empty password",
            )
            .with_evidence(format!(
                "uid 0 account '{}' has an empty password field",
                root_empty.unwrap().name
            ))
            .with_impact("Full administrative control is available without authentication.")
            .with_recommendation("Set a strong root password or lock the account and use sudo."),
        );
    }

    let privileged_non_root: Vec<&Account> = accounts
        .iter()
        .filter(|a| a.privileged && a.uid != Some(0) && a.login_shell)
        .collect();
    if !privileged_non_root.is_empty() {
        findings.push(
            Finding::new(
                "accounts.privileged",
                Severity::Info,
                "accounts",
                "Additional privileged accounts exist",
            )
            .with_evidence(format!(
                "privileged login accounts: {}",
                privileged_non_root
                    .iter()
                    .map(|a| a.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_impact(
                "Administrative accounts are expected but expand the set of credentials that \
                 must be protected.",
            )
            .with_recommendation(
                "Review this list and remove administrative rights that are not required.",
            ),
        );
    }

    let unlocked_system_login: Vec<&Account> = accounts
        .iter()
        .filter(|a| a.is_system && a.login_shell && a.password == PasswordStatus::Set)
        .collect();
    if !unlocked_system_login.is_empty() {
        findings.push(
            Finding::new(
                "accounts.system-login-shells",
                Severity::Low,
                "accounts",
                "System accounts have interactive login shells",
            )
            .with_evidence(format!(
                "{} system account(s): {}",
                unlocked_system_login.len(),
                unlocked_system_login
                    .iter()
                    .map(|a| a.name.as_str())
                    .take(12)
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .with_impact(
                "Service accounts with login shells can be used for interactive access if \
                 their credentials are compromised.",
            )
            .with_recommendation(
                "Set /usr/sbin/nologin (or equivalent) for accounts that do not need to log in.",
            ),
        );
    }

    findings
}

fn analyze_password_policy(policy: &PasswordPolicy) -> Vec<Finding> {
    let mut findings = Vec::new();
    if let Some(min) = policy.min_length {
        if min < 8 {
            findings.push(
                Finding::new(
                    "policy.min-length",
                    Severity::Medium,
                    "policy",
                    "Minimum password length is below 8 characters",
                )
                .with_evidence(format!(
                    "minimum length = {min} (source: {})",
                    policy.source
                ))
                .with_impact("Short passwords are more susceptible to brute force and guessing.")
                .with_recommendation(
                    "Set the minimum password length to at least 8-12 characters.",
                ),
            );
        }
    } else {
        findings.push(
            Finding::new(
                "policy.min-length-unknown",
                Severity::Low,
                "policy",
                "Minimum password length is not defined",
            )
            .with_evidence(format!("no min length found (source: {})", policy.source))
            .with_impact("Without a minimum length, very short passwords may be accepted.")
            .with_recommendation("Define a minimum password length in the system policy."),
        );
    }
    if let Some(max_age) = policy.max_age_days {
        if max_age == 0 || max_age > 365 {
            findings.push(
                Finding::new(
                    "policy.max-age",
                    Severity::Low,
                    "policy",
                    "Password maximum age is very long or disabled",
                )
                .with_evidence(format!(
                    "maximum age = {max_age} days (source: {})",
                    policy.source
                ))
                .with_impact("Passwords that never expire remain valid indefinitely if leaked.")
                .with_recommendation(
                    "Consider an expiration period aligned with your security requirements \
                     (e.g. 90-365 days) or rely on strong unique passwords plus MFA.",
                ),
            );
        }
    }
    if policy.lockout_threshold.is_none() {
        findings.push(
            Finding::new(
                "policy.lockout-unknown",
                Severity::Low,
                "policy",
                "No account lockout threshold detected",
            )
            .with_evidence(format!(
                "lockout threshold not found (source: {})",
                policy.source
            ))
            .with_impact("Online password guessing may be attempted indefinitely.")
            .with_recommendation("Configure failed-login lockout or rate limiting."),
        );
    }
    findings
}

/// Parse sshd_config (first match per key, comments ignored).
pub fn parse_sshd_config(content: &str) -> std::collections::HashMap<String, String> {
    let mut map = std::collections::HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let key = match parts.next() {
            Some(k) => k.to_ascii_lowercase(),
            None => continue,
        };
        if let Some(value) = parts.next() {
            map.entry(key).or_insert_with(|| value.to_string());
        }
    }
    map
}

fn analyze_sshd_config(listening: &[ListeningPort]) -> Vec<Finding> {
    let mut findings = Vec::new();
    let ssh_listening = listening
        .iter()
        .any(|p| p.port == 22 && p.protocol == "tcp");
    let path = std::path::Path::new("/etc/ssh/sshd_config");
    let content = match std::fs::read_to_string(path) {
        Ok(c) => c,
        Err(_) => return findings,
    };
    let config = parse_sshd_config(&content);
    let active_note = if ssh_listening {
        "SSH is currently listening"
    } else {
        "note: no listener detected on port 22 right now"
    };

    if config
        .get("permitrootlogin")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
    {
        findings.push(
            Finding::new(
                "config.ssh-permit-root",
                Severity::Medium,
                "configuration",
                "SSH permits direct root login",
            )
            .with_evidence(format!(
                "/etc/ssh/sshd_config: PermitRootLogin yes ({active_note})"
            ))
            .with_impact(
                "Direct root login removes accountability and gives attackers a known \
                 privileged account to target.",
            )
            .with_recommendation(
                "Set PermitRootLogin no (or prohibit-password) and use sudo/an admin account.",
            ),
        );
    }
    if config
        .get("permitemptypasswords")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
    {
        findings.push(
            Finding::new(
                "config.ssh-empty-passwords",
                Severity::Critical,
                "configuration",
                "SSH permits empty passwords",
            )
            .with_evidence(format!(
                "/etc/ssh/sshd_config: PermitEmptyPasswords yes ({active_note})"
            ))
            .with_impact(
                "Accounts with empty passwords can log in over SSH without authentication.",
            )
            .with_recommendation(
                "Set PermitEmptyPasswords no and fix accounts with empty passwords.",
            ),
        );
    }
    if config
        .get("passwordauthentication")
        .map(|v| v.eq_ignore_ascii_case("yes"))
        .unwrap_or(false)
    {
        findings.push(
            Finding::new(
                "config.ssh-password-auth",
                Severity::Low,
                "configuration",
                "SSH password authentication is enabled",
            )
            .with_evidence(format!(
                "/etc/ssh/sshd_config: PasswordAuthentication yes ({active_note})"
            ))
            .with_impact(
                "Password authentication is exposed to brute force/credential stuffing; keys \
                 are generally stronger.",
            )
            .with_recommendation(
                "Prefer public-key authentication and disable password authentication where \
                 operational constraints allow.",
            ),
        );
    }
    findings
}

/// Detect optional external scanners. They are only executed when
/// `run_external` is true, and their output is labelled `ExternalTool`.
pub fn external_tools(run_external: bool) -> Vec<ExternalToolResult> {
    let mut out = Vec::new();
    let tools: [(&str, &str, &[&str], u64); 3] = [
        (
            "rkhunter",
            "rkhunter",
            &["--check", "--sk", "--nocolors", "--rwo", "/var/lib/netro"],
            180,
        ),
        ("chkrootkit", "chkrootkit", &["-q"], 180),
        (
            "lynis",
            "lynis",
            &["audit", "system", "--quick", "--no-colors"],
            180,
        ),
    ];
    for (name, binary, args, timeout_secs) in tools {
        if util::which(binary).is_none() {
            out.push(ExternalToolResult {
                tool: name.into(),
                installed: false,
                ran: false,
                summary: None,
                error: None,
                source: EvidenceSource::ExternalTool,
                note: Some("not installed".into()),
            });
            continue;
        }
        if !run_external {
            out.push(ExternalToolResult {
                tool: name.into(),
                installed: true,
                ran: false,
                summary: None,
                error: None,
                source: EvidenceSource::ExternalTool,
                note: Some("installed but not run (use --run-external)".into()),
            });
            continue;
        }
        let started = Instant::now();
        let result = util::run_command(binary, args, Duration::from_secs(timeout_secs));
        match result {
            Ok(o) => {
                let combined = o.combined();
                let warnings = combined
                    .lines()
                    .filter(|l| {
                        let lower = l.to_ascii_lowercase();
                        lower.contains("warning")
                            || lower.contains("infected")
                            || lower.contains("vulnerable")
                    })
                    .count();
                out.push(ExternalToolResult {
                    tool: name.into(),
                    installed: true,
                    ran: true,
                    summary: Some(format!(
                        "exit status {:?}, {} warning-like lines, ran in {}",
                        o.status,
                        warnings,
                        util::human_duration(started.elapsed())
                    )),
                    error: None,
                    source: EvidenceSource::ExternalTool,
                    note: Some(
                        "raw output belongs to the external tool and is not interpreted as a \
                         confirmed netro finding"
                            .into(),
                    ),
                });
            }
            Err(e) => out.push(ExternalToolResult {
                tool: name.into(),
                installed: true,
                ran: true,
                summary: None,
                error: Some(e.to_string()),
                source: EvidenceSource::ExternalTool,
                note: None,
            }),
        }
    }
    out
}

/// Build a transparent score from findings.
pub fn score_findings(findings: &[Finding]) -> HealthScore {
    let mut categories: Vec<CategoryScore> = SCORE_CATEGORIES
        .iter()
        .map(|(name, max)| CategoryScore {
            category: (*name).to_string(),
            score: *max,
            max: *max,
            deductions: Vec::new(),
        })
        .collect();

    for finding in findings {
        let impact = finding.score_impact;
        if impact <= 0 {
            continue;
        }
        let target_index = categories
            .iter()
            .position(|c| c.category == finding.category)
            .or_else(|| {
                categories
                    .iter()
                    .position(|c| c.category == "configuration")
            });
        if let Some(index) = target_index {
            let category = &mut categories[index];
            if category.score > 0 {
                let applied = impact.min(category.score);
                category.score -= applied;
                category.deductions.push(ScoreDeduction {
                    finding_id: finding.id.clone(),
                    points: applied,
                    reason: format!("{}: {}", finding.severity, finding.title),
                });
            }
        }
    }

    let total: i32 = categories.iter().map(|c| c.score).sum();
    let max: i32 = categories.iter().map(|c| c.max).sum();
    let methodology = format!(
        "Starts at {max}. Categories: {}. Each finding deducts its documented \
         score_impact (confirmed severity weight; likely x0.6; heuristic x0.3), capped at the \
         category maximum. Informational findings never deduct. Unknown/unsupported checks do \
         not deduct and are reported separately.",
        SCORE_CATEGORIES
            .iter()
            .map(|(name, max)| format!("{name} {max}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    HealthScore {
        total,
        max,
        grade: HealthScore::grade_for(total, max).to_string(),
        categories,
        methodology,
    }
}

/// Convenience wrapper returning only findings (used by doctor).
pub fn collect_findings() -> Result<Vec<Finding>> {
    Ok(audit(false).findings)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn score_starts_at_full_when_no_findings() {
        let score = score_findings(&[]);
        assert_eq!(score.total, 100);
        assert_eq!(score.max, 100);
        assert_eq!(score.grade, "A");
        assert!(score.methodology.contains("Categories"));
    }

    #[test]
    fn score_never_below_zero_and_capped_per_category() {
        let mut findings = Vec::new();
        for i in 0..20 {
            findings.push(Finding::new(
                format!("exposure.{i}"),
                Severity::Critical,
                "exposure",
                "critical exposure",
            ));
        }
        let score = score_findings(&findings);
        assert_eq!(score.total, 70); // exposure capped at 30 points lost
        let exposure = score
            .categories
            .iter()
            .find(|c| c.category == "exposure")
            .unwrap();
        assert_eq!(exposure.score, 0);
        assert!(!exposure.deductions.is_empty());
    }

    #[test]
    fn info_findings_do_not_deduct() {
        let findings = vec![Finding::new(
            "exposure.ssh",
            Severity::Info,
            "exposure",
            "ssh exposed",
        )];
        let score = score_findings(&findings);
        assert_eq!(score.total, 100);
    }

    #[test]
    fn ssh_config_parser_ignores_comments_and_takes_first_key() {
        let content = "# PermitRootLogin no\nPermitRootLogin yes\npermitrootlogin no\nPasswordAuthentication no\n";
        let map = parse_sshd_config(content);
        assert_eq!(map.get("permitrootlogin").map(|s| s.as_str()), Some("yes"));
        assert_eq!(
            map.get("passwordauthentication").map(|s| s.as_str()),
            Some("no")
        );
    }

    #[test]
    fn listening_analysis_flags_wildcard_binds_only() {
        let ports = vec![
            ListeningPort {
                protocol: "tcp".into(),
                address: "0.0.0.0".into(),
                port: 6379,
                scope: ExposureScope::All,
                state: "LISTEN".into(),
                pid: Some(1),
                process: Some("redis".into()),
            },
            ListeningPort {
                protocol: "tcp".into(),
                address: "127.0.0.1".into(),
                port: 6379,
                scope: ExposureScope::Local,
                state: "LISTEN".into(),
                pid: Some(1),
                process: Some("redis".into()),
            },
        ];
        let (_, findings, exposed) = analyze_listening_ports(&ports);
        assert_eq!(exposed, 1);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].id, "exposure.redis");
        assert_eq!(findings[0].severity, Severity::High);
    }

    #[test]
    fn empty_password_analysis() {
        let accounts = vec![
            Account {
                name: "alice".into(),
                uid: Some(1000),
                gid: Some(1000),
                home: None,
                shell: Some("/bin/bash".into()),
                privileged: false,
                is_system: false,
                login_shell: true,
                password: PasswordStatus::Empty,
                groups: vec![],
                note: None,
            },
            Account {
                name: "daemon".into(),
                uid: Some(1),
                gid: Some(1),
                home: None,
                shell: Some("/usr/sbin/nologin".into()),
                privileged: false,
                is_system: true,
                login_shell: false,
                password: PasswordStatus::Locked,
                groups: vec![],
                note: None,
            },
        ];
        let findings = analyze_accounts(&accounts);
        assert!(findings
            .iter()
            .any(|f| f.id == "accounts.empty-password" && f.severity == Severity::Critical));
    }

    #[test]
    fn weak_password_policy_flagged() {
        let policy = PasswordPolicy {
            min_length: Some(4),
            max_age_days: Some(99999),
            min_age_days: None,
            warn_days: None,
            remember: None,
            lockout_threshold: None,
            lockout_duration_secs: None,
            source: "test".into(),
        };
        let findings = analyze_password_policy(&policy);
        assert!(findings.iter().any(|f| f.id == "policy.min-length"));
        assert!(findings.iter().any(|f| f.id == "policy.max-age"));
        assert!(findings.iter().any(|f| f.id == "policy.lockout-unknown"));
    }

    #[test]
    fn audit_runs_without_panicking() {
        let audit = audit(false);
        assert_eq!(audit.platform, crate::platform::platform_id());
        assert!(audit.score.total <= audit.score.max);
    }
}
