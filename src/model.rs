//! Serializable domain model shared by platform providers, core logic, and
//! every output format. These types define the JSON contract of netRo.

use serde::{Deserialize, Serialize};

pub const MODEL_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
#[derive(Default)]
pub enum PlatformId {
    Linux,
    Windows,
    Macos,
    #[default]
    Unknown,
}

impl std::fmt::Display for PlatformId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            PlatformId::Linux => "linux",
            PlatformId::Windows => "windows",
            PlatformId::Macos => "macos",
            PlatformId::Unknown => "unknown",
        })
    }
}

// ---------------------------------------------------------------------------
// Severity / findings / checks
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Severity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl Severity {
    pub fn as_str(self) -> &'static str {
        match self {
            Severity::Info => "INFO",
            Severity::Low => "LOW",
            Severity::Medium => "MEDIUM",
            Severity::High => "HIGH",
            Severity::Critical => "CRITICAL",
        }
    }

    /// Points deducted from the security score when confirmed.
    pub fn score_weight(self) -> i32 {
        match self {
            Severity::Info => 0,
            Severity::Low => 2,
            Severity::Medium => 6,
            Severity::High => 12,
            Severity::Critical => 20,
        }
    }
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How strongly the evidence supports a finding.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Confidence {
    /// Directly observed configuration or state.
    Confirmed,
    /// Consistent with the evidence but not proven.
    Likely,
    /// Pattern-based; must not be presented as fact.
    Heuristic,
}

/// Where a piece of evidence came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSource {
    /// netRo itself observed this (e.g. parsed OS state).
    NativeCheck,
    /// An external tool produced this result and netRo only relayed it.
    ExternalTool,
    /// Heuristic inference performed by netRo.
    Heuristic,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Finding {
    pub id: String,
    pub severity: Severity,
    pub category: String,
    pub title: String,
    pub evidence: Vec<String>,
    pub impact: String,
    pub recommendation: String,
    pub confidence: Confidence,
    pub source: EvidenceSource,
    /// Points this finding removes from the score (computed from severity and
    /// confidence). Recorded explicitly for transparency.
    pub score_impact: i32,
}

impl Finding {
    pub fn new(
        id: impl Into<String>,
        severity: Severity,
        category: impl Into<String>,
        title: impl Into<String>,
    ) -> Self {
        let confidence = Confidence::Confirmed;
        let score_impact = match confidence {
            Confidence::Confirmed => severity.score_weight(),
            Confidence::Likely => (severity.score_weight() as f64 * 0.6).round() as i32,
            Confidence::Heuristic => (severity.score_weight() as f64 * 0.3).round() as i32,
        };
        Self {
            id: id.into(),
            severity,
            category: category.into(),
            title: title.into(),
            evidence: Vec::new(),
            impact: String::new(),
            recommendation: String::new(),
            confidence,
            source: EvidenceSource::NativeCheck,
            score_impact,
        }
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_impact(mut self, impact: impl Into<String>) -> Self {
        self.impact = impact.into();
        self
    }

    pub fn with_recommendation(mut self, rec: impl Into<String>) -> Self {
        self.recommendation = rec.into();
        self
    }

    pub fn with_confidence(mut self, confidence: Confidence) -> Self {
        self.confidence = confidence;
        self.score_impact = match confidence {
            Confidence::Confirmed => self.severity.score_weight(),
            Confidence::Likely => (self.severity.score_weight() as f64 * 0.6).round() as i32,
            Confidence::Heuristic => (self.severity.score_weight() as f64 * 0.3).round() as i32,
        };
        self
    }

    pub fn with_source(mut self, source: EvidenceSource) -> Self {
        self.source = source;
        self
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum CheckStatus {
    Pass,
    Warning,
    Fail,
    Unsupported,
    Skipped,
}

impl CheckStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            CheckStatus::Pass => "PASS",
            CheckStatus::Warning => "WARNING",
            CheckStatus::Fail => "FAIL",
            CheckStatus::Unsupported => "UNSUPPORTED",
            CheckStatus::Skipped => "SKIPPED",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CheckResult {
    pub id: String,
    pub label: String,
    pub status: CheckStatus,
    pub summary: String,
    pub evidence: Vec<String>,
    pub findings: Vec<Finding>,
    pub duration_ms: u64,
}

impl CheckResult {
    pub fn new(id: impl Into<String>, label: impl Into<String>, status: CheckStatus) -> Self {
        Self {
            id: id.into(),
            label: label.into(),
            status,
            summary: String::new(),
            evidence: Vec::new(),
            findings: Vec::new(),
            duration_ms: 0,
        }
    }

    pub fn with_summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = summary.into();
        self
    }

    pub fn with_evidence(mut self, evidence: impl Into<String>) -> Self {
        self.evidence.push(evidence.into());
        self
    }

    pub fn with_findings(mut self, findings: Vec<Finding>) -> Self {
        self.findings = findings;
        self
    }
}

// ---------------------------------------------------------------------------
// System
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct OsInfo {
    pub name: Option<String>,
    pub long_name: Option<String>,
    pub version: Option<String>,
    pub kernel: Option<String>,
    pub arch: String,
    pub hostname: Option<String>,
    pub distro_id: Option<String>,
    pub uptime_secs: u64,
    pub boot_time_epoch: Option<u64>,
    pub virtualization: Option<String>,
    pub platform: PlatformId,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CpuInfo {
    pub model: Option<String>,
    pub vendor: Option<String>,
    pub arch: String,
    pub logical_cores: usize,
    pub physical_cores: Option<usize>,
    /// Global CPU utilization in percent.
    pub usage_percent: Option<f32>,
    pub per_core_usage: Vec<f32>,
    pub frequency_mhz: Option<u64>,
    pub load_average: Option<[f64; 3]>,
    pub temperatures_c: Vec<Temperature>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Temperature {
    pub label: String,
    pub current_c: f32,
    pub max_c: Option<f32>,
    pub critical_c: Option<f32>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MemoryInfo {
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub free_bytes: u64,
    pub utilization_percent: f64,
    pub swap_total_bytes: u64,
    pub swap_used_bytes: u64,
    pub swap_free_bytes: u64,
    pub swap_utilization_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskInfo {
    pub device: String,
    pub mount_point: String,
    pub file_system: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub free_bytes: u64,
    pub utilization_percent: f64,
    pub read_only: bool,
    pub removable: bool,
    pub kind: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GpuInfo {
    pub vendor: Option<String>,
    pub model: Option<String>,
    pub vram_bytes: Option<u64>,
    pub driver: Option<String>,
    pub utilization_percent: Option<f32>,
    pub temperature_c: Option<f32>,
    pub power_watts: Option<f32>,
    pub compute_backend: Option<String>,
    pub source: String,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemSnapshot {
    pub generated_at_epoch: i64,
    pub platform: PlatformId,
    pub os: OsInfo,
    pub cpu: CpuInfo,
    pub memory: MemoryInfo,
    pub disks: Vec<DiskInfo>,
    pub gpus: Vec<GpuInfo>,
    pub warnings: Vec<String>,
}

// ---------------------------------------------------------------------------
// Processes
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub ppid: Option<u32>,
    pub name: String,
    pub exe: Option<String>,
    pub cmdline: Option<String>,
    pub user: Option<String>,
    pub uid: Option<u32>,
    pub cpu_percent: f32,
    pub memory_bytes: u64,
    pub virtual_memory_bytes: u64,
    pub start_time_epoch: u64,
    pub run_time_secs: u64,
    pub status: String,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Network
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InterfaceKind {
    Loopback,
    Ethernet,
    Wifi,
    Vpn,
    Bridge,
    Virtual,
    Docker,
    Tunnel,
    Bond,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpWithPrefix {
    pub addr: String,
    pub prefix: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Interface {
    pub name: String,
    pub kind: InterfaceKind,
    pub mac: Option<String>,
    pub ipv4: Vec<IpWithPrefix>,
    pub ipv6: Vec<IpWithPrefix>,
    pub up: bool,
    pub oper_state: Option<String>,
    pub speed_mbps: Option<u64>,
    pub mtu: Option<u64>,
    pub dhcp: Option<bool>,
    pub dhcp_source: Option<String>,
    pub default_route: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Route {
    pub family: String,
    pub destination: String,
    pub prefix: u8,
    pub gateway: Option<String>,
    pub interface: Option<String>,
    pub metric: Option<u32>,
    pub flags: Vec<String>,
    pub is_default: bool,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DnsConfig {
    pub servers: Vec<String>,
    pub search_domains: Vec<String>,
    pub source: String,
    pub systemd_resolved_stub: bool,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Neighbor {
    pub ip: String,
    pub mac: Option<String>,
    pub interface: Option<String>,
    pub state: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
}

// ---------------------------------------------------------------------------
// Connections / listening ports
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Connection {
    pub protocol: String,
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListeningPort {
    pub protocol: String,
    pub address: String,
    pub port: u16,
    pub scope: ExposureScope,
    pub state: String,
    pub pid: Option<u32>,
    pub process: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ExposureScope {
    /// Bound to loopback only.
    Local,
    /// Bound to a specific interface address (not wildcard).
    Interface,
    /// Bound to all interfaces (0.0.0.0 / ::).
    All,
    /// Could not determine.
    Unknown,
}

// ---------------------------------------------------------------------------
// Diagnostics
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeMethod {
    Icmp,
    TcpConnect,
    SystemUtility,
    Dns,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PingResult {
    pub target: String,
    pub resolved: Vec<String>,
    pub method: ProbeMethod,
    pub transmitted: u32,
    pub received: u32,
    pub loss_percent: f64,
    pub min_ms: Option<f64>,
    pub avg_ms: Option<f64>,
    pub max_ms: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub rtts: Vec<f64>,
    pub error: Option<String>,
}

impl PingResult {
    pub fn failed(target: &str, method: ProbeMethod, error: impl Into<String>) -> Self {
        Self {
            target: target.to_string(),
            resolved: Vec::new(),
            method,
            transmitted: 0,
            received: 0,
            loss_percent: 100.0,
            min_ms: None,
            avg_ms: None,
            max_ms: None,
            jitter_ms: None,
            rtts: Vec::new(),
            error: Some(error.into()),
        }
    }
}

/// Compute min/avg/max/jitter from a series of RTT samples.
pub fn rtt_stats(rtts: &[f64]) -> (Option<f64>, Option<f64>, Option<f64>, Option<f64>) {
    if rtts.is_empty() {
        return (None, None, None, None);
    }
    let min = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
    let max = rtts.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let avg = rtts.iter().sum::<f64>() / rtts.len() as f64;
    // Mean absolute deviation between consecutive samples (RFC 3550-style
    // jitter smoothed mean).
    let jitter = if rtts.len() < 2 {
        0.0
    } else {
        let mut sum = 0.0;
        for pair in rtts.windows(2) {
            sum += (pair[1] - pair[0]).abs();
        }
        sum / (rtts.len() - 1) as f64
    };
    (Some(min), Some(avg), Some(max), Some(jitter))
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityCheck {
    pub name: String,
    pub target: String,
    pub method: ProbeMethod,
    pub ok: bool,
    pub latency_ms: Option<f64>,
    pub error: Option<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConnectivityReport {
    pub checks: Vec<ConnectivityCheck>,
    pub ipv4_available: bool,
    pub ipv6_available: bool,
    pub internet_reachable: bool,
    pub dns_working: bool,
    pub gateway_reachable: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceHop {
    pub hop: u8,
    pub address: Option<String>,
    pub hostname: Option<String>,
    pub rtt_ms: Vec<f64>,
    pub timeout: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TraceResult {
    pub target: String,
    pub method: ProbeMethod,
    pub hops: Vec<TraceHop>,
    pub reached: bool,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Discovery / scanning
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveredHost {
    pub ip: String,
    pub mac: Option<String>,
    pub vendor: Option<String>,
    pub hostname: Option<String>,
    pub response_ms: Option<f64>,
    pub open_ports: Vec<u16>,
    pub discovery_sources: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub subnets: Vec<String>,
    pub method: String,
    pub hosts: Vec<DiscoveredHost>,
    pub scanned: usize,
    pub duration_ms: u64,
    pub note: Option<String>,
    /// True when discovery was stopped early; `hosts` then contains partial
    /// results only.
    #[serde(default)]
    pub cancelled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PortState {
    Open,
    Closed,
    Filtered,
    OpenOrFiltered,
}

impl PortState {
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Closed => "closed",
            PortState::Filtered => "filtered",
            PortState::OpenOrFiltered => "open|filtered",
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TlsInfo {
    pub handshake_ok: bool,
    pub error: Option<String>,
    pub protocol_version: Option<String>,
    pub cipher_suite: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
    pub not_before: Option<String>,
    pub not_after: Option<String>,
    pub days_remaining: Option<i64>,
    pub san: Vec<String>,
    pub self_signed: Option<bool>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScannedPort {
    pub port: u16,
    pub protocol: String,
    pub state: PortState,
    pub service: Option<String>,
    pub product: Option<String>,
    pub version: Option<String>,
    pub banner: Option<String>,
    pub tls: Option<TlsInfo>,
    pub detection: Option<String>,
    pub confidence: Confidence,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScanReport {
    pub target: String,
    pub resolved: Vec<String>,
    pub ports: Vec<ScannedPort>,
    pub started_epoch: i64,
    pub duration_ms: u64,
    pub concurrency: usize,
    pub timeout_ms: u64,
    pub scan_type: String,
    pub note: Option<String>,
    /// True when the scan was stopped early; `ports` then only contains
    /// results collected before cancellation.
    #[serde(default)]
    pub cancelled: bool,
}

// ---------------------------------------------------------------------------
// Services / security
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceInfo {
    pub name: String,
    pub display_name: Option<String>,
    pub status: String,
    pub startup: Option<String>,
    pub description: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PasswordStatus {
    Set,
    Locked,
    Empty,
    NoShadowEntry,
    Unknown,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Account {
    pub name: String,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub home: Option<String>,
    pub shell: Option<String>,
    pub privileged: bool,
    pub is_system: bool,
    pub login_shell: bool,
    pub password: PasswordStatus,
    pub groups: Vec<String>,
    pub note: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasswordPolicy {
    pub min_length: Option<u32>,
    pub max_age_days: Option<u32>,
    pub min_age_days: Option<u32>,
    pub warn_days: Option<u32>,
    pub remember: Option<u32>,
    pub lockout_threshold: Option<u32>,
    pub lockout_duration_secs: Option<u32>,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallBackend {
    pub name: String,
    pub active: Option<bool>,
    pub detail: Option<String>,
    pub via: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub backend: String,
    pub chain: Option<String>,
    pub action: String,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub ports: Option<String>,
    pub protocol: Option<String>,
    pub raw: String,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct FirewallStatus {
    pub enabled: Option<bool>,
    pub backends: Vec<FirewallBackend>,
    pub notes: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallChange {
    pub action: String,
    pub ip: String,
    pub backend: String,
    pub commands: Vec<String>,
    pub applied: bool,
    pub output: Option<String>,
    pub rollback: Vec<String>,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Integrity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityEntry {
    pub path: String,
    pub sha256: Option<String>,
    pub size: u64,
    pub mtime_epoch: i64,
    pub mode: Option<u32>,
    pub uid: Option<u32>,
    pub gid: Option<u32>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityBaseline {
    pub schema_version: u32,
    pub created_epoch: i64,
    pub hostname: String,
    pub platform: PlatformId,
    pub paths: Vec<String>,
    pub entries: Vec<IntegrityEntry>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum IntegrityStatus {
    Added,
    Removed,
    Modified,
    Unchanged,
    PermissionDenied,
    Missing,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityChange {
    pub path: String,
    pub status: IntegrityStatus,
    pub details: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IntegrityReport {
    pub baseline_created_epoch: Option<i64>,
    pub scanned_epoch: i64,
    pub changes: Vec<IntegrityChange>,
    pub unchanged: usize,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Dependencies
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Dependency {
    pub name: String,
    pub binary: String,
    pub installed: bool,
    pub path: Option<String>,
    pub version: Option<String>,
    pub purpose: String,
    pub required: bool,
    pub platform: Option<PlatformId>,
}

// ---------------------------------------------------------------------------
// Doctor / scoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScoreDeduction {
    pub finding_id: String,
    pub points: i32,
    pub reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CategoryScore {
    pub category: String,
    pub score: i32,
    pub max: i32,
    pub deductions: Vec<ScoreDeduction>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthScore {
    pub total: i32,
    pub max: i32,
    pub grade: String,
    pub categories: Vec<CategoryScore>,
    pub methodology: String,
}

impl HealthScore {
    pub fn grade_for(total: i32, max: i32) -> &'static str {
        let pct = if max <= 0 {
            0.0
        } else {
            total as f64 / max as f64 * 100.0
        };
        match pct {
            p if p >= 95.0 => "A",
            p if p >= 85.0 => "B",
            p if p >= 70.0 => "C",
            p if p >= 55.0 => "D",
            _ => "F",
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct DoctorSummary {
    pub passed: usize,
    pub warnings: usize,
    pub failed: usize,
    pub unsupported: usize,
    pub skipped: usize,
    pub recommendations: Vec<String>,
    pub score: Option<HealthScore>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DoctorReport {
    pub generated_at_epoch: i64,
    pub platform: PlatformId,
    pub hostname: Option<String>,
    pub checks: Vec<CheckResult>,
    pub findings: Vec<Finding>,
    pub summary: DoctorSummary,
    pub dependencies: Vec<Dependency>,
    pub note: Option<String>,
}

// ---------------------------------------------------------------------------
// Monitoring
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetRate {
    pub interface: String,
    pub rx_bytes_per_sec: f64,
    pub tx_bytes_per_sec: f64,
    pub rx_total_bytes: u64,
    pub tx_total_bytes: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MonitorSample {
    pub timestamp_epoch: i64,
    pub uptime_secs: u64,
    pub cpu_usage_percent: f32,
    pub per_core_usage: Vec<f32>,
    pub load_average: Option<[f64; 3]>,
    pub memory_used_bytes: u64,
    pub memory_total_bytes: u64,
    pub memory_utilization_percent: f64,
    pub swap_used_bytes: u64,
    pub swap_total_bytes: u64,
    pub network: Vec<NetRate>,
    pub temperatures: Vec<Temperature>,
    pub top_cpu: Vec<ProcessInfo>,
    pub top_memory: Vec<ProcessInfo>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rtt_stats_empty_is_none() {
        assert_eq!(rtt_stats(&[]), (None, None, None, None));
    }

    #[test]
    fn rtt_stats_basic() {
        let (min, avg, max, jitter) = rtt_stats(&[10.0, 20.0, 30.0]);
        assert_eq!(min, Some(10.0));
        assert_eq!(avg, Some(20.0));
        assert_eq!(max, Some(30.0));
        assert!(jitter.unwrap() > 0.0);
    }

    #[test]
    fn severity_weights_are_monotonic() {
        assert!(Severity::Info.score_weight() < Severity::Low.score_weight());
        assert!(Severity::Low.score_weight() < Severity::Medium.score_weight());
        assert!(Severity::Medium.score_weight() < Severity::High.score_weight());
        assert!(Severity::High.score_weight() < Severity::Critical.score_weight());
    }

    #[test]
    fn heuristic_findings_score_less_than_confirmed() {
        let confirmed = Finding::new("x", Severity::High, "c", "t");
        let heuristic =
            Finding::new("x", Severity::High, "c", "t").with_confidence(Confidence::Heuristic);
        assert!(heuristic.score_impact < confirmed.score_impact);
    }

    #[test]
    fn grades_are_sane() {
        assert_eq!(HealthScore::grade_for(100, 100), "A");
        assert_eq!(HealthScore::grade_for(90, 100), "B");
        assert_eq!(HealthScore::grade_for(75, 100), "C");
        assert_eq!(HealthScore::grade_for(60, 100), "D");
        assert_eq!(HealthScore::grade_for(20, 100), "F");
    }

    #[test]
    fn severity_serializes_uppercase() {
        assert_eq!(
            serde_json::to_string(&Severity::Critical).unwrap(),
            "\"CRITICAL\""
        );
    }
}
