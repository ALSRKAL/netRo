//! Application state: caches, per-screen UI state and overlays.
//!
//! State is deliberately free of rendering and IO; the app layer fills it from
//! task results and caches, and components only read it.

use crate::config::Config;
use crate::core::security::SecurityAudit;
use crate::error::NetroError;
use crate::model::*;
use crate::tui::action::Action;
use crate::tui::theme::ThemeKind;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Screen {
    Dashboard,
    System,
    Network,
    Discovery,
    Scanner,
    Security,
    Monitor,
    Doctor,
    Reports,
    Snapshots,
    Settings,
}

impl Screen {
    pub const ALL: [Screen; 11] = [
        Screen::Dashboard,
        Screen::System,
        Screen::Network,
        Screen::Discovery,
        Screen::Scanner,
        Screen::Security,
        Screen::Monitor,
        Screen::Doctor,
        Screen::Reports,
        Screen::Snapshots,
        Screen::Settings,
    ];

    pub fn title(self) -> &'static str {
        let t = &crate::tui::text::T;
        match self {
            Screen::Dashboard => t.screen_dashboard,
            Screen::System => t.screen_system,
            Screen::Network => t.screen_network,
            Screen::Discovery => t.screen_discovery,
            Screen::Scanner => t.screen_scanner,
            Screen::Security => t.screen_security,
            Screen::Monitor => t.screen_monitor,
            Screen::Doctor => t.screen_doctor,
            Screen::Reports => t.screen_reports,
            Screen::Snapshots => t.screen_snapshots,
            Screen::Settings => t.screen_settings,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkTab {
    Overview,
    Interfaces,
    Routes,
    Dns,
    Connectivity,
    Latency,
    Trace,
    Connections,
}

impl NetworkTab {
    pub const ALL: [NetworkTab; 8] = [
        NetworkTab::Overview,
        NetworkTab::Interfaces,
        NetworkTab::Routes,
        NetworkTab::Dns,
        NetworkTab::Connectivity,
        NetworkTab::Latency,
        NetworkTab::Trace,
        NetworkTab::Connections,
    ];

    pub fn label(self) -> &'static str {
        let t = &crate::tui::text::T;
        match self {
            NetworkTab::Overview => t.tab_overview,
            NetworkTab::Interfaces => t.tab_interfaces,
            NetworkTab::Routes => t.tab_routes,
            NetworkTab::Dns => t.tab_dns,
            NetworkTab::Connectivity => t.tab_connectivity,
            NetworkTab::Latency => t.tab_latency,
            NetworkTab::Trace => t.tab_trace,
            NetworkTab::Connections => t.tab_connections,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecurityTab {
    Overview,
    Findings,
    Accounts,
    Listening,
    Firewall,
    Integrity,
    External,
}

impl SecurityTab {
    pub const ALL: [SecurityTab; 7] = [
        SecurityTab::Overview,
        SecurityTab::Findings,
        SecurityTab::Accounts,
        SecurityTab::Listening,
        SecurityTab::Firewall,
        SecurityTab::Integrity,
        SecurityTab::External,
    ];

    pub fn label(self) -> &'static str {
        let t = &crate::tui::text::T;
        match self {
            SecurityTab::Overview => t.tab_overview,
            SecurityTab::Findings => t.tab_findings,
            SecurityTab::Accounts => t.tab_accounts,
            SecurityTab::Listening => t.tab_listening,
            SecurityTab::Firewall => t.tab_firewall,
            SecurityTab::Integrity => t.tab_integrity,
            SecurityTab::External => t.tab_external,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScannerTab {
    PortScan,
    HostScan,
    Nmap,
}

impl ScannerTab {
    pub const ALL: [ScannerTab; 3] = [ScannerTab::PortScan, ScannerTab::HostScan, ScannerTab::Nmap];

    pub fn label(self) -> &'static str {
        let t = &crate::tui::text::T;
        match self {
            ScannerTab::PortScan => t.tab_port_scan,
            ScannerTab::HostScan => t.tab_host_scan,
            ScannerTab::Nmap => t.tab_nmap,
        }
    }
}

/// A cached value with the time it was captured.
#[derive(Debug)]
pub struct Fresh<T> {
    pub value: T,
    pub at: Instant,
}

impl<T> Fresh<T> {
    pub fn new(value: T) -> Self {
        Self {
            value,
            at: Instant::now(),
        }
    }

    pub fn age(&self) -> Duration {
        self.at.elapsed()
    }

    pub fn is_fresh(&self, ttl: Duration) -> bool {
        self.age() < ttl
    }
}

/// Session cache. Freshness matters: the UI must show whether data is live or
/// stale, and must not re-probe just because a frame was drawn.
#[derive(Default)]
pub struct Caches {
    pub os: Option<Fresh<OsInfo>>,
    pub system: Option<Fresh<SystemSnapshot>>,
    pub interfaces: Option<Fresh<Vec<Interface>>>,
    pub routes: Option<Fresh<Vec<Route>>>,
    pub dns: Option<Fresh<DnsConfig>>,
    pub connectivity: Option<Fresh<ConnectivityReport>>,
    pub audit: Option<Fresh<SecurityAudit>>,
    pub doctor: Option<Fresh<DoctorReport>>,
    pub connections: Option<Fresh<Vec<Connection>>>,
    pub processes: Option<Fresh<Vec<ProcessInfo>>>,
    pub listening: Option<Fresh<Vec<ListeningPort>>>,
    pub firewall: Option<Fresh<FirewallStatus>>,
    pub rules: Option<Fresh<Vec<FirewallRule>>>,
    pub baseline: Option<IntegrityBaseline>,
    pub integrity_report: Option<Fresh<IntegrityReport>>,
    pub external_tools: Option<Fresh<Vec<crate::core::security::ExternalToolResult>>>,
    pub snapshots: Option<Fresh<Vec<(PathBuf, crate::core::snapshot::Snapshot)>>>,
}

pub const TTL_SYSTEM: Duration = Duration::from_secs(4);
pub const TTL_NETWORK: Duration = Duration::from_secs(30);
pub const TTL_DNS: Duration = Duration::from_secs(60);
pub const TTL_CONNECTIVITY: Duration = Duration::from_secs(45);
pub const TTL_AUDIT: Duration = Duration::from_secs(120);
pub const TTL_DOCTOR: Duration = Duration::from_secs(120);
pub const TTL_CONNECTIONS: Duration = Duration::from_secs(5);
pub const TTL_PROCESSES: Duration = Duration::from_secs(5);
pub const TTL_FIREWALL: Duration = Duration::from_secs(30);

#[derive(Default)]
pub struct DoctorUi {
    pub checks: Vec<CheckResult>,
    pub running: Option<u64>,
    pub report: Option<DoctorReport>,
    pub error: Option<NetroError>,
    pub selected: usize,
    pub started: Option<Instant>,
}

impl DoctorUi {
    /// Findings from the finished report, or the union of streamed checks.
    pub fn findings(&self) -> Vec<&Finding> {
        if let Some(report) = &self.report {
            let mut findings: Vec<&Finding> = report.findings.iter().collect();
            findings.sort_by(|a, b| b.severity.cmp(&a.severity));
            return findings;
        }
        let mut seen = std::collections::BTreeSet::new();
        let mut findings: Vec<&Finding> = Vec::new();
        for check in &self.checks {
            for finding in &check.findings {
                if seen.insert(finding.id.clone()) {
                    findings.push(finding);
                }
            }
        }
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    pub fn findings_len(&self) -> usize {
        self.findings().len()
    }

    pub fn is_running(&self) -> bool {
        self.running.is_some()
    }
}

pub struct MonitorUi {
    pub sample: Option<MonitorSample>,
    pub cpu_history: Vec<f64>,
    pub mem_history: Vec<f64>,
    pub rx_history: Vec<f64>,
    pub tx_history: Vec<f64>,
    pub peak_rx: f64,
    pub peak_tx: f64,
    pub interval_millis: Arc<AtomicU64>,
    pub paused: Arc<AtomicBool>,
    pub task: Option<u64>,
    pub errors: usize,
    pub show_processes: bool,
}

impl MonitorUi {
    pub fn new(interval_secs: f64) -> Self {
        Self {
            sample: None,
            cpu_history: Vec::new(),
            mem_history: Vec::new(),
            rx_history: Vec::new(),
            tx_history: Vec::new(),
            peak_rx: 1.0,
            peak_tx: 1.0,
            interval_millis: Arc::new(AtomicU64::new((interval_secs * 1000.0) as u64)),
            paused: Arc::new(AtomicBool::new(false)),
            task: None,
            errors: 0,
            show_processes: true,
        }
    }

    pub fn interval_secs(&self) -> f64 {
        self.interval_millis
            .load(std::sync::atomic::Ordering::Relaxed) as f64
            / 1000.0
    }

    pub fn push_sample(&mut self, sample: MonitorSample) {
        const HISTORY: usize = 120;
        self.cpu_history.push(sample.cpu_usage_percent as f64);
        self.mem_history.push(sample.memory_utilization_percent);
        let (rx, tx) = sample.network.iter().fold((0.0f64, 0.0f64), |acc, n| {
            (acc.0 + n.rx_bytes_per_sec, acc.1 + n.tx_bytes_per_sec)
        });
        self.rx_history.push(rx);
        self.tx_history.push(tx);
        self.peak_rx = self.peak_rx.max(rx).max(1.0);
        self.peak_tx = self.peak_tx.max(tx).max(1.0);
        for history in [
            &mut self.cpu_history,
            &mut self.mem_history,
            &mut self.rx_history,
            &mut self.tx_history,
        ] {
            if history.len() > HISTORY {
                let excess = history.len() - HISTORY;
                history.drain(0..excess);
            }
        }
        self.sample = Some(sample);
    }
}

pub enum ScanProfile {
    Common,
    FullTcp,
    Custom,
}

impl ScanProfile {
    pub const ALL: [ScanProfile; 3] = [
        ScanProfile::Common,
        ScanProfile::FullTcp,
        ScanProfile::Custom,
    ];

    pub fn label(&self) -> &'static str {
        match self {
            ScanProfile::Common => "Common ports",
            ScanProfile::FullTcp => "Full TCP (1-65535)",
            ScanProfile::Custom => "Custom port list",
        }
    }

    pub fn ports(&self, custom: &str) -> String {
        match self {
            ScanProfile::Common => "common".into(),
            ScanProfile::FullTcp => "all".into(),
            ScanProfile::Custom => custom.to_string(),
        }
    }
}

pub struct ScannerUi {
    pub tab: ScannerTab,
    pub target: String,
    pub custom_ports: String,
    pub profile: usize,
    pub authorized: bool,
    pub banner: bool,
    pub tls: bool,
    pub udp: bool,
    pub field: usize,
    pub task: Option<u64>,
    pub progress: Option<crate::core::scan::ScanProgress>,
    pub report: Option<ScanReport>,
    pub error: Option<NetroError>,
    pub selected: usize,
    pub export_path: String,
}

impl Default for ScannerUi {
    fn default() -> Self {
        Self {
            tab: ScannerTab::PortScan,
            target: "127.0.0.1".into(),
            custom_ports: "22,80,443".into(),
            profile: 0,
            authorized: false,
            banner: true,
            tls: true,
            udp: false,
            field: 0,
            task: None,
            progress: None,
            report: None,
            error: None,
            selected: 0,
            export_path: "netro-scan.json".into(),
        }
    }
}

pub struct DiscoveryUi {
    pub target: String,
    pub method: usize,
    pub resolve_hostnames: bool,
    pub vendor_lookup: bool,
    pub task: Option<u64>,
    pub progress: Option<crate::core::discovery::DiscoveryProgress>,
    pub report: Option<DiscoveryReport>,
    pub error: Option<NetroError>,
    pub selected: usize,
    pub field: usize,
}

impl Default for DiscoveryUi {
    fn default() -> Self {
        Self {
            target: String::new(),
            method: 0,
            resolve_hostnames: true,
            vendor_lookup: true,
            task: None,
            progress: None,
            report: None,
            error: None,
            selected: 0,
            field: 0,
        }
    }
}

/// Network tab inputs and last results.
#[derive(Default)]
pub struct NetworkUi {
    pub latency_target: String,
    pub latency: Option<PingResult>,
    pub latency_error: Option<NetroError>,
    pub trace_target: String,
    pub trace: Option<TraceResult>,
    pub trace_error: Option<NetroError>,
    pub dns_name: String,
    pub dns_server: String,
    pub dns_query: Option<crate::core::dns::DnsResponse>,
    pub dns_error: Option<NetroError>,
    pub selected: usize,
}

pub struct ReportsUi {
    pub format: usize,
    pub scope: usize,
    pub path: String,
    pub task: Option<u64>,
    pub last: Option<PathBuf>,
    pub last_format: String,
    pub error: Option<NetroError>,
}

impl Default for ReportsUi {
    fn default() -> Self {
        Self {
            format: 0,
            scope: 0,
            path: "netro-report.html".into(),
            task: None,
            last: None,
            last_format: String::new(),
            error: None,
        }
    }
}

impl ReportsUi {
    pub const FORMATS: [(&'static str, &'static str); 4] = [
        ("HTML", "html"),
        ("JSON", "json"),
        ("CSV", "csv"),
        ("Text", "text"),
    ];
    pub const SCOPES: [&'static str; 4] = ["Full", "System", "Network", "Security"];

    pub fn format(&self) -> &'static str {
        Self::FORMATS[self.format.min(Self::FORMATS.len() - 1)].1
    }

    pub fn scope(&self) -> &'static str {
        Self::SCOPES[self.scope.min(Self::SCOPES.len() - 1)]
    }
}

#[derive(Default)]
pub struct SnapshotsUi {
    pub list: Vec<(PathBuf, crate::core::snapshot::Snapshot)>,
    pub selected: usize,
    pub marked: Option<usize>,
    pub diff: Option<crate::core::snapshot::SnapshotDiff>,
    pub task: Option<u64>,
    pub error: Option<NetroError>,
    pub loaded: bool,
}

pub struct SettingsUi {
    pub selected: usize,
    pub draft: Config,
    pub dirty: bool,
}

impl SettingsUi {
    pub fn new(config: &Config) -> Self {
        Self {
            selected: 0,
            draft: config.clone(),
            dirty: false,
        }
    }

    pub fn row_labels() -> [&'static str; 14] {
        use crate::tui::text::T;
        [
            T.set_theme,
            T.set_colors,
            T.set_unicode,
            T.set_refresh,
            T.set_monitor_interval,
            T.set_discovery_method,
            T.set_scan_ports,
            T.set_scan_timeout,
            T.set_scan_concurrency,
            T.set_reverse_dns,
            T.set_vendor_lookup,
            T.set_oui_file,
            T.set_speedtest_server,
            T.set_save,
        ]
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterTarget {
    None,
    Screen,
    Findings,
    Accounts,
    Listening,
    Connections,
    Processes,
    Routes,
    Interfaces,
    Hosts,
    ScanPorts,
    Snapshots,
}

pub struct PaletteState {
    pub query: String,
    pub selected: usize,
}

pub enum InputKind {
    ScannerTarget,
    ScannerPorts,
    DiscoveryTarget,
    LatencyTarget,
    TraceTarget,
    DnsName,
    DnsServer,
    FirewallIp,
    ReportPath,
    SnapshotLabel,
    SnapshotExport,
    ScanExport,
    SettingText(usize),
}

pub struct InputState {
    pub prompt: String,
    pub value: String,
    pub kind: InputKind,
}

pub struct ConfirmState {
    pub title: String,
    pub lines: Vec<String>,
    pub action: Action,
}

pub struct DetailState {
    pub title: String,
    pub sections: Vec<(String, Vec<String>)>,
    pub scroll: u16,
}

pub enum Overlay {
    None,
    Help,
    Palette(PaletteState),
    Confirm(ConfirmState),
    Input(InputState),
    Error(NetroError),
    Detail(DetailState),
}

impl Overlay {
    pub fn is_open(&self) -> bool {
        !matches!(self, Overlay::None)
    }
}

pub struct AppState {
    pub screen: Screen,
    pub network_tab: NetworkTab,
    pub security_tab: SecurityTab,
    pub caches: Caches,
    pub doctor: DoctorUi,
    pub monitor: MonitorUi,
    pub network: NetworkUi,
    pub scanner: ScannerUi,
    pub discovery: DiscoveryUi,
    pub reports: ReportsUi,
    pub snapshots: SnapshotsUi,
    pub settings: SettingsUi,
    pub overlay: Overlay,
    /// Overlays reopened after closing a detail view opened from a modal.
    pub overlay_stack: Vec<Overlay>,
    pub filter: String,
    pub filter_target: FilterTarget,
    pub filtering: bool,
    pub tick: u64,
    pub theme_kind: ThemeKind,
    pub last_error: Option<NetroError>,
    pub config: Config,
    pub dashboard_selected: usize,
    pub system_selected: usize,
    pub security_sel: usize,
    pub status_message: Option<(String, Instant)>,
    /// Detected once at startup; rendering must not probe the filesystem.
    pub nmap_installed: bool,
    /// Display strings for environment-dependent paths, resolved at startup so
    /// components render identically on every platform.
    pub config_path_display: String,
    pub snapshots_dir_display: String,
}

impl AppState {
    pub fn new(config: Config, theme_kind: ThemeKind) -> Self {
        let monitor = MonitorUi::new(config.monitor.interval_secs);
        Self {
            screen: Screen::Dashboard,
            network_tab: NetworkTab::Overview,
            security_tab: SecurityTab::Overview,
            caches: Caches::default(),
            doctor: DoctorUi::default(),
            monitor,
            network: NetworkUi::default(),
            scanner: ScannerUi::default(),
            discovery: DiscoveryUi::default(),
            reports: ReportsUi::default(),
            snapshots: SnapshotsUi::default(),
            settings: SettingsUi::new(&config),
            overlay: Overlay::None,
            overlay_stack: Vec::new(),
            filter: String::new(),
            filter_target: FilterTarget::None,
            filtering: false,
            tick: 0,
            theme_kind,
            last_error: None,
            dashboard_selected: 0,
            system_selected: 0,
            security_sel: 0,
            status_message: None,
            nmap_installed: crate::util::which("nmap").is_some(),
            config_path_display: crate::config::display_path(&crate::config::config_file()),
            snapshots_dir_display: crate::config::display_path(
                &crate::core::snapshot::snapshots_dir(),
            ),
            config,
        }
    }

    pub fn set_status(&mut self, message: impl Into<String>) {
        self.status_message = Some((message.into(), Instant::now()));
    }

    pub fn active_status(&self) -> Option<&str> {
        self.status_message
            .as_ref()
            .filter(|(_, at)| at.elapsed() < Duration::from_secs(5))
            .map(|(message, _)| message.as_str())
    }

    pub fn security_selected(&self) -> usize {
        self.security_sel
    }

    pub fn set_security_selected(&mut self, index: usize) {
        self.security_sel = index;
    }

    /// Reset list selections when switching tabs/screens so stale indices do
    /// not point outside the new list.
    pub fn selected_reset(&mut self) {
        self.dashboard_selected = 0;
        self.system_selected = 0;
        self.network.selected = 0;
        self.security_sel = 0;
        self.doctor.selected = 0;
        self.discovery.selected = 0;
        self.scanner.selected = 0;
    }

    pub fn security_list_len(&self, caches: &Caches, filter: &str) -> usize {
        let matches = |value: &str| {
            filter.is_empty()
                || value
                    .to_ascii_lowercase()
                    .contains(&filter.to_ascii_lowercase())
        };
        match self.security_tab {
            SecurityTab::Findings => caches
                .audit
                .as_ref()
                .map(|fresh| {
                    fresh
                        .value
                        .findings
                        .iter()
                        .filter(|f| matches(&f.title) || matches(&f.id))
                        .count()
                })
                .unwrap_or(0),
            SecurityTab::Accounts => caches
                .audit
                .as_ref()
                .map(|fresh| {
                    fresh
                        .value
                        .accounts
                        .iter()
                        .filter(|a| matches(&a.name))
                        .count()
                })
                .unwrap_or(0),
            SecurityTab::Listening => caches
                .listening
                .as_ref()
                .map(|fresh| {
                    fresh
                        .value
                        .iter()
                        .filter(|p| {
                            matches(&p.address)
                                || matches(&p.process.clone().unwrap_or_default())
                                || matches(&p.port.to_string())
                        })
                        .count()
                })
                .unwrap_or(0),
            SecurityTab::Firewall => caches
                .rules
                .as_ref()
                .map(|fresh| fresh.value.iter().filter(|r| matches(&r.raw)).count())
                .unwrap_or(0),
            _ => 0,
        }
    }

    /// Push a detail overlay that returns to the previous overlay on close.
    pub fn open_detail(&mut self, title: impl Into<String>, sections: Vec<(String, Vec<String>)>) {
        let previous = std::mem::replace(&mut self.overlay, Overlay::None);
        if previous.is_open() {
            self.overlay_stack.push(previous);
        }
        self.overlay = Overlay::Detail(DetailState {
            title: title.into(),
            sections,
            scroll: 0,
        });
    }

    pub fn close_overlay(&mut self) {
        self.overlay = self.overlay_stack.pop().unwrap_or(Overlay::None);
    }

    /// Clear the active filter and stop filtering mode.
    pub fn clear_filter(&mut self) {
        self.filter.clear();
        self.filter_target = FilterTarget::None;
        self.filtering = false;
    }

    pub fn filter_matches(&self, haystack: &str) -> bool {
        if self.filter.is_empty() {
            return true;
        }
        haystack
            .to_ascii_lowercase()
            .contains(&self.filter.to_ascii_lowercase())
    }

    pub fn freshness_label(&self, at: Instant) -> String {
        let age = at.elapsed().as_secs_f64();
        if age < 1.5 {
            "now".to_string()
        } else if age < 60.0 {
            format!("{:.0}s ago", age)
        } else {
            format!("{:.0}m ago", age / 60.0)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn screens_are_complete() {
        assert_eq!(Screen::ALL.len(), 11);
        for screen in Screen::ALL {
            assert!(!screen.title().is_empty());
        }
        assert_eq!(NetworkTab::ALL.len(), 8);
        assert_eq!(SecurityTab::ALL.len(), 7);
        assert_eq!(ScannerTab::ALL.len(), 3);
    }

    #[test]
    fn monitor_history_is_bounded() {
        let mut ui = MonitorUi::new(1.0);
        for index in 0..500 {
            ui.push_sample(MonitorSample {
                timestamp_epoch: index,
                uptime_secs: 0,
                cpu_usage_percent: 10.0,
                per_core_usage: vec![],
                load_average: None,
                memory_used_bytes: 1,
                memory_total_bytes: 2,
                memory_utilization_percent: 50.0,
                swap_used_bytes: 0,
                swap_total_bytes: 0,
                network: vec![],
                temperatures: vec![],
                top_cpu: vec![],
                top_memory: vec![],
            });
        }
        assert_eq!(ui.cpu_history.len(), 120);
        assert_eq!(ui.mem_history.len(), 120);
        assert!(ui.sample.is_some());
    }

    #[test]
    fn filters_are_case_insensitive() {
        let mut state = AppState::new(Config::default(), ThemeKind::Auto);
        state.filter = "SSH".into();
        assert!(state.filter_matches("openssh server"));
        assert!(!state.filter_matches("nginx"));
    }

    #[test]
    fn detail_overlay_returns_to_previous_overlay() {
        let mut state = AppState::new(Config::default(), ThemeKind::Auto);
        state.overlay = Overlay::Palette(PaletteState {
            query: "x".into(),
            selected: 0,
        });
        state.open_detail("t", vec![]);
        assert!(matches!(state.overlay, Overlay::Detail(_)));
        state.close_overlay();
        assert!(matches!(state.overlay, Overlay::Palette(_)));
    }

    #[test]
    fn scan_profiles_map_to_real_specs() {
        assert_eq!(ScanProfile::Common.ports("x"), "common");
        assert_eq!(ScanProfile::FullTcp.ports("x"), "all");
        assert_eq!(ScanProfile::Custom.ports("22,80"), "22,80");
    }
}
