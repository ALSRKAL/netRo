//! Application orchestration: input handling, task results, caching policy and
//! render dispatch. Contains no diagnostics logic itself — it composes the
//! existing `core` APIs through the task manager.

use crate::config::Config;
use crate::core::{
    diagnostics, discovery, dns, health, integrity, reporting, scan, security, snapshot,
};
use crate::error::{ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::platform;
use crate::tui::action::Action;
use crate::tui::caps::Caps;
use crate::tui::event::AppEvent;
use crate::tui::state::*;
use crate::tui::tasks::*;
use crate::tui::terminal::TerminalGuard;
use crate::tui::theme::{Theme, ThemeKind};
use crate::tui::{components, text::T};
use crate::util;
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers, MouseEventKind};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::Frame;
use std::path::PathBuf;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

/// Read-only context passed to components.
pub struct Ui<'a> {
    pub state: &'a AppState,
    pub theme: &'a Theme,
    pub caps: &'a Caps,
    pub tick: u64,
    pub running: &'a [(TaskKind, u64)],
}

impl Ui<'_> {
    pub fn is_running(&self, kind: TaskKind) -> bool {
        self.running.iter().any(|(k, _)| *k == kind)
    }

    pub fn task_ids(&self, kind: TaskKind) -> Vec<u64> {
        self.running
            .iter()
            .filter(|(k, _)| *k == kind)
            .map(|(_, id)| *id)
            .collect()
    }
}

pub struct TuiOptions {
    pub mouse: bool,
    pub theme: Option<ThemeKind>,
}

impl Default for TuiOptions {
    fn default() -> Self {
        Self {
            mouse: true,
            theme: None,
        }
    }
}

pub struct App {
    pub state: AppState,
    pub tasks: TaskManager,
    pub theme: Theme,
    pub caps: Caps,
    pub should_quit: bool,
    pub dirty: bool,
    pub options: TuiOptions,
}

impl App {
    pub fn new(caps: Caps, config: Config, options: TuiOptions) -> Self {
        let theme_kind = options.theme.unwrap_or(match config.output.color.as_str() {
            "never" => ThemeKind::NoColor,
            _ => ThemeKind::Dark,
        });
        let theme = Theme::new(theme_kind, caps.colors, caps.unicode);
        let state = AppState::new(config, theme_kind);
        Self {
            state,
            tasks: TaskManager::new(),
            theme,
            caps,
            should_quit: false,
            dirty: true,
            options,
        }
    }

    /// Start the checks needed for a useful first screen without blocking.
    pub fn bootstrap(&mut self) {
        self.spawn_system();
        self.spawn_network_basics();
        self.spawn_connectivity();
        self.spawn_doctor();
    }

    // -----------------------------------------------------------------------
    // Task spawning
    // -----------------------------------------------------------------------

    fn spawn_system(&mut self) {
        if self.tasks.is_running(TaskKind::System) {
            return;
        }
        self.tasks.spawn(TaskKind::System, |_ctx| {
            Ok(TaskResult::System(Box::new(reporting::system_snapshot()?)))
        });
    }

    fn spawn_network_basics(&mut self) {
        if !self.tasks.is_running(TaskKind::NetworkBasics) {
            let fresh_interfaces = self
                .state
                .caches
                .interfaces
                .as_ref()
                .map(|f| f.is_fresh(TTL_NETWORK))
                .unwrap_or(false);
            let fresh_routes = self
                .state
                .caches
                .routes
                .as_ref()
                .map(|f| f.is_fresh(TTL_NETWORK))
                .unwrap_or(false);
            let fresh_dns = self
                .state
                .caches
                .dns
                .as_ref()
                .map(|f| f.is_fresh(TTL_DNS))
                .unwrap_or(false);
            if fresh_interfaces && fresh_routes && fresh_dns {
                return;
            }
            self.tasks.spawn(TaskKind::NetworkBasics, |ctx| {
                let interfaces = platform().interfaces()?;
                ctx.progress(TaskProgress::Message("interfaces".into()));
                let routes = platform().routes()?;
                ctx.progress(TaskProgress::Message("routes".into()));
                let dns = platform().dns_config()?;
                // Return the first payload and stash the rest via progress is
                // not possible with typed results, so run them as one task per
                // artifact instead: this closure keeps the order and errors.
                let _ = routes;
                let _ = dns;
                Ok(TaskResult::Interfaces(interfaces))
            });
            // Routes/DNS as their own tasks keeps each result typed.
            self.spawn_routes();
            self.spawn_dns_config();
        }
    }

    fn spawn_routes(&mut self) {
        if !self.tasks.is_running(TaskKind::NetworkBasics)
            && !matches!(
                self.state
                    .caches
                    .routes
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_NETWORK)),
                Some(true)
            )
        {
            self.tasks.spawn(TaskKind::NetworkBasics, |_ctx| {
                Ok(TaskResult::Routes(platform().routes()?))
            });
        }
    }

    fn spawn_dns_config(&mut self) {
        if !matches!(
            self.state.caches.dns.as_ref().map(|f| f.is_fresh(TTL_DNS)),
            Some(true)
        ) {
            self.tasks.spawn(TaskKind::NetworkBasics, |_ctx| {
                Ok(TaskResult::DnsConfig(Box::new(platform().dns_config()?)))
            });
        }
    }

    fn spawn_connectivity(&mut self) {
        if self.tasks.is_running(TaskKind::Connectivity)
            || matches!(
                self.state
                    .caches
                    .connectivity
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_CONNECTIVITY)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::Connectivity, |_ctx| {
            Ok(TaskResult::Connectivity(Box::new(
                diagnostics::connectivity(&diagnostics::ConnectivityOptions::default()),
            )))
        });
    }

    fn spawn_doctor(&mut self) {
        if self.tasks.is_running(TaskKind::Doctor) {
            self.state.set_status(T.doc_running);
            return;
        }
        self.state.doctor.checks.clear();
        self.state.doctor.error = None;
        self.state.doctor.started = Some(Instant::now());
        // Reuse fresh connectivity/audit results so the doctor does not repeat
        // network probes or the audit (session cache reuse, spec §53).
        let connectivity = self
            .state
            .caches
            .connectivity
            .as_ref()
            .filter(|fresh| fresh.is_fresh(TTL_CONNECTIVITY))
            .map(|fresh| fresh.value.clone());
        let audit = self
            .state
            .caches
            .audit
            .as_ref()
            .filter(|fresh| fresh.is_fresh(TTL_AUDIT))
            .map(|fresh| fresh.value.clone());
        let options = health::DoctorOptions {
            skip_internet: connectivity.is_none(),
            ..health::DoctorOptions::default()
        };
        let id = self.tasks.spawn(TaskKind::Doctor, move |ctx| {
            let report = health::run_streaming_with(
                &options,
                connectivity.as_ref(),
                audit.as_ref(),
                &mut |check| {
                    ctx.progress(TaskProgress::Check(Box::new(check.clone())));
                },
            );
            Ok(TaskResult::Doctor(Box::new(report)))
        });
        self.state.doctor.running = Some(id);
    }

    fn spawn_audit(&mut self, run_external: bool) {
        if self.tasks.is_running(TaskKind::Audit)
            || matches!(
                self.state
                    .caches
                    .audit
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_AUDIT)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::Audit, move |_ctx| {
            Ok(TaskResult::Audit(Box::new(security::audit(run_external))))
        });
    }

    pub fn spawn_external_tools(&mut self) {
        if self.tasks.is_running(TaskKind::ExternalTools) {
            self.state.set_status("External tools are already running.");
            return;
        }
        self.tasks.spawn(TaskKind::ExternalTools, |_ctx| {
            Ok(TaskResult::ExternalTools(security::external_tools(true)))
        });
    }

    fn spawn_connections(&mut self) {
        if self.tasks.is_running(TaskKind::Connections)
            || matches!(
                self.state
                    .caches
                    .connections
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_CONNECTIONS)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::Connections, |_ctx| {
            Ok(TaskResult::Connections(platform().connections()?))
        });
    }

    fn spawn_processes(&mut self) {
        if self.tasks.is_running(TaskKind::Processes)
            || matches!(
                self.state
                    .caches
                    .processes
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_PROCESSES)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::Processes, |_ctx| {
            Ok(TaskResult::Processes(platform().processes()?))
        });
    }

    fn spawn_listening(&mut self) {
        if self.tasks.is_running(TaskKind::Listening)
            || matches!(
                self.state
                    .caches
                    .listening
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_NETWORK)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::Listening, |_ctx| {
            Ok(TaskResult::Listening(platform().listening_ports()?))
        });
    }

    fn spawn_firewall_status(&mut self) {
        if self.tasks.is_running(TaskKind::FirewallStatus)
            || matches!(
                self.state
                    .caches
                    .firewall
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_FIREWALL)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::FirewallStatus, |_ctx| {
            Ok(TaskResult::Firewall(Box::new(
                platform().firewall_status()?,
            )))
        });
    }

    fn spawn_firewall_rules(&mut self) {
        if self.tasks.is_running(TaskKind::FirewallRules)
            || matches!(
                self.state
                    .caches
                    .rules
                    .as_ref()
                    .map(|f| f.is_fresh(TTL_FIREWALL)),
                Some(true)
            )
        {
            return;
        }
        self.tasks.spawn(TaskKind::FirewallRules, |_ctx| {
            Ok(TaskResult::FirewallRules(platform().firewall_rules(50)?))
        });
    }

    fn spawn_monitor(&mut self) {
        if self.state.monitor.task.is_some() || self.tasks.is_running(TaskKind::Monitor) {
            return;
        }
        let interval = self.state.monitor.interval_millis.clone();
        let paused = self.state.monitor.paused.clone();
        let include_processes = self.state.monitor.show_processes;
        let id = self.tasks.spawn(TaskKind::Monitor, move |ctx| {
            use crate::core::monitoring::{Monitor, MonitorOptions};
            let options = MonitorOptions {
                interval: Duration::from_millis(interval.load(Ordering::Relaxed).max(200)),
                iterations: None,
                top_n: 5,
                show_temperatures: true,
                include_processes,
            };
            let mut monitor = Monitor::new(&options);
            monitor.prime();
            loop {
                if ctx.is_cancelled() {
                    return Ok(TaskResult::MonitorStopped);
                }
                if paused.load(Ordering::Relaxed) {
                    std::thread::sleep(Duration::from_millis(150));
                    continue;
                }
                let sample = monitor.sample();
                let wait = Duration::from_millis(interval.load(Ordering::Relaxed).max(200));
                ctx.progress(TaskProgress::Monitor(Box::new(sample)));
                let mut slept = Duration::ZERO;
                while slept < wait {
                    if ctx.is_cancelled() {
                        return Ok(TaskResult::MonitorStopped);
                    }
                    if paused.load(Ordering::Relaxed) {
                        break;
                    }
                    std::thread::sleep(Duration::from_millis(100));
                    slept += Duration::from_millis(100);
                }
            }
        });
        self.state.monitor.task = Some(id);
    }

    fn stop_monitor(&mut self) {
        if let Some(id) = self.state.monitor.task {
            self.tasks.cancel(id);
            self.state.monitor.task = None;
        }
    }

    fn spawn_discovery(&mut self) {
        if self.tasks.is_running(TaskKind::Discovery) {
            self.state.set_status("Discovery is already running.");
            return;
        }
        let mut options = discovery::DiscoveryOptions {
            interface: None,
            target: if self.state.discovery.target.trim().is_empty() {
                None
            } else {
                Some(self.state.discovery.target.trim().to_string())
            },
            method: match self.state.discovery.method {
                1 => discovery::DiscoveryMethod::Neighbors,
                2 => discovery::DiscoveryMethod::Icmp,
                3 => discovery::DiscoveryMethod::Tcp,
                4 => discovery::DiscoveryMethod::Nmap,
                _ => discovery::DiscoveryMethod::Auto,
            },
            max_hosts: self.state.config.discovery.max_hosts,
            tcp_ports: self.state.config.discovery.tcp_ports.clone(),
            resolve_hostnames: self.state.discovery.resolve_hostnames,
            vendor_lookup: self.state.discovery.vendor_lookup,
            oui_file: self
                .state
                .config
                .integrations
                .oui_file
                .as_ref()
                .map(PathBuf::from),
            concurrency: 64,
            timeout: Duration::from_millis(800),
            cancel: None,
        };
        self.state.discovery.error = None;
        self.state.discovery.progress = None;
        let id = self.tasks.spawn(TaskKind::Discovery, move |ctx| {
            options.cancel = Some(ctx.cancel_flag());
            let report = discovery::discover_with(&options, &mut |progress| {
                ctx.progress(TaskProgress::Discovery(progress));
            })?;
            Ok(TaskResult::Discovery(Box::new(report)))
        });
        let _ = id;
    }

    fn spawn_scan(&mut self) {
        if self.tasks.is_running(TaskKind::Scan) {
            self.state.set_status("A scan is already running.");
            return;
        }
        let target = self.state.scanner.target.trim().to_string();
        if target.is_empty() {
            self.state.scanner.error = Some(NetroError::new(
                ErrorCode::InvalidTarget,
                "enter a target IP or hostname",
            ));
            return;
        }
        let profile = match self.state.scanner.profile {
            1 => ScanProfile::FullTcp,
            2 => ScanProfile::Custom,
            _ => ScanProfile::Common,
        };
        let spec = profile.ports(&self.state.scanner.custom_ports);
        let ports = match scan::parse_ports(&spec) {
            Ok(ports) => ports,
            Err(error) => {
                self.state.scanner.error = Some(error);
                return;
            }
        };
        if !self.state.scanner.authorized {
            self.state.scanner.error = Some(
                NetroError::new(ErrorCode::UnauthorizedScan, T.scan_authorization)
                    .with_hint(T.scan_public_warning),
            );
            return;
        }
        let mut options = scan::ScanOptions {
            timeout: Duration::from_millis(self.state.config.scan.timeout_ms),
            concurrency: self.state.config.scan.concurrency,
            banner: self.state.scanner.banner,
            tls: self.state.scanner.tls,
            udp: self.state.scanner.udp,
            authorized: true,
            cancel: None,
        };
        self.state.scanner.error = None;
        self.state.scanner.progress = None;
        let _ = self.tasks.spawn(TaskKind::Scan, move |ctx| {
            options.cancel = Some(ctx.cancel_flag());
            let report = scan::scan_with(&target, &ports, &options, &mut |progress| {
                ctx.progress(TaskProgress::Scan(progress));
            })?;
            Ok(TaskResult::Scan(Box::new(report)))
        });
    }

    fn spawn_integrity_baseline(&mut self) {
        let paths = self.effective_integrity_paths();
        let max_size = self.state.config.integrity.max_file_size_mb.max(64) * 1024 * 1024;
        let _ = self.tasks.spawn(TaskKind::IntegrityBaseline, move |_ctx| {
            let baseline = integrity::create_baseline(&paths, max_size)?;
            let _ = integrity::save_baseline(&baseline)?;
            Ok(TaskResult::IntegrityBaseline(Box::new(baseline)))
        });
    }

    fn spawn_integrity_scan(&mut self) {
        if self.tasks.is_running(TaskKind::IntegrityScan) {
            return;
        }
        let max_size = self.state.config.integrity.max_file_size_mb.max(64) * 1024 * 1024;
        let _ = self.tasks.spawn(TaskKind::IntegrityScan, move |_ctx| {
            let baseline = match integrity::load_baseline() {
                Ok(baseline) => baseline,
                Err(error) if error.code() == ErrorCode::NotFound => {
                    return Ok(TaskResult::BaselineMissing);
                }
                Err(error) => return Err(error),
            };
            let report = integrity::scan_baseline(&baseline, max_size)?;
            Ok(TaskResult::IntegrityReport(Box::new(report)))
        });
    }

    fn spawn_snapshot_create(&mut self, label: Option<String>) {
        let _ = self.tasks.spawn(TaskKind::SnapshotCreate, move |_ctx| {
            let snapshot = snapshot::capture(label)?;
            let path = snapshot::save(&snapshot)?;
            Ok(TaskResult::SnapshotCreated(path, Box::new(snapshot)))
        });
    }

    fn spawn_snapshot_compare(&mut self, a: usize, b: usize) {
        let list = self.state.snapshots.list.clone();
        if a >= list.len() || b >= list.len() {
            return;
        }
        let (_, older) = list[a].clone();
        let (_, newer) = list[b].clone();
        // Always diff older -> newer regardless of selection order.
        let (older, newer) = if older.created_epoch <= newer.created_epoch {
            (older, newer)
        } else {
            (newer, older)
        };
        let diff = snapshot::compare(&older, &newer);
        self.state.snapshots.diff = Some(diff);
        self.state.snapshots.marked = None;
        self.state.set_status("Snapshot comparison ready");
    }

    fn spawn_firewall_change(&mut self, ip: String, unblock: bool) {
        let _ = self.tasks.spawn(TaskKind::FirewallChange, move |_ctx| {
            let change = if unblock {
                platform().unblock_ip(&ip, false)?
            } else {
                platform().block_ip(&ip, false)?
            };
            Ok(TaskResult::FirewallChanged(Box::new(change)))
        });
    }

    fn spawn_latency(&mut self) {
        let target = self.state.network.latency_target.trim().to_string();
        if target.is_empty() {
            self.state.network.latency_error =
                Some(NetroError::new(ErrorCode::InvalidTarget, "enter a target"));
            return;
        }
        self.state.network.latency_error = None;
        let _ = self.tasks.spawn(TaskKind::Latency, move |_ctx| {
            Ok(TaskResult::Latency(Box::new(diagnostics::ping(
                &target,
                diagnostics::PingMethod::Auto,
                &diagnostics::PingOptions::default(),
            ))))
        });
    }

    fn spawn_trace(&mut self) {
        let target = self.state.network.trace_target.trim().to_string();
        if target.is_empty() {
            self.state.network.trace_error =
                Some(NetroError::new(ErrorCode::InvalidTarget, "enter a target"));
            return;
        }
        self.state.network.trace_error = None;
        let _ = self.tasks.spawn(TaskKind::Trace, move |_ctx| {
            Ok(TaskResult::Trace(Box::new(diagnostics::traceroute(
                &target,
                diagnostics::TraceMethod::Auto,
                &diagnostics::TraceOptions {
                    max_hops: 20,
                    ..diagnostics::TraceOptions::default()
                },
            )?)))
        });
    }

    fn spawn_dns_query(&mut self) {
        let name = self.state.network.dns_name.trim().to_string();
        if name.is_empty() {
            self.state.network.dns_error =
                Some(NetroError::new(ErrorCode::InvalidTarget, "enter a name"));
            return;
        }
        let server = self.state.network.dns_server.trim().to_string();
        self.state.network.dns_error = None;
        let _ = self.tasks.spawn(TaskKind::DnsQuery, move |_ctx| {
            let response = if server.is_empty() {
                dns::resolve_via_system(&name, dns::RecordType::A, Duration::from_secs(5))?
            } else {
                dns::query(&server, &name, dns::RecordType::A, Duration::from_secs(5))?
            };
            Ok(TaskResult::DnsQuery(Box::new(response)))
        });
    }

    fn spawn_report(&mut self) {
        if self.tasks.is_running(TaskKind::Report) {
            self.state
                .set_status("A report is already being generated.");
            return;
        }
        let format = self.state.reports.format().to_string();
        let scope = self.state.reports.scope();
        let path = PathBuf::from(self.state.reports.path.trim());
        if path.as_os_str().is_empty() {
            self.state.reports.error = Some(NetroError::new(
                ErrorCode::InvalidTarget,
                "enter an output path",
            ));
            return;
        }
        let report = self.build_report(scope);
        self.state.reports.error = None;
        let _ = self.tasks.spawn(TaskKind::Report, move |_ctx| {
            match format.as_str() {
                "html" => reporting::write_file(&path, &reporting::render_html(&report))?,
                "json" => reporting::write_file(
                    &path,
                    &serde_json::to_string_pretty(&report)
                        .map_err(|e| NetroError::new(ErrorCode::ParseError, e.to_string()))?,
                )?,
                "csv" => reporting::write_file(&path, &reporting::render_csv(&report))?,
                _ => reporting::write_file(&path, &reporting::render_text(&report))?,
            }
            Ok(TaskResult::ReportWritten(path, format))
        });
    }

    fn spawn_config_save(&mut self) {
        let draft = self.state.settings.draft.clone();
        let _ = self.tasks.spawn(TaskKind::ConfigSave, move |_ctx| {
            let path = draft.save()?;
            Ok(TaskResult::ConfigSaved(path))
        });
    }

    fn spawn_scan_export(&mut self) {
        let Some(report) = self.state.scanner.report.clone() else {
            return;
        };
        let path = PathBuf::from(self.state.scanner.export_path.trim());
        if path.as_os_str().is_empty() {
            return;
        }
        let _ = self.tasks.spawn(TaskKind::ExportScan, move |_ctx| {
            let json = serde_json::to_string_pretty(&report)
                .map_err(|e| NetroError::new(ErrorCode::ParseError, e.to_string()))?;
            reporting::write_file(&path, &json)?;
            Ok(TaskResult::Exported(path))
        });
    }

    fn effective_integrity_paths(&self) -> Vec<String> {
        if !self.state.config.integrity.paths.is_empty() {
            return self.state.config.integrity.paths.clone();
        }
        platform().default_integrity_paths()
    }

    // -----------------------------------------------------------------------
    // Reports from cache
    // -----------------------------------------------------------------------

    fn build_report(&self, scope: &str) -> reporting::Report {
        let caches = &self.state.caches;
        let mut limitations = Vec::new();
        let include_system = matches!(scope, "Full" | "System");
        let include_network = matches!(scope, "Full" | "Network");
        let include_security = matches!(scope, "Full" | "Security");

        let system = if include_system {
            match &caches.system {
                Some(fresh) => Some(fresh.value.clone()),
                None => {
                    limitations.push(
                        "system section not collected in this session; run the CLI for a full capture"
                            .into(),
                    );
                    None
                }
            }
        } else {
            None
        };
        let interfaces = if include_network {
            caches
                .interfaces
                .as_ref()
                .map(|f| f.value.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let routes = if include_network {
            caches
                .routes
                .as_ref()
                .map(|f| f.value.clone())
                .unwrap_or_default()
        } else {
            Vec::new()
        };
        let dns_config = if include_network {
            caches.dns.as_ref().map(|f| f.value.clone())
        } else {
            None
        };
        let connectivity = if include_network {
            caches.connectivity.as_ref().map(|f| f.value.clone())
        } else {
            None
        };
        let security_audit = if include_security {
            caches.audit.as_ref().map(|f| f.value.clone())
        } else {
            None
        };
        let doctor = if matches!(scope, "Full") {
            caches.doctor.as_ref().map(|f| f.value.clone())
        } else {
            None
        };

        reporting::Report {
            generated_at_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            netro_version: crate::version::VERSION.to_string(),
            hostname: caches
                .os
                .as_ref()
                .and_then(|f| f.value.hostname.clone())
                .or_else(sysinfo::System::host_name),
            platform: platform().id(),
            system,
            interfaces,
            routes,
            dns: dns_config,
            connectivity,
            security: security_audit,
            doctor,
            limitations,
        }
    }

    // -----------------------------------------------------------------------
    // Event handling
    // -----------------------------------------------------------------------

    pub fn handle_event(&mut self, event: AppEvent) {
        match event {
            AppEvent::Key(key) => self.handle_key(key),
            AppEvent::Mouse(mouse) => match mouse.kind {
                MouseEventKind::ScrollDown => self.move_selection(1),
                MouseEventKind::ScrollUp => self.move_selection(-1),
                _ => {}
            },
            AppEvent::Resize(width, height) => {
                self.caps = self.caps.clone().with_size(width, height);
                self.dirty = true;
            }
            AppEvent::Tick => {
                self.state.tick = self.state.tick.wrapping_add(1);
                // Idle redraws only need to refresh freshness labels (1 Hz).
                // Spinners and live progress only animate while work is
                // running, so a busy tick still redraws at the full rate.
                let busy = self.tasks.active_count() > 0
                    || self.state.status_message.is_some()
                    || self.state.screen == Screen::Monitor;
                if busy || self.state.tick % 4 == 0 {
                    self.dirty = true;
                }
            }
        }
    }

    fn handle_key(&mut self, key: KeyEvent) {
        if key.modifiers.contains(KeyModifiers::CONTROL) && key.code == KeyCode::Char('c') {
            self.tasks.cancel_all();
            self.should_quit = true;
            return;
        }
        if self.state.overlay.is_open() {
            self.handle_overlay_key(key);
            return;
        }
        if self.state.filtering {
            self.handle_filter_key(key);
            return;
        }
        match key.code {
            KeyCode::Char('q') => self.should_quit = true,
            KeyCode::Char('?') => {
                self.state.overlay = Overlay::Help;
            }
            // Some terminals/layouts deliver '?' as Shift+'/'.
            KeyCode::Char('/') if key.modifiers.contains(KeyModifiers::SHIFT) => {
                self.state.overlay = Overlay::Help;
            }
            KeyCode::Char('p') if key.modifiers.contains(KeyModifiers::CONTROL) => {
                self.state.overlay = Overlay::Palette(PaletteState {
                    query: String::new(),
                    selected: 0,
                });
            }
            KeyCode::Char('/') => self.start_filter(),
            KeyCode::Tab => self.change_screen(1),
            KeyCode::BackTab => self.change_screen(-1),
            // Windows ConPTY can deliver Tab as a control character.
            KeyCode::Char('\t') => {
                if key.modifiers.contains(KeyModifiers::SHIFT) {
                    self.change_screen(-1);
                } else {
                    self.change_screen(1);
                }
            }
            KeyCode::Esc => self.escape(),
            KeyCode::Up | KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Down | KeyCode::Char('j') => self.move_selection(1),
            KeyCode::PageUp => self.move_selection(-10),
            KeyCode::PageDown => self.move_selection(10),
            KeyCode::Home => self.select_edge(0),
            KeyCode::End => self.select_edge(usize::MAX),
            KeyCode::Left | KeyCode::Char('h') => self.move_horizontal(-1),
            KeyCode::Right | KeyCode::Char('l') => self.move_horizontal(1),
            KeyCode::Enter => self.activate(),
            KeyCode::Char('r') => self.refresh_current(),
            KeyCode::Char('R') => self.refresh_all(),
            KeyCode::Char('d') => self.perform(Action::RunDoctor),
            KeyCode::Char('c') => self.screen_char('c'),
            KeyCode::Char('s') => self.screen_char('s'),
            KeyCode::Char('b') => self.screen_char('b'),
            KeyCode::Char('u') => self.screen_char('u'),
            KeyCode::Char('x') => self.screen_char('x'),
            KeyCode::Char('e') => self.screen_char('e'),
            KeyCode::Char('m') => self.screen_char('m'),
            KeyCode::Char('g') => self.screen_char('g'),
            KeyCode::Char('p') => self.screen_char('p'),
            KeyCode::Char('+') | KeyCode::Char('=') => self.screen_char('+'),
            KeyCode::Char('-') => self.screen_char('-'),
            KeyCode::Char(' ') => self.screen_char(' '),
            KeyCode::Char(c) if c.is_ascii_digit() => self.screen_char(c),
            _ => {}
        }
    }

    fn handle_filter_key(&mut self, key: KeyEvent) {
        match key.code {
            KeyCode::Esc => self.state.clear_filter(),
            KeyCode::Enter => {
                self.state.filtering = false;
            }
            KeyCode::Backspace => {
                self.state.filter.pop();
                if self.state.filter.is_empty() {
                    self.state.filter_target = FilterTarget::None;
                }
            }
            KeyCode::Char(c) => {
                if self.state.filter.len() < 64 {
                    self.state.filter.push(c);
                }
            }
            _ => {}
        }
    }

    fn handle_overlay_key(&mut self, key: KeyEvent) {
        match &mut self.state.overlay {
            Overlay::Help => {
                if matches!(
                    key.code,
                    KeyCode::Esc | KeyCode::Char('?') | KeyCode::Char('q')
                ) {
                    self.state.close_overlay();
                }
            }
            Overlay::Palette(palette) => match key.code {
                KeyCode::Esc => self.state.close_overlay(),
                KeyCode::Enter => {
                    let matches = palette_matches(&palette.query);
                    if let Some(command) = matches.get(palette.selected).cloned() {
                        self.state.close_overlay();
                        self.perform(command.action);
                    }
                }
                KeyCode::Up => {
                    palette.selected = palette.selected.saturating_sub(1);
                }
                KeyCode::Down => {
                    let len = palette_matches(&palette.query).len();
                    if palette.selected + 1 < len {
                        palette.selected += 1;
                    }
                }
                KeyCode::Backspace => {
                    palette.query.pop();
                    palette.selected = 0;
                }
                KeyCode::Char(c) => {
                    palette.query.push(c);
                    palette.selected = 0;
                }
                _ => {}
            },
            Overlay::Confirm(confirm) => match key.code {
                KeyCode::Enter | KeyCode::Char('y') => {
                    let action = confirm.action.clone();
                    self.state.close_overlay();
                    self.perform(action);
                }
                KeyCode::Esc | KeyCode::Char('n') => self.state.close_overlay(),
                _ => {}
            },
            Overlay::Input(input) => match key.code {
                KeyCode::Esc => self.state.close_overlay(),
                KeyCode::Enter => {
                    let value = input.value.clone();
                    let kind = std::mem::replace(&mut input.kind, InputKind::SettingText(0));
                    self.state.close_overlay();
                    self.apply_input(kind, value);
                }
                KeyCode::Backspace => {
                    input.value.pop();
                }
                KeyCode::Char(c) => {
                    if input.value.len() < 512 {
                        input.value.push(c);
                    }
                }
                _ => {}
            },
            Overlay::Error(_) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.state.close_overlay(),
                KeyCode::Enter => {
                    if let Overlay::Error(error) = &self.state.overlay {
                        let title = error.code().as_str().to_string();
                        let sections = vec![
                            (
                                T.error_reason.to_string(),
                                vec![error.message().to_string()],
                            ),
                            (
                                "Remediation".to_string(),
                                vec![error.hint().unwrap_or("no additional detail").to_string()],
                            ),
                        ];
                        self.state.open_detail(title, sections);
                    }
                }
                _ => {}
            },
            Overlay::Detail(detail) => match key.code {
                KeyCode::Esc | KeyCode::Char('q') => self.state.close_overlay(),
                KeyCode::Down | KeyCode::Char('j') => {
                    detail.scroll = detail.scroll.saturating_add(1)
                }
                KeyCode::Up | KeyCode::Char('k') => detail.scroll = detail.scroll.saturating_sub(1),
                KeyCode::PageDown => detail.scroll = detail.scroll.saturating_add(10),
                KeyCode::PageUp => detail.scroll = detail.scroll.saturating_sub(10),
                _ => {}
            },
            Overlay::None => {}
        }
    }

    fn apply_input(&mut self, kind: InputKind, value: String) {
        match kind {
            InputKind::ScannerTarget => self.state.scanner.target = value,
            InputKind::ScannerPorts => {
                self.state.scanner.custom_ports = value;
                self.state.scanner.profile = 2;
            }
            InputKind::DiscoveryTarget => self.state.discovery.target = value,
            InputKind::LatencyTarget => {
                self.state.network.latency_target = value;
                self.spawn_latency();
            }
            InputKind::TraceTarget => {
                self.state.network.trace_target = value;
                self.spawn_trace();
            }
            InputKind::DnsName => {
                self.state.network.dns_name = value;
                self.spawn_dns_query();
            }
            InputKind::DnsServer => self.state.network.dns_server = value,
            InputKind::FirewallIp => {
                self.open_firewall_confirm(value, false);
            }
            InputKind::ReportPath => {
                self.state.reports.path = value;
                self.spawn_report();
            }
            InputKind::SnapshotLabel => {
                self.spawn_snapshot_create(if value.trim().is_empty() {
                    None
                } else {
                    Some(value)
                });
            }
            InputKind::SnapshotExport => {
                if let Some(index) = self.selected_index() {
                    if let Some((path, _)) = self.state.snapshots.list.get(index) {
                        let from = path.clone();
                        let to = PathBuf::from(value.trim());
                        match std::fs::copy(&from, &to) {
                            Ok(_) => self
                                .state
                                .set_status(format!("exported to {}", to.display())),
                            Err(e) => {
                                self.state.last_error = Some(NetroError::new(
                                    ErrorCode::Io,
                                    format!("export failed: {e}"),
                                ))
                            }
                        }
                    }
                }
            }
            InputKind::ScanExport => {
                self.state.scanner.export_path = value;
                self.spawn_scan_export();
            }
            InputKind::SettingText(row) => {
                self.apply_setting_text(row, value);
            }
        }
    }

    fn apply_setting_text(&mut self, row: usize, value: String) {
        let draft = &mut self.state.settings.draft;
        let result = match row {
            3 => value
                .parse::<f64>()
                .map(|v| {
                    if (0.2..=3600.0).contains(&v) {
                        draft.monitor.interval_secs = v;
                        Ok(())
                    } else {
                        Err("refresh interval must be 0.2 - 3600 seconds")
                    }
                })
                .unwrap_or(Err("invalid number")),
            4 => value
                .parse::<f64>()
                .map(|v| {
                    if (0.2..=3600.0).contains(&v) {
                        draft.monitor.interval_secs = v;
                        Ok(())
                    } else {
                        Err("monitor interval must be 0.2 - 3600 seconds")
                    }
                })
                .unwrap_or(Err("invalid number")),
            6 => match scan::parse_ports(&value) {
                Ok(_) => {
                    draft.scan.ports = value;
                    Ok(())
                }
                Err(_) => Err("invalid port specification"),
            },
            7 => value
                .parse::<u64>()
                .map(|v| {
                    draft.scan.timeout_ms = v.clamp(50, 60_000);
                    Ok(())
                })
                .unwrap_or(Err("invalid number")),
            8 => value
                .parse::<usize>()
                .map(|v| {
                    draft.scan.concurrency = v.clamp(1, 1024);
                    Ok(())
                })
                .unwrap_or(Err("invalid number")),
            11 => {
                draft.integrations.oui_file = (!value.trim().is_empty()).then(|| value.clone());
                Ok(())
            }
            12 => {
                draft.integrations.speedtest_server =
                    (!value.trim().is_empty()).then(|| value.clone());
                Ok(())
            }
            _ => Ok(()),
        };
        match result {
            Ok(()) => {
                self.state.settings.dirty = true;
                self.state.set_status("value updated (press s to save)");
            }
            Err(message) => {
                self.state.last_error = Some(NetroError::new(ErrorCode::ConfigError, message));
            }
        }
    }

    // -----------------------------------------------------------------------
    // Actions
    // -----------------------------------------------------------------------

    pub fn perform(&mut self, action: Action) {
        match action {
            Action::Quit => self.should_quit = true,
            Action::Back => self.escape(),
            Action::OpenScreen(screen, tab) => {
                self.state.screen = screen;
                if let Some(tab) = tab {
                    self.set_tab_for_screen(screen, tab);
                }
                self.ensure_screen_data();
            }
            Action::RefreshCurrent => self.refresh_current(),
            Action::RefreshAll => self.refresh_all(),
            Action::RunDoctor => {
                self.state.screen = Screen::Doctor;
                self.spawn_doctor();
            }
            Action::RunAudit => self.spawn_audit(false),
            Action::RunConnectivity => {
                if let Some(fresh) = &self.state.caches.connectivity {
                    let _ = fresh;
                }
                self.state.caches.connectivity = None;
                self.spawn_connectivity();
            }
            Action::RunInterfaces => {
                self.state.caches.interfaces = None;
                self.spawn_network_basics();
            }
            Action::RunRoutes => {
                self.state.caches.routes = None;
                self.spawn_routes();
            }
            Action::RunDnsConfig => {
                self.state.caches.dns = None;
                self.spawn_dns_config();
            }
            Action::RunListening => {
                self.state.caches.listening = None;
                self.spawn_listening();
            }
            Action::RunFirewallStatus => {
                self.state.caches.firewall = None;
                self.spawn_firewall_status();
            }
            Action::RunIntegrityScan => self.spawn_integrity_scan(),
            Action::RunExternalTools => self.spawn_external_tools(),
            Action::RunLatency(target) => {
                self.state.network.latency_target = target;
                self.spawn_latency();
            }
            Action::RunTrace(target) => {
                self.state.network.trace_target = target;
                self.spawn_trace();
            }
            Action::RunDnsQuery(name, server) => {
                self.state.network.dns_name = name;
                self.state.network.dns_server = server;
                self.spawn_dns_query();
            }
            Action::RunSpeedtest(_server) => {
                self.state
                    .set_status("use `netro network speedtest` for throughput tests");
            }
            Action::StartDiscovery => {
                self.state.screen = Screen::Discovery;
                self.spawn_discovery();
            }
            Action::StartScan => {
                self.state.screen = Screen::Scanner;
                self.spawn_scan();
            }
            Action::CancelTask => {
                if let Some((_, id)) = self.tasks.oldest_expensive() {
                    self.tasks.cancel(id);
                    self.state.set_status(T.cancelled_note);
                } else {
                    self.tasks.cancel_all();
                }
            }
            Action::StartMonitor => {
                self.state.screen = Screen::Monitor;
                self.spawn_monitor();
            }
            Action::StopMonitor => self.stop_monitor(),
            Action::TogglePause => {
                let paused = self.state.monitor.paused.load(Ordering::Relaxed);
                self.state.monitor.paused.store(!paused, Ordering::Relaxed);
            }
            Action::MonitorIntervalDelta(delta) => {
                let current = self.state.monitor.interval_millis.load(Ordering::Relaxed) as i64;
                let next = (current + delta as i64 * 250).clamp(250, 10_000);
                self.state
                    .monitor
                    .interval_millis
                    .store(next as u64, Ordering::Relaxed);
                self.state
                    .set_status(format!("monitor interval {:.2}s", next as f64 / 1000.0));
            }
            Action::CreateSnapshot(label) => self.spawn_snapshot_create(label),
            Action::DeleteSnapshot(index) => {
                if let Some((path, _)) = self.state.snapshots.list.get(index).cloned() {
                    match snapshot::delete_file(&path) {
                        Ok(()) => {
                            self.reload_snapshots();
                            self.state.set_status("snapshot deleted");
                        }
                        Err(error) => self.state.last_error = Some(error),
                    }
                }
            }
            Action::ExportSnapshot(index, path) => {
                if let Some((from, _)) = self.state.snapshots.list.get(index).cloned() {
                    let to = PathBuf::from(path.trim());
                    match std::fs::copy(&from, &to) {
                        Ok(_) => self
                            .state
                            .set_status(format!("exported to {}", to.display())),
                        Err(e) => {
                            self.state.last_error = Some(NetroError::new(
                                ErrorCode::Io,
                                format!("export failed: {e}"),
                            ))
                        }
                    }
                }
            }
            Action::CompareSnapshots(a, b) => self.spawn_snapshot_compare(a, b),
            Action::GenerateReport(_format, _scope, _path) => self.spawn_report(),
            Action::SaveSettings => self.spawn_config_save(),
            // Reaching these actions means confirmation already happened.
            Action::FirewallBlock(ip) => self.spawn_firewall_change(ip, false),
            Action::FirewallUnblock(ip) => self.spawn_firewall_change(ip, true),
            Action::SwitchNetworkTab(tab) => {
                self.state.screen = Screen::Network;
                self.state.network_tab = tab;
                self.ensure_screen_data();
            }
            Action::SwitchSecurityTab(tab) => {
                self.state.screen = Screen::Security;
                self.state.security_tab = tab;
                self.ensure_screen_data();
            }
        }
    }

    fn set_tab_for_screen(&mut self, screen: Screen, tab: usize) {
        if screen == Screen::Network {
            if let Some(tab) = NetworkTab::ALL.get(tab) {
                self.state.network_tab = *tab;
            }
        } else if screen == Screen::Security {
            if let Some(tab) = SecurityTab::ALL.get(tab) {
                self.state.security_tab = *tab;
            }
        } else if screen == Screen::Scanner {
            if let Some(tab) = ScannerTab::ALL.get(tab) {
                self.state.scanner.tab = *tab;
            }
        }
    }

    fn open_firewall_confirm(&mut self, ip: String, unblock: bool) {
        let ip = ip.trim().to_string();
        if ip.parse::<std::net::IpAddr>().is_err() {
            self.state.last_error = Some(NetroError::new(
                ErrorCode::InvalidTarget,
                format!("'{ip}' is not an IP address"),
            ));
            return;
        }
        let title = if unblock {
            format!("{} {ip}", T.fw_unblock)
        } else {
            format!("{} {ip}", T.fw_block)
        };
        self.state.overlay = Overlay::Confirm(ConfirmState {
            title,
            lines: vec![
                format!("IP: {ip}"),
                format!("Scope: {}", T.fw_this_machine),
                T.fw_scope_warning.to_string(),
                T.confirm_continue.to_string(),
            ],
            action: if unblock {
                Action::FirewallUnblock(ip)
            } else {
                Action::FirewallBlock(ip)
            },
        });
    }

    fn escape(&mut self) {
        if self.state.filtering {
            self.state.clear_filter();
            return;
        }
        if !self.state.filter.is_empty() {
            self.state.clear_filter();
            return;
        }
        if self.state.screen == Screen::Monitor {
            // Esc stops the monitor and leaves the screen so it is not
            // restarted by the auto-refresh rule.
            if let Some(id) = self.state.monitor.task {
                self.tasks.cancel(id);
                self.state.monitor.task = None;
            }
            self.state.screen = Screen::Dashboard;
            self.ensure_screen_data();
            return;
        }
        if let Some((_, id)) = self.tasks.oldest_expensive() {
            self.tasks.cancel(id);
            self.state.set_status(T.cancelled_note);
            return;
        }
        if self.state.snapshots.diff.is_some() {
            self.state.snapshots.diff = None;
            return;
        }
        if self.state.screen != Screen::Dashboard {
            self.state.screen = Screen::Dashboard;
            self.ensure_screen_data();
        }
    }

    fn start_filter(&mut self) {
        self.state.filtering = true;
        self.state.filter_target = match self.state.screen {
            Screen::Security => match self.state.security_tab {
                SecurityTab::Findings => FilterTarget::Findings,
                SecurityTab::Accounts => FilterTarget::Accounts,
                SecurityTab::Listening => FilterTarget::Listening,
                _ => FilterTarget::Screen,
            },
            Screen::Network => match self.state.network_tab {
                NetworkTab::Interfaces => FilterTarget::Interfaces,
                NetworkTab::Routes => FilterTarget::Routes,
                NetworkTab::Connections => FilterTarget::Connections,
                _ => FilterTarget::Screen,
            },
            Screen::Discovery => FilterTarget::Hosts,
            Screen::Scanner => FilterTarget::ScanPorts,
            Screen::Snapshots => FilterTarget::Snapshots,
            _ => FilterTarget::Screen,
        };
    }

    fn change_screen(&mut self, delta: i32) {
        let current = Screen::ALL
            .iter()
            .position(|s| *s == self.state.screen)
            .unwrap_or(0) as i32;
        let next = (current + delta).rem_euclid(Screen::ALL.len() as i32) as usize;
        self.state.screen = Screen::ALL[next];
        self.state.clear_filter();
        self.ensure_screen_data();
    }

    fn move_horizontal(&mut self, delta: i32) {
        match self.state.screen {
            Screen::Network => {
                let current = NetworkTab::ALL
                    .iter()
                    .position(|t| *t == self.state.network_tab)
                    .unwrap_or(0) as i32;
                let next = (current + delta).rem_euclid(NetworkTab::ALL.len() as i32) as usize;
                self.state.network_tab = NetworkTab::ALL[next];
                self.state.selected_reset();
                self.ensure_screen_data();
            }
            Screen::Security => {
                let current = SecurityTab::ALL
                    .iter()
                    .position(|t| *t == self.state.security_tab)
                    .unwrap_or(0) as i32;
                let next = (current + delta).rem_euclid(SecurityTab::ALL.len() as i32) as usize;
                self.state.security_tab = SecurityTab::ALL[next];
                self.state.selected_reset();
                self.ensure_screen_data();
            }
            Screen::Scanner => {
                // Left/Right move through the form fields; scanner tabs are
                // selected with 1/2/3 so global Tab navigation keeps working.
                let fields = 7i32;
                self.state.scanner.field =
                    ((self.state.scanner.field as i32 + delta).rem_euclid(fields)) as usize;
            }
            Screen::Reports => {
                let len = ReportsUi::FORMATS.len() as i32;
                self.state.reports.format =
                    ((self.state.reports.format as i32 + delta).rem_euclid(len)) as usize;
            }
            Screen::Settings => self.settings_horizontal(delta),
            _ => {}
        }
    }

    fn settings_horizontal(&mut self, delta: i32) {
        let row = self.state.settings.selected;
        let draft = &mut self.state.settings.draft;
        let mut changed = true;
        match row {
            0 => {
                self.state.theme_kind = self.state.theme_kind.next();
                let kind = if self.state.settings.draft.output.color == "never" {
                    ThemeKind::NoColor
                } else {
                    self.state.theme_kind
                };
                self.theme = self.theme.with_kind(kind);
            }
            1 => {
                draft.output.color = match draft.output.color.as_str() {
                    "auto" => "always".into(),
                    "always" => "never".into(),
                    _ => "auto".into(),
                };
                let kind = if draft.output.color == "never" {
                    ThemeKind::NoColor
                } else if draft.output.color == "always" {
                    ThemeKind::Dark
                } else {
                    self.state.theme_kind
                };
                self.theme = self.theme.with_kind(kind);
            }
            2 => {
                self.caps.unicode = !self.caps.unicode;
                self.theme = Theme::new(self.theme.kind, self.caps.colors, self.caps.unicode);
            }
            5 => {
                let methods = ["auto", "neighbors", "icmp", "tcp", "nmap"];
                let current = methods
                    .iter()
                    .position(|m| *m == draft.discovery.method)
                    .unwrap_or(0) as i32;
                let next = (current + delta).rem_euclid(methods.len() as i32) as usize;
                draft.discovery.method = methods[next].to_string();
            }
            9 => draft.privacy.reverse_dns = !draft.privacy.reverse_dns,
            10 => draft.privacy.vendor_lookup = !draft.privacy.vendor_lookup,
            _ => changed = false,
        }
        if changed {
            self.state.settings.dirty = true;
        }
    }

    fn move_selection(&mut self, delta: i32) {
        let len = self.current_list_len();
        if len == 0 {
            return;
        }
        let current = self.selected_index().unwrap_or(0) as i32;
        let next = (current + delta).clamp(0, len as i32 - 1) as usize;
        self.set_selected_index(next);
        if self.state.screen == Screen::Snapshots {
            self.state.snapshots.selected = next;
        }
    }

    fn select_edge(&mut self, edge: usize) {
        let len = self.current_list_len();
        if len == 0 {
            return;
        }
        let index = if edge == usize::MAX { len - 1 } else { 0 };
        self.set_selected_index(index);
    }

    fn selected_index(&self) -> Option<usize> {
        match self.state.screen {
            Screen::Dashboard => Some(self.state.dashboard_selected),
            Screen::System => Some(self.state.system_selected),
            Screen::Network => Some(self.state.network.selected),
            Screen::Discovery => Some(self.state.discovery.selected),
            Screen::Scanner => Some(self.state.scanner.selected),
            Screen::Security => Some(self.state.security_selected()),
            Screen::Doctor => Some(self.state.doctor.selected),
            Screen::Snapshots => Some(self.state.snapshots.selected),
            _ => None,
        }
    }

    fn set_selected_index(&mut self, index: usize) {
        match self.state.screen {
            Screen::Dashboard => self.state.dashboard_selected = index,
            Screen::System => self.state.system_selected = index,
            Screen::Network => self.state.network.selected = index,
            Screen::Discovery => self.state.discovery.selected = index,
            Screen::Scanner => self.state.scanner.selected = index,
            Screen::Security => self.state.set_security_selected(index),
            Screen::Doctor => self.state.doctor.selected = index,
            Screen::Snapshots => self.state.snapshots.selected = index,
            _ => {}
        }
    }

    fn current_list_len(&self) -> usize {
        match self.state.screen {
            Screen::Dashboard => self.visible_findings().len(),
            Screen::System => self.visible_processes().len(),
            Screen::Network => match self.state.network_tab {
                NetworkTab::Interfaces => self.visible_interfaces().len(),
                NetworkTab::Routes => self.visible_routes().len(),
                NetworkTab::Connections => self.visible_connections().len(),
                _ => 0,
            },
            Screen::Discovery => self
                .state
                .discovery
                .report
                .as_ref()
                .map(|r| r.hosts.len())
                .unwrap_or(0),
            Screen::Scanner => self
                .state
                .scanner
                .report
                .as_ref()
                .map(|r| r.ports.len())
                .unwrap_or(0),
            Screen::Security => self
                .state
                .security_list_len(&self.state.caches, &self.state.filter),
            Screen::Doctor => self.state.doctor.findings_len(),
            Screen::Snapshots => self.state.snapshots.list.len(),
            _ => 0,
        }
    }

    fn visible_findings(&self) -> Vec<&Finding> {
        let mut findings: Vec<&Finding> = self
            .state
            .doctor
            .findings()
            .into_iter()
            .filter(|f| self.state.filter_matches(&f.title) || self.state.filter_matches(&f.id))
            .collect();
        findings.sort_by(|a, b| b.severity.cmp(&a.severity));
        findings
    }

    fn visible_processes(&self) -> Vec<&ProcessInfo> {
        self.state
            .caches
            .processes
            .as_ref()
            .map(|fresh| {
                fresh
                    .value
                    .iter()
                    .filter(|process| {
                        self.state.filter_matches(&process.name)
                            || self
                                .state
                                .filter_matches(&process.user.clone().unwrap_or_default())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn visible_interfaces(&self) -> Vec<&Interface> {
        self.state
            .caches
            .interfaces
            .as_ref()
            .map(|fresh| {
                fresh
                    .value
                    .iter()
                    .filter(|iface| self.state.filter_matches(&iface.name))
                    .collect()
            })
            .unwrap_or_default()
    }

    fn visible_routes(&self) -> Vec<&Route> {
        self.state
            .caches
            .routes
            .as_ref()
            .map(|fresh| {
                fresh
                    .value
                    .iter()
                    .filter(|route| {
                        self.state.filter_matches(&route.destination)
                            || self
                                .state
                                .filter_matches(&route.gateway.clone().unwrap_or_default())
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn visible_connections(&self) -> Vec<&Connection> {
        self.state
            .caches
            .connections
            .as_ref()
            .map(|fresh| {
                fresh
                    .value
                    .iter()
                    .filter(|connection| {
                        self.state
                            .filter_matches(&connection.process.clone().unwrap_or_default())
                            || self
                                .state
                                .filter_matches(&connection.remote_addr.clone().unwrap_or_default())
                            || self.state.filter_matches(&connection.state)
                    })
                    .collect()
            })
            .unwrap_or_default()
    }

    fn activate(&mut self) {
        match self.state.screen {
            Screen::Dashboard => {
                let index = self.state.dashboard_selected;
                let detail = {
                    let findings = self.visible_findings();
                    findings.get(index).map(|finding| finding_detail(finding))
                };
                if let Some((title, sections)) = detail {
                    self.state.open_detail(title, sections);
                }
            }
            Screen::System => {
                if let Some(process) = self.visible_processes().get(self.state.system_selected) {
                    let detail = process_detail(process);
                    self.state.open_detail(detail.0, detail.1);
                }
            }
            Screen::Network => match self.state.network_tab {
                NetworkTab::Interfaces => {
                    if let Some(iface) = self.visible_interfaces().get(self.state.network.selected)
                    {
                        let detail = interface_detail(iface);
                        self.state.open_detail(detail.0, detail.1);
                    }
                }
                NetworkTab::Routes => {
                    if let Some(route) = self.visible_routes().get(self.state.network.selected) {
                        let detail = route_detail(route);
                        self.state.open_detail(detail.0, detail.1);
                    }
                }
                NetworkTab::Connections => {
                    if let Some(connection) =
                        self.visible_connections().get(self.state.network.selected)
                    {
                        let detail = connection_detail(connection);
                        self.state.open_detail(detail.0, detail.1);
                    }
                }
                NetworkTab::Latency => {
                    let value = self.state.network.latency_target.clone();
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.net_target.to_string(),
                        value,
                        kind: InputKind::LatencyTarget,
                    });
                }
                NetworkTab::Trace => {
                    let value = self.state.network.trace_target.clone();
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.net_target.to_string(),
                        value,
                        kind: InputKind::TraceTarget,
                    });
                }
                NetworkTab::Dns => {
                    let value = self.state.network.dns_name.clone();
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.net_query.to_string(),
                        value,
                        kind: InputKind::DnsName,
                    });
                }
                _ => {}
            },
            Screen::Discovery => {
                if let Some(host) = self
                    .state
                    .discovery
                    .report
                    .as_ref()
                    .and_then(|report| report.hosts.get(self.state.discovery.selected))
                {
                    let detail = host_detail(host);
                    self.state.open_detail(detail.0, detail.1);
                }
            }
            Screen::Scanner => match self.state.scanner.field {
                0 => {
                    let value = self.state.scanner.target.clone();
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.scan_target.to_string(),
                        value,
                        kind: InputKind::ScannerTarget,
                    });
                }
                2 => {
                    let value = self.state.scanner.custom_ports.clone();
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: "Custom ports".to_string(),
                        value,
                        kind: InputKind::ScannerPorts,
                    });
                }
                6 => {
                    self.state.scanner.authorized = !self.state.scanner.authorized;
                }
                _ => {
                    if let Some(port) = self
                        .state
                        .scanner
                        .report
                        .as_ref()
                        .and_then(|report| report.ports.get(self.state.scanner.selected))
                    {
                        let detail = scanned_port_detail(port);
                        self.state.open_detail(detail.0, detail.1);
                    }
                }
            },
            Screen::Security => self.security_activate(),
            Screen::Doctor => {
                // Enter investigates: navigate to the screen that can explain
                // the finding (spec: smart finding navigation). `i` opens the
                // detail drawer instead.
                let target = self
                    .state
                    .doctor
                    .findings()
                    .get(self.state.doctor.selected)
                    .map(|finding| finding_target(&finding.id));
                if let Some((screen, tab)) = target {
                    self.state.screen = screen;
                    if let Some(tab) = tab {
                        self.set_tab_for_screen(screen, tab);
                    }
                    self.ensure_screen_data();
                }
            }
            Screen::Snapshots => {
                if let Some((_, snap)) =
                    self.state.snapshots.list.get(self.state.snapshots.selected)
                {
                    let detail = snapshot_detail(snap);
                    self.state.open_detail(detail.0, detail.1);
                }
            }
            _ => {}
        }
    }

    fn security_activate(&mut self) {
        let tab = self.state.security_tab;
        match tab {
            SecurityTab::Findings => {
                if let Some(finding) = self
                    .state
                    .caches
                    .audit
                    .as_ref()
                    .and_then(|fresh| fresh.value.findings.get(self.state.security_selected()))
                {
                    let detail = finding_detail(finding);
                    self.state.open_detail(detail.0, detail.1);
                }
            }
            SecurityTab::Accounts => {
                if let Some(account) = self
                    .state
                    .caches
                    .audit
                    .as_ref()
                    .and_then(|fresh| fresh.value.accounts.get(self.state.security_selected()))
                {
                    let sections = vec![
                        (
                            T.sec_account.to_string(),
                            vec![
                                format!("name: {}", account.name),
                                format!(
                                    "uid: {}",
                                    account
                                        .uid
                                        .map(|u| u.to_string())
                                        .unwrap_or_else(|| "-".into())
                                ),
                                format!(
                                    "gid: {}",
                                    account
                                        .gid
                                        .map(|g| g.to_string())
                                        .unwrap_or_else(|| "-".into())
                                ),
                                format!(
                                    "home: {}",
                                    account.home.clone().unwrap_or_else(|| "-".into())
                                ),
                                format!(
                                    "shell: {}",
                                    account.shell.clone().unwrap_or_else(|| "-".into())
                                ),
                            ],
                        ),
                        (
                            "Status".to_string(),
                            vec![
                                format!("privileged: {}", account.privileged),
                                format!("system account: {}", account.is_system),
                                format!("login shell: {}", account.login_shell),
                                format!("password: {:?}", account.password),
                                format!("groups: {}", account.groups.join(", ")),
                            ],
                        ),
                    ];
                    self.state
                        .open_detail(format!("account {}", account.name), sections);
                }
            }
            SecurityTab::Listening => {
                if let Some(port) = self
                    .state
                    .caches
                    .listening
                    .as_ref()
                    .and_then(|fresh| fresh.value.get(self.state.security_selected()))
                {
                    let detail = listening_detail(port);
                    self.state.open_detail(detail.0, detail.1);
                }
            }
            SecurityTab::Firewall => {
                if let Some(rule) = self
                    .state
                    .caches
                    .rules
                    .as_ref()
                    .and_then(|fresh| fresh.value.get(self.state.security_selected()))
                {
                    self.state.open_detail(
                        "firewall rule",
                        vec![("Rule".to_string(), vec![rule.raw.clone()])],
                    );
                }
            }
            _ => {}
        }
    }

    fn screen_char(&mut self, ch: char) {
        match self.state.screen {
            Screen::System => {
                if ch == 'p' {
                    self.spawn_processes();
                }
            }
            Screen::Doctor => {
                if ch == 'i' {
                    if let Some(finding) =
                        self.state.doctor.findings().get(self.state.doctor.selected)
                    {
                        let detail = finding_detail(finding);
                        self.state.open_detail(detail.0, detail.1);
                    }
                }
            }
            Screen::Security => match (self.state.security_tab, ch) {
                (SecurityTab::Firewall, 'b') => {
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.fw_block.to_string(),
                        value: String::new(),
                        kind: InputKind::FirewallIp,
                    });
                }
                (SecurityTab::Firewall, 'u') => {
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.fw_unblock.to_string(),
                        value: String::new(),
                        kind: InputKind::FirewallIp,
                    });
                }
                (SecurityTab::Integrity, 'c') => self.spawn_integrity_baseline(),
                (SecurityTab::Integrity, 's') => self.spawn_integrity_scan(),
                (SecurityTab::External, 'x') => {
                    self.state.overlay = Overlay::Confirm(ConfirmState {
                        title: T.tab_external.to_string(),
                        lines: vec![
                            "This runs external scanners (rkhunter/chkrootkit/lynis) and can take minutes."
                                .to_string(),
                            "Results will be labelled as external tool output.".to_string(),
                            T.confirm_continue.to_string(),
                        ],
                        action: Action::RunExternalTools,
                    });
                }
                _ => {}
            },
            Screen::Scanner => match ch {
                ' ' => match self.state.scanner.field {
                    1 => {
                        self.state.scanner.profile = (self.state.scanner.profile + 1)
                            % crate::tui::state::ScanProfile::ALL.len()
                    }
                    3 => self.state.scanner.banner = !self.state.scanner.banner,
                    4 => self.state.scanner.tls = !self.state.scanner.tls,
                    5 => self.state.scanner.udp = !self.state.scanner.udp,
                    6 => self.state.scanner.authorized = !self.state.scanner.authorized,
                    _ => {}
                },
                'g' => self.spawn_scan(),
                'e' => {
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: "Export scan JSON to".to_string(),
                        value: self.state.scanner.export_path.clone(),
                        kind: InputKind::ScanExport,
                    });
                }
                '1' => self.state.scanner.tab = ScannerTab::PortScan,
                '2' => self.state.scanner.tab = ScannerTab::HostScan,
                '3' => self.state.scanner.tab = ScannerTab::Nmap,
                _ => {}
            },
            Screen::Discovery => match ch {
                'g' => self.spawn_discovery(),
                'n' => {
                    self.state.discovery.resolve_hostnames = !self.state.discovery.resolve_hostnames
                }
                'v' => self.state.discovery.vendor_lookup = !self.state.discovery.vendor_lookup,
                _ => {}
            },
            Screen::Monitor => match ch {
                'p' => self.perform(Action::TogglePause),
                '+' => self.perform(Action::MonitorIntervalDelta(1)),
                '-' => self.perform(Action::MonitorIntervalDelta(-1)),
                _ => {}
            },
            Screen::Reports => {
                if ch == 'g' {
                    self.spawn_report();
                }
            }
            Screen::Snapshots => match ch {
                'c' => {
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: T.snap_label_prompt.to_string(),
                        value: String::new(),
                        kind: InputKind::SnapshotLabel,
                    });
                }
                'm' => {
                    self.state.snapshots.marked = Some(self.state.snapshots.selected);
                    self.state.set_status("marked for comparison");
                }
                'x' => {
                    if let Some(marked) = self.state.snapshots.marked {
                        let selected = self.state.snapshots.selected;
                        self.spawn_snapshot_compare(marked, selected);
                    } else {
                        self.state
                            .set_status("press m on one snapshot, then x on another");
                    }
                }
                'd' => {
                    let index = self.state.snapshots.selected;
                    if let Some((_, snap)) = self.state.snapshots.list.get(index) {
                        let label = snap.label.clone().unwrap_or_else(|| {
                            crate::core::reporting::format_epoch(snap.created_epoch)
                        });
                        self.state.overlay = Overlay::Confirm(ConfirmState {
                            title: format!("Delete snapshot {label}"),
                            lines: vec![
                                "This deletes the snapshot file from disk.".to_string(),
                                T.confirm_continue.to_string(),
                            ],
                            action: Action::DeleteSnapshot(index),
                        });
                    }
                }
                'e' => {
                    let index = self.state.snapshots.selected;
                    self.state.overlay = Overlay::Input(InputState {
                        prompt: "Export snapshot to".to_string(),
                        value: "netro-snapshot.json".to_string(),
                        kind: InputKind::SnapshotExport,
                    });
                    let _ = index;
                }
                _ => {}
            },
            Screen::Settings => {
                if ch == 's' {
                    self.spawn_config_save();
                }
            }
            Screen::Network => {
                if ch == 'g' {
                    match self.state.network_tab {
                        NetworkTab::Latency => self.spawn_latency(),
                        NetworkTab::Trace => self.spawn_trace(),
                        NetworkTab::Dns => self.spawn_dns_query(),
                        _ => self.refresh_current(),
                    }
                }
            }
            _ => {}
        }
    }

    fn refresh_current(&mut self) {
        match self.state.screen {
            Screen::Dashboard | Screen::System => {
                self.state.caches.system = None;
                self.spawn_system();
                if self.state.screen == Screen::System {
                    self.state.caches.processes = None;
                    self.spawn_processes();
                }
            }
            Screen::Network => match self.state.network_tab {
                NetworkTab::Overview | NetworkTab::Interfaces => {
                    self.state.caches.interfaces = None;
                    self.spawn_network_basics();
                }
                NetworkTab::Routes => {
                    self.state.caches.routes = None;
                    self.spawn_routes();
                }
                NetworkTab::Dns => {
                    self.state.caches.dns = None;
                    self.spawn_dns_config();
                }
                NetworkTab::Connectivity => {
                    self.state.caches.connectivity = None;
                    self.spawn_connectivity();
                }
                NetworkTab::Connections => {
                    self.state.caches.connections = None;
                    self.spawn_connections();
                }
                _ => {}
            },
            Screen::Security => match self.state.security_tab {
                SecurityTab::Firewall => {
                    self.state.caches.firewall = None;
                    self.state.caches.rules = None;
                    self.spawn_firewall_status();
                    self.spawn_firewall_rules();
                }
                SecurityTab::Listening => {
                    self.state.caches.listening = None;
                    self.spawn_listening();
                }
                _ => {
                    self.state.caches.audit = None;
                    self.spawn_audit(false);
                }
            },
            Screen::Doctor => self.spawn_doctor(),
            Screen::Snapshots => self.reload_snapshots(),
            _ => {}
        }
    }

    fn refresh_all(&mut self) {
        self.state.caches = Caches::default();
        self.state.doctor.report = None;
        self.spawn_system();
        self.spawn_network_basics();
        self.spawn_connectivity();
        self.spawn_doctor();
        self.state.set_status("refreshing all data");
    }

    fn reload_snapshots(&mut self) {
        let list = snapshot::list();
        self.state.snapshots.list = list;
        self.state.snapshots.loaded = true;
        let len = self.state.snapshots.list.len();
        if self.state.snapshots.selected >= len {
            self.state.snapshots.selected = len.saturating_sub(1);
        }
    }

    fn ensure_screen_data(&mut self) {
        match self.state.screen {
            Screen::Dashboard => {
                self.spawn_system();
                self.spawn_network_basics();
                self.spawn_connectivity();
                if self.state.doctor.report.is_none() && !self.tasks.is_running(TaskKind::Doctor) {
                    self.spawn_doctor();
                }
            }
            Screen::System => {
                self.spawn_system();
                self.spawn_processes();
            }
            Screen::Network => match self.state.network_tab {
                NetworkTab::Overview | NetworkTab::Interfaces => self.spawn_network_basics(),
                NetworkTab::Routes => self.spawn_routes(),
                NetworkTab::Dns => self.spawn_dns_config(),
                NetworkTab::Connectivity => self.spawn_connectivity(),
                NetworkTab::Connections => self.spawn_connections(),
                _ => {}
            },
            Screen::Security => match self.state.security_tab {
                SecurityTab::Firewall => {
                    self.spawn_firewall_status();
                    self.spawn_firewall_rules();
                }
                SecurityTab::Listening => self.spawn_listening(),
                _ => self.spawn_audit(false),
            },
            Screen::Monitor => self.spawn_monitor(),
            Screen::Doctor => {
                if self.state.doctor.report.is_none() {
                    self.spawn_doctor();
                }
            }
            Screen::Snapshots => {
                if !self.state.snapshots.loaded {
                    self.reload_snapshots();
                }
            }
            _ => {}
        }
    }

    // -----------------------------------------------------------------------
    // Update loop
    // -----------------------------------------------------------------------

    pub fn update(&mut self) {
        for event in self.tasks.drain() {
            self.dirty = true;
            match event.payload {
                TaskPayload::Progress(progress) => self.apply_progress(event.kind, progress),
                TaskPayload::Done(result) => self.apply_result(event.kind, *result),
                TaskPayload::Failed(error) => self.apply_failure(event.kind, error),
            }
        }
        self.auto_refresh();
    }

    fn apply_progress(&mut self, kind: TaskKind, progress: TaskProgress) {
        match progress {
            TaskProgress::Check(check) => {
                if kind == TaskKind::Doctor
                    && !self.state.doctor.checks.iter().any(|c| c.id == check.id)
                {
                    self.state.doctor.checks.push(*check);
                }
            }
            TaskProgress::Scan(progress) => self.state.scanner.progress = Some(progress),
            TaskProgress::Discovery(progress) => self.state.discovery.progress = Some(progress),
            TaskProgress::Monitor(sample) => self.state.monitor.push_sample(*sample),
            TaskProgress::Message(_) => {}
        }
    }

    fn apply_failure(&mut self, kind: TaskKind, error: NetroError) {
        crate::log_warn!("tui task {kind:?} failed: {error}");
        match kind {
            TaskKind::Doctor => {
                self.state.doctor.running = None;
                self.state.doctor.error = Some(error);
            }
            TaskKind::Scan => {
                self.state.scanner.error = Some(error);
                self.state.scanner.progress = None;
            }
            TaskKind::Discovery => {
                self.state.discovery.error = Some(error);
                self.state.discovery.progress = None;
            }
            TaskKind::Report => self.state.reports.error = Some(error),
            TaskKind::IntegrityBaseline | TaskKind::IntegrityScan => {
                self.state.last_error = Some(error)
            }
            TaskKind::Latency => self.state.network.latency_error = Some(error),
            TaskKind::Trace => self.state.network.trace_error = Some(error),
            TaskKind::DnsQuery => self.state.network.dns_error = Some(error),
            TaskKind::SnapshotCreate => self.state.snapshots.error = Some(error),
            TaskKind::FirewallChange => self.state.last_error = Some(error),
            _ => self.state.last_error = Some(error),
        }
    }

    fn apply_result(&mut self, kind: TaskKind, result: TaskResult) {
        match result {
            TaskResult::Os(info) => self.state.caches.os = Some(Fresh::new(*info)),
            TaskResult::System(snapshot) => {
                self.state.caches.os = Some(Fresh::new(snapshot.os.clone()));
                self.state.caches.system = Some(Fresh::new(*snapshot));
            }
            TaskResult::Interfaces(interfaces) => {
                self.state.caches.interfaces = Some(Fresh::new(interfaces))
            }
            TaskResult::Routes(routes) => self.state.caches.routes = Some(Fresh::new(routes)),
            TaskResult::DnsConfig(config) => {
                self.state.caches.dns = Some(Fresh::new(*config));
            }
            TaskResult::Connectivity(report) => {
                self.state.caches.connectivity = Some(Fresh::new(*report));
            }
            TaskResult::Audit(audit) => self.state.caches.audit = Some(Fresh::new(*audit)),
            TaskResult::Doctor(report) => {
                self.state.doctor.running = None;
                self.state.doctor.error = None;
                self.state.doctor.report = Some(*report);
                self.state.caches.doctor = self.state.doctor.report.clone().map(Fresh::new);
            }
            TaskResult::Connections(connections) => {
                self.state.caches.connections = Some(Fresh::new(connections));
            }
            TaskResult::Processes(processes) => {
                self.state.caches.processes = Some(Fresh::new(processes));
            }
            TaskResult::Listening(ports) => self.state.caches.listening = Some(Fresh::new(ports)),
            TaskResult::Firewall(status) => self.state.caches.firewall = Some(Fresh::new(*status)),
            TaskResult::FirewallRules(rules) => self.state.caches.rules = Some(Fresh::new(rules)),
            TaskResult::Discovery(report) => {
                self.state.discovery.progress = None;
                let hosts = report.hosts.len();
                let cancelled = report.cancelled;
                self.state.discovery.report = Some(*report);
                self.state.discovery.selected = 0;
                self.state.set_status(if cancelled {
                    format!("discovery cancelled ({hosts} hosts found)")
                } else {
                    format!("discovery complete: {hosts} host(s)")
                });
            }
            TaskResult::Scan(report) => {
                self.state.scanner.progress = None;
                let open = report
                    .ports
                    .iter()
                    .filter(|p| p.state == PortState::Open)
                    .count();
                let cancelled = report.cancelled;
                self.state.scanner.report = Some(*report);
                self.state.scanner.selected = 0;
                self.state.set_status(if cancelled {
                    format!("scan cancelled ({open} open ports found)")
                } else {
                    format!("scan complete: {open} open port(s)")
                });
            }
            TaskResult::MonitorStopped => {
                self.state.monitor.task = None;
            }
            TaskResult::SnapshotCreated(path, snapshot) => {
                self.reload_snapshots();
                if let Some(index) = self
                    .state
                    .snapshots
                    .list
                    .iter()
                    .position(|(p, _)| *p == path)
                {
                    self.state.snapshots.selected = index;
                }
                let _ = snapshot;
                self.state
                    .set_status(format!("{} {}", T.snap_created, path.display()));
            }
            TaskResult::IntegrityBaseline(baseline) => {
                self.state.caches.baseline = Some(*baseline);
                self.state.set_status("integrity baseline created");
            }
            TaskResult::IntegrityReport(report) => {
                let changes = report
                    .changes
                    .iter()
                    .filter(|c| c.status != IntegrityStatus::Unchanged)
                    .count();
                self.state.caches.integrity_report = Some(Fresh::new(*report));
                self.state
                    .set_status(format!("integrity scan: {changes} change(s)"));
            }
            TaskResult::BaselineMissing => {
                self.state.set_status(T.integ_no_baseline);
            }
            TaskResult::ExternalTools(tools) => {
                self.state.caches.external_tools = Some(Fresh::new(tools));
                self.state.set_status("external tool scan finished");
            }
            TaskResult::ReportWritten(path, format) => {
                self.state.reports.last = Some(path.clone());
                self.state.reports.last_format = format;
                self.state
                    .set_status(format!("{} {}", T.rep_written, path.display()));
            }
            TaskResult::FirewallChanged(change) => {
                let sections = vec![
                    (
                        "Action".to_string(),
                        vec![
                            format!("{} {} via {}", change.action, change.ip, change.backend),
                            format!("applied: {}", change.applied),
                        ],
                    ),
                    ("Commands".to_string(), change.commands.clone()),
                    ("Rollback".to_string(), change.rollback.clone()),
                    (
                        "Output".to_string(),
                        vec![change.output.clone().unwrap_or_default()],
                    ),
                ];
                self.state.open_detail("firewall change", sections);
                self.state.caches.firewall = None;
                self.spawn_firewall_status();
            }
            TaskResult::Latency(result) => {
                self.state.network.latency = Some(*result);
                self.state.network.latency_error = None;
            }
            TaskResult::Trace(result) => {
                self.state.network.trace = Some(*result);
                self.state.network.trace_error = None;
            }
            TaskResult::DnsQuery(response) => {
                self.state.network.dns_query = Some(*response);
                self.state.network.dns_error = None;
            }
            TaskResult::Speedtest(result) => {
                self.state
                    .set_status(format!("speed test finished ({})", result.server));
            }
            TaskResult::ConfigSaved(path) => {
                self.state.settings.dirty = false;
                self.state.config = self.state.settings.draft.clone();
                self.state
                    .set_status(format!("{}: {}", T.set_saved, path.display()));
            }
            TaskResult::SnapshotDiff(diff) => {
                self.state.snapshots.diff = Some(*diff);
            }
            TaskResult::Exported(path) => {
                self.state
                    .set_status(format!("exported to {}", path.display()));
            }
        }
        let _ = kind;
    }

    fn auto_refresh(&mut self) {
        match self.state.screen {
            Screen::System => {
                let stale = self
                    .state
                    .caches
                    .system
                    .as_ref()
                    .map(|f| !f.is_fresh(Duration::from_secs(3)))
                    .unwrap_or(true);
                if stale {
                    self.spawn_system();
                }
                let processes_stale = self
                    .state
                    .caches
                    .processes
                    .as_ref()
                    .map(|f| !f.is_fresh(Duration::from_secs(5)))
                    .unwrap_or(true);
                if processes_stale {
                    self.spawn_processes();
                }
            }
            Screen::Network => match self.state.network_tab {
                NetworkTab::Connections => {
                    let stale = self
                        .state
                        .caches
                        .connections
                        .as_ref()
                        .map(|f| !f.is_fresh(TTL_CONNECTIONS))
                        .unwrap_or(true);
                    if stale {
                        self.spawn_connections();
                    }
                }
                NetworkTab::Overview => {
                    let stale = self
                        .state
                        .caches
                        .connectivity
                        .as_ref()
                        .map(|f| !f.is_fresh(TTL_CONNECTIVITY))
                        .unwrap_or(true);
                    if stale {
                        self.spawn_connectivity();
                    }
                }
                _ => {}
            },
            Screen::Monitor => {
                if self.state.monitor.task.is_none() {
                    self.spawn_monitor();
                }
            }
            _ => {}
        }
    }

    pub fn running(&self) -> Vec<(TaskKind, u64)> {
        self.tasks.running_kinds()
    }

    // -----------------------------------------------------------------------
    // Rendering
    // -----------------------------------------------------------------------

    pub fn render(&mut self, frame: &mut Frame) {
        let area = frame.area();
        if area.width < 40 || area.height < 12 {
            components::too_small::render(frame, area, &self.theme, &self.caps);
            return;
        }
        let ui = Ui {
            state: &self.state,
            theme: &self.theme,
            caps: &self.caps,
            tick: self.state.tick,
            running: &self.running(),
        };
        let (nav_area, main_area, status_area, footer_area) = layout(&self.caps, area);
        components::nav::render(&ui, frame, nav_area);
        components::screen(self.state.screen, &ui, frame, main_area);
        if let Some(status_area) = status_area {
            components::status::render(&ui, frame, status_area);
        }
        components::footer::render(&ui, frame, footer_area);
        if self.state.overlay.is_open() {
            components::overlays::render(&self.state.overlay, &ui, frame, area);
        }
    }
}

/// Layout breakpoints: three panes on large terminals, two on medium, a top
/// selector on small, single pane on tiny.
fn layout(caps: &Caps, area: Rect) -> (Rect, Rect, Option<Rect>, Rect) {
    use BreakpointLayout::*;
    let breakpoint = match caps.breakpoint() {
        crate::tui::caps::Breakpoint::Large => Large,
        crate::tui::caps::Breakpoint::Medium => Medium,
        crate::tui::caps::Breakpoint::Small => Small,
        crate::tui::caps::Breakpoint::Tiny => Tiny,
    };
    let footer_height = if area.height >= 16 { 2 } else { 1 };
    match breakpoint {
        Large => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(6), Constraint::Length(footer_height)])
                .split(area);
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([
                    Constraint::Length(24),
                    Constraint::Min(40),
                    Constraint::Length(28),
                ])
                .split(rows[0]);
            (columns[0], columns[1], Some(columns[2]), rows[1])
        }
        Medium => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(6), Constraint::Length(footer_height)])
                .split(area);
            let columns = Layout::default()
                .direction(Direction::Horizontal)
                .constraints([Constraint::Length(22), Constraint::Min(30)])
                .split(rows[0]);
            (columns[0], columns[1], None, rows[1])
        }
        Small => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(2),
                    Constraint::Min(4),
                    Constraint::Length(footer_height),
                ])
                .split(area);
            (rows[0], rows[1], None, rows[2])
        }
        Tiny => {
            let rows = Layout::default()
                .direction(Direction::Vertical)
                .constraints([Constraint::Min(3), Constraint::Length(1)])
                .split(area);
            (Rect::default(), rows[0], None, rows[1])
        }
    }
}

enum BreakpointLayout {
    Large,
    Medium,
    Small,
    Tiny,
}

// ---------------------------------------------------------------------------
// Command palette
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct PaletteCommand {
    pub label: &'static str,
    pub hint: &'static str,
    pub action: Action,
}

pub fn palette_commands() -> Vec<PaletteCommand> {
    vec![
        PaletteCommand {
            label: "Run Doctor",
            hint: "full diagnostics",
            action: Action::RunDoctor,
        },
        PaletteCommand {
            label: "Refresh All",
            hint: "re-probe every section",
            action: Action::RefreshAll,
        },
        PaletteCommand {
            label: "Scan Ports",
            hint: "scanner screen",
            action: Action::OpenScreen(Screen::Scanner, Some(0)),
        },
        PaletteCommand {
            label: "Discover Network",
            hint: "local subnets",
            action: Action::OpenScreen(Screen::Discovery, None),
        },
        PaletteCommand {
            label: "Security Audit",
            hint: "findings and score",
            action: Action::RunAudit,
        },
        PaletteCommand {
            label: "View Connections",
            hint: "TCP/UDP sockets",
            action: Action::SwitchNetworkTab(NetworkTab::Connections),
        },
        PaletteCommand {
            label: "View Interfaces",
            hint: "addresses and state",
            action: Action::SwitchNetworkTab(NetworkTab::Interfaces),
        },
        PaletteCommand {
            label: "Inspect DNS",
            hint: "resolver and queries",
            action: Action::SwitchNetworkTab(NetworkTab::Dns),
        },
        PaletteCommand {
            label: "Run Connectivity Checks",
            hint: "gateway/DNS/internet",
            action: Action::SwitchNetworkTab(NetworkTab::Connectivity),
        },
        PaletteCommand {
            label: "Measure Latency",
            hint: "ICMP or TCP",
            action: Action::SwitchNetworkTab(NetworkTab::Latency),
        },
        PaletteCommand {
            label: "Trace Route",
            hint: "hop by hop",
            action: Action::SwitchNetworkTab(NetworkTab::Trace),
        },
        PaletteCommand {
            label: "Open System",
            hint: "CPU, memory, storage, GPU",
            action: Action::OpenScreen(Screen::System, None),
        },
        PaletteCommand {
            label: "Start Monitor",
            hint: "live metrics",
            action: Action::StartMonitor,
        },
        PaletteCommand {
            label: "View Firewall",
            hint: "status and rules",
            action: Action::SwitchSecurityTab(SecurityTab::Firewall),
        },
        PaletteCommand {
            label: "Run Integrity Scan",
            hint: "compare against baseline",
            action: Action::SwitchSecurityTab(SecurityTab::Integrity),
        },
        PaletteCommand {
            label: "Generate Report",
            hint: "HTML/JSON/CSV/text",
            action: Action::OpenScreen(Screen::Reports, None),
        },
        PaletteCommand {
            label: "Create Snapshot",
            hint: "capture current state",
            action: Action::OpenScreen(Screen::Snapshots, None),
        },
        PaletteCommand {
            label: "Open Settings",
            hint: "appearance, privacy",
            action: Action::OpenScreen(Screen::Settings, None),
        },
        PaletteCommand {
            label: "Run External Security Tools",
            hint: "requires installation",
            action: Action::RunExternalTools,
        },
        PaletteCommand {
            label: "Quit",
            hint: "exit netro",
            action: Action::Quit,
        },
    ]
}

/// Simple case-insensitive subsequence match used by the palette and filters.
pub fn fuzzy_match(query: &str, candidate: &str) -> bool {
    if query.is_empty() {
        return true;
    }
    let query_lower = query.to_ascii_lowercase();
    let candidate_lower = candidate.to_ascii_lowercase();
    let mut query_chars = query_lower.chars().peekable();
    for ch in candidate_lower.chars() {
        if let Some(next) = query_chars.peek() {
            if *next == ch {
                query_chars.next();
            }
        }
        if query_chars.peek().is_none() {
            return true;
        }
    }
    query_chars.peek().is_none()
}

pub fn palette_matches(query: &str) -> Vec<PaletteCommand> {
    palette_commands()
        .into_iter()
        .filter(|command| fuzzy_match(query, command.label) || fuzzy_match(query, command.hint))
        .collect()
}

// ---------------------------------------------------------------------------
// Detail builders
// ---------------------------------------------------------------------------

fn interface_detail(iface: &Interface) -> (String, Vec<(String, Vec<String>)>) {
    let addresses: Vec<String> = iface
        .ipv4
        .iter()
        .map(|a| format!("{}/{} (IPv4)", a.addr, a.prefix))
        .chain(
            iface
                .ipv6
                .iter()
                .map(|a| format!("{}/{} (IPv6)", a.addr, a.prefix)),
        )
        .collect();
    (
        format!("interface {}", iface.name),
        vec![
            (
                "State".to_string(),
                vec![
                    format!("kind: {:?}", iface.kind).to_lowercase(),
                    format!("up: {}", iface.up),
                    format!(
                        "oper state: {}",
                        iface.oper_state.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!(
                        "speed: {}",
                        iface
                            .speed_mbps
                            .map(|s| format!("{s} Mbps"))
                            .unwrap_or_else(|| "-".into())
                    ),
                    format!(
                        "mtu: {}",
                        iface
                            .mtu
                            .map(|m| m.to_string())
                            .unwrap_or_else(|| "-".into())
                    ),
                ],
            ),
            ("Addresses".to_string(), addresses),
            (
                "Details".to_string(),
                vec![
                    format!("mac: {}", iface.mac.clone().unwrap_or_else(|| "-".into())),
                    format!(
                        "dhcp: {}",
                        iface
                            .dhcp
                            .map(|d| d.to_string())
                            .unwrap_or_else(|| "unknown".into())
                    ),
                    format!(
                        "dhcp source: {}",
                        iface.dhcp_source.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!(
                        "default route: {}",
                        iface.default_route.clone().unwrap_or_else(|| "-".into())
                    ),
                ],
            ),
        ],
    )
}

fn route_detail(route: &Route) -> (String, Vec<(String, Vec<String>)>) {
    (
        format!("route {}/{}", route.destination, route.prefix),
        vec![(
            "Route".to_string(),
            vec![
                format!("family: {}", route.family),
                format!(
                    "gateway: {}",
                    route.gateway.clone().unwrap_or_else(|| "-".into())
                ),
                format!(
                    "interface: {}",
                    route.interface.clone().unwrap_or_else(|| "-".into())
                ),
                format!(
                    "metric: {}",
                    route
                        .metric
                        .map(|m| m.to_string())
                        .unwrap_or_else(|| "-".into())
                ),
                format!("flags: {}", route.flags.join(", ")),
                format!("default: {}", route.is_default),
            ],
        )],
    )
}

fn listening_detail(port: &ListeningPort) -> (String, Vec<(String, Vec<String>)>) {
    let exposure = format!("{:?}", port.scope).to_lowercase();
    (
        format!("{} {}:{}", port.protocol, port.address, port.port),
        vec![(
            "Socket".to_string(),
            vec![
                format!("state: {}", port.state),
                format!("exposure: {exposure}"),
                format!(
                    "pid: {}",
                    port.pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into())
                ),
                format!(
                    "process: {}",
                    port.process.clone().unwrap_or_else(|| "-".into())
                ),
            ],
        )],
    )
}

fn process_detail(process: &ProcessInfo) -> (String, Vec<(String, Vec<String>)>) {
    (
        format!("process {} ({})", process.name, process.pid),
        vec![
            (
                "Process".to_string(),
                vec![
                    format!("pid: {}", process.pid),
                    format!(
                        "parent: {}",
                        process
                            .ppid
                            .map(|p| p.to_string())
                            .unwrap_or_else(|| "-".into())
                    ),
                    format!(
                        "user: {}",
                        process.user.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!("status: {}", process.status),
                    format!("cpu: {:.1}%", process.cpu_percent),
                    format!("memory: {}", util::human_bytes(process.memory_bytes)),
                    format!("runtime: {}", util::human_uptime(process.run_time_secs)),
                ],
            ),
            (
                "Executable".to_string(),
                vec![
                    process.exe.clone().unwrap_or_else(|| "-".into()),
                    process.cmdline.clone().unwrap_or_else(|| "-".into()),
                ],
            ),
        ],
    )
}

fn connection_detail(connection: &Connection) -> (String, Vec<(String, Vec<String>)>) {
    (
        format!(
            "{} {}:{}",
            connection.protocol, connection.local_addr, connection.local_port
        ),
        vec![(
            "Connection".to_string(),
            vec![
                format!("state: {}", connection.state),
                format!(
                    "remote: {}:{}",
                    connection.remote_addr.clone().unwrap_or_else(|| "-".into()),
                    connection
                        .remote_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into())
                ),
                format!(
                    "pid: {}",
                    connection
                        .pid
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "-".into())
                ),
                format!(
                    "process: {}",
                    connection.process.clone().unwrap_or_else(|| "-".into())
                ),
            ],
        )],
    )
}

fn finding_detail(finding: &Finding) -> (String, Vec<(String, Vec<String>)>) {
    (
        finding.title.clone(),
        vec![
            (
                "Finding".to_string(),
                vec![
                    format!("id: {}", finding.id),
                    format!("severity: {}", finding.severity),
                    format!("category: {}", finding.category),
                    format!("confidence: {:?}", finding.confidence).to_lowercase(),
                    format!("source: {:?}", finding.source).to_lowercase(),
                    format!("score impact: -{}", finding.score_impact),
                ],
            ),
            (T.sec_evidence.to_string(), finding.evidence.clone()),
            (T.sec_impact.to_string(), vec![finding.impact.clone()]),
            (
                T.sec_recommendation.to_string(),
                vec![finding.recommendation.clone()],
            ),
        ],
    )
}

fn host_detail(host: &DiscoveredHost) -> (String, Vec<(String, Vec<String>)>) {
    (
        format!("host {}", host.ip),
        vec![
            (
                "Host".to_string(),
                vec![
                    format!("ip: {}", host.ip),
                    format!(
                        "hostname: {}",
                        host.hostname.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!("mac: {}", host.mac.clone().unwrap_or_else(|| "-".into())),
                    format!(
                        "vendor: {}",
                        host.vendor.clone().unwrap_or_else(|| "unknown".into())
                    ),
                    format!(
                        "rtt: {}",
                        host.response_ms
                            .map(|r| format!("{r:.1} ms"))
                            .unwrap_or_else(|| "-".into())
                    ),
                    format!("sources: {}", host.discovery_sources.join("+")),
                ],
            ),
            (
                "Open ports".to_string(),
                if host.open_ports.is_empty() {
                    vec!["-".to_string()]
                } else {
                    host.open_ports.iter().map(|p| p.to_string()).collect()
                },
            ),
        ],
    )
}

fn scanned_port_detail(port: &ScannedPort) -> (String, Vec<(String, Vec<String>)>) {
    let mut service = Vec::new();
    service.push(format!("state: {}", port.state.as_str()));
    service.push(format!(
        "service: {}",
        port.service.clone().unwrap_or_else(|| "unknown".into())
    ));
    service.push(format!(
        "product: {}",
        port.product.clone().unwrap_or_else(|| "-".into())
    ));
    service.push(format!(
        "version: {}",
        port.version.clone().unwrap_or_else(|| "-".into())
    ));
    service.push(format!("confidence: {:?}", port.confidence).to_lowercase());
    if let Some(detection) = &port.detection {
        service.push(format!("detection: {detection}"));
    }
    let mut sections = vec![
        (
            "Port".to_string(),
            vec![
                format!("{} {}", port.port, port.protocol),
                port.state.as_str().to_string(),
            ],
        ),
        (T.scan_service.to_string(), service),
    ];
    if let Some(banner) = &port.banner {
        sections.push((T.scan_banner.to_string(), vec![banner.clone()]));
    }
    if let Some(tls) = &port.tls {
        let lines = vec![
            format!(
                "handshake: {}",
                if tls.handshake_ok { "ok" } else { "failed" }
            ),
            format!(
                "protocol: {}",
                tls.protocol_version.clone().unwrap_or_else(|| "-".into())
            ),
            format!(
                "cipher: {}",
                tls.cipher_suite.clone().unwrap_or_else(|| "-".into())
            ),
            format!(
                "subject: {}",
                tls.subject.clone().unwrap_or_else(|| "-".into())
            ),
            format!(
                "issuer: {}",
                tls.issuer.clone().unwrap_or_else(|| "-".into())
            ),
            format!(
                "valid until: {}",
                tls.not_after.clone().unwrap_or_else(|| "-".into())
            ),
            format!(
                "days remaining: {}",
                tls.days_remaining
                    .map(|d| d.to_string())
                    .unwrap_or_else(|| "-".into())
            ),
            format!(
                "self-signed: {}",
                tls.self_signed
                    .map(|v| v.to_string())
                    .unwrap_or_else(|| "unknown".into())
            ),
        ];
        sections.push(("TLS".to_string(), lines));
    }
    (format!("port {}", port.port), sections)
}

fn snapshot_detail(snap: &snapshot::Snapshot) -> (String, Vec<(String, Vec<String>)>) {
    let ports: Vec<String> = snap
        .listening
        .iter()
        .take(50)
        .map(|p| format!("{} {}:{}", p.protocol, p.address, p.port))
        .collect();
    let findings: Vec<String> = snap
        .findings
        .iter()
        .map(|f| format!("{} [{}] {}", f.severity, f.id, f.title))
        .collect();
    (
        snap.label
            .clone()
            .unwrap_or_else(|| crate::core::reporting::format_epoch(snap.created_epoch)),
        vec![
            (
                "Snapshot".to_string(),
                vec![
                    format!(
                        "created: {}",
                        crate::core::reporting::format_epoch(snap.created_epoch)
                    ),
                    format!(
                        "host: {}",
                        snap.hostname.clone().unwrap_or_else(|| "-".into())
                    ),
                    format!("os: {}", snap.os_summary),
                    format!("interfaces: {}", snap.interfaces.len()),
                    format!("routes: {}", snap.routes.len()),
                    format!("listening sockets: {}", snap.listening.len()),
                    format!("firewall enabled: {:?}", snap.firewall_enabled),
                ],
            ),
            ("Listening ports".to_string(), ports),
            ("Findings".to_string(), findings),
        ],
    )
}

/// Map a finding to the screen/tab where the user can investigate it.
pub fn finding_target(id: &str) -> (Screen, Option<usize>) {
    if id.starts_with("firewall") {
        (Screen::Security, Some(4))
    } else if id.starts_with("exposure") {
        (Screen::Security, Some(3))
    } else if id.starts_with("accounts") || id.starts_with("policy") {
        (Screen::Security, Some(2))
    } else if id.starts_with("config.ssh") {
        (Screen::Security, Some(0))
    } else if id.starts_with("health.storage") {
        (Screen::System, None)
    } else if id.starts_with("health.dns")
        || id.starts_with("health.internet")
        || id.starts_with("health.network")
        || id.starts_with("health.routes")
    {
        (Screen::Network, Some(0))
    } else if id.starts_with("health.cpu")
        || id.starts_with("health.memory")
        || id.starts_with("health.processes")
    {
        (Screen::System, None)
    } else {
        (Screen::Security, Some(1))
    }
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

pub fn run(options: TuiOptions) -> Result<()> {
    let caps = Caps::detect();
    if !caps.interactive {
        return Err(NetroError::new(
            ErrorCode::NotATerminal,
            "the TUI requires an interactive terminal",
        )
        .with_hint("use the CLI commands or --help for scriptable output"));
    }
    let (config, warnings) = Config::load();
    for warning in warnings {
        crate::log_warn!("config: {warning}");
    }
    let _guard = TerminalGuard::enter(options.mouse)?;
    let stop = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let (events, _wake) =
        crate::tui::event::spawn_input_thread(stop.clone(), Duration::from_millis(250));

    let mut app = App::new(caps, config, options);
    app.bootstrap();

    let mut terminal = ratatui::Terminal::new(CrosstermBackend::new(std::io::stdout()))
        .map_err(|e| NetroError::new(ErrorCode::Io, format!("terminal init failed: {e}")))?;

    while !app.should_quit {
        // Block for at most 50ms; draw only when something changed.
        if let Some(event) = crate::tui::event::recv_timeout(&events, Duration::from_millis(50)) {
            app.handle_event(event);
            while let Ok(event) = events.try_recv() {
                app.handle_event(event);
            }
        }
        app.update();
        if app.dirty {
            terminal
                .draw(|frame| app.render(frame))
                .map_err(|e| NetroError::new(ErrorCode::Io, format!("render failed: {e}")))?;
            app.dirty = false;
        }
    }

    app.tasks.cancel_all();
    stop.store(true, Ordering::Relaxed);
    Ok(())
}
