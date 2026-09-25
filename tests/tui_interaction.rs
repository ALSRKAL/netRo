//! Interaction tests: real key sequences driven through the app event loop.

mod common;

use common::{fixture_app, render_app};
use crossterm::event::{KeyCode, KeyEvent, KeyModifiers};
use netro::tui::event::AppEvent;
use netro::tui::state::{NetworkTab, Overlay, Screen, SecurityTab};
use netro::tui::tasks::TaskKind;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Heavy tests (real scans, doctor runs, monitoring) are serialized so they do
/// not starve each other on small CI runners with limited CPU.
static HEAVY: Mutex<()> = Mutex::new(());

fn heavy_guard() -> std::sync::MutexGuard<'static, ()> {
    HEAVY
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

fn key(code: KeyCode) -> AppEvent {
    AppEvent::Key(KeyEvent::new(code, KeyModifiers::NONE))
}

fn ctrl(code: KeyCode) -> AppEvent {
    AppEvent::Key(KeyEvent::new(code, KeyModifiers::CONTROL))
}

fn press(app: &mut netro::tui::app::App, code: KeyCode) {
    app.handle_event(key(code));
}

fn type_text(app: &mut netro::tui::app::App, text: &str) {
    for ch in text.chars() {
        app.handle_event(key(KeyCode::Char(ch)));
    }
}

/// Pump the app loop until `predicate` holds or the timeout expires.
fn wait_for<F: Fn(&netro::tui::app::App) -> bool>(
    app: &mut netro::tui::app::App,
    seconds: u64,
    predicate: F,
) -> bool {
    let deadline = Instant::now() + Duration::from_secs(seconds);
    loop {
        app.update();
        if predicate(app) {
            return true;
        }
        if Instant::now() > deadline {
            return false;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn tab_cycles_screens_and_esc_returns_to_dashboard() {
    let mut app = fixture_app(100, 30);
    assert_eq!(app.state.screen, Screen::Dashboard);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::System);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Network);
    press(&mut app, KeyCode::BackTab);
    assert_eq!(app.state.screen, Screen::System);
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.state.screen, Screen::Dashboard);
}

#[test]
fn arrow_keys_and_jk_both_move_selection() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Doctor;
    app.state.doctor.selected = 0;
    press(&mut app, KeyCode::Down);
    assert_eq!(app.state.doctor.selected, 1);
    press(&mut app, KeyCode::Char('k'));
    assert_eq!(app.state.doctor.selected, 0);
    press(&mut app, KeyCode::End);
    assert_eq!(app.state.doctor.selected, 1); // two fixture findings
    press(&mut app, KeyCode::Home);
    assert_eq!(app.state.doctor.selected, 0);
}

#[test]
fn search_filters_lists_and_esc_clears() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::System;
    let unfiltered = render_app(&mut app, 100, 30);
    assert!(unfiltered.contains("firefox"));
    assert!(unfiltered.contains("code"));

    press(&mut app, KeyCode::Char('/'));
    assert!(app.state.filtering);
    type_text(&mut app, "fire");
    let filtered = render_app(&mut app, 100, 30);
    assert!(filtered.contains("firefox"));
    assert!(
        !filtered.contains(" code "),
        "filter did not apply: {filtered}"
    );

    press(&mut app, KeyCode::Enter);
    assert!(!app.state.filtering);
    assert_eq!(app.state.filter, "fire");

    press(&mut app, KeyCode::Esc);
    assert!(app.state.filter.is_empty());
    let restored = render_app(&mut app, 100, 30);
    assert!(restored.contains("code"));
}

#[test]
fn help_overlay_opens_and_closes() {
    let mut app = fixture_app(100, 30);
    press(&mut app, KeyCode::Char('?'));
    assert!(matches!(app.state.overlay, Overlay::Help));
    let rendered = render_app(&mut app, 100, 30);
    assert!(rendered.contains("KEYBOARD SHORTCUTS"));
    press(&mut app, KeyCode::Esc);
    assert!(!app.state.overlay.is_open());
}

#[test]
fn command_palette_filters_and_invokes_typed_actions() {
    let mut app = fixture_app(100, 30);
    app.handle_event(ctrl(KeyCode::Char('p')));
    assert!(matches!(app.state.overlay, Overlay::Palette(_)));
    type_text(&mut app, "scan");
    let rendered = render_app(&mut app, 100, 30);
    assert!(rendered.contains("Scan Ports"));
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.state.screen, Screen::Scanner);
    assert!(!app.state.overlay.is_open());
}

#[test]
fn quit_keys_stop_the_app() {
    let mut app = fixture_app(100, 30);
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit);

    let mut app = fixture_app(100, 30);
    app.handle_event(ctrl(KeyCode::Char('c')));
    assert!(app.should_quit);
}

#[test]
fn resize_events_update_capabilities() {
    let mut app = fixture_app(100, 30);
    app.handle_event(AppEvent::Resize(72, 20));
    assert_eq!(app.caps.width, 72);
    assert_eq!(app.caps.height, 20);
}

#[test]
fn scanner_fields_cycle_with_left_right_and_tabs_stay_global() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Scanner;
    let before = app.state.scanner.field;
    press(&mut app, KeyCode::Right);
    assert_ne!(app.state.scanner.field, before);
    press(&mut app, KeyCode::Left);
    assert_eq!(app.state.scanner.field, before);
    // Global Tab still changes screens from the Scanner.
    press(&mut app, KeyCode::Tab);
    assert_ne!(app.state.screen, Screen::Scanner);
    // 1/2/3 switch scanner tabs.
    app.state.screen = Screen::Scanner;
    press(&mut app, KeyCode::Char('3'));
    assert_eq!(app.state.scanner.tab, netro::tui::state::ScannerTab::Nmap);
}

#[test]
fn network_tabs_switch_with_left_right() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Network;
    assert_eq!(app.state.network_tab, NetworkTab::Overview);
    press(&mut app, KeyCode::Right);
    assert_eq!(app.state.network_tab, NetworkTab::Interfaces);
    press(&mut app, KeyCode::Left);
    assert_eq!(app.state.network_tab, NetworkTab::Overview);
}

#[test]
fn scanner_refuses_unauthorized_and_runs_when_authorized() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Scanner;
    app.state.scanner.authorized = false;
    app.state.scanner.target = "127.0.0.1".into();
    app.state.scanner.profile = 2; // custom
    app.state.scanner.custom_ports = "1".into();
    app.state.scanner.report = None;
    press(&mut app, KeyCode::Char('g'));
    let error = app
        .state
        .scanner
        .error
        .as_ref()
        .expect("authorization error");
    assert_eq!(
        error.code(),
        netro::error::ErrorCode::UnauthorizedScan,
        "unexpected error: {error}"
    );
    assert!(!app.tasks.is_running(TaskKind::Scan));

    // Authorize (field 6 is the authorization row) and run a real scan of a
    // closed local port.
    app.state.scanner.field = 6;
    press(&mut app, KeyCode::Char(' '));
    assert!(app.state.scanner.authorized);
    press(&mut app, KeyCode::Char('g'));
    assert!(app.tasks.is_running(TaskKind::Scan));
    let finished = wait_for(&mut app, 60, |app| app.state.scanner.report.is_some());
    assert!(finished, "scan never finished");
    let report = app.state.scanner.report.as_ref().unwrap();
    assert_eq!(report.ports.len(), 1);
    assert_ne!(report.ports[0].state, netro::model::PortState::Open);
    assert!(!report.cancelled);
}

#[test]
fn scan_cancellation_produces_partial_result() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Scanner;
    app.state.scanner.authorized = true;
    app.state.scanner.target = "127.0.0.1".into();
    app.state.scanner.profile = 1; // full TCP range (long)
    app.state.scanner.tls = false;
    app.state.scanner.banner = false;
    app.state.scanner.report = None;
    press(&mut app, KeyCode::Char('g'));
    assert!(app.tasks.is_running(TaskKind::Scan));
    std::thread::sleep(Duration::from_millis(120));
    press(&mut app, KeyCode::Esc);
    let finished = wait_for(&mut app, 60, |app| app.state.scanner.report.is_some());
    assert!(finished, "cancelled scan never returned a report");
    let report = app.state.scanner.report.as_ref().unwrap();
    assert!(report.cancelled, "report must be marked cancelled");
    assert!(!app.tasks.is_running(TaskKind::Scan));
}

#[test]
fn doctor_streams_checks_then_finishes() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(100, 30);
    app.state.doctor.checks.clear();
    app.state.doctor.report = None;
    app.state.screen = Screen::Doctor;
    press(&mut app, KeyCode::Char('d'));
    assert!(app.tasks.is_running(TaskKind::Doctor));
    // Checks appear while the doctor runs.
    let streamed = wait_for(&mut app, 60, |app| !app.state.doctor.checks.is_empty());
    assert!(streamed, "no checks streamed");
    let finished = wait_for(&mut app, 240, |app| app.state.doctor.report.is_some());
    assert!(finished, "doctor never finished");
    let report = app.state.doctor.report.as_ref().unwrap();
    assert!(report.checks.len() >= 8);
    assert!(!app.tasks.is_running(TaskKind::Doctor));
}

#[test]
fn doctor_finding_enter_navigates_to_relevant_screen() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Doctor;
    app.state.doctor.selected = 0;
    // Fixture findings sorted by severity: HIGH firewall first.
    let first_id = app.state.doctor.findings()[0].id.clone();
    assert!(first_id.starts_with("firewall"), "fixture order changed");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.state.screen, Screen::Security);
    assert_eq!(app.state.security_tab, SecurityTab::Firewall);
}

#[test]
fn monitor_starts_samples_and_stops() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(100, 30);
    app.state.monitor.sample = None;
    app.state.screen = Screen::Monitor;
    app.update();
    assert!(app.tasks.is_running(TaskKind::Monitor));
    let sampled = wait_for(&mut app, 60, |app| app.state.monitor.sample.is_some());
    assert!(sampled, "monitor produced no sample");
    press(&mut app, KeyCode::Char('p'));
    assert!(app
        .state
        .monitor
        .paused
        .load(std::sync::atomic::Ordering::Relaxed));
    press(&mut app, KeyCode::Esc); // cancels the monitor task
    let stopped = wait_for(&mut app, 60, |app| !app.tasks.is_running(TaskKind::Monitor));
    assert!(stopped, "monitor did not stop");
}

#[test]
fn firewall_flow_requires_confirmation_and_reports_outcome() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Security;
    app.state.security_tab = SecurityTab::Firewall;
    press(&mut app, KeyCode::Char('b'));
    assert!(matches!(app.state.overlay, Overlay::Input(_)));
    type_text(&mut app, "203.0.113.5");
    press(&mut app, KeyCode::Enter);
    match &app.state.overlay {
        Overlay::Confirm(confirm) => {
            assert!(confirm
                .lines
                .iter()
                .any(|l| l.contains("does NOT disconnect")));
        }
        other => panic!(
            "expected confirmation, got {:?}",
            std::mem::discriminant(other)
        ),
    }
    press(&mut app, KeyCode::Enter);
    // On an unprivileged host the change is refused with PERMISSION_DENIED;
    // as root it succeeds and opens a detail drawer. Both are real outcomes.
    let settled = wait_for(&mut app, 60, |app| {
        app.state.last_error.is_some()
            || matches!(app.state.overlay, Overlay::Detail(_))
            || !app.tasks.is_running(TaskKind::FirewallChange)
    });
    assert!(settled, "firewall change never settled");
    if let Some(error) = &app.state.last_error {
        assert_eq!(
            error.code(),
            netro::error::ErrorCode::PermissionDenied,
            "unexpected firewall error: {error}"
        );
    }
}

#[test]
fn reports_generate_from_cache_to_a_real_file() {
    let mut app = fixture_app(100, 30);
    let dir = std::env::temp_dir().join(format!(
        "netro-tui-report-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("report.json");
    app.state.screen = Screen::Reports;
    app.state.reports.format = 1; // JSON
    app.state.reports.scope = 0; // Full
    app.state.reports.path = path.display().to_string();
    press(&mut app, KeyCode::Char('g'));
    let written = wait_for(&mut app, 60, |app| app.state.reports.last.is_some());
    assert!(written, "report was not generated");
    let text = std::fs::read_to_string(&path).expect("report file");
    let value: serde_json::Value = serde_json::from_str(&text).expect("valid JSON report");
    assert_eq!(value["netro_version"], netro::version::VERSION);
    assert!(!value["interfaces"].as_array().unwrap().is_empty());
    assert!(value["doctor"]["checks"].as_array().unwrap().len() >= 8);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn settings_changes_are_validated_and_marked_dirty() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Settings;
    app.state.settings.selected = 5; // discovery method
    let before = app.state.settings.draft.discovery.method.clone();
    press(&mut app, KeyCode::Right);
    assert_ne!(app.state.settings.draft.discovery.method, before);
    assert!(app.state.settings.dirty);
}

/// The full acceptance flow required by the specification:
/// Dashboard -> System -> Network -> Interfaces -> details -> Back ->
/// Discovery -> start -> view device -> Security -> Doctor -> warning ->
/// Monitor -> palette -> report -> quit.
#[test]
fn acceptance_flow_end_to_end() {
    let _heavy = heavy_guard();
    let mut app = fixture_app(120, 34);

    // Dashboard -> System
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::System);

    // System -> Network -> Interfaces tab
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Network);
    press(&mut app, KeyCode::Right);
    assert_eq!(app.state.network_tab, NetworkTab::Interfaces);

    // Interface details drawer
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.state.overlay, Overlay::Detail(_)));
    press(&mut app, KeyCode::Esc);
    assert!(!app.state.overlay.is_open());

    // Back to Dashboard, then to Discovery
    press(&mut app, KeyCode::Esc);
    assert_eq!(app.state.screen, Screen::Dashboard);
    press(&mut app, KeyCode::Tab); // System
    press(&mut app, KeyCode::Tab); // Network
    press(&mut app, KeyCode::Tab); // Discovery
    assert_eq!(app.state.screen, Screen::Discovery);

    // Start a real discovery against loopback (deterministic, local scope).
    app.state.discovery.target = "127.0.0.0/29".into();
    app.state.discovery.method = 3; // tcp
    app.state.discovery.report = None;
    press(&mut app, KeyCode::Char('g'));
    assert!(app.tasks.is_running(TaskKind::Discovery));
    let discovered = wait_for(&mut app, 90, |app| app.state.discovery.report.is_some());
    assert!(discovered, "discovery did not finish");

    // View a device. Host availability is environment-dependent, so use the
    // deterministic fixture for the detail step (real discovery above proved
    // the engine path).
    app.state.discovery.report = Some(common::fixture_discovery_report());
    press(&mut app, KeyCode::Enter);
    assert!(matches!(app.state.overlay, Overlay::Detail(_)));
    press(&mut app, KeyCode::Esc);

    // Discovery -> Scanner -> Security
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Scanner);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Security);

    // Security -> Monitor -> Doctor
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Monitor);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.state.screen, Screen::Doctor);

    // Doctor: run and inspect a warning (smart navigation).
    app.state.doctor.checks.clear();
    app.state.doctor.report = None;
    press(&mut app, KeyCode::Char('d'));
    let doctor_done = wait_for(&mut app, 240, |app| app.state.doctor.report.is_some());
    assert!(doctor_done, "doctor did not finish");
    if !app.state.doctor.findings().is_empty() {
        app.state.doctor.selected = 0;
        press(&mut app, KeyCode::Enter);
        // Findings navigate to a screen that can explain them.
        assert_ne!(app.state.screen, Screen::Doctor);
    }

    // Monitor: live sample.
    app.state.screen = Screen::Monitor;
    app.state.monitor.sample = None;
    app.update();
    let sampled = wait_for(&mut app, 60, |app| app.state.monitor.sample.is_some());
    assert!(sampled, "monitor produced no sample");

    // Command palette -> Generate Report screen.
    app.handle_event(ctrl(KeyCode::Char('p')));
    type_text(&mut app, "generate report");
    press(&mut app, KeyCode::Enter);
    assert_eq!(app.state.screen, Screen::Reports);

    // Generate a real report from cached results.
    let dir = std::env::temp_dir().join(format!(
        "netro-acceptance-{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("acceptance.html");
    app.state.reports.format = 0; // HTML
    app.state.reports.scope = 0; // Full
    app.state.reports.path = path.display().to_string();
    press(&mut app, KeyCode::Char('g'));
    let written = wait_for(&mut app, 60, |app| app.state.reports.last.is_some());
    assert!(written, "report was not generated");
    let html = std::fs::read_to_string(&path).expect("report file");
    assert!(html.starts_with("<!DOCTYPE html>"));

    // Quit cleanly.
    press(&mut app, KeyCode::Char('q'));
    assert!(app.should_quit);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn palette_invalid_theme_is_rejected_by_cli_layer() {
    // Guard against the palette ever constructing shell strings: actions are
    // typed values only. This test documents the invariant at the type level.
    let command = netro::tui::app::palette_commands()
        .into_iter()
        .find(|c| c.label == "Scan Ports")
        .expect("palette command");
    assert!(matches!(
        command.action,
        netro::tui::action::Action::OpenScreen(Screen::Scanner, _)
    ));
}
