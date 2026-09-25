//! Deterministic TUI rendering tests using ratatui's `TestBackend`.
//!
//! Snapshots are intentional: run with `INSTA_UPDATE=always` only when the
//! visual change is reviewed (see docs/TUI.md).

mod common;

use common::{empty_app, fixture_app, fixture_diff, render_app};
use netro::tui::state::{
    ConfirmState, DetailState, InputKind, InputState, NetworkTab, Overlay, PaletteState, Screen,
    SecurityTab,
};

/// Assert a snapshot after normalizing environment-dependent content.
/// Timestamps render in the local timezone, so they are replaced with a token
/// to keep snapshots identical on every platform and timezone.
fn assert_render(name: &str, output: String) {
    insta::with_settings!({filters => vec![
        (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} [+-]\d{4}", "<TIMESTAMP>"),
        (r"\d{4}-\d{2}-\d{2} \d{2}:\d{2}", "<DATETIME>"),
    ]}, {
        insta::assert_snapshot!(name, output);
    });
}

const SIZES: [(u16, u16); 6] = [
    (40, 12),
    (60, 20),
    (80, 24),
    (100, 30),
    (120, 32),
    (160, 45),
];

#[test]
fn dashboard_at_all_required_sizes() {
    for (width, height) in SIZES {
        let mut app = fixture_app(width, height);
        let output = render_app(&mut app, width, height);
        assert_render(&format!("dashboard_{width}x{height}"), output);
    }
}

#[test]
fn every_screen_at_100x30() {
    let screens = [
        (Screen::System, "system"),
        (Screen::Network, "network"),
        (Screen::Discovery, "discovery"),
        (Screen::Scanner, "scanner"),
        (Screen::Security, "security"),
        (Screen::Monitor, "monitor"),
        (Screen::Doctor, "doctor"),
        (Screen::Reports, "reports"),
        (Screen::Snapshots, "snapshots"),
        (Screen::Settings, "settings"),
    ];
    for (screen, name) in screens {
        let mut app = fixture_app(100, 30);
        app.state.screen = screen;
        let output = render_app(&mut app, 100, 30);
        assert_render(&format!("screen_{name}_100x30"), output);
    }
}

#[test]
fn network_tabs_render() {
    for tab in NetworkTab::ALL {
        let mut app = fixture_app(100, 30);
        app.state.screen = Screen::Network;
        app.state.network_tab = tab;
        let output = render_app(&mut app, 100, 30);
        let name = format!("network_{:?}", tab).to_lowercase();
        assert_render(&format!("network_tab_{name}"), output);
    }
}

#[test]
fn security_tabs_render() {
    for tab in SecurityTab::ALL {
        let mut app = fixture_app(100, 30);
        app.state.screen = Screen::Security;
        app.state.security_tab = tab;
        let output = render_app(&mut app, 100, 30);
        let name = format!("{:?}", tab).to_lowercase();
        assert_render(&format!("security_tab_{name}"), output);
    }
}

#[test]
fn scanner_tabs_render() {
    use netro::tui::state::ScannerTab;
    for tab in ScannerTab::ALL {
        let mut app = fixture_app(100, 30);
        app.state.screen = Screen::Scanner;
        app.state.scanner.tab = tab;
        let output = render_app(&mut app, 100, 30);
        let name = format!("{:?}", tab).to_lowercase();
        assert_render(&format!("scanner_tab_{name}"), output);
    }
}

#[test]
fn overlays_render() {
    let mut app = fixture_app(100, 30);

    app.state.overlay = Overlay::Help;
    assert_render("overlay_help", render_app(&mut app, 100, 30));

    app.state.overlay = Overlay::Palette(PaletteState {
        query: "scan".into(),
        selected: 0,
    });
    assert_render("overlay_palette", render_app(&mut app, 100, 30));

    app.state.overlay = Overlay::Confirm(ConfirmState {
        title: "Block 192.168.1.15".into(),
        lines: vec![
            "IP: 192.168.1.15".into(),
            "Scope: This machine".into(),
            "This changes the firewall of THIS machine only. It does NOT disconnect the device from the router.".into(),
            "Continue?".into(),
        ],
        action: netro::tui::action::Action::FirewallBlock("192.168.1.15".into()),
    });
    assert_render("overlay_confirm", render_app(&mut app, 100, 30));

    app.state.overlay = Overlay::Input(InputState {
        prompt: "Target".into(),
        value: "192.168.1.0/24".into(),
        kind: InputKind::DiscoveryTarget,
    });
    assert_render("overlay_input", render_app(&mut app, 100, 30));

    app.state.overlay = Overlay::Error(
        netro::error::NetroError::new(
            netro::error::ErrorCode::PermissionDenied,
            "blocking traffic requires root on Linux",
        )
        .with_hint("run the command with sudo, or as root"),
    );
    assert_render("overlay_error", render_app(&mut app, 100, 30));

    app.state.overlay = Overlay::Detail(DetailState {
        title: "port 443".into(),
        sections: vec![
            (
                "Port".to_string(),
                vec!["443 tcp".to_string(), "open".to_string()],
            ),
            (
                "Service".to_string(),
                vec!["https/tls".to_string(), "nginx 1.24.0".to_string()],
            ),
            (
                "TLS".to_string(),
                vec!["handshake: ok".to_string(), "protocol: TLSv1.3".to_string()],
            ),
        ],
        scroll: 0,
    });
    assert_render("overlay_detail", render_app(&mut app, 100, 30));
}

#[test]
fn snapshot_diff_renders() {
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Snapshots;
    app.state.snapshots.diff = Some(fixture_diff());
    assert_render("snapshots_diff", render_app(&mut app, 100, 30));
}

#[test]
fn empty_states_render_with_guidance() {
    let mut app = empty_app(80, 24);
    app.state.screen = Screen::System;
    let output = render_app(&mut app, 80, 24);
    assert!(output.contains("Loading") || output.contains("No "));
    assert_render("empty_system_80x24", output);

    let mut app = empty_app(80, 24);
    app.state.screen = Screen::Network;
    app.state.network_tab = NetworkTab::Interfaces;
    let output = render_app(&mut app, 80, 24);
    assert_render("empty_network_80x24", output);

    let mut app = empty_app(80, 24);
    app.state.screen = Screen::Snapshots;
    let output = render_app(&mut app, 80, 24);
    assert_render("empty_snapshots_80x24", output);
}

#[test]
fn too_small_terminal_shows_guidance() {
    let mut app = fixture_app(30, 8);
    let output = render_app(&mut app, 30, 8);
    assert!(output.contains("Terminal too small"));
    assert_render("too_small_30x8", output);
}

#[test]
fn no_color_theme_renders_without_panicking() {
    use netro::tui::caps::{Caps, ColorMode};
    use netro::tui::theme::ThemeKind;
    let caps = Caps {
        width: 80,
        height: 24,
        colors: ColorMode::None,
        unicode: false,
        mouse: false,
        interactive: true,
    };
    let mut app = netro::tui::app::App::new(
        caps,
        netro::config::Config::default(),
        netro::tui::app::TuiOptions {
            mouse: false,
            theme: Some(ThemeKind::NoColor),
        },
    );
    app.state.screen = Screen::Dashboard;
    let output = render_app(&mut app, 80, 24);
    assert!(!output.is_empty());
}

#[test]
fn hostile_strings_are_sanitized_in_rendering() {
    // A service banner with ANSI escapes must not reach the terminal buffer.
    let mut app = fixture_app(100, 30);
    app.state.screen = Screen::Scanner;
    if let Some(report) = app.state.scanner.report.as_mut() {
        report.ports[0].banner = Some("SSH-2.0-\x1b[31mEvil\x1b[0m".into());
    }
    let output = render_app(&mut app, 100, 30);
    assert!(
        !output.contains('\x1b'),
        "escape sequence leaked into the UI"
    );

    // Detail drawers sanitize every entry.
    app.state.overlay = Overlay::Detail(DetailState {
        title: "hostile".into(),
        sections: vec![(
            "Evidence".to_string(),
            vec!["\x1b]0;owned\x07 0.0.0.0:22 LISTEN".to_string()],
        )],
        scroll: 0,
    });
    let output = render_app(&mut app, 100, 30);
    assert!(!output.contains('\x1b'));
    assert!(!output.contains("owned"));
}
