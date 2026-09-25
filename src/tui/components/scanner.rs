//! Scanner screen: port scan with authorization, real progress and results,
//! plus host-scan and nmap tabs that delegate to the same core engines.

use crate::tui::app::Ui;
use crate::tui::components::{checkbox, list_table};
use crate::tui::state::ScannerTab;
use crate::tui::text::T;
use crate::tui::widgets::{progress_bar, safe, spinner_frame, truncate};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    render_tabs(ui, frame, rows[0]);
    match ui.state.scanner.tab {
        ScannerTab::PortScan => port_scan(ui, frame, rows[1]),
        ScannerTab::HostScan => host_scan(ui, frame, rows[1]),
        ScannerTab::Nmap => nmap(ui, frame, rows[1]),
    }
}

fn render_tabs(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    for tab in ScannerTab::ALL {
        let selected = tab == ui.state.scanner.tab;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        spans.push(Span::styled(
            format!("{marker} {} ", tab.label()),
            if selected {
                ui.theme.selected
            } else {
                ui.theme.muted
            },
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn panel(ui: &Ui, title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {title} "), ui.theme.muted))
}

fn port_scan(ui: &Ui, frame: &mut Frame, area: Rect) {
    let form_height = 11u16.min(area.height.saturating_sub(4));
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(form_height),
            Constraint::Length(if ui.state.scanner.progress.is_some() {
                3
            } else {
                0
            }),
            Constraint::Min(4),
        ])
        .split(area);
    render_form(ui, frame, rows[0]);
    if ui.state.scanner.progress.is_some() {
        render_progress(ui, frame, rows[1]);
    }
    render_results(ui, frame, rows[2]);
}

fn render_form(ui: &Ui, frame: &mut Frame, area: Rect) {
    let profiles = crate::tui::state::ScanProfile::ALL;
    let profile = profiles
        .get(ui.state.scanner.profile)
        .map(|p| p.label())
        .unwrap_or("Common ports");
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {:<13}", T.scan_target), ui.theme.muted),
            Span::styled(
                if ui.state.scanner.target.is_empty() {
                    "(press Enter to set)".to_string()
                } else {
                    ui.state.scanner.target.clone()
                },
                ui.theme.text,
            ),
        ]),
        Line::from(vec![
            Span::styled(format!(" {:<13}", T.scan_profile), ui.theme.muted),
            Span::styled(
                format!("{} {}   (Left/Right)", ui.theme.symbols.arrow, profile),
                ui.theme.text,
            ),
        ]),
    ];
    if ui.state.scanner.profile == 2 {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<13}", "Ports"), ui.theme.muted),
            Span::styled(
                format!("{}   (press Enter to edit)", ui.state.scanner.custom_ports),
                ui.theme.text,
            ),
        ]));
    }
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<13}", "Detection"), ui.theme.muted),
        Span::styled(
            format!(
                "{} banners   {} TLS   {} UDP",
                checkbox(ui, ui.state.scanner.banner),
                checkbox(ui, ui.state.scanner.tls),
                checkbox(ui, ui.state.scanner.udp)
            ),
            ui.theme.text,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<13}", T.scan_authorization), ui.theme.muted),
        Span::styled(
            format!(
                "{} {}",
                checkbox(ui, ui.state.scanner.authorized),
                T.scan_authorization_text
            ),
            if ui.state.scanner.authorized {
                ui.theme.success
            } else {
                ui.theme.warning
            },
        ),
    ]));
    lines.push(Line::styled(
        format!("  {}", T.scan_suggest),
        ui.theme.muted,
    ));
    lines.push(Line::styled(
        format!("  {}", T.scan_public_warning),
        ui.theme.muted,
    ));
    lines.push(Line::styled(
        "  Left/Right field   Space toggle   Enter edit   g start scan   e export   1/2/3 tabs",
        ui.theme.muted,
    ));
    if let Some(error) = &ui.state.scanner.error {
        lines.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.scan_new))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_progress(ui: &Ui, frame: &mut Frame, area: Rect) {
    let Some(progress) = &ui.state.scanner.progress else {
        return;
    };
    let spinner = spinner_frame(ui.theme, ui.tick);
    let mut bar = progress_bar(ui.theme, progress.completed, progress.total, 30);
    bar.spans.insert(0, Span::raw("  "));
    bar.spans
        .push(Span::styled("   Esc cancel", ui.theme.muted));
    frame.render_widget(
        Paragraph::new(vec![
            Line::from(vec![
                Span::styled(format!(" {spinner} "), ui.theme.accent),
                Span::styled(
                    format!("scanning {} ({})", ui.state.scanner.target, T.scan_title),
                    ui.theme.text,
                ),
            ]),
            bar,
        ]),
        area,
    );
}

fn render_results(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, "RESULTS");
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(report) = &ui.state.scanner.report else {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if ui.state.scanner.progress.is_some() {
                    T.loading
                } else {
                    "no scan yet"
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = report
        .ports
        .iter()
        .filter(|port| {
            filter.is_empty()
                || port.port.to_string().contains(&filter)
                || port
                    .service
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
        })
        .map(|port| {
            let service = match (&port.service, &port.product, &port.version) {
                (Some(service), Some(product), Some(version)) => {
                    format!("{} ({} {})", safe(service), safe(product), safe(version))
                }
                (Some(service), Some(product), None) => {
                    format!("{} ({})", safe(service), safe(product))
                }
                (Some(service), None, _) => safe(service),
                _ => "-".into(),
            };
            let state_style = match port.state {
                crate::model::PortState::Open => "open",
                crate::model::PortState::Closed => "closed",
                crate::model::PortState::Filtered => "filtered",
                crate::model::PortState::OpenOrFiltered => "open|filtered",
            };
            vec![
                port.port.to_string(),
                port.protocol.clone(),
                state_style.to_string(),
                service,
                port.banner
                    .clone()
                    .map(|b| truncate(&safe(&b), 40, ui.theme))
                    .unwrap_or_else(|| "-".into()),
                port.tls
                    .as_ref()
                    .map(|tls| {
                        if tls.handshake_ok {
                            safe(&tls.protocol_version.clone().unwrap_or_else(|| "TLS".into()))
                        } else {
                            "failed".into()
                        }
                    })
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if report.ports.is_empty() {
                    "no ports probed"
                } else {
                    T.empty_filtered
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &["Port", "Proto", "State", "Service", "Banner", "TLS"],
            rows,
            Some(ui.state.scanner.selected),
            &[
                Constraint::Length(6),
                Constraint::Length(6),
                Constraint::Length(13),
                Constraint::Min(16),
                Constraint::Min(12),
                Constraint::Length(9),
            ],
        ),
        inner,
    );
}

fn host_scan(ui: &Ui, frame: &mut Frame, area: Rect) {
    let lines = vec![
        Line::styled(
            "Host discovery runs on the Discovery screen.".to_string(),
            ui.theme.text,
        ),
        Line::styled(
            "It uses the same core engine (neighbor table / ICMP / TCP probes / nmap).".to_string(),
            ui.theme.muted,
        ),
        Line::from(""),
        Line::styled(
            "Press Tab to reach Discovery, or use the command palette (Ctrl+P).".to_string(),
            ui.theme.muted,
        ),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.tab_host_scan))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn nmap(ui: &Ui, frame: &mut Frame, area: Rect) {
    let installed = crate::util::which("nmap").is_some();
    let mut lines = Vec::new();
    if installed {
        lines.push(Line::styled(
            "nmap is installed. Host discovery can use it as a method.".to_string(),
            ui.theme.success,
        ));
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "The Discovery screen offers method 'nmap' (Left/Right to select).".to_string(),
            ui.theme.muted,
        ));
        lines.push(Line::styled(
            "netro parses nmap -sn grepable output; it never builds shell strings.".to_string(),
            ui.theme.muted,
        ));
    } else {
        lines.push(Line::styled(
            "nmap is not installed.".to_string(),
            ui.theme.warning,
        ));
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "Basic discovery works without nmap (neighbor table, ICMP, TCP probes).".to_string(),
            ui.theme.muted,
        ));
        lines.push(Line::styled(
            "Install nmap to enable the nmap method; netro detects it automatically.".to_string(),
            ui.theme.muted,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.tab_nmap))
            .wrap(Wrap { trim: false }),
        area,
    );
}
