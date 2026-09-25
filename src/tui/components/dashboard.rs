//! Dashboard: the default screen. Composes cached results only — no probes are
//! started by rendering.

use crate::tui::app::Ui;
use crate::tui::components::status_symbol;
use crate::tui::text::T;
use crate::tui::theme::UiStatus;
use crate::tui::widgets::gauge_line;
use crate::util;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(5),
            Constraint::Min(10),
            Constraint::Length(7),
        ])
        .split(area);

    render_overview(ui, frame, rows[0]);
    render_middle(ui, frame, rows[1]);
    render_findings(ui, frame, rows[2]);
}

fn render_overview(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.dash_overview),
            ui.theme.muted,
        ));
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.os {
        Some(os) => {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_host), ui.theme.muted),
                Span::styled(
                    os.value
                        .hostname
                        .clone()
                        .unwrap_or_else(|| "unknown".into()),
                    ui.theme.title,
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_os), ui.theme.muted),
                Span::styled(
                    format!(
                        "{} {}",
                        os.value
                            .long_name
                            .clone()
                            .or(os.value.name.clone())
                            .unwrap_or_else(|| "unknown".into()),
                        os.value.version.clone().unwrap_or_default()
                    ),
                    ui.theme.text,
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_kernel), ui.theme.muted),
                Span::styled(
                    os.value.kernel.clone().unwrap_or_else(|| "unknown".into()),
                    ui.theme.text,
                ),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_uptime), ui.theme.muted),
                Span::styled(util::human_uptime(os.value.uptime_secs), ui.theme.text),
            ]));
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_middle(ui: &Ui, frame: &mut Frame, area: Rect) {
    if area.width >= 90 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        render_health(ui, frame, columns[0]);
        render_network_and_resources(ui, frame, columns[1]);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
            .split(area);
        render_health(ui, frame, rows[0]);
        render_network_and_resources(ui, frame, rows[1]);
    }
}

fn render_health(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.dash_health), ui.theme.muted));
    let mut lines: Vec<Line> = Vec::new();
    let checks = if let Some(report) = &ui.state.doctor.report {
        report.checks.clone()
    } else {
        ui.state.doctor.checks.clone()
    };
    let expected = [
        ("system", "System"),
        ("cpu", "CPU"),
        ("memory", "Memory"),
        ("storage", "Storage"),
        ("gpu", "GPU"),
        ("network", "Network"),
        ("routes", "Routes"),
        ("dns", "DNS"),
        ("internet", "Internet"),
        ("firewall", "Firewall"),
        ("processes", "Processes"),
        ("security", "Security"),
    ];
    // Two-column grid keeps the dashboard readable on short terminals.
    let running =
        ui.is_running(crate::tui::tasks::TaskKind::Doctor) || ui.state.doctor.is_running();
    let cell = |id: &str, label: &str| -> Vec<Span<'static>> {
        match checks.iter().find(|c| c.id == id) {
            Some(check) => vec![
                Span::styled(format!(" {:<10}", label), ui.theme.text),
                status_symbol(ui, UiStatus::from_check(check.status)),
            ],
            None if running => vec![
                Span::styled(format!(" {:<10}", label), ui.theme.muted),
                Span::styled(
                    crate::tui::widgets::spinner_frame(ui.theme, ui.tick).to_string(),
                    ui.theme.accent,
                ),
            ],
            None => vec![
                Span::styled(format!(" {:<10}", label), ui.theme.muted),
                Span::styled(ui.theme.symbols.info.to_string(), ui.theme.muted),
            ],
        }
    };
    let half = expected.len().div_ceil(2);
    for row in 0..half {
        let mut spans = cell(expected[row].0, expected[row].1);
        if let Some((id, label)) = expected.get(row + half) {
            spans.push(Span::raw("   "));
            spans.extend(cell(id, label));
        }
        lines.push(Line::from(spans));
    }
    if let Some(score) = ui
        .state
        .doctor
        .report
        .as_ref()
        .and_then(|r| r.summary.score.as_ref())
    {
        lines.push(Line::from(""));
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<16}", T.dash_overall), ui.theme.muted),
            Span::styled(format!("{}/{}", score.total, score.max), ui.theme.title),
            Span::styled(format!("  grade {}", score.grade), ui.theme.muted),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_network_and_resources(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);
    render_network(ui, frame, rows[0]);
    render_resources(ui, frame, rows[1]);
}

fn render_network(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.dash_network),
            ui.theme.muted,
        ));
    let mut lines: Vec<Line> = Vec::new();
    let default_iface = ui.state.caches.interfaces.as_ref().and_then(|fresh| {
        fresh
            .value
            .iter()
            .find(|i| i.default_route.is_some() && i.up)
            .or_else(|| fresh.value.iter().find(|i| i.up && !i.ipv4.is_empty()))
    });
    match default_iface {
        Some(iface) => {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_interface), ui.theme.muted),
                Span::styled(iface.name.clone(), ui.theme.text),
            ]));
            let address = iface
                .ipv4
                .first()
                .map(|a| format!("{}/{}", a.addr, a.prefix))
                .unwrap_or_else(|| "-".into());
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_address), ui.theme.muted),
                Span::styled(address, ui.theme.text),
            ]));
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_gateway), ui.theme.muted),
                Span::styled(
                    iface.default_route.clone().unwrap_or_else(|| "-".into()),
                    ui.theme.text,
                ),
            ]));
        }
        None => lines.push(Line::styled(T.net_no_interface.to_string(), ui.theme.muted)),
    }
    if let Some(dns) = &ui.state.caches.dns {
        lines.push(Line::from(vec![
            Span::styled(format!("{:<12}", T.dash_dns), ui.theme.muted),
            Span::styled(dns.value.servers.join(", "), ui.theme.text),
        ]));
    }
    if let Some(connectivity) = &ui.state.caches.connectivity {
        let internet = if connectivity.value.internet_reachable {
            Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_internet), ui.theme.muted),
                Span::styled(
                    format!("{} {}", ui.theme.symbols.pass, T.net_connected),
                    ui.theme.success,
                ),
            ])
        } else if connectivity.value.gateway_reachable == Some(true) {
            Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_internet), ui.theme.muted),
                Span::styled(
                    format!("{} {}", ui.theme.symbols.warn, T.net_disconnected),
                    ui.theme.warning,
                ),
            ])
        } else {
            Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_internet), ui.theme.muted),
                Span::styled(
                    format!("{} {}", ui.theme.symbols.fail, T.net_disconnected),
                    ui.theme.error,
                ),
            ])
        };
        lines.push(internet);
        let latency = connectivity
            .value
            .checks
            .iter()
            .find(|c| c.name == "gateway" || c.name == "internet_ipv4")
            .and_then(|c| c.latency_ms);
        if let Some(latency) = latency {
            lines.push(Line::from(vec![
                Span::styled(format!("{:<12}", T.dash_latency), ui.theme.muted),
                Span::styled(format!("{latency:.0} ms"), ui.theme.text),
            ]));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_resources(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.dash_resources),
            ui.theme.muted,
        ));
    let mut lines: Vec<Line> = Vec::new();
    if let Some(system) = &ui.state.caches.system {
        lines.push(gauge_line(
            ui.theme,
            "CPU",
            system.value.cpu.usage_percent.unwrap_or(0.0) as f64,
            12,
        ));
        lines.push(gauge_line(
            ui.theme,
            "RAM",
            system.value.memory.utilization_percent,
            12,
        ));
        let worst = system.value.disks.iter().max_by(|a, b| {
            a.utilization_percent
                .partial_cmp(&b.utilization_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        });
        if let Some(disk) = worst {
            lines.push(gauge_line(ui.theme, "Disk", disk.utilization_percent, 12));
        }
    } else {
        lines.push(Line::styled(T.loading.to_string(), ui.theme.muted));
    }
    if let Some(sample) = &ui.state.monitor.sample {
        let (rx, tx) = sample.network.iter().fold((0.0f64, 0.0f64), |acc, n| {
            (acc.0 + n.rx_bytes_per_sec, acc.1 + n.tx_bytes_per_sec)
        });
        lines.push(Line::from(vec![
            Span::styled(format!("{:<10}", "Network"), ui.theme.muted),
            Span::styled(
                format!(
                    "{} {}  {} {}",
                    ui.theme.symbols.arrow,
                    util::human_bytes(rx as u64),
                    ui.theme.symbols.arrow,
                    util::human_bytes(tx as u64)
                ),
                ui.theme.text,
            ),
        ]));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_findings(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.dash_findings),
            ui.theme.muted,
        ));
    let findings = ui.state.doctor.findings();
    let mut lines: Vec<Line> = Vec::new();
    if findings.is_empty() {
        if ui.is_running(crate::tui::tasks::TaskKind::Doctor) || ui.state.doctor.is_running() {
            lines.push(Line::styled(
                T.dash_checks_running.to_string(),
                ui.theme.muted,
            ));
        } else {
            lines.push(Line::styled(T.dash_no_findings.to_string(), ui.theme.muted));
        }
    }
    for (index, finding) in findings.iter().enumerate().take(6) {
        let selected = index == ui.state.dashboard_selected;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker} "), ui.theme.accent),
            status_badge(ui, UiStatus::from_severity(finding.severity)),
            Span::styled(
                format!("  {}", finding.title),
                if selected {
                    ui.theme.selected
                } else {
                    ui.theme.text
                },
            ),
        ]));
    }
    if findings.len() > 6 {
        lines.push(Line::styled(
            format!("   ... {} more (open Doctor for all)", findings.len() - 6),
            ui.theme.muted,
        ));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn status_badge(ui: &Ui, status: UiStatus) -> Span<'static> {
    crate::tui::widgets::status_badge(ui.theme, status)
}
