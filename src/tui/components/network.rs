//! Network screen with tabs: Overview, Interfaces, Routes, DNS, Connectivity,
//! Latency, Trace and Connections.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::components::status_symbol;
use crate::tui::state::NetworkTab;
use crate::tui::text::T;
use crate::tui::theme::UiStatus;
use crate::tui::widgets::{safe, truncate};
use crate::util;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    render_tabs(ui, frame, rows[0]);
    match ui.state.network_tab {
        NetworkTab::Overview => overview(ui, frame, rows[1]),
        NetworkTab::Interfaces => interfaces(ui, frame, rows[1]),
        NetworkTab::Routes => routes(ui, frame, rows[1]),
        NetworkTab::Dns => dns(ui, frame, rows[1]),
        NetworkTab::Connectivity => connectivity(ui, frame, rows[1]),
        NetworkTab::Latency => latency(ui, frame, rows[1]),
        NetworkTab::Trace => trace(ui, frame, rows[1]),
        NetworkTab::Connections => connections(ui, frame, rows[1]),
    }
}

fn render_tabs(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    for tab in NetworkTab::ALL {
        let selected = tab == ui.state.network_tab;
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

fn overview(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Percentage(55), Constraint::Percentage(45)])
        .split(area);
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.connectivity {
        Some(report) => {
            for check in &report.value.checks {
                let status = if check.ok {
                    UiStatus::Pass
                } else if check.note.is_some() && check.error.is_none() {
                    UiStatus::Unsupported
                } else {
                    UiStatus::Error
                };
                let detail = check
                    .latency_ms
                    .map(|l| format!("{l:.0} ms"))
                    .or_else(|| check.error.clone())
                    .or_else(|| check.note.clone())
                    .unwrap_or_default();
                lines.push(Line::from(vec![
                    Span::styled(format!(" {:<14}", check.name), ui.theme.text),
                    status_symbol(ui, status),
                    Span::raw("  "),
                    Span::styled(detail, ui.theme.muted),
                ]));
            }
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    lines.push(Line::from(""));
    let ifaces: Vec<&crate::model::Interface> = ui
        .state
        .caches
        .interfaces
        .as_ref()
        .map(|fresh| fresh.value.iter().filter(|i| i.up).collect())
        .unwrap_or_default();
    lines.push(Line::styled(
        format!("{} up interface(s)", ifaces.len()),
        ui.theme.muted,
    ));
    frame.render_widget(
        Paragraph::new(lines).block(panel(ui, T.tab_overview)),
        rows[0],
    );

    let mut summary: Vec<Line> = Vec::new();
    if let Some(connectivity) = &ui.state.caches.connectivity {
        summary.push(Line::from(vec![
            Span::styled(format!("{:<14}", "IPv4"), ui.theme.muted),
            status_symbol(
                ui,
                if connectivity.value.ipv4_available {
                    UiStatus::Pass
                } else {
                    UiStatus::Error
                },
            ),
        ]));
        summary.push(Line::from(vec![
            Span::styled(format!("{:<14}", "IPv6"), ui.theme.muted),
            if connectivity.value.ipv6_available {
                status_symbol(ui, UiStatus::Pass)
            } else {
                Span::styled(
                    format!("{} {}", ui.theme.symbols.warn, "not reachable"),
                    ui.theme.warning,
                )
            },
        ]));
        summary.push(Line::from(vec![
            Span::styled(format!("{:<14}", T.dash_dns), ui.theme.muted),
            status_symbol(
                ui,
                if connectivity.value.dns_working {
                    UiStatus::Pass
                } else {
                    UiStatus::Error
                },
            ),
        ]));
    } else {
        summary.push(Line::styled(T.loading.to_string(), ui.theme.muted));
    }
    if ui.state.caches.connectivity.is_none()
        && !ui.is_running(crate::tui::tasks::TaskKind::Connectivity)
    {
        summary.push(Line::styled(T.offline_note.to_string(), ui.theme.warning));
    }
    frame.render_widget(
        Paragraph::new(summary).block(panel(ui, T.tab_connectivity)),
        rows[1],
    );
}

fn interfaces(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, T.tab_interfaces);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(fresh) = &ui.state.caches.interfaces else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = fresh
        .value
        .iter()
        .filter(|iface| filter.is_empty() || iface.name.to_ascii_lowercase().contains(&filter))
        .map(|iface| {
            let kind = format!("{:?}", iface.kind).to_lowercase();
            let addresses: String = iface
                .ipv4
                .iter()
                .map(|a| format!("{}/{}", a.addr, a.prefix))
                .chain(
                    iface
                        .ipv6
                        .iter()
                        .map(|a| format!("{}/{}", a.addr, a.prefix)),
                )
                .collect::<Vec<_>>()
                .join(" ");
            vec![
                iface.name.clone(),
                kind,
                if iface.up { "up" } else { "down" }.to_string(),
                truncate(&addresses, 44, ui.theme),
                iface.mac.clone().unwrap_or_else(|| "-".into()),
                iface
                    .speed_mbps
                    .map(|s| format!("{s}M"))
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(T.empty_filtered.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &["Interface", "Kind", "State", "Addresses", "MAC", "Speed"],
            rows,
            Some(ui.state.network.selected),
            &[
                Constraint::Length(14),
                Constraint::Length(9),
                Constraint::Length(5),
                Constraint::Min(20),
                Constraint::Length(18),
                Constraint::Length(7),
            ],
        ),
        inner,
    );
}

fn routes(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, T.tab_routes);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(fresh) = &ui.state.caches.routes else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = fresh
        .value
        .iter()
        .filter(|route| {
            filter.is_empty()
                || route.destination.to_ascii_lowercase().contains(&filter)
                || route
                    .gateway
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
        })
        .map(|route| {
            vec![
                route.family.clone(),
                format!("{}/{}", route.destination, route.prefix),
                route.gateway.clone().unwrap_or_else(|| "-".into()),
                route.interface.clone().unwrap_or_else(|| "-".into()),
                route
                    .metric
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".into()),
                if route.is_default { "default" } else { "" }.to_string(),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(T.empty_filtered.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &[
                "Family",
                "Destination",
                "Gateway",
                "Interface",
                "Metric",
                "Role",
            ],
            rows,
            Some(ui.state.network.selected),
            &[
                Constraint::Length(7),
                Constraint::Min(18),
                Constraint::Length(18),
                Constraint::Length(12),
                Constraint::Length(7),
                Constraint::Length(8),
            ],
        ),
        inner,
    );
}

fn dns(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(4)])
        .split(area);
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.dns {
        Some(config) => {
            lines.push(Line::from(vec![
                Span::styled(format!(" {:<14}", T.net_resolver), ui.theme.muted),
                Span::styled(config.value.servers.join(", "), ui.theme.text),
            ]));
            lines.push(Line::styled(
                format!(" source: {}", config.value.source),
                ui.theme.muted,
            ));
            if !config.value.search_domains.is_empty() {
                lines.push(Line::styled(
                    format!(" search: {}", config.value.search_domains.join(" ")),
                    ui.theme.muted,
                ));
            }
            if let Some(note) = &config.value.note {
                lines.push(Line::styled(
                    format!(
                        " note: {}",
                        truncate(note, area.width as usize - 4, ui.theme)
                    ),
                    ui.theme.muted,
                ));
            }
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<14}", T.net_query), ui.theme.muted),
        Span::styled(
            if ui.state.network.dns_name.is_empty() {
                "(press Enter to query a name)".to_string()
            } else {
                ui.state.network.dns_name.clone()
            },
            ui.theme.text,
        ),
        if ui.state.network.dns_server.is_empty() {
            Span::raw("")
        } else {
            Span::styled(
                format!("  via {}", ui.state.network.dns_server),
                ui.theme.muted,
            )
        },
    ]));
    frame.render_widget(Paragraph::new(lines).block(panel(ui, T.tab_dns)), rows[0]);

    let mut result: Vec<Line> = Vec::new();
    if let Some(error) = &ui.state.network.dns_error {
        result.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
    }
    if let Some(response) = &ui.state.network.dns_query {
        result.push(Line::from(vec![Span::styled(
            format!(
                " {}/{} via {} in {:.0} ms",
                response.query_name, response.record_type, response.server, response.rtt_ms
            ),
            ui.theme.text,
        )]));
        for answer in &response.answers {
            result.push(Line::styled(
                format!(
                    "   {:<28} {:<6} TTL {:>6}  {}",
                    truncate(&safe(&answer.name), 28, ui.theme),
                    answer.record_type,
                    answer.ttl,
                    util::sanitize_terminal(&answer.value)
                ),
                ui.theme.muted,
            ));
        }
        if response.answers.is_empty() {
            result.push(Line::styled("   (no answers)", ui.theme.muted));
        }
    } else if ui.state.network.dns_error.is_none() {
        result.push(Line::styled(T.loading.to_string(), ui.theme.muted));
    }
    frame.render_widget(
        Paragraph::new(result).block(panel(ui, T.net_result)),
        rows[1],
    );
}

fn connectivity(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, T.tab_connectivity);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(report) = &ui.state.caches.connectivity else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let rows: Vec<Vec<String>> = report
        .value
        .checks
        .iter()
        .map(|check| {
            vec![
                check.name.clone(),
                check.target.clone(),
                if check.ok { "ok" } else { "failed" }.to_string(),
                check
                    .latency_ms
                    .map(|l| format!("{l:.0} ms"))
                    .unwrap_or_else(|| "-".into()),
                check
                    .error
                    .clone()
                    .or_else(|| check.note.clone())
                    .unwrap_or_default(),
            ]
        })
        .collect();
    frame.render_widget(
        list_table(
            ui,
            &["Check", "Target", "Result", "Latency", "Detail"],
            rows,
            None,
            &[
                Constraint::Length(15),
                Constraint::Length(28),
                Constraint::Length(7),
                Constraint::Length(9),
                Constraint::Min(10),
            ],
        ),
        inner,
    );
}

fn latency(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {:<10}", T.net_target), ui.theme.muted),
            Span::styled(
                if ui.state.network.latency_target.is_empty() {
                    "(press Enter to set a target)".to_string()
                } else {
                    ui.state.network.latency_target.clone()
                },
                ui.theme.text,
            ),
        ]),
        Line::styled(
            format!(
                "  {}    {} g",
                T.hint_run, "press Enter to set target, then"
            ),
            ui.theme.muted,
        ),
    ];
    if let Some(error) = &ui.state.network.latency_error {
        lines.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines).block(panel(ui, T.tab_latency)),
        rows[0],
    );

    let mut result: Vec<Line> = Vec::new();
    match &ui.state.network.latency {
        Some(ping) => {
            result.push(Line::styled(
                format!(
                    " {:?}  {}/{} packets, {:.0}% loss",
                    ping.method, ping.received, ping.transmitted, ping.loss_percent
                ),
                ui.theme.text,
            ));
            if !ping.rtts.is_empty() {
                result.push(Line::styled(
                    format!(
                        "  min {:.1} ms   avg {:.1} ms   max {:.1} ms   jitter {:.1} ms",
                        ping.min_ms.unwrap_or(0.0),
                        ping.avg_ms.unwrap_or(0.0),
                        ping.max_ms.unwrap_or(0.0),
                        ping.jitter_ms.unwrap_or(0.0),
                    ),
                    ui.theme.muted,
                ));
                let series: Vec<f64> = ping.rtts.clone();
                let max = series.iter().cloned().fold(1.0f64, f64::max);
                result.push(Line::styled(
                    format!(
                        "  {}",
                        crate::tui::widgets::sparkline(
                            ui.theme,
                            &series,
                            max,
                            series.len().min(60)
                        )
                    ),
                    ui.theme.progress,
                ));
            }
            if let Some(error) = &ping.error {
                result.push(Line::styled(
                    format!("  {}", truncate(error, 100, ui.theme)),
                    ui.theme.warning,
                ));
            }
        }
        None => result.push(Line::styled(
            if ui.is_running(crate::tui::tasks::TaskKind::Latency) {
                T.loading.to_string()
            } else {
                "no measurement yet".to_string()
            },
            ui.theme.muted,
        )),
    }
    frame.render_widget(
        Paragraph::new(result).block(panel(ui, T.net_result)),
        rows[1],
    );
}

fn trace(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(4), Constraint::Min(4)])
        .split(area);
    let mut lines = vec![Line::from(vec![
        Span::styled(format!(" {:<10}", T.net_target), ui.theme.muted),
        Span::styled(
            if ui.state.network.trace_target.is_empty() {
                "(press Enter to set a target)".to_string()
            } else {
                ui.state.network.trace_target.clone()
            },
            ui.theme.text,
        ),
    ])];
    if let Some(error) = &ui.state.network.trace_error {
        lines.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
    }
    frame.render_widget(Paragraph::new(lines).block(panel(ui, T.tab_trace)), rows[0]);

    let mut result: Vec<Line> = Vec::new();
    match &ui.state.network.trace {
        Some(trace) => {
            result.push(Line::styled(
                format!(" reached: {}   method: {:?}", trace.reached, trace.method),
                ui.theme.text,
            ));
            for hop in &trace.hops {
                let address = hop.address.clone().unwrap_or_else(|| "*".into());
                let rtts = if hop.rtt_ms.is_empty() {
                    "*".to_string()
                } else {
                    hop.rtt_ms
                        .iter()
                        .map(|r| format!("{r:.0}ms"))
                        .collect::<Vec<_>>()
                        .join(" ")
                };
                result.push(Line::styled(
                    format!(
                        " {:>2}  {:<32} {}",
                        hop.hop,
                        truncate(&address, 32, ui.theme),
                        rtts
                    ),
                    if hop.timeout {
                        ui.theme.muted
                    } else {
                        ui.theme.text
                    },
                ));
            }
            if let Some(note) = &trace.note {
                result.push(Line::styled(
                    format!(" note: {}", truncate(note, 100, ui.theme)),
                    ui.theme.muted,
                ));
            }
        }
        None => result.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    frame.render_widget(
        Paragraph::new(result).block(panel(ui, T.net_result)),
        rows[1],
    );
}

fn connections(ui: &Ui, frame: &mut Frame, area: Rect) {
    let title = if !ui.state.filter.is_empty() {
        format!(" {} — filter: {} ", T.tab_connections, ui.state.filter)
    } else {
        format!(" {} ", T.tab_connections)
    };
    let block = panel(ui, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(fresh) = &ui.state.caches.connections else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = fresh
        .value
        .iter()
        .filter(|connection| {
            filter.is_empty()
                || connection
                    .process
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
                || connection
                    .remote_addr
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
                || connection.state.to_ascii_lowercase().contains(&filter)
        })
        .take(inner.height as usize)
        .map(|connection| {
            vec![
                connection.protocol.to_uppercase(),
                format!("{}:{}", connection.local_addr, connection.local_port),
                format!(
                    "{}:{}",
                    connection.remote_addr.clone().unwrap_or_else(|| "*".into()),
                    connection
                        .remote_port
                        .map(|p| p.to_string())
                        .unwrap_or_else(|| "*".into())
                ),
                connection.state.clone(),
                connection
                    .process
                    .clone()
                    .map(|p| safe(&p))
                    .unwrap_or_else(|| "-".into()),
                connection
                    .pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if fresh.value.is_empty() {
                    T.empty_no_connections
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
            &["Protocol", "Local", "Remote", "State", "Process", "PID"],
            rows,
            Some(ui.state.network.selected),
            &[
                Constraint::Length(8),
                Constraint::Length(24),
                Constraint::Length(24),
                Constraint::Length(13),
                Constraint::Min(10),
                Constraint::Length(7),
            ],
        ),
        inner,
    );
}
