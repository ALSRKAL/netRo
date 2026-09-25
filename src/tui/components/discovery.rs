//! Discovery screen: target/method form, real progress, results and details.

use crate::tui::app::Ui;
use crate::tui::components::{checkbox, list_table};
use crate::tui::text::T;
use crate::tui::widgets::{progress_bar, safe, spinner_frame, truncate};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(6),
            Constraint::Length(if ui.state.discovery.progress.is_some() {
                3
            } else {
                0
            }),
            Constraint::Min(5),
        ])
        .split(area);
    render_form(ui, frame, rows[0]);
    if ui.state.discovery.progress.is_some() {
        render_progress(ui, frame, rows[1]);
    }
    render_results(ui, frame, rows[2]);
}

fn render_form(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.disc_title), ui.theme.muted));
    let methods = ["auto", "neighbors", "icmp", "tcp", "nmap"];
    let method = methods
        .get(ui.state.discovery.method)
        .copied()
        .unwrap_or("auto");
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {:<14} ", T.disc_target), ui.theme.muted),
            Span::styled(
                if ui.state.discovery.target.is_empty() {
                    "(local subnets — press Enter to set a CIDR)".to_string()
                } else {
                    ui.state.discovery.target.clone()
                },
                ui.theme.text,
            ),
        ]),
        Line::from(vec![
            Span::styled(format!(" {:<14} ", T.disc_method), ui.theme.muted),
            Span::styled(
                format!("{} {}   (Left/Right)", ui.theme.symbols.arrow, method),
                ui.theme.text,
            ),
        ]),
        Line::from(vec![
            Span::styled(format!(" {:<14} ", "Options"), ui.theme.muted),
            Span::styled(
                format!(
                    "{} resolve hostnames   {} vendor lookup",
                    checkbox(ui, ui.state.discovery.resolve_hostnames),
                    checkbox(ui, ui.state.discovery.vendor_lookup)
                ),
                ui.theme.text,
            ),
        ]),
        Line::styled(format!("  {}", T.disc_local_only), ui.theme.muted),
        Line::from(vec![Span::styled(
            format!("  g {}   Space toggle options", T.disc_start),
            ui.theme.muted,
        )]),
    ];
    if let Some(error) = &ui.state.discovery.error {
        lines.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_progress(ui: &Ui, frame: &mut Frame, area: Rect) {
    let Some(progress) = &ui.state.discovery.progress else {
        return;
    };
    let spinner = spinner_frame(ui.theme, ui.tick);
    let mut lines = vec![
        Line::from(vec![
            Span::styled(format!(" {spinner} "), ui.theme.accent),
            Span::styled(
                format!(
                    "phase: {}   {}: {}/{}",
                    progress.phase, T.disc_probed, progress.probed, progress.total
                ),
                ui.theme.text,
            ),
            Span::styled(
                format!("   {}: {}", T.disc_hosts_found, progress.found),
                ui.theme.muted,
            ),
        ]),
        {
            let mut bar = progress_bar(ui.theme, progress.probed, progress.total, 30);
            bar.spans.insert(0, Span::raw("  "));
            bar.spans
                .push(Span::styled("   Esc cancel", ui.theme.muted));
            bar
        },
    ];
    lines.push(Line::styled(
        format!("  {} discovering", T.hint_cancel),
        ui.theme.muted,
    ));
    frame.render_widget(Paragraph::new(lines), area);
}

fn render_results(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.disc_hosts_found),
            ui.theme.muted,
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(report) = &ui.state.discovery.report else {
        let message = if ui.state.discovery.progress.is_some() {
            T.loading
        } else {
            T.empty_no_hosts
        };
        frame.render_widget(
            Paragraph::new(Line::styled(message.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = report
        .hosts
        .iter()
        .filter(|host| {
            filter.is_empty()
                || host.ip.to_ascii_lowercase().contains(&filter)
                || host
                    .hostname
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
                || host
                    .mac
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
        })
        .map(|host| {
            vec![
                host.ip.clone(),
                host.hostname
                    .clone()
                    .map(|h| safe(&h))
                    .unwrap_or_else(|| "-".into()),
                host.mac.clone().unwrap_or_else(|| "-".into()),
                host.vendor
                    .clone()
                    .map(|v| safe(&v))
                    .unwrap_or_else(|| "unknown".into()),
                host.response_ms
                    .map(|r| format!("{r:.1} ms"))
                    .unwrap_or_else(|| "-".into()),
                if host.open_ports.is_empty() {
                    "-".into()
                } else {
                    host.open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                },
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if report.hosts.is_empty() {
                    T.empty_no_hosts
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
    if let Some(note) = &report.note {
        let mut lines = Vec::new();
        lines.push(Line::styled(
            format!(" {}", truncate(note, inner.width as usize - 4, ui.theme)),
            if report.cancelled {
                ui.theme.warning
            } else {
                ui.theme.muted
            },
        ));
        frame.render_widget(Paragraph::new(lines), Rect { height: 1, ..inner });
    }
    let table_area = if report.note.is_some() {
        Rect {
            y: inner.y + 1,
            height: inner.height.saturating_sub(1),
            ..inner
        }
    } else {
        inner
    };
    frame.render_widget(
        list_table(
            ui,
            &["IP", "Hostname", "MAC", "Vendor", "RTT", "Open ports"],
            rows,
            Some(ui.state.discovery.selected),
            &[
                Constraint::Length(16),
                Constraint::Length(18),
                Constraint::Length(18),
                Constraint::Min(12),
                Constraint::Length(9),
                Constraint::Length(14),
            ],
        ),
        table_area,
    );
}
