//! Monitor screen: rolling sparklines, gauges and top processes.
//!
//! The worker samples at the configured interval; this component only draws
//! the history it already has.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::text::T;
use crate::tui::widgets::{sparkline, truncate};
use crate::util;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::sync::atomic::Ordering;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let Some(sample) = &ui.state.monitor.sample else {
        let lines = vec![
            Line::styled("Starting monitor...".to_string(), ui.theme.muted),
            Line::styled(
                "The first sample needs a short measuring window.".to_string(),
                ui.theme.muted,
            ),
        ];
        frame.render_widget(
            Paragraph::new(lines).block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_style(ui.theme.border)
                    .title(Span::styled(
                        format!(" {} ", T.screen_monitor),
                        ui.theme.muted,
                    )),
            ),
            area,
        );
        return;
    };

    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(10), Constraint::Min(8)])
        .split(area);
    render_metrics(ui, frame, rows[0], sample);
    render_processes(ui, frame, rows[1], sample);
}

fn render_metrics(ui: &Ui, frame: &mut Frame, area: Rect, sample: &crate::model::MonitorSample) {
    let paused = ui.state.monitor.paused.load(Ordering::Relaxed);
    let title = if paused {
        format!(" {} — {} ", T.screen_monitor, T.mon_paused)
    } else {
        format!(
            " {} — interval {:.2}s ",
            T.screen_monitor,
            ui.state.monitor.interval_secs()
        )
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(if paused {
            ui.theme.warning
        } else {
            ui.theme.border
        })
        .title(Span::styled(title, ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let width = inner.width.saturating_sub(24) as usize;
    let mut lines: Vec<Line> = Vec::new();

    // CPU history uses a real 0-100 scale.
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<10}", T.mon_cpu), ui.theme.muted),
        Span::styled(
            sparkline(ui.theme, &ui.state.monitor.cpu_history, 100.0, width),
            ui.theme.progress,
        ),
        Span::styled(
            format!(" {:>5.1}%", sample.cpu_usage_percent),
            ui.theme.text,
        ),
    ]));
    if let Some(load) = sample.load_average {
        lines.push(Line::styled(
            format!(
                " {:<10} load {:.2} {:.2} {:.2}",
                "", load[0], load[1], load[2]
            ),
            ui.theme.muted,
        ));
    }
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<10}", T.mon_memory), ui.theme.muted),
        Span::styled(
            sparkline(ui.theme, &ui.state.monitor.mem_history, 100.0, width),
            ui.theme.progress,
        ),
        Span::styled(
            format!(" {:>5.1}%", sample.memory_utilization_percent),
            ui.theme.text,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<10}", T.mon_network), ui.theme.muted),
        Span::styled(
            format!(
                "{} interfaces: {}",
                ui.theme.symbols.arrow,
                sample.network.len()
            ),
            ui.theme.muted,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<10}", ""), ui.theme.muted),
        Span::styled(format!("{} ", T.mon_download), ui.theme.muted),
        Span::styled(
            sparkline(
                ui.theme,
                &ui.state.monitor.rx_history,
                ui.state.monitor.peak_rx,
                width / 2,
            ),
            ui.theme.success,
        ),
        Span::styled(
            format!(
                " {:>10}/s",
                util::human_bytes(
                    sample
                        .network
                        .iter()
                        .map(|n| n.rx_bytes_per_sec)
                        .sum::<f64>() as u64
                )
            ),
            ui.theme.text,
        ),
    ]));
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<10}", ""), ui.theme.muted),
        Span::styled(format!("{}   ", T.mon_upload), ui.theme.muted),
        Span::styled(
            sparkline(
                ui.theme,
                &ui.state.monitor.tx_history,
                ui.state.monitor.peak_tx,
                width / 2,
            ),
            ui.theme.warning,
        ),
        Span::styled(
            format!(
                " {:>10}/s",
                util::human_bytes(
                    sample
                        .network
                        .iter()
                        .map(|n| n.tx_bytes_per_sec)
                        .sum::<f64>() as u64
                )
            ),
            ui.theme.text,
        ),
    ]));
    if !sample.temperatures.is_empty() {
        let temps: Vec<String> = sample
            .temperatures
            .iter()
            .take(4)
            .map(|t| format!("{} {:.0}C", truncate(&t.label, 14, ui.theme), t.current_c))
            .collect();
        lines.push(Line::styled(
            format!(" {:<10} {}", T.mon_temperatures, temps.join("  ")),
            ui.theme.muted,
        ));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_processes(ui: &Ui, frame: &mut Frame, area: Rect, sample: &crate::model::MonitorSample) {
    if area.width >= 100 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(50), Constraint::Percentage(50)])
            .split(area);
        render_process_table(ui, frame, columns[0], T.mon_top_cpu, &sample.top_cpu);
        render_process_table(ui, frame, columns[1], T.mon_top_memory, &sample.top_memory);
    } else {
        render_process_table(ui, frame, area, T.mon_top_cpu, &sample.top_cpu);
    }
}

fn render_process_table(
    ui: &Ui,
    frame: &mut Frame,
    area: Rect,
    title: &str,
    processes: &[crate::model::ProcessInfo],
) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {title} "), ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if processes.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                T.empty_no_processes.to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    let rows: Vec<Vec<String>> = processes
        .iter()
        .map(|process| {
            vec![
                process.pid.to_string(),
                truncate(&process.name, 16, ui.theme),
                format!("{:.1}", process.cpu_percent),
                util::human_bytes(process.memory_bytes),
            ]
        })
        .collect();
    frame.render_widget(
        list_table(
            ui,
            &["PID", "Process", "CPU%", "Memory"],
            rows,
            None,
            &[
                Constraint::Length(7),
                Constraint::Min(10),
                Constraint::Length(6),
                Constraint::Length(9),
            ],
        ),
        inner,
    );
}
