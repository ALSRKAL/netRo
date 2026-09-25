//! Live status panel: task progress, resource gauges and freshness.

use crate::tui::app::Ui;
use crate::tui::tasks::TaskKind;
use crate::tui::text::T;
use crate::tui::widgets::{gauge_line, progress_bar, spinner_frame};
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;
use std::sync::atomic::Ordering;
use std::time::Duration;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.status_panel),
            ui.theme.muted,
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if inner.height == 0 {
        return;
    }

    let mut lines: Vec<Line> = Vec::new();

    // Tasks with real progress (never fake percentages).
    let running = ui.running;
    if running.is_empty() {
        lines.push(Line::styled(
            format!(" {} idle", ui.theme.symbols.bullet),
            ui.theme.muted,
        ));
    } else {
        for (kind, _) in running.iter().take(4) {
            let spinner = spinner_frame(ui.theme, ui.tick);
            lines.push(Line::from(vec![
                Span::styled(format!(" {spinner} "), ui.theme.accent),
                Span::styled(kind.label().to_string(), ui.theme.text),
            ]));
            match kind {
                TaskKind::Scan => {
                    if let Some(progress) = &ui.state.scanner.progress {
                        lines.push(Line::from(""));
                        lines.push(Line::from(vec![Span::raw("  ")]));
                        let mut bar =
                            progress_bar(ui.theme, progress.completed, progress.total, 14);
                        bar.spans.insert(0, Span::raw("  "));
                        lines.push(bar);
                    }
                }
                TaskKind::Discovery => {
                    if let Some(progress) = &ui.state.discovery.progress {
                        let mut line = progress_bar(ui.theme, progress.probed, progress.total, 14);
                        line.spans.insert(
                            0,
                            Span::styled(format!("  {} ", progress.phase), ui.theme.muted),
                        );
                        lines.push(line);
                    }
                }
                _ => {}
            }
        }
    }
    lines.push(Line::from(""));

    // Resource gauges (only when a monitor sample exists; otherwise omit).
    if let Some(sample) = &ui.state.monitor.sample {
        lines.push(Line::styled(T.dash_resources.to_string(), ui.theme.muted));
        lines.push(gauge_line(
            ui.theme,
            "CPU",
            sample.cpu_usage_percent as f64,
            10,
        ));
        lines.push(gauge_line(
            ui.theme,
            "RAM",
            sample.memory_utilization_percent,
            10,
        ));
        let (rx, tx) = sample.network.iter().fold((0.0f64, 0.0f64), |acc, n| {
            (acc.0 + n.rx_bytes_per_sec, acc.1 + n.tx_bytes_per_sec)
        });
        lines.push(Line::from(vec![
            Span::styled(format!("{:<10}", T.mon_network), ui.theme.muted),
            Span::styled(
                format!(
                    "{} {}  {} {}",
                    ui.theme.symbols.arrow,
                    crate::util::human_bytes(rx as u64),
                    ui.theme.symbols.arrow,
                    crate::util::human_bytes(tx as u64)
                ),
                ui.theme.text,
            ),
        ]));
        if ui.state.monitor.paused.load(Ordering::Relaxed) {
            lines.push(Line::styled(
                format!(" {} {}", ui.theme.symbols.warn, T.mon_paused),
                ui.theme.warning,
            ));
        }
    } else if let Some(system) = &ui.state.caches.system {
        lines.push(Line::styled(T.dash_resources.to_string(), ui.theme.muted));
        lines.push(gauge_line(
            ui.theme,
            "CPU",
            system.value.cpu.usage_percent.unwrap_or(0.0) as f64,
            10,
        ));
        lines.push(gauge_line(
            ui.theme,
            "RAM",
            system.value.memory.utilization_percent,
            10,
        ));
    }

    lines.push(Line::from(""));

    // Freshness indicators for cached sections.
    lines.push(Line::styled("Data".to_string(), ui.theme.muted));
    let entries: [(&str, Option<Duration>); 4] = [
        (
            T.screen_system,
            ui.state.caches.system.as_ref().map(|f| f.age()),
        ),
        (
            T.tab_interfaces,
            ui.state.caches.interfaces.as_ref().map(|f| f.age()),
        ),
        (
            T.tab_connectivity,
            ui.state.caches.connectivity.as_ref().map(|f| f.age()),
        ),
        (
            T.screen_security,
            ui.state.caches.audit.as_ref().map(|f| f.age()),
        ),
    ];
    for (label, age) in entries {
        let text = match age {
            Some(age) if age < Duration::from_secs(2) => "now".to_string(),
            Some(age) if age < Duration::from_secs(60) => format!("{:.0}s", age.as_secs_f64()),
            Some(age) => format!("{:.0}m", age.as_secs_f64() / 60.0),
            None => T.never.to_string(),
        };
        let style = match age {
            Some(age) if age > Duration::from_secs(120) => ui.theme.warning,
            Some(_) => ui.theme.text,
            None => ui.theme.muted,
        };
        lines.push(Line::from(vec![
            Span::styled(format!("{label:<12}"), ui.theme.muted),
            Span::styled(text, style),
        ]));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}
