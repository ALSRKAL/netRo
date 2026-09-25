//! Reports screen: format/scope/path selection and generation from cached
//! results (no duplicate probes).

use crate::tui::app::Ui;
use crate::tui::state::ReportsUi;
use crate::tui::text::T;
use crate::tui::widgets::spinner_frame;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(6)])
        .split(area);
    render_form(ui, frame, rows[0]);
    render_status(ui, frame, rows[1]);
}

fn render_form(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.rep_title), ui.theme.muted));
    let reports = &ui.state.reports;
    let mut lines: Vec<Line> = Vec::new();

    lines.push(Line::styled(T.rep_format.to_string(), ui.theme.muted));
    for (index, (label, _)) in ReportsUi::FORMATS.iter().enumerate() {
        let selected = index == reports.format;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        lines.push(Line::styled(
            format!(" {marker} {label}"),
            if selected {
                ui.theme.selected
            } else {
                ui.theme.text
            },
        ));
    }
    lines.push(Line::from(""));

    lines.push(Line::styled(T.rep_scope.to_string(), ui.theme.muted));
    for (index, label) in ReportsUi::SCOPES.iter().enumerate() {
        let selected = index == reports.scope;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        lines.push(Line::styled(
            format!(" {marker} {label}"),
            if selected {
                ui.theme.selected
            } else {
                ui.theme.text
            },
        ));
    }
    lines.push(Line::from(""));

    lines.push(Line::from(vec![
        Span::styled(format!(" {:<12}", T.rep_output), ui.theme.muted),
        Span::styled(
            if reports.path.is_empty() {
                "(press Enter to set a path)".to_string()
            } else {
                reports.path.clone()
            },
            ui.theme.text,
        ),
    ]));
    lines.push(Line::from(""));
    lines.push(Line::styled(
        format!("  {}", T.rep_reuse_note),
        ui.theme.muted,
    ));
    lines.push(Line::styled(
        "  Left/Right select   Enter edit path/generate   g generate".to_string(),
        ui.theme.muted,
    ));
    if let Some(error) = &reports.error {
        lines.push(Line::from(""));
        lines.push(Line::styled(
            format!(" {} {}", ui.theme.symbols.fail, error.message()),
            ui.theme.error,
        ));
        if let Some(hint) = error.hint() {
            lines.push(Line::styled(format!("   hint: {hint}"), ui.theme.muted));
        }
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(block)
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_status(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(" STATUS ", ui.theme.muted));
    let mut lines: Vec<Line> = Vec::new();
    if ui.is_running(crate::tui::tasks::TaskKind::Report) {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {} ", spinner_frame(ui.theme, ui.tick)),
                ui.theme.accent,
            ),
            Span::styled("generating report...".to_string(), ui.theme.text),
        ]));
    } else if let Some(path) = &ui.state.reports.last {
        lines.push(Line::styled(
            format!(" {}: {}", T.rep_written, path.display()),
            ui.theme.success,
        ));
        lines.push(Line::styled(
            format!(" format: {}", ui.state.reports.last_format),
            ui.theme.muted,
        ));
    } else {
        lines.push(Line::styled(
            " no report generated in this session".to_string(),
            ui.theme.muted,
        ));
    }
    let ready = ui.state.caches.system.is_some()
        || ui.state.caches.interfaces.is_some()
        || ui.state.caches.audit.is_some();
    lines.push(Line::styled(
        format!(
            " cached sections: system={} network={} security={} doctor={}",
            ui.state.caches.system.is_some(),
            ui.state.caches.interfaces.is_some() || ui.state.caches.routes.is_some(),
            ui.state.caches.audit.is_some(),
            ui.state.caches.doctor.is_some()
        ),
        if ready {
            ui.theme.muted
        } else {
            ui.theme.warning
        },
    ));
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
