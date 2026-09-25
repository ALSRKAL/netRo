//! Doctor screen: streamed checks, summary, findings with smart navigation.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::components::status_symbol;
use crate::tui::text::T;
use crate::tui::theme::UiStatus;
use crate::tui::widgets::{spinner_frame, truncate};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(9)])
        .split(area);
    render_checks(ui, frame, rows[0]);
    render_findings(ui, frame, rows[1]);
}

fn render_checks(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.doc_title), ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let running =
        ui.state.doctor.is_running() || ui.is_running(crate::tui::tasks::TaskKind::Doctor);
    let mut lines: Vec<Line> = Vec::new();

    if ui.state.doctor.checks.is_empty() && !running {
        if let Some(error) = &ui.state.doctor.error {
            lines.push(Line::styled(
                format!(" {} {}", ui.theme.symbols.fail, error.message()),
                ui.theme.error,
            ));
            if let Some(hint) = error.hint() {
                lines.push(Line::styled(format!("  hint: {hint}"), ui.theme.muted));
            }
        } else {
            lines.push(Line::styled(T.doc_started.to_string(), ui.theme.muted));
        }
        lines.push(Line::from(""));
        lines.push(Line::styled(
            "  Press d to run diagnostics".to_string(),
            ui.theme.muted,
        ));
        frame.render_widget(Paragraph::new(lines), inner);
        return;
    }

    for check in &ui.state.doctor.checks {
        let status = UiStatus::from_check(check.status);
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", check.label), ui.theme.text),
            status_symbol(ui, status),
            Span::raw("  "),
            Span::styled(
                truncate(&check.summary, inner.width as usize - 20, ui.theme),
                ui.theme.muted,
            ),
        ]));
    }
    if running {
        let remaining = 12usize.saturating_sub(ui.state.doctor.checks.len());
        if remaining > 0 {
            let spinner = spinner_frame(ui.theme, ui.tick);
            lines.push(Line::from(vec![
                Span::styled(format!(" {spinner} "), ui.theme.accent),
                Span::styled(
                    format!("running remaining checks ({remaining})"),
                    ui.theme.muted,
                ),
            ]));
        }
    }
    if let Some(report) = &ui.state.doctor.report {
        lines.push(Line::from(""));
        lines.push(Line::styled(T.doc_summary.to_string(), ui.theme.muted));
        let summary = &report.summary;
        lines.push(Line::from(vec![
            Span::styled("  ", ui.theme.text),
            status_symbol(ui, UiStatus::Pass),
            Span::styled(
                format!(" {} {}", summary.passed, T.doc_passed),
                ui.theme.text,
            ),
            Span::styled(
                format!(
                    "   {} {} {}",
                    ui.theme.symbols.warn, summary.warnings, T.doc_warnings
                ),
                ui.theme.warning,
            ),
            Span::styled(
                format!(
                    "   {} {} {}",
                    ui.theme.symbols.fail, summary.failed, T.doc_failed
                ),
                if summary.failed > 0 {
                    ui.theme.error
                } else {
                    ui.theme.muted
                },
            ),
            Span::styled(
                format!("   {} unsupported", summary.unsupported),
                ui.theme.muted,
            ),
        ]));
        if let Some(score) = &summary.score {
            lines.push(Line::from(vec![
                Span::styled("  ", ui.theme.text),
                Span::styled(format!("{}/{}", score.total, score.max), ui.theme.title),
                Span::styled(format!("  grade {}", score.grade), ui.theme.muted),
            ]));
        }
        if !summary.recommendations.is_empty() {
            lines.push(Line::from(""));
            lines.push(Line::styled(
                T.doc_recommendations.to_string(),
                ui.theme.muted,
            ));
            for recommendation in summary.recommendations.iter().take(4) {
                lines.push(Line::styled(
                    format!(
                        "  - {}",
                        truncate(recommendation, inner.width as usize - 6, ui.theme)
                    ),
                    ui.theme.text,
                ));
            }
        }
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_findings(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.doc_problems),
            ui.theme.muted,
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let findings = ui.state.doctor.findings();
    if findings.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if ui.state.doctor.report.is_some() {
                    T.sec_good
                } else {
                    T.doc_started
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    let rows: Vec<Vec<String>> = findings
        .iter()
        .map(|finding| {
            let target = match crate::tui::app::finding_target(&finding.id) {
                (screen, Some(tab)) => format!("{} #{}", screen.title(), tab + 1),
                (screen, None) => screen.title().to_string(),
            };
            vec![
                finding.severity.as_str().to_string(),
                truncate(&finding.title, 56, ui.theme),
                finding.category.clone(),
                target,
                format!("-{}", finding.score_impact),
            ]
        })
        .collect();
    frame.render_widget(
        list_table(
            ui,
            &["Severity", "Finding", "Category", "Investigate", "Impact"],
            rows,
            Some(ui.state.doctor.selected),
            &[
                Constraint::Length(9),
                Constraint::Min(24),
                Constraint::Length(14),
                Constraint::Length(14),
                Constraint::Length(7),
            ],
        ),
        inner,
    );
}
