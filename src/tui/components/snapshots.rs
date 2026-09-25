//! Snapshots screen: list, create, view, compare, delete, export.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::text::T;
use crate::tui::widgets::{safe, truncate};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    if let Some(diff) = &ui.state.snapshots.diff {
        render_diff(ui, frame, area, diff);
        return;
    }
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(8), Constraint::Length(3)])
        .split(area);
    render_list(ui, frame, rows[0]);
    render_hints(ui, frame, rows[1]);
}

fn render_list(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.snap_title), ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    if ui.state.snapshots.list.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(T.snap_none.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    }
    let rows: Vec<Vec<String>> = ui
        .state
        .snapshots
        .list
        .iter()
        .enumerate()
        .map(|(index, (_, snap))| {
            let marked = ui.state.snapshots.marked == Some(index);
            vec![
                if marked { "[marked]" } else { "" }.to_string(),
                snap.label
                    .clone()
                    .map(|l| safe(&l))
                    .unwrap_or_else(|| "-".into()),
                crate::core::reporting::format_epoch(snap.created_epoch),
                snap.hostname.clone().unwrap_or_else(|| "-".into()),
                snap.listening.len().to_string(),
                snap.findings.len().to_string(),
            ]
        })
        .collect();
    frame.render_widget(
        list_table(
            ui,
            &["", "Label", "Created", "Host", "Ports", "Findings"],
            rows,
            Some(ui.state.snapshots.selected),
            &[
                Constraint::Length(8),
                Constraint::Length(18),
                Constraint::Length(22),
                Constraint::Length(14),
                Constraint::Length(7),
                Constraint::Length(9),
            ],
        ),
        inner,
    );
}

fn render_hints(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border);
    let lines = vec![
        Line::styled(
            format!(
                " c {}   m {}   x {}   d {}   e {}",
                T.snap_create, T.snap_mark, T.snap_compare, T.snap_delete, T.snap_export
            ),
            ui.theme.muted,
        ),
        Line::styled(
            format!(
                " Enter {}   snapshots stored under {}",
                T.snap_view,
                crate::config::display_path(&crate::core::snapshot::snapshots_dir())
            ),
            ui.theme.muted,
        ),
    ];
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_diff(ui: &Ui, frame: &mut Frame, area: Rect, diff: &crate::core::snapshot::SnapshotDiff) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.snap_diff_title),
            ui.theme.muted,
        ));
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::styled(
        format!(" {}  ->  {}", diff.from, diff.to),
        ui.theme.muted,
    ));
    lines.push(Line::from(""));
    let mut section = |title: &str, items: &[String], style: ratatui::style::Style| {
        if items.is_empty() {
            return;
        }
        lines.push(Line::styled(title.to_string(), style));
        for item in items.iter().take(20) {
            lines.push(Line::styled(
                format!("  {}", truncate(item, inner.width as usize - 4, ui.theme)),
                ui.theme.text,
            ));
        }
        lines.push(Line::from(""));
    };
    section(T.snap_added_ports, &diff.added_ports, ui.theme.success);
    section(T.snap_removed_ports, &diff.removed_ports, ui.theme.error);
    section(
        T.snap_added_interfaces,
        &diff.added_interfaces,
        ui.theme.success,
    );
    section(
        T.snap_removed_interfaces,
        &diff.removed_interfaces,
        ui.theme.error,
    );
    section(T.snap_route_changes, &diff.route_changes, ui.theme.warning);
    section(T.snap_findings, &diff.new_findings, ui.theme.warning);
    section(T.snap_resolved, &diff.resolved_findings, ui.theme.success);
    section(T.snap_accounts, &diff.account_changes, ui.theme.warning);
    if let Some(firewall) = &diff.firewall_change {
        section(
            T.snap_firewall,
            std::slice::from_ref(firewall),
            ui.theme.warning,
        );
    }
    if diff.is_empty() {
        lines.push(Line::styled(T.snap_no_diff.to_string(), ui.theme.success));
    }
    if let Some(note) = &diff.note {
        lines.push(Line::styled(format!(" note: {note}"), ui.theme.muted));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(" Esc close".to_string(), ui.theme.muted));
    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default()),
        inner,
    );
}
