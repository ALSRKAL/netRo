//! Settings screen: edit validated configuration with selectors and toggles.

use crate::tui::app::Ui;
use crate::tui::state::SettingsUi;
use crate::tui::text::T;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Min(10), Constraint::Length(4)])
        .split(area);
    render_rows(ui, frame, rows[0]);
    render_footer(ui, frame, rows[1]);
}

fn section_label(ui: &Ui, label: &str, lines: &mut Vec<Line>) {
    lines.push(Line::styled(label.to_string(), ui.theme.muted));
}

fn value_line(ui: &Ui, selected: bool, label: &str, value: String) -> Line<'static> {
    let marker = if selected {
        ui.theme.symbols.selected
    } else {
        " "
    };
    Line::from(vec![
        Span::styled(format!(" {marker} "), ui.theme.accent),
        Span::styled(format!("{label:<22}"), ui.theme.text),
        Span::styled(
            value,
            if selected {
                ui.theme.selected
            } else {
                ui.theme.muted
            },
        ),
    ])
}

fn render_rows(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.set_title), ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let draft = &ui.state.settings.draft;
    let selected = ui.state.settings.selected;
    let mut lines: Vec<Line> = Vec::new();
    let labels = SettingsUi::row_labels();

    section_label(ui, T.set_appearance, &mut lines);
    lines.push(value_line(
        ui,
        selected == 0,
        labels[0],
        format!("{} (Left/Right)", ui.state.theme_kind.label()),
    ));
    lines.push(value_line(
        ui,
        selected == 1,
        labels[1],
        format!("{} (Left/Right)", draft.output.color),
    ));
    lines.push(value_line(
        ui,
        selected == 2,
        labels[2],
        format!(
            "{} (Left/Right)",
            if ui.caps.unicode { "on" } else { "off" }
        ),
    ));

    section_label(ui, T.set_monitoring, &mut lines);
    lines.push(value_line(
        ui,
        selected == 3,
        labels[3],
        format!("{:.1}s (Enter to edit)", draft.monitor.interval_secs),
    ));
    lines.push(value_line(
        ui,
        selected == 4,
        labels[4],
        format!("{:.1}s (Enter to edit)", draft.monitor.interval_secs),
    ));

    section_label(ui, T.set_scan, &mut lines);
    lines.push(value_line(
        ui,
        selected == 5,
        labels[5],
        format!("{} (Left/Right)", draft.discovery.method),
    ));
    lines.push(value_line(
        ui,
        selected == 6,
        labels[6],
        format!("{} (Enter to edit)", draft.scan.ports),
    ));
    lines.push(value_line(
        ui,
        selected == 7,
        labels[7],
        format!("{} (Enter to edit)", draft.scan.timeout_ms),
    ));
    lines.push(value_line(
        ui,
        selected == 8,
        labels[8],
        format!("{} (Enter to edit)", draft.scan.concurrency),
    ));

    section_label(ui, T.set_privacy, &mut lines);
    lines.push(value_line(
        ui,
        selected == 9,
        labels[9],
        format!(
            "{} (Space/Left/Right)",
            if draft.privacy.reverse_dns {
                "on"
            } else {
                "off"
            }
        ),
    ));
    lines.push(value_line(
        ui,
        selected == 10,
        labels[10],
        format!(
            "{} (Space/Left/Right)",
            if draft.privacy.vendor_lookup {
                "on"
            } else {
                "off"
            }
        ),
    ));

    section_label(ui, T.set_integrations, &mut lines);
    lines.push(value_line(
        ui,
        selected == 11,
        labels[11],
        format!(
            "{} (Enter to edit)",
            draft
                .integrations
                .oui_file
                .clone()
                .unwrap_or_else(|| "-".into())
        ),
    ));
    lines.push(value_line(
        ui,
        selected == 12,
        labels[12],
        format!(
            "{} (Enter to edit)",
            draft
                .integrations
                .speedtest_server
                .clone()
                .unwrap_or_else(|| "-".into())
        ),
    ));

    lines.push(Line::from(""));
    lines.push(value_line(
        ui,
        selected == 13,
        labels[13],
        if ui.state.settings.dirty {
            "press Enter or s to save (unsaved changes)".to_string()
        } else {
            "press Enter or s to save".to_string()
        },
    ));
    lines.push(Line::styled(
        "  Configuration is written with 0600 permissions where supported.".to_string(),
        ui.theme.muted,
    ));

    frame.render_widget(
        Paragraph::new(lines)
            .wrap(Wrap { trim: false })
            .block(Block::default()),
        inner,
    );
}

fn render_footer(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border);
    let mut lines = vec![Line::styled(
        " Up/Down move   Left/Right change   Enter edit/save   s save".to_string(),
        ui.theme.muted,
    )];
    if ui.state.settings.dirty {
        lines.push(Line::styled(
            format!(" {} unsaved changes", ui.theme.symbols.warn),
            ui.theme.warning,
        ));
    } else {
        lines.push(Line::styled(
            format!(
                " saved config: {}",
                crate::config::display_path(&crate::config::config_file())
            ),
            ui.theme.muted,
        ));
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}
