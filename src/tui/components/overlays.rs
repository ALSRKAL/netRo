//! Overlay components: help, command palette, confirmation, input, error and
//! detail drawers. Overlays are drawn last and never modify state themselves.

use crate::tui::app::{palette_matches, Ui};
use crate::tui::state::Overlay;
use crate::tui::text::T;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(overlay: &Overlay, ui: &Ui, frame: &mut Frame, area: Rect) {
    match overlay {
        Overlay::None => {}
        Overlay::Help => render_help(ui, frame, area),
        Overlay::Palette(state) => render_palette(ui, frame, area, state),
        Overlay::Confirm(state) => render_confirm(ui, frame, area, state),
        Overlay::Input(state) => render_input(ui, frame, area, state),
        Overlay::Error(error) => render_error(ui, frame, area, error),
        Overlay::Detail(state) => render_detail(ui, frame, area, state),
    }
}

fn centered(area: Rect, width: u16, height: u16) -> Rect {
    let width = width.min(area.width.saturating_sub(2)).max(20);
    let height = height.min(area.height.saturating_sub(2)).max(5);
    let x = area.x + (area.width.saturating_sub(width)) / 2;
    let y = area.y + (area.height.saturating_sub(height)) / 2;
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn block(ui: &Ui, title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.accent)
        .title(Span::styled(format!(" {title} "), ui.theme.title))
}

fn render_help(ui: &Ui, frame: &mut Frame, area: Rect) {
    let area = centered(area, 64, 26);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::styled(T.overlay_help.to_string(), ui.theme.title),
        Line::from(""),
    ];
    let sections: Vec<(&str, Vec<(&str, &str)>)> = vec![
        (
            "Navigation",
            vec![
                ("↑ ↓ / j k", "Move selection"),
                ("Enter", "Open / activate"),
                ("Esc", "Back / cancel / clear filter"),
                ("Tab / Shift+Tab", "Next / previous screen"),
                ("q", "Quit netro"),
            ],
        ),
        (
            "Global",
            vec![
                ("/", "Filter the current list"),
                ("Ctrl+P", "Command palette"),
                ("r", "Refresh current screen"),
                ("R", "Refresh everything"),
                ("?", "This help"),
                ("Ctrl+C", "Quit immediately"),
            ],
        ),
        (
            "Screens",
            vec![
                ("d", "Run doctor"),
                ("g", "Run current action (scan/discovery/report)"),
                ("p", "Pause monitor"),
                ("+ / -", "Monitor interval"),
                ("c / s", "Create baseline / scan integrity"),
                ("b / u", "Block / unblock IP (firewall)"),
                ("x / e / m", "Compare / export / mark snapshot"),
            ],
        ),
    ];
    for (title, entries) in sections {
        lines.push(Line::styled(title.to_string(), ui.theme.muted));
        for (key, label) in entries {
            lines.push(Line::from(vec![
                Span::styled(format!("  {key:<16}"), ui.theme.keycap),
                Span::styled(label.to_string(), ui.theme.text),
            ]));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(
        "Esc closes this help".to_string(),
        ui.theme.muted,
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block(ui, T.overlay_help))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_palette(ui: &Ui, frame: &mut Frame, area: Rect, state: &crate::tui::state::PaletteState) {
    let matches = palette_matches(&state.query);
    let height = (matches.len() as u16 + 6).clamp(7, 20);
    let area = centered(area, 62, height);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::styled(
            format!("> {}", state.query),
            if state.query.is_empty() {
                ui.theme.muted
            } else {
                ui.theme.text
            },
        ),
        Line::from(""),
    ];
    if matches.is_empty() {
        lines.push(Line::styled(T.palette_empty.to_string(), ui.theme.muted));
    }
    for (index, command) in matches.iter().enumerate() {
        let selected = index == state.selected;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        lines.push(Line::from(vec![
            Span::styled(format!(" {marker} "), ui.theme.accent),
            Span::styled(
                command.label.to_string(),
                if selected {
                    ui.theme.selected
                } else {
                    ui.theme.text
                },
            ),
            Span::styled(format!("   {}", command.hint), ui.theme.muted),
        ]));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        format!(" {}   {}   {}", T.palette_query, "Enter run", "Esc close"),
        ui.theme.muted,
    ));
    frame.render_widget(
        Paragraph::new(lines).block(block(ui, T.overlay_palette)),
        area,
    );
}

fn render_confirm(ui: &Ui, frame: &mut Frame, area: Rect, state: &crate::tui::state::ConfirmState) {
    let height = (state.lines.len() as u16 + 5).clamp(7, 16);
    let area = centered(area, 64, height);
    frame.render_widget(Clear, area);
    let mut lines = vec![
        Line::styled(state.title.clone(), ui.theme.title),
        Line::from(""),
    ];
    for line in &state.lines {
        let style = if line.starts_with("This does NOT") || line.contains("NOT disconnect") {
            ui.theme.warning
        } else {
            ui.theme.text
        };
        lines.push(Line::styled(line.clone(), style));
    }
    lines.push(Line::from(""));
    lines.push(Line::from(vec![Span::styled(
        "  Enter/y Apply    Esc/n Cancel",
        ui.theme.muted,
    )]));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block(ui, T.overlay_confirm))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_input(ui: &Ui, frame: &mut Frame, area: Rect, state: &crate::tui::state::InputState) {
    let area = centered(area, 60, 7);
    frame.render_widget(Clear, area);
    let lines = vec![
        Line::styled(state.prompt.clone(), ui.theme.title),
        Line::from(""),
        Line::from(vec![
            Span::styled("  > ", ui.theme.accent),
            Span::styled(state.value.clone(), ui.theme.text),
            Span::styled("_", ui.theme.accent),
        ]),
        Line::from(""),
        Line::styled("  Enter confirm    Esc cancel", ui.theme.muted),
    ];
    frame.render_widget(Paragraph::new(lines).block(block(ui, "INPUT")), area);
}

fn render_error(ui: &Ui, frame: &mut Frame, area: Rect, error: &crate::error::NetroError) {
    let area = centered(area, 66, 12);
    frame.render_widget(Clear, area);
    let status = crate::tui::theme::UiStatus::from_error(error);
    let required = match error.code() {
        crate::error::ErrorCode::PermissionDenied
        | crate::error::ErrorCode::OperationNotPermitted => Some(T.permission_required),
        crate::error::ErrorCode::DependencyMissing => Some("Install the missing dependency"),
        crate::error::ErrorCode::PlatformUnsupported => Some(T.unsupported),
        _ => None,
    };
    let mut lines = vec![
        Line::from(vec![
            crate::tui::components::status_symbol(ui, status),
            Span::styled(format!("  {}", error.code().as_str()), ui.theme.error),
        ]),
        Line::from(""),
        Line::styled(T.error_reason.to_string(), ui.theme.muted),
        Line::styled(format!("  {}", error.message()), ui.theme.text),
    ];
    if let Some(required) = required {
        lines.push(Line::from(""));
        lines.push(Line::styled(T.error_required.to_string(), ui.theme.muted));
        lines.push(Line::styled(format!("  {required}"), ui.theme.warning));
    }
    if let Some(hint) = error.hint() {
        lines.push(Line::styled(format!("  {hint}"), ui.theme.muted));
    }
    lines.push(Line::from(""));
    lines.push(Line::styled(
        T.error_details_hint.to_string(),
        ui.theme.muted,
    ));
    frame.render_widget(
        Paragraph::new(lines)
            .block(block(ui, T.overlay_error))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn render_detail(ui: &Ui, frame: &mut Frame, area: Rect, state: &crate::tui::state::DetailState) {
    let width = (area.width * 3 / 4).clamp(40, 100);
    let height = (area.height * 3 / 4).clamp(10, area.height.saturating_sub(2));
    let area = centered(area, width, height);
    frame.render_widget(Clear, area);
    let inner = block(ui, &state.title).inner(area);
    frame.render_widget(block(ui, &state.title), area);

    let mut lines: Vec<Line> = Vec::new();
    for (title, entries) in &state.sections {
        lines.push(Line::styled(title.clone().to_uppercase(), ui.theme.muted));
        for entry in entries {
            if entry.is_empty() {
                continue;
            }
            lines.push(Line::styled(
                format!("  {}", crate::util::sanitize_terminal(entry)),
                ui.theme.text,
            ));
        }
        lines.push(Line::from(""));
    }
    lines.push(Line::styled(T.detail_close.to_string(), ui.theme.muted));

    let paragraph = Paragraph::new(lines)
        .wrap(Wrap { trim: false })
        .scroll((state.scroll, 0));
    frame.render_widget(paragraph, inner);
}

/// Re-export used by settings/forms that need a two-column layout.
pub fn form_layout(area: Rect) -> Vec<Rect> {
    Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(1),
            Constraint::Min(3),
            Constraint::Length(2),
        ])
        .split(area)
        .to_vec()
}
