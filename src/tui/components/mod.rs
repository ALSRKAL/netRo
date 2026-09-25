//! Component dispatch and shared helpers.
//!
//! Each screen is a component: it receives the read-only [`crate::tui::app::Ui`]
//! context and a `Rect`, and renders itself. Components never perform IO.

use crate::tui::app::Ui;
use crate::tui::state::Screen;
use ratatui::layout::Constraint;
use ratatui::widgets::{Cell, Row, Table};
use ratatui::Frame;

pub mod dashboard;
pub mod discovery;
pub mod doctor;
pub mod footer;
pub mod monitor;
pub mod nav;
pub mod network;
pub mod overlays;
pub mod reports;
pub mod scanner;
pub mod security;
pub mod settings;
pub mod snapshots;
pub mod status;
pub mod system;
pub mod too_small;

pub fn screen(screen: Screen, ui: &Ui, frame: &mut Frame, area: ratatui::layout::Rect) {
    match screen {
        Screen::Dashboard => dashboard::render(ui, frame, area),
        Screen::System => system::render(ui, frame, area),
        Screen::Network => network::render(ui, frame, area),
        Screen::Discovery => discovery::render(ui, frame, area),
        Screen::Scanner => scanner::render(ui, frame, area),
        Screen::Security => security::render(ui, frame, area),
        Screen::Monitor => monitor::render(ui, frame, area),
        Screen::Doctor => doctor::render(ui, frame, area),
        Screen::Reports => reports::render(ui, frame, area),
        Screen::Snapshots => snapshots::render(ui, frame, area),
        Screen::Settings => settings::render(ui, frame, area),
    }
}

/// Selected-aware table used by every list component.
pub fn list_table(
    ui: &Ui,
    headers: &[&str],
    rows: Vec<Vec<String>>,
    selected: Option<usize>,
    widths: &[Constraint],
) -> Table<'static> {
    let theme = ui.theme;
    let header = Row::new(headers.iter().map(|h| Cell::from((*h).to_string()))).style(theme.muted);
    let body: Vec<Row<'static>> = rows
        .into_iter()
        .enumerate()
        .map(|(index, cells)| {
            let is_selected = Some(index) == selected;
            let mut rendered: Vec<Cell<'static>> = Vec::with_capacity(cells.len());
            for (cell_index, cell) in cells.into_iter().enumerate() {
                if cell_index == 0 && is_selected {
                    rendered.push(Cell::from(format!("{} {}", theme.symbols.selected, cell)));
                } else {
                    rendered.push(Cell::from(cell));
                }
            }
            let style = if is_selected {
                theme.selected
            } else {
                theme.text
            };
            Row::new(rendered).style(style)
        })
        .collect();
    Table::new(body, widths.to_vec())
        .header(header)
        .column_spacing(1)
}

/// Centered empty-state paragraph text.
pub fn empty_state(ui: &Ui, message: &str) -> ratatui::text::Text<'static> {
    ratatui::text::Text::from(vec![
        ratatui::text::Line::from(""),
        ratatui::text::Line::styled(format!("  {}", message), ui.theme.muted),
        ratatui::text::Line::styled(
            format!("  {}", crate::tui::text::T.retry_hint),
            ui.theme.muted,
        ),
    ])
}

/// Theme-bound status helpers so components can pass the Ui context directly.
pub fn status_symbol(ui: &Ui, status: crate::tui::theme::UiStatus) -> ratatui::text::Span<'static> {
    crate::tui::widgets::status_symbol(ui.theme, status)
}

pub fn status_badge(ui: &Ui, status: crate::tui::theme::UiStatus) -> ratatui::text::Span<'static> {
    crate::tui::widgets::status_badge(ui.theme, status)
}

/// Render a toggled checkbox with a real state symbol.
pub fn checkbox(ui: &Ui, value: bool) -> String {
    let symbols = ui.theme.symbols;
    if value {
        symbols.check_on.to_string()
    } else {
        symbols.check_off.to_string()
    }
}

/// Format an error for inline display (never a raw `Debug` dump).
pub fn error_text(error: &crate::error::NetroError) -> Vec<String> {
    let mut lines = vec![format!("{}", error.message())];
    if let Some(hint) = error.hint() {
        lines.push(format!("hint: {hint}"));
    }
    lines.push(format!("code: {}", error.code().as_str()));
    lines
}
