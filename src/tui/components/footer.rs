//! Contextual key hints footer.

use crate::tui::app::Ui;
use crate::tui::state::Screen;
use crate::tui::text::T;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::Paragraph;
use ratatui::Frame;

fn hint(ui: &Ui, key: &str, label: &str) -> Vec<Span<'static>> {
    vec![
        Span::styled(format!(" {key} "), ui.theme.keycap),
        Span::styled(format!("{label}  "), ui.theme.muted),
    ]
}

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    if ui.state.overlay.is_open() {
        spans.extend(hint(ui, "Esc", T.hint_back));
    } else if ui.state.filtering || !ui.state.filter.is_empty() {
        spans.extend(hint(ui, "Enter", "Apply filter"));
        spans.extend(hint(ui, "Esc", "Clear"));
    } else {
        spans.extend(hint(ui, ui.theme.symbols.arrow, T.hint_navigate));
        spans.extend(hint(ui, "Enter", T.hint_open));
        spans.extend(hint(ui, "/", T.hint_search));
        spans.extend(hint(ui, "r", T.hint_refresh));
        spans.extend(hint(ui, "?", T.hint_help));
        if ui.tasks_running() {
            spans.extend(hint(ui, "Esc", T.hint_cancel));
        }
        spans.extend(hint(ui, "q", T.hint_quit));
    }
    let mut lines = vec![Line::from(spans)];
    if area.height >= 2 {
        let context = match ui.state.screen {
            Screen::Monitor => format!(
                "  p pause   +/- interval ({:.2}s)   {} {}",
                ui.state.monitor.interval_secs(),
                T.mon_history,
                ui.state.monitor.cpu_history.len()
            ),
            Screen::Scanner => {
                "  \u{2190}/\u{2192} field   Space toggle   1/2/3 tabs   g start scan   e export"
                    .to_string()
            }
            Screen::Discovery => "  Space options   g start   Esc cancel".to_string(),
            Screen::Security => "  Left/Right tabs   Enter details".to_string(),
            Screen::Snapshots => {
                "  c create   m mark   x compare   d delete   e export".to_string()
            }
            Screen::Settings => "  Left/Right change   Enter edit   s save".to_string(),
            Screen::Doctor => "  Enter investigate   i details   d re-run".to_string(),
            Screen::Reports => "  Left/Right select   Enter edit/generate   g generate".to_string(),
            _ => format!("  Tab next screen   Ctrl+P {}", T.hint_palette),
        };
        lines.push(Line::styled(context, ui.theme.muted));
    }
    frame.render_widget(Paragraph::new(lines), area);
}

impl Ui<'_> {
    fn tasks_running(&self) -> bool {
        !self.running.is_empty()
    }
}
