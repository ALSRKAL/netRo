//! Degraded state for terminals below the minimum usable size.

use crate::tui::caps::Caps;
use crate::tui::text::T;
use crate::tui::theme::Theme;
use ratatui::layout::{Alignment, Rect};
use ratatui::text::Line;
use ratatui::widgets::{Paragraph, Wrap};
use ratatui::Frame;

pub fn render(frame: &mut Frame, area: Rect, theme: &Theme, caps: &Caps) {
    let lines = vec![
        Line::styled(T.too_small.to_string(), theme.title),
        Line::from(""),
        Line::styled(
            format!("current: {}x{}", caps.width, caps.height),
            theme.muted,
        ),
        Line::styled(T.too_small_hint.to_string(), theme.muted),
    ];
    frame.render_widget(
        Paragraph::new(lines)
            .alignment(Alignment::Center)
            .wrap(Wrap { trim: true }),
        area,
    );
}
