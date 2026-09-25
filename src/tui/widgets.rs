//! Reusable presentation widgets: badges, gauges, bars, sparklines and tables.
//!
//! All of them are pure formatting helpers over domain data and take the theme
//! as an argument; none of them perform IO.

use crate::tui::theme::{Theme, UiStatus};
use ratatui::layout::Constraint;
use ratatui::style::Style;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Cell, Row, Table, TableState};
use unicode_width::UnicodeWidthStr;

/// Status badge: symbol + label, colored semantically. Never color-only.
pub fn status_badge(theme: &Theme, status: UiStatus) -> Span<'static> {
    let symbol = theme.symbols.for_status(status);
    Span::styled(
        format!("{symbol} {}", status.label()),
        theme.status_style(status),
    )
}

pub fn severity_badge(theme: &Theme, severity: crate::model::Severity) -> Span<'static> {
    status_badge(theme, UiStatus::from_severity(severity))
}

pub fn status_symbol(theme: &Theme, status: UiStatus) -> Span<'static> {
    Span::styled(
        theme.symbols.for_status(status).to_string(),
        theme.status_style(status),
    )
}

/// Sanitize any string that originated outside the process (service banners,
/// certificate fields, DNS answers, discovered hostnames) before it reaches a
/// terminal cell. TUI-specific regression tests assert this cannot regress.
pub fn safe(text: &str) -> String {
    crate::util::sanitize_terminal(text)
}

/// Truncate to a display width, appending the theme ellipsis when cut.
pub fn truncate(text: &str, width: usize, theme: &Theme) -> String {
    if width == 0 {
        return String::new();
    }
    if UnicodeWidthStr::width(text) <= width {
        return text.to_string();
    }
    let ellipsis = theme.symbols.ellipsis;
    let ellipsis_width = UnicodeWidthStr::width(ellipsis);
    if width <= ellipsis_width {
        return ellipsis.chars().take(width).collect();
    }
    let budget = width - ellipsis_width;
    let mut out = String::new();
    let mut used = 0usize;
    for ch in text.chars() {
        let w = unicode_width::UnicodeWidthChar::width(ch).unwrap_or(0);
        if used + w > budget {
            break;
        }
        out.push(ch);
        used += w;
    }
    out.push_str(ellipsis);
    out
}

/// `label  ██████░░░░  68%` using theme symbols (ASCII fallback included).
pub fn gauge_line(theme: &Theme, label: &str, percent: f64, width: usize) -> Line<'static> {
    let pct = percent.clamp(0.0, 100.0);
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    let bar = format!(
        "{}{}",
        theme.symbols.bar_full.repeat(filled),
        theme.symbols.bar_empty.repeat(width.saturating_sub(filled))
    );
    let color = if pct >= 90.0 {
        theme.error
    } else if pct >= 75.0 {
        theme.warning
    } else {
        theme.progress
    };
    Line::from(vec![
        Span::styled(format!("{label:<10}"), theme.muted),
        Span::styled(bar, color),
        Span::styled(format!("  {pct:>5.1}%"), theme.text),
    ])
}

/// Compact inline bar used inside table cells.
pub fn mini_bar(theme: &Theme, percent: f64, width: usize) -> String {
    let pct = percent.clamp(0.0, 100.0);
    let filled = ((pct / 100.0) * width as f64).round() as usize;
    format!(
        "{}{}",
        theme.symbols.bar_full.repeat(filled),
        theme.symbols.bar_empty.repeat(width.saturating_sub(filled))
    )
}

/// Sparkline from a rolling history (values are scaled to `max`, which must be
/// a real bound, e.g. 100 for percentages).
pub fn sparkline(theme: &Theme, values: &[f64], max: f64, width: usize) -> String {
    if values.is_empty() || max <= 0.0 {
        return theme.symbols.bar_empty.repeat(width);
    }
    let take = values.len().min(width);
    let slice = &values[values.len() - take..];
    let levels = theme.symbols.spark.len();
    let mut out = String::new();
    for value in slice {
        let ratio = (value / max).clamp(0.0, 1.0);
        let index = ((ratio * (levels - 1) as f64).round() as usize).min(levels - 1);
        out.push(theme.symbols.spark[index]);
    }
    // Right-align short histories.
    let pad = width.saturating_sub(take);
    format!("{}{}", theme.symbols.bar_empty.repeat(pad), out)
}

/// `[██████░░░░] 67%` determinate progress from real counts.
pub fn progress_bar(theme: &Theme, completed: usize, total: usize, width: usize) -> Line<'static> {
    let percent = if total == 0 {
        0.0
    } else {
        completed as f64 / total as f64 * 100.0
    };
    let filled = if total == 0 {
        0
    } else {
        ((completed as f64 / total as f64) * width as f64).round() as usize
    };
    let bar = format!(
        "{}{}",
        theme.symbols.bar_full.repeat(filled.min(width)),
        theme.symbols.bar_empty.repeat(width.saturating_sub(filled))
    );
    Line::from(vec![
        Span::styled(bar, theme.progress),
        Span::styled(
            format!(" {completed}/{total} ({percent:>3.0}%)"),
            theme.muted,
        ),
    ])
}

/// Indeterminate spinner frame from a tick counter (never a fake percentage).
pub fn spinner_frame(theme: &Theme, tick: u64) -> &'static str {
    let frames = theme.symbols.spinner;
    frames[(tick as usize) % frames.len()]
}

/// Key-value lines with muted keys, for detail panes.
pub fn kv_lines(theme: &Theme, pairs: &[(String, String)]) -> Vec<Line<'static>> {
    let width = pairs
        .iter()
        .map(|(k, _)| UnicodeWidthStr::width(k.as_str()))
        .max()
        .unwrap_or(0);
    pairs
        .iter()
        .map(|(k, v)| {
            Line::from(vec![
                Span::styled(format!("{:<width$}  ", k, width = width), theme.muted),
                Span::styled(v.clone(), theme.text),
            ])
        })
        .collect()
}

pub fn section_title(theme: &Theme, title: &str) -> Line<'static> {
    Line::from(Span::styled(title.to_string(), theme.title))
}

pub fn muted_line(theme: &Theme, text: &str) -> Line<'static> {
    Line::from(Span::styled(text.to_string(), theme.muted))
}

pub fn error_line(theme: &Theme, text: &str) -> Line<'static> {
    Line::from(vec![
        Span::styled(format!("{} ", theme.symbols.fail), theme.error),
        Span::styled(text.to_string(), theme.error),
    ])
}

/// Build a selectable table. Cells are already-styled strings; long values must
/// be truncated by the caller with real widths.
pub fn selectable_table<'a>(
    rows: Vec<Row<'a>>,
    headers: &'a [&'a str],
    widths: &[Constraint],
    selected: Option<usize>,
) -> Table<'a> {
    let header = Row::new(headers.iter().map(|h| Cell::from(h.to_string())));
    let mut table = Table::new(rows, widths.to_vec())
        .header(header)
        .column_spacing(1);
    if let Some(index) = selected {
        table = table.row_highlight_style(Style::default());
        let mut state = TableState::default();
        state.select(Some(index));
        // ratatui renders the highlight for the state passed via StatefulWidget;
        // callers using `render_widget` rely on `Table::highlight_symbol`.
        table = table.highlight_symbol("");
    }
    table
}

/// Convenience for computing widths that always sum to `total`.
pub fn flex_widths(weights: &[u16], total: u16) -> Vec<Constraint> {
    let total_weight: u32 = weights.iter().map(|w| *w as u32).sum();
    if total_weight == 0 {
        return weights.iter().map(|_| Constraint::Length(0)).collect();
    }
    let mut out = Vec::with_capacity(weights.len());
    let mut used = 0u16;
    for (index, weight) in weights.iter().enumerate() {
        if index == weights.len() - 1 {
            out.push(Constraint::Length(total.saturating_sub(used)));
        } else {
            let width = ((*weight as u32 * total as u32) / total_weight) as u16;
            used = used.saturating_add(width);
            out.push(Constraint::Length(width));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::caps::ColorMode;
    use crate::tui::theme::ThemeKind;

    fn theme() -> Theme {
        Theme::new(ThemeKind::Dark, ColorMode::Ansi16, false)
    }

    #[test]
    fn truncation_respects_width_and_marks_cut() {
        let theme = theme();
        assert_eq!(truncate("short", 10, &theme), "short");
        let cut = truncate("a very long value indeed", 10, &theme);
        assert!(cut.chars().count() <= 10);
        assert!(cut.ends_with(".."));
    }

    #[test]
    fn gauge_and_bar_have_expected_length() {
        let theme = theme();
        let line = gauge_line(&theme, "CPU", 50.0, 10);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("#####....."));
        assert!(text.contains("50.0%"));
    }

    #[test]
    fn sparkline_scales_and_pads() {
        let theme = theme();
        let line = sparkline(&theme, &[0.0, 50.0, 100.0], 100.0, 6);
        assert_eq!(line.chars().count(), 6);
        assert!(line.starts_with("..."));
    }

    #[test]
    fn progress_bar_uses_real_counts() {
        let theme = theme();
        let line = progress_bar(&theme, 67, 100, 10);
        let text: String = line.spans.iter().map(|s| s.content.to_string()).collect();
        assert!(text.contains("67/100"));
        assert!(text.contains("67%"));
    }

    #[test]
    fn status_badge_is_never_empty() {
        let theme = theme();
        for status in [UiStatus::Pass, UiStatus::Error, UiStatus::Running] {
            let badge = status_badge(&theme, status);
            assert!(!badge.content.is_empty());
        }
    }

    #[test]
    fn flex_widths_sum_to_total() {
        let widths = flex_widths(&[2, 1, 1], 80);
        let sum: u16 = widths
            .iter()
            .map(|c| match c {
                Constraint::Length(l) => *l,
                _ => 0,
            })
            .sum();
        assert_eq!(sum, 80);
    }
}
