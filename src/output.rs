//! Output handling: text tables, machine-readable JSON, CSV, and color policy.
//!
//! JSON output is always a single valid JSON document with no ANSI escapes and
//! no human text mixed in.

use crate::error::Result;
use crate::model::{CheckStatus, Severity};
use serde::Serialize;
use std::io::{IsTerminal, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputFormat {
    Text,
    Json,
    Csv,
}

impl OutputFormat {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "text" => Some(Self::Text),
            "json" => Some(Self::Json),
            "csv" => Some(Self::Csv),
            _ => None,
        }
    }
}

/// Resolved presentation options for a command.
#[derive(Debug, Clone)]
pub struct OutputOptions {
    pub format: OutputFormat,
    pub color: bool,
}

impl OutputOptions {
    pub fn new(format: OutputFormat, color_request: &str) -> Self {
        let color = match color_request {
            "always" => true,
            "never" => false,
            _ => std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none(),
        };
        Self { format, color }
    }

    pub fn is_json(&self) -> bool {
        self.format == OutputFormat::Json
    }

    pub fn is_csv(&self) -> bool {
        self.format == OutputFormat::Csv
    }
}

// ---------------------------------------------------------------------------
// Color
// ---------------------------------------------------------------------------

pub const RESET: &str = "\x1b[0m";
pub const BOLD: &str = "\x1b[1m";
pub const DIM: &str = "\x1b[2m";
pub const RED: &str = "\x1b[31m";
pub const GREEN: &str = "\x1b[32m";
pub const YELLOW: &str = "\x1b[33m";
pub const BLUE: &str = "\x1b[34m";
pub const CYAN: &str = "\x1b[36m";
pub const MAGENTA: &str = "\x1b[35m";

pub fn paint(enabled: bool, color: &str, text: &str) -> String {
    if enabled {
        format!("{color}{text}{RESET}")
    } else {
        text.to_string()
    }
}

pub fn severity_color(severity: Severity) -> &'static str {
    match severity {
        Severity::Info => BLUE,
        Severity::Low => CYAN,
        Severity::Medium => YELLOW,
        Severity::High => RED,
        Severity::Critical => MAGENTA,
    }
}

pub fn status_color(status: CheckStatus) -> &'static str {
    match status {
        CheckStatus::Pass => GREEN,
        CheckStatus::Warning => YELLOW,
        CheckStatus::Fail => RED,
        CheckStatus::Unsupported => DIM,
        CheckStatus::Skipped => DIM,
    }
}

// ---------------------------------------------------------------------------
// Emitters
// ---------------------------------------------------------------------------

pub fn emit_json<T: Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer_pretty(&mut lock, value)?;
    lock.write_all(b"\n")?;
    Ok(())
}

/// Emit one compact JSON value per line (JSON Lines, for monitoring streams).
pub fn emit_json_line<T: Serialize>(value: &T) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    serde_json::to_writer(&mut lock, value)?;
    lock.write_all(b"\n")?;
    lock.flush()?;
    Ok(())
}

/// Render RFC 4180 CSV.
pub fn render_csv(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut out = String::new();
    out.push_str(
        &headers
            .iter()
            .map(|h| crate::util::csv_escape(h))
            .collect::<Vec<_>>()
            .join(","),
    );
    out.push('\n');
    for row in rows {
        out.push_str(
            &row.iter()
                .map(|c| crate::util::csv_escape(c))
                .collect::<Vec<_>>()
                .join(","),
        );
        out.push('\n');
    }
    out
}

pub fn emit_csv(headers: &[&str], rows: &[Vec<String>]) -> Result<()> {
    let stdout = std::io::stdout();
    let mut lock = stdout.lock();
    lock.write_all(render_csv(headers, rows).as_bytes())?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tables
// ---------------------------------------------------------------------------

/// Simple width-aware table for text output. Uses display width naive
/// calculation (ASCII); wide characters are treated as width 1 which keeps
/// alignment stable for the ASCII report data netRo emits.
pub struct Table {
    headers: Vec<String>,
    rows: Vec<Vec<String>>,
}

impl Table {
    pub fn new(headers: &[&str]) -> Self {
        Self {
            headers: headers.iter().map(|h| h.to_string()).collect(),
            rows: Vec::new(),
        }
    }

    pub fn row<S: AsRef<str>>(&mut self, cells: &[S]) -> &mut Self {
        self.rows
            .push(cells.iter().map(|c| c.as_ref().to_string()).collect());
        self
    }

    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn render(&self) -> String {
        let cols = self.headers.len();
        let mut widths: Vec<usize> = self.headers.iter().map(|h| display_width(h)).collect();
        for row in &self.rows {
            for (i, cell) in row.iter().enumerate().take(cols) {
                widths[i] = widths[i].max(display_width(cell));
            }
        }
        let mut out = String::new();
        out.push_str(&render_row(&self.headers, &widths));
        out.push('\n');
        let sep: Vec<String> = widths.iter().map(|w| "-".repeat(*w)).collect();
        out.push_str(&sep.join("  "));
        out.push('\n');
        for row in &self.rows {
            out.push_str(&render_row(row, &widths));
            out.push('\n');
        }
        out
    }

    pub fn print(&self) {
        print!("{}", self.render());
    }
}

fn display_width(s: &str) -> usize {
    s.chars().count()
}

fn render_row(cells: &[String], widths: &[usize]) -> String {
    let mut parts: Vec<String> = Vec::with_capacity(widths.len());
    for (i, width) in widths.iter().enumerate() {
        let cell = cells.get(i).cloned().unwrap_or_default();
        let pad = width.saturating_sub(display_width(&cell));
        parts.push(format!("{cell}{}", " ".repeat(pad)));
    }
    parts.join("  ").trim_end().to_string()
}

/// Key/value block renderer.
pub fn render_kv(pairs: &[(String, String)]) -> String {
    let width = pairs
        .iter()
        .map(|(k, _)| display_width(k))
        .max()
        .unwrap_or(0);
    let mut out = String::new();
    for (k, v) in pairs {
        out.push_str(&format!("{k:<width$}  {v}\n", width = width));
    }
    out
}

/// Section header used by all text reports.
pub fn section(title: &str, color: bool) -> String {
    let line = "─".repeat(60);
    format!(
        "\n{}\n{}\n{}\n",
        paint(color, BOLD, title),
        paint(color, DIM, &line),
        ""
    )
}

/// Standard scanner-authorization notice. Always emitted on stderr in text
/// mode so it never pollutes machine-readable stdout.
pub fn authorization_notice(quiet: bool) {
    if quiet {
        return;
    }
    eprintln!(
        "note: only scan systems you own or are explicitly authorized to test. \
         Public targets require --authorized."
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn csv_render_quotes_fields() {
        let csv = render_csv(&["a", "b"], &[vec!["x,y".to_string(), "z\"q".to_string()]]);
        assert_eq!(csv, "a,b\n\"x,y\",\"z\"\"q\"\n");
    }

    #[test]
    fn table_aligns_columns() {
        let mut t = Table::new(&["name", "value"]);
        t.row(&["a", "1"]);
        t.row(&["longer", "22"]);
        let rendered = t.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert!(lines[0].starts_with("name"));
        assert!(lines.iter().any(|l| l.starts_with("longer  22")));
    }

    #[test]
    fn json_output_is_valid_and_has_no_ansi() {
        let value = serde_json::json!({"status": "PASS", "count": 3});
        let text = serde_json::to_string_pretty(&value).unwrap();
        assert!(serde_json::from_str::<serde_json::Value>(&text).is_ok());
        assert!(!text.contains("\x1b["));
    }

    #[test]
    fn format_parsing() {
        assert_eq!(OutputFormat::parse("JSON"), Some(OutputFormat::Json));
        assert_eq!(OutputFormat::parse("csv"), Some(OutputFormat::Csv));
        assert_eq!(OutputFormat::parse("xml"), None);
    }

    #[test]
    fn color_never_is_respected() {
        let opts = OutputOptions::new(OutputFormat::Text, "never");
        assert!(!opts.color);
        let opts = OutputOptions::new(OutputFormat::Text, "always");
        assert!(opts.color);
    }
}
