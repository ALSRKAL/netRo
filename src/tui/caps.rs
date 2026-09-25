//! Terminal capability detection.
//!
//! Everything the UI adapts to (size, color depth, Unicode support) is
//! detected here once at startup. Nothing assumes a modern terminal.

use crossterm::terminal;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ColorMode {
    /// No color at all (NO_COLOR, TERM=dumb, or an unknown terminal).
    None,
    /// Basic 16 ANSI colors.
    Ansi16,
    /// 256 indexed colors.
    Ansi256,
    /// 24-bit color.
    TrueColor,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Breakpoint {
    /// < 40 columns: single pane, minimal chrome.
    Tiny,
    /// < 60 columns: compact navigation.
    Small,
    /// < 120 columns: no live status panel.
    Medium,
    /// Full three-pane layout.
    Large,
}

#[derive(Debug, Clone)]
pub struct Caps {
    pub width: u16,
    pub height: u16,
    pub colors: ColorMode,
    pub unicode: bool,
    pub mouse: bool,
    /// True when stdin/stdout are a terminal.
    pub interactive: bool,
}

impl Caps {
    pub fn detect() -> Self {
        let (width, height) = terminal::size().unwrap_or((80, 24));
        Self {
            width,
            height,
            colors: detect_color_mode(),
            unicode: detect_unicode(),
            mouse: true,
            interactive: std::io::IsTerminal::is_terminal(&std::io::stdout())
                && std::io::IsTerminal::is_terminal(&std::io::stdin()),
        }
    }

    pub fn breakpoint(&self) -> Breakpoint {
        match self.width {
            w if w < 40 => Breakpoint::Tiny,
            w if w < 60 => Breakpoint::Small,
            w if w < 120 => Breakpoint::Medium,
            _ => Breakpoint::Large,
        }
    }

    pub fn with_size(&self, width: u16, height: u16) -> Self {
        let mut caps = self.clone();
        caps.width = width;
        caps.height = height;
        caps
    }
}

pub fn detect_color_mode() -> ColorMode {
    if std::env::var_os("NO_COLOR").is_some() {
        return ColorMode::None;
    }
    let term = std::env::var("TERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if term == "dumb" {
        return ColorMode::None;
    }
    let colorterm = std::env::var("COLORTERM")
        .unwrap_or_default()
        .to_ascii_lowercase();
    if colorterm.contains("truecolor") || colorterm.contains("24bit") {
        return ColorMode::TrueColor;
    }
    if term.contains("truecolor") || term.contains("24bit") {
        return ColorMode::TrueColor;
    }
    if term.contains("256color") || term.contains("256") {
        return ColorMode::Ansi256;
    }
    if std::env::var("COLORTERM").is_ok() {
        return ColorMode::Ansi16;
    }
    // Unknown TERM: basic colors are still safer than none.
    if term.is_empty() && cfg!(windows) {
        return ColorMode::Ansi16;
    }
    ColorMode::Ansi16
}

pub fn detect_unicode() -> bool {
    if std::env::var_os("NETRO_ASCII").is_some() {
        return false;
    }
    for key in ["LC_ALL", "LC_CTYPE", "LANG"] {
        if let Ok(value) = std::env::var(key) {
            if !value.is_empty() {
                let lowered = value.to_ascii_lowercase();
                return lowered.contains("utf-8") || lowered.contains("utf8");
            }
        }
    }
    // Windows Terminal / modern consoles default to UTF-8 capable output.
    cfg!(windows)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn breakpoints_are_monotonic() {
        let caps = Caps {
            width: 30,
            height: 20,
            colors: ColorMode::Ansi16,
            unicode: false,
            mouse: false,
            interactive: true,
        };
        assert_eq!(caps.breakpoint(), Breakpoint::Tiny);
        assert_eq!(caps.with_size(50, 20).breakpoint(), Breakpoint::Small);
        assert_eq!(caps.with_size(100, 20).breakpoint(), Breakpoint::Medium);
        assert_eq!(caps.with_size(160, 40).breakpoint(), Breakpoint::Large);
    }

    #[test]
    fn color_mode_ordering() {
        assert!(ColorMode::None < ColorMode::Ansi16);
        assert!(ColorMode::Ansi16 < ColorMode::Ansi256);
        assert!(ColorMode::Ansi256 < ColorMode::TrueColor);
    }
}
