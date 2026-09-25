//! Centralized semantic theme.
//!
//! Components never hardcode colors; they ask the theme for a semantic role.
//! Status is always conveyed by a symbol + text as well as color.

use crate::model::{CheckStatus, Severity};
use crate::tui::caps::ColorMode;
use ratatui::style::{Color, Modifier, Style};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThemeKind {
    /// Follow the terminal (currently maps to Dark; kept for future detection).
    Auto,
    Dark,
    Light,
    HighContrast,
    NoColor,
}

impl ThemeKind {
    pub fn label(self) -> &'static str {
        match self {
            ThemeKind::Auto => "Auto",
            ThemeKind::Dark => "Dark",
            ThemeKind::Light => "Light",
            ThemeKind::HighContrast => "High contrast",
            ThemeKind::NoColor => "No color",
        }
    }

    pub fn next(self) -> Self {
        match self {
            ThemeKind::Auto => ThemeKind::Dark,
            ThemeKind::Dark => ThemeKind::Light,
            ThemeKind::Light => ThemeKind::HighContrast,
            ThemeKind::HighContrast => ThemeKind::NoColor,
            ThemeKind::NoColor => ThemeKind::Auto,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum UiStatus {
    Pass,
    Warning,
    Error,
    Critical,
    Running,
    Cancelled,
    Unsupported,
    PermissionRequired,
    Unavailable,
    Info,
    Unknown,
}

impl UiStatus {
    pub fn label(self) -> &'static str {
        match self {
            UiStatus::Pass => "PASS",
            UiStatus::Warning => "WARNING",
            UiStatus::Error => "ERROR",
            UiStatus::Critical => "CRITICAL",
            UiStatus::Running => "RUNNING",
            UiStatus::Cancelled => "CANCELLED",
            UiStatus::Unsupported => "UNSUPPORTED",
            UiStatus::PermissionRequired => "PERMISSION REQUIRED",
            UiStatus::Unavailable => "UNAVAILABLE",
            UiStatus::Info => "INFO",
            UiStatus::Unknown => "UNKNOWN",
        }
    }

    pub fn from_check(status: CheckStatus) -> Self {
        match status {
            CheckStatus::Pass => UiStatus::Pass,
            CheckStatus::Warning => UiStatus::Warning,
            CheckStatus::Fail => UiStatus::Error,
            CheckStatus::Unsupported => UiStatus::Unsupported,
            CheckStatus::Skipped => UiStatus::Cancelled,
        }
    }

    pub fn from_severity(severity: Severity) -> Self {
        match severity {
            Severity::Info => UiStatus::Info,
            Severity::Low => UiStatus::Warning,
            Severity::Medium => UiStatus::Warning,
            Severity::High => UiStatus::Error,
            Severity::Critical => UiStatus::Critical,
        }
    }

    pub fn from_error(error: &crate::error::NetroError) -> Self {
        use crate::error::ErrorCode;
        match error.code() {
            ErrorCode::PermissionDenied | ErrorCode::OperationNotPermitted => {
                UiStatus::PermissionRequired
            }
            ErrorCode::DependencyMissing => UiStatus::Unavailable,
            ErrorCode::PlatformUnsupported => UiStatus::Unsupported,
            ErrorCode::Cancelled => UiStatus::Cancelled,
            _ => UiStatus::Error,
        }
    }
}

/// Unicode or ASCII status symbols. Far more robust than color alone.
#[derive(Debug, Clone, Copy)]
pub struct Symbols {
    pub pass: &'static str,
    pub warn: &'static str,
    pub fail: &'static str,
    pub info: &'static str,
    pub arrow: &'static str,
    pub selected: &'static str,
    pub bullet: &'static str,
    pub bar_full: &'static str,
    pub bar_empty: &'static str,
    pub check_on: &'static str,
    pub check_off: &'static str,
    pub spinner: &'static [&'static str],
    pub spark: &'static [char],
    pub ellipsis: &'static str,
}

pub const UNICODE_SYMBOLS: Symbols = Symbols {
    pass: "✓",
    warn: "!",
    fail: "×",
    info: "•",
    arrow: "→",
    selected: "▶",
    bullet: "•",
    bar_full: "█",
    bar_empty: "░",
    check_on: "[x]",
    check_off: "[ ]",
    spinner: &["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"],
    spark: &['▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'],
    ellipsis: "…",
};

pub const ASCII_SYMBOLS: Symbols = Symbols {
    pass: "+",
    warn: "!",
    fail: "x",
    info: "-",
    arrow: "->",
    selected: ">",
    bullet: "*",
    bar_full: "#",
    bar_empty: ".",
    check_on: "[x]",
    check_off: "[ ]",
    spinner: &["|", "/", "-", "\\"],
    spark: &['.', ':', '-', '=', '+', '*', '#', '@'],
    ellipsis: "..",
};

impl Symbols {
    pub fn for_status(&self, status: UiStatus) -> &'static str {
        match status {
            UiStatus::Pass => self.pass,
            UiStatus::Warning => self.warn,
            UiStatus::Error | UiStatus::Critical => self.fail,
            UiStatus::Running => self.spinner.first().copied().unwrap_or("*"),
            UiStatus::Cancelled => self.bullet,
            UiStatus::Unsupported | UiStatus::Unavailable => self.info,
            UiStatus::PermissionRequired => self.warn,
            UiStatus::Info => self.info,
            UiStatus::Unknown => "?",
        }
    }
}

#[derive(Debug, Clone)]
pub struct Theme {
    pub kind: ThemeKind,
    pub colors: ColorMode,
    pub symbols: Symbols,
    // Semantic roles.
    pub text: Style,
    pub muted: Style,
    pub accent: Style,
    pub primary: Style,
    pub success: Style,
    pub warning: Style,
    pub error: Style,
    pub critical: Style,
    pub border: Style,
    pub title: Style,
    pub selected: Style,
    pub panel: Style,
    pub progress: Style,
    pub keycap: Style,
}

impl Theme {
    pub fn new(kind: ThemeKind, colors: ColorMode, unicode: bool) -> Self {
        let symbols = if unicode {
            UNICODE_SYMBOLS
        } else {
            ASCII_SYMBOLS
        };
        // NoColor always uses ASCII-safe, attribute-based styling.
        let kind = if colors == ColorMode::None {
            ThemeKind::NoColor
        } else {
            kind
        };
        let mut theme = match kind {
            ThemeKind::Auto | ThemeKind::Dark => Self::dark(colors),
            ThemeKind::Light => Self::light(colors),
            ThemeKind::HighContrast => Self::high_contrast(colors),
            ThemeKind::NoColor => Self::no_color(),
        };
        theme.symbols = symbols;
        theme
    }

    fn color(rgb: (u8, u8, u8), index: u8, basic: Color, mode: ColorMode) -> Color {
        match mode {
            ColorMode::None => Color::Reset,
            ColorMode::Ansi16 => basic,
            ColorMode::Ansi256 => Color::Indexed(index),
            ColorMode::TrueColor => Color::Rgb(rgb.0, rgb.1, rgb.2),
        }
    }

    fn dark(mode: ColorMode) -> Self {
        let text = Self::color((226, 232, 240), 252, Color::White, mode);
        let muted = Self::color((148, 163, 184), 245, Color::Gray, mode);
        let accent = Self::color((56, 189, 248), 39, Color::Cyan, mode);
        let primary = Self::color((129, 140, 248), 63, Color::Blue, mode);
        let success = Self::color((74, 222, 128), 77, Color::Green, mode);
        let warning = Self::color((250, 204, 21), 220, Color::Yellow, mode);
        let error = Self::color((248, 113, 113), 203, Color::Red, mode);
        let critical = Self::color((217, 70, 239), 171, Color::Magenta, mode);
        let border = Self::color((71, 85, 105), 238, Color::DarkGray, mode);
        let selected_bg = Self::color((30, 41, 59), 236, Color::DarkGray, mode);
        Self {
            kind: ThemeKind::Dark,
            colors: mode,
            symbols: UNICODE_SYMBOLS,
            text: Style::default().fg(text),
            muted: Style::default().fg(muted),
            accent: Style::default().fg(accent),
            primary: Style::default().fg(primary),
            success: Style::default().fg(success),
            warning: Style::default().fg(warning),
            error: Style::default().fg(error),
            critical: Style::default().fg(critical),
            border: Style::default().fg(border),
            title: Style::default().fg(text).add_modifier(Modifier::BOLD),
            selected: Style::default()
                .bg(selected_bg)
                .fg(text)
                .add_modifier(Modifier::BOLD),
            panel: Style::default(),
            progress: Style::default().fg(accent),
            keycap: Style::default().fg(accent).add_modifier(Modifier::BOLD),
        }
    }

    fn light(mode: ColorMode) -> Self {
        let text = Self::color((15, 23, 42), 232, Color::Black, mode);
        let muted = Self::color((71, 85, 105), 240, Color::DarkGray, mode);
        let accent = Self::color((3, 105, 161), 31, Color::Blue, mode);
        let primary = Self::color((67, 56, 202), 63, Color::Blue, mode);
        let success = Self::color((21, 128, 61), 28, Color::Green, mode);
        let warning = Self::color((161, 98, 7), 130, Color::Yellow, mode);
        let error = Self::color((185, 28, 28), 124, Color::Red, mode);
        let critical = Self::color((134, 25, 143), 127, Color::Magenta, mode);
        let border = Self::color((148, 163, 184), 246, Color::Gray, mode);
        let selected_bg = Self::color((191, 219, 254), 153, Color::Cyan, mode);
        Self {
            kind: ThemeKind::Light,
            colors: mode,
            symbols: UNICODE_SYMBOLS,
            text: Style::default().fg(text),
            muted: Style::default().fg(muted),
            accent: Style::default().fg(accent),
            primary: Style::default().fg(primary),
            success: Style::default().fg(success),
            warning: Style::default().fg(warning),
            error: Style::default().fg(error),
            critical: Style::default().fg(critical),
            border: Style::default().fg(border),
            title: Style::default().fg(text).add_modifier(Modifier::BOLD),
            selected: Style::default()
                .bg(selected_bg)
                .fg(text)
                .add_modifier(Modifier::BOLD),
            panel: Style::default(),
            progress: Style::default().fg(accent),
            keycap: Style::default().fg(accent).add_modifier(Modifier::BOLD),
        }
    }

    fn high_contrast(mode: ColorMode) -> Self {
        let text = match mode {
            ColorMode::None => Color::Reset,
            _ => Color::White,
        };
        let mut theme = Self::dark(mode);
        theme.kind = ThemeKind::HighContrast;
        theme.text = Style::default().fg(text);
        theme.muted = Style::default().fg(text).add_modifier(Modifier::DIM);
        theme.border = Style::default().fg(text);
        theme.selected = Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD);
        theme.accent = Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::BOLD);
        theme.title = Style::default()
            .fg(text)
            .add_modifier(Modifier::BOLD | Modifier::UNDERLINED);
        theme
    }

    fn no_color() -> Self {
        Self {
            kind: ThemeKind::NoColor,
            colors: ColorMode::None,
            symbols: ASCII_SYMBOLS,
            text: Style::default(),
            muted: Style::default().add_modifier(Modifier::DIM),
            accent: Style::default().add_modifier(Modifier::BOLD),
            primary: Style::default().add_modifier(Modifier::BOLD),
            success: Style::default(),
            warning: Style::default().add_modifier(Modifier::BOLD),
            error: Style::default().add_modifier(Modifier::BOLD),
            critical: Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            border: Style::default().add_modifier(Modifier::DIM),
            title: Style::default().add_modifier(Modifier::BOLD | Modifier::UNDERLINED),
            selected: Style::default().add_modifier(Modifier::REVERSED | Modifier::BOLD),
            panel: Style::default(),
            progress: Style::default(),
            keycap: Style::default().add_modifier(Modifier::BOLD),
        }
    }

    pub fn status_style(&self, status: UiStatus) -> Style {
        match status {
            UiStatus::Pass => self.success,
            UiStatus::Warning => self.warning,
            UiStatus::Error | UiStatus::Critical => self.error,
            UiStatus::Running => self.accent,
            UiStatus::Cancelled | UiStatus::Info => self.muted,
            UiStatus::Unsupported | UiStatus::Unavailable | UiStatus::Unknown => self.muted,
            UiStatus::PermissionRequired => self.warning,
        }
    }

    pub fn severity_style(&self, severity: Severity) -> Style {
        self.status_style(UiStatus::from_severity(severity))
    }

    /// Set the theme kind, keeping capability-derived settings.
    pub fn with_kind(&self, kind: ThemeKind) -> Self {
        Self::new(kind, self.colors, self.symbols.pass == UNICODE_SYMBOLS.pass)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_color_theme_has_no_colors() {
        let theme = Theme::new(ThemeKind::Dark, ColorMode::None, true);
        assert_eq!(theme.kind, ThemeKind::NoColor);
        // NoColor must not set any foreground color.
        assert!(
            theme.text.fg.is_none() || theme.text.fg == Some(Color::Reset),
            "unexpected color in NoColor theme: {:?}",
            theme.text.fg
        );
        assert_eq!(theme.colors, ColorMode::None);
    }

    #[test]
    fn status_always_has_symbol() {
        for status in [
            UiStatus::Pass,
            UiStatus::Warning,
            UiStatus::Error,
            UiStatus::Critical,
            UiStatus::Unsupported,
            UiStatus::PermissionRequired,
            UiStatus::Running,
            UiStatus::Cancelled,
        ] {
            assert!(!ASCII_SYMBOLS.for_status(status).is_empty());
            assert!(!UNICODE_SYMBOLS.for_status(status).is_empty());
        }
    }

    #[test]
    fn theme_kind_cycles() {
        let mut kind = ThemeKind::Auto;
        for _ in 0..5 {
            kind = kind.next();
        }
        assert_eq!(kind, ThemeKind::Auto);
    }

    #[test]
    fn truecolor_uses_rgb() {
        let theme = Theme::new(ThemeKind::Dark, ColorMode::TrueColor, true);
        assert!(matches!(theme.accent.fg, Some(Color::Rgb(_, _, _))));
    }

    #[test]
    fn ansi16_uses_basic_colors() {
        let theme = Theme::new(ThemeKind::Dark, ColorMode::Ansi16, false);
        assert!(matches!(theme.accent.fg, Some(Color::Cyan)));
        assert_eq!(theme.symbols.pass, "+");
    }
}
