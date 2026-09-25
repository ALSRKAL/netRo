//! Terminal lifecycle management.
//!
//! The guard enters raw mode + alternate screen and always restores them: on
//! normal exit, on error, and on panic (via a panic hook). A crashed TUI must
//! never leave the user's terminal unusable.

use crate::error::Result;
use crossterm::cursor::{Hide, Show};
use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use std::io::{stdout, Write};

pub struct TerminalGuard {
    mouse: bool,
}

fn restore(mouse: bool) {
    let mut out = stdout();
    if mouse {
        let _ = execute!(out, DisableMouseCapture);
    }
    let _ = execute!(out, Show, LeaveAlternateScreen);
    let _ = disable_raw_mode();
    let _ = out.flush();
}

fn install_panic_hook(mouse: bool) {
    let previous = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        restore(mouse);
        previous(info);
    }));
}

impl TerminalGuard {
    pub fn enter(mouse: bool) -> Result<Self> {
        enable_raw_mode()?;
        let mut out = stdout();
        execute!(out, EnterAlternateScreen, Hide)?;
        if mouse {
            let _ = execute!(out, EnableMouseCapture);
        }
        install_panic_hook(mouse);
        Ok(Self { mouse })
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        restore(self.mouse);
    }
}
