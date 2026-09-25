//! Terminal user interface.
//!
//! The TUI is a presentation layer over the same `core` APIs the CLI uses; it
//! contains no diagnostic logic of its own. See `docs/TUI.md`.

pub mod action;
pub mod app;
pub mod caps;
pub mod components;
pub mod event;
pub mod state;
pub mod tasks;
pub mod terminal;
pub mod text;
pub mod theme;
pub mod widgets;

pub use app::{run, TuiOptions};
