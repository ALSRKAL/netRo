//! netRo — cross-platform system, network, diagnostics, monitoring and
//! security-audit library.
//!
//! The binary is a thin shell over this library so that every capability is
//! unit- and integration-testable.

pub mod cli;
pub mod commands;
pub mod config;
pub mod core;
pub mod error;
pub mod logging;
pub mod model;
pub mod output;
pub mod platform;
pub mod tui;
pub mod util;
pub mod version;
