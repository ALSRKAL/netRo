//! Core diagnostics logic. Every module here works through the platform
//! abstraction layer and never contains OS-specific shell commands.

pub mod diagnostics;
pub mod discovery;
pub mod dns;
pub mod health;
pub mod integrity;
pub mod monitoring;
pub mod oui;
pub mod reporting;
pub mod scan;
pub mod security;
pub mod snapshot;
pub mod speedtest;
