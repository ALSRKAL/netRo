//! Structured file logger.
//!
//! - Levels: DEBUG, INFO, WARN, ERROR.
//! - Redacts values whose key looks secret before writing.
//! - Log file lives under the per-user data dir with 0600 permissions.
//! - Never panics when the log cannot be written.

use crate::config;
use crate::util::redact;
use std::fs::{File, OpenOptions};
use std::io::Write;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum LogLevel {
    Debug,
    Info,
    Warn,
    Error,
}

impl LogLevel {
    pub fn as_str(self) -> &'static str {
        match self {
            LogLevel::Debug => "DEBUG",
            LogLevel::Info => "INFO",
            LogLevel::Warn => "WARN",
            LogLevel::Error => "ERROR",
        }
    }

    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "debug" => Some(LogLevel::Debug),
            "info" => Some(LogLevel::Info),
            "warn" | "warning" => Some(LogLevel::Warn),
            "error" => Some(LogLevel::Error),
            _ => None,
        }
    }
}

struct LoggerState {
    level: LogLevel,
    file: Option<File>,
    path: Option<PathBuf>,
    echo_stderr: bool,
}

static LOGGER: OnceLock<Mutex<LoggerState>> = OnceLock::new();

fn state() -> &'static Mutex<LoggerState> {
    LOGGER.get_or_init(|| {
        Mutex::new(LoggerState {
            level: LogLevel::Info,
            file: None,
            path: None,
            echo_stderr: false,
        })
    })
}

const MAX_LOG_BYTES: u64 = 5 * 1024 * 1024;

/// Initialize the logger. Failures are non-fatal: logging degrades to stderr.
pub fn init(level: LogLevel, file: Option<PathBuf>, echo_stderr: bool) -> Option<PathBuf> {
    let file = file.or_else(|| {
        config::ensure_dirs().ok()?;
        Some(config::log_dir().join("netro.log"))
    });
    let mut opened = None;
    let mut path = None;
    if let Some(candidate) = file {
        if let Some(parent) = candidate.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        rotate_if_needed(&candidate);
        if let Ok(f) = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&candidate)
        {
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ =
                    std::fs::set_permissions(&candidate, std::fs::Permissions::from_mode(0o600));
            }
            opened = Some(f);
            path = Some(candidate);
        }
    }
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.level = level;
    guard.file = opened;
    guard.path = path.clone();
    guard.echo_stderr = echo_stderr;
    path
}

fn rotate_if_needed(path: &std::path::Path) {
    if let Ok(meta) = std::fs::metadata(path) {
        if meta.len() > MAX_LOG_BYTES {
            let rotated = path.with_extension("log.1");
            let _ = std::fs::rename(path, rotated);
        }
    }
}

pub fn enabled(level: LogLevel) -> bool {
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());
    level >= guard.level
}

pub fn log(level: LogLevel, message: &str) {
    let sanitized = redact(message);
    let mut guard = state().lock().unwrap_or_else(|e| e.into_inner());
    if level < guard.level {
        return;
    }
    let timestamp = chrono::Local::now().format("%Y-%m-%d %H:%M:%S%.3f");
    let line = format!("[{timestamp}] [{}] {sanitized}\n", level.as_str());
    if let Some(file) = guard.file.as_mut() {
        let _ = file.write_all(line.as_bytes());
        let _ = file.flush();
    }
    if guard.echo_stderr && level >= LogLevel::Warn {
        eprint!("{line}");
    }
}

pub fn current_path() -> Option<PathBuf> {
    let guard = state().lock().unwrap_or_else(|e| e.into_inner());
    guard.path.clone()
}

/// Return the last `n` lines of the active log file (for diagnostics).
pub fn tail(n: usize) -> Vec<String> {
    let path = match current_path() {
        Some(p) => p,
        None => return Vec::new(),
    };
    let content = std::fs::read_to_string(path).unwrap_or_default();
    let mut lines: Vec<String> = content.lines().map(|s| s.to_string()).collect();
    if lines.len() > n {
        lines.split_off(lines.len() - n)
    } else {
        lines
    }
}

#[macro_export]
macro_rules! log_debug {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::LogLevel::Debug, &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_info {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::LogLevel::Info, &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_warn {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::LogLevel::Warn, &format!($($arg)*)) };
}

#[macro_export]
macro_rules! log_error {
    ($($arg:tt)*) => { $crate::logging::log($crate::logging::LogLevel::Error, &format!($($arg)*)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parsing() {
        assert_eq!(LogLevel::parse("DEBUG"), Some(LogLevel::Debug));
        assert_eq!(LogLevel::parse("warning"), Some(LogLevel::Warn));
        assert_eq!(LogLevel::parse("nope"), None);
    }

    #[test]
    fn level_ordering() {
        assert!(LogLevel::Error > LogLevel::Warn);
        assert!(LogLevel::Warn > LogLevel::Info);
        assert!(LogLevel::Info > LogLevel::Debug);
    }

    #[test]
    fn log_writes_redacted_lines() {
        let dir = std::env::temp_dir().join(format!("netro-log-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("t.log");
        let _ = init(LogLevel::Debug, Some(path.clone()), false);
        log(LogLevel::Error, "password=hunter2 failed");
        let content = std::fs::read_to_string(&path).unwrap_or_default();
        assert!(content.contains("[ERROR]"));
        assert!(!content.contains("hunter2"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
