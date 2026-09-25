//! Structured error model.
//!
//! Every failure carries a stable machine-readable [`ErrorCode`] plus a human
//! message and an optional remediation hint. Error codes are part of the public
//! JSON contract and are covered by tests.

use std::fmt;

/// Stable machine-readable error codes. These strings appear in `--json` output
/// and must not change without a major version bump.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ErrorCode {
    /// The operation needs root/administrator privileges.
    PermissionDenied,
    /// The operation is not permitted by the operating system (e.g. sandbox).
    OperationNotPermitted,
    /// A required optional dependency (binary/tool) is not installed.
    DependencyMissing,
    /// The current platform does not implement this capability.
    PlatformUnsupported,
    /// An operation timed out.
    Timeout,
    /// The target could not be parsed or is not a valid host/IP/CIDR.
    InvalidTarget,
    /// The user asked to touch a target outside the authorized scope.
    UnauthorizedScan,
    /// DNS configuration or resolution is unavailable.
    NetworkDnsUnavailable,
    /// The network destination is unreachable.
    NetworkUnreachable,
    /// A requested resource does not exist.
    NotFound,
    /// Filesystem or IO failure.
    Io,
    /// Output of an external tool could not be parsed.
    ParseError,
    /// Invalid configuration value.
    ConfigError,
    /// The operation was cancelled by the user or a signal.
    Cancelled,
    /// The operation was refused because it is destructive and no explicit
    /// confirmation (`--yes`) was provided.
    ConfirmationRequired,
    /// The application is not running in a terminal but needs one.
    NotATerminal,
    /// Some other, unclassified failure.
    Other,
}

impl ErrorCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            ErrorCode::PermissionDenied => "PERMISSION_DENIED",
            ErrorCode::OperationNotPermitted => "OPERATION_NOT_PERMITTED",
            ErrorCode::DependencyMissing => "DEPENDENCY_MISSING",
            ErrorCode::PlatformUnsupported => "PLATFORM_UNSUPPORTED",
            ErrorCode::Timeout => "TIMEOUT",
            ErrorCode::InvalidTarget => "INVALID_TARGET",
            ErrorCode::UnauthorizedScan => "UNAUTHORIZED_SCAN",
            ErrorCode::NetworkDnsUnavailable => "NETWORK_DNS_UNAVAILABLE",
            ErrorCode::NetworkUnreachable => "NETWORK_UNREACHABLE",
            ErrorCode::NotFound => "NOT_FOUND",
            ErrorCode::Io => "IO_ERROR",
            ErrorCode::ParseError => "PARSE_ERROR",
            ErrorCode::ConfigError => "CONFIG_ERROR",
            ErrorCode::Cancelled => "CANCELLED",
            ErrorCode::ConfirmationRequired => "CONFIRMATION_REQUIRED",
            ErrorCode::NotATerminal => "NOT_A_TERMINAL",
            ErrorCode::Other => "ERROR",
        }
    }

    /// Process exit code associated with this error class.
    pub const fn exit_code(self) -> i32 {
        match self {
            ErrorCode::Other => 1,
            ErrorCode::PermissionDenied | ErrorCode::OperationNotPermitted => 3,
            ErrorCode::DependencyMissing => 4,
            ErrorCode::PlatformUnsupported => 5,
            ErrorCode::Timeout => 6,
            ErrorCode::InvalidTarget | ErrorCode::UnauthorizedScan => 7,
            ErrorCode::NetworkDnsUnavailable | ErrorCode::NetworkUnreachable => 8,
            _ => 1,
        }
    }

    /// Whether this error means "capability unavailable" rather than "the
    /// command failed". Used by the doctor to distinguish FAIL from UNSUPPORTED.
    pub const fn is_unavailable(self) -> bool {
        matches!(
            self,
            ErrorCode::PlatformUnsupported | ErrorCode::DependencyMissing
        )
    }
}

impl serde::Serialize for ErrorCode {
    fn serialize<S: serde::Serializer>(
        &self,
        serializer: S,
    ) -> std::result::Result<S::Ok, S::Error> {
        serializer.serialize_str(self.as_str())
    }
}

/// The error type used across netRo.
#[derive(Debug)]
pub struct NetroError {
    code: ErrorCode,
    message: String,
    hint: Option<String>,
    source: Option<Box<dyn std::error::Error + Send + Sync>>,
}

impl NetroError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self {
            code,
            message: message.into(),
            hint: None,
            source: None,
        }
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn with_source(mut self, source: impl std::error::Error + Send + Sync + 'static) -> Self {
        self.source = Some(Box::new(source));
        self
    }

    pub fn code(&self) -> ErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub fn hint(&self) -> Option<&str> {
        self.hint.as_deref()
    }

    /// Return a copy with `context` prepended to the message.
    pub fn context(mut self, context: impl AsRef<str>) -> Self {
        self.message = format!("{}: {}", context.as_ref(), self.message);
        self
    }
}

impl fmt::Display for NetroError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, " (hint: {hint})")?;
        }
        Ok(())
    }
}

impl std::error::Error for NetroError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source
            .as_ref()
            .map(|s| s.as_ref() as &(dyn std::error::Error + 'static))
    }
}

impl From<std::io::Error> for NetroError {
    fn from(err: std::io::Error) -> Self {
        let code = match err.kind() {
            std::io::ErrorKind::PermissionDenied => ErrorCode::PermissionDenied,
            std::io::ErrorKind::TimedOut => ErrorCode::Timeout,
            std::io::ErrorKind::NotFound => ErrorCode::NotFound,
            _ => ErrorCode::Io,
        };
        NetroError::new(code, err.to_string()).with_source(err)
    }
}

impl From<serde_json::Error> for NetroError {
    fn from(err: serde_json::Error) -> Self {
        NetroError::new(ErrorCode::ParseError, format!("invalid JSON: {err}")).with_source(err)
    }
}

pub type Result<T> = std::result::Result<T, NetroError>;

/// Convenience constructors.
pub fn err<T>(code: ErrorCode, msg: impl Into<String>) -> Result<T> {
    Err(NetroError::new(code, msg))
}

pub fn permission_denied(msg: impl Into<String>) -> NetroError {
    NetroError::new(ErrorCode::PermissionDenied, msg)
}

pub fn dependency_missing(bin: &str, purpose: &str) -> NetroError {
    NetroError::new(
        ErrorCode::DependencyMissing,
        format!("'{bin}' is not installed or not on PATH"),
    )
    .with_hint(format!("install it to enable {purpose}"))
}

pub fn unsupported(msg: impl Into<String>) -> NetroError {
    NetroError::new(ErrorCode::PlatformUnsupported, msg)
}

pub fn invalid_target(msg: impl Into<String>) -> NetroError {
    NetroError::new(ErrorCode::InvalidTarget, msg)
}

pub fn timeout(msg: impl Into<String>) -> NetroError {
    NetroError::new(ErrorCode::Timeout, msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codes_are_unique_and_stable() {
        let codes = [
            ErrorCode::PermissionDenied,
            ErrorCode::OperationNotPermitted,
            ErrorCode::DependencyMissing,
            ErrorCode::PlatformUnsupported,
            ErrorCode::Timeout,
            ErrorCode::InvalidTarget,
            ErrorCode::UnauthorizedScan,
            ErrorCode::NetworkDnsUnavailable,
            ErrorCode::NetworkUnreachable,
            ErrorCode::NotFound,
            ErrorCode::Io,
            ErrorCode::ParseError,
            ErrorCode::ConfigError,
            ErrorCode::Cancelled,
            ErrorCode::ConfirmationRequired,
            ErrorCode::NotATerminal,
            ErrorCode::Other,
        ];
        let mut names: Vec<&str> = codes.iter().map(|c| c.as_str()).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), codes.len(), "error codes must be unique");
    }

    #[test]
    fn permission_error_maps_to_exit_code_3() {
        assert_eq!(ErrorCode::PermissionDenied.exit_code(), 3);
        assert_eq!(ErrorCode::DependencyMissing.exit_code(), 4);
        assert_eq!(ErrorCode::Timeout.exit_code(), 6);
    }

    #[test]
    fn io_permission_error_is_classified() {
        let io = std::io::Error::new(std::io::ErrorKind::PermissionDenied, "nope");
        let e: NetroError = io.into();
        assert_eq!(e.code(), ErrorCode::PermissionDenied);
    }

    #[test]
    fn display_contains_code_and_hint() {
        let e = dependency_missing("nmap", "network discovery");
        let s = e.to_string();
        assert!(s.starts_with("DEPENDENCY_MISSING:"));
        assert!(s.contains("hint:"));
    }

    #[test]
    fn error_code_serializes_to_stable_string() {
        let v = serde_json::to_value(ErrorCode::InvalidTarget).unwrap();
        assert_eq!(v, serde_json::json!("INVALID_TARGET"));
    }
}
