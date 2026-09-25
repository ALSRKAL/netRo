//! PowerShell bridge for Windows providers.
//!
//! Scripts are passed via `-EncodedCommand` (UTF-16LE base64) so that no
//! quoting, escaping, or shell interpretation of user data can occur. Scripts
//! are fixed literals in the provider code — never built from user input.

use crate::error::{dependency_missing, ErrorCode, NetroError, Result};
use crate::util::{self, which};
use std::time::Duration;

const PS_TIMEOUT: Duration = Duration::from_secs(20);

pub fn powershell_path() -> Option<std::path::PathBuf> {
    which("powershell").or_else(|| which("pwsh"))
}

pub fn ensure_available() -> Result<std::path::PathBuf> {
    powershell_path().ok_or_else(|| {
        dependency_missing("PowerShell", "Windows system information")
            .with_hint("PowerShell is part of every supported Windows version")
    })
}

/// Run a PowerShell script and parse its JSON output.
///
/// The script must emit a single JSON document. `ConvertTo-Json` depth is set
/// high enough for CIM objects.
pub fn run_json(script: &str) -> Result<serde_json::Value> {
    let exe = ensure_available()?;
    let full =
        format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';{script}");
    let encoded = encode_utf16le_base64(&full);
    let out = util::run_command(
        &exe.to_string_lossy(),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ],
        PS_TIMEOUT,
    )
    .map_err(|e| {
        if e.code() == ErrorCode::DependencyMissing {
            dependency_missing("PowerShell", "Windows system information")
        } else {
            e
        }
    })?;

    let text = out.stdout.trim();
    if text.is_empty() {
        if out.success() {
            return Ok(serde_json::Value::Null);
        }
        return Err(NetroError::new(
            ErrorCode::Other,
            format!(
                "PowerShell command failed: {}",
                out.stderr.trim().lines().next().unwrap_or("unknown error")
            ),
        ));
    }
    serde_json::from_str(text).map_err(|e| {
        NetroError::new(
            ErrorCode::ParseError,
            format!("PowerShell returned non-JSON output: {e}"),
        )
        .with_hint(out.stderr.trim().chars().take(200).collect::<String>())
    })
}

/// Run a PowerShell script for its side effect, returning combined output.
pub fn run_text(script: &str) -> Result<String> {
    let exe = ensure_available()?;
    let full =
        format!("$ErrorActionPreference='Stop';$ProgressPreference='SilentlyContinue';{script}");
    let encoded = encode_utf16le_base64(&full);
    let out = util::run_command(
        &exe.to_string_lossy(),
        &[
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-EncodedCommand",
            &encoded,
        ],
        PS_TIMEOUT,
    )?;
    if !out.success() {
        return Err(NetroError::new(
            ErrorCode::Other,
            format!("PowerShell command failed: {}", out.stderr.trim()),
        ));
    }
    Ok(out.stdout)
}

/// PowerShell emits a bare object when a pipeline produces one item; normalize
/// to an array.
pub fn as_array(value: &serde_json::Value) -> Vec<&serde_json::Value> {
    match value {
        serde_json::Value::Array(items) => items.iter().collect(),
        serde_json::Value::Null => Vec::new(),
        other => vec![other],
    }
}

pub fn str_field<'a>(value: &'a serde_json::Value, keys: &[&str]) -> Option<String> {
    let obj = value.as_object()?;
    for key in keys {
        if let Some(v) = obj.get(*key) {
            match v {
                serde_json::Value::String(s) if !s.trim().is_empty() => {
                    return Some(s.trim().to_string())
                }
                serde_json::Value::Number(n) => return Some(n.to_string()),
                serde_json::Value::Bool(b) => return Some(b.to_string()),
                _ => {}
            }
        }
    }
    None
}

pub fn u64_field(value: &serde_json::Value, keys: &[&str]) -> Option<u64> {
    let obj = value.as_object()?;
    for key in keys {
        if let Some(v) = obj.get(*key) {
            if let Some(n) = v.as_u64() {
                return Some(n);
            }
            if let Some(s) = v.as_str() {
                if let Ok(n) = s.trim().parse::<u64>() {
                    return Some(n);
                }
            }
        }
    }
    None
}

pub fn bool_field(value: &serde_json::Value, keys: &[&str]) -> Option<bool> {
    let obj = value.as_object()?;
    for key in keys {
        if let Some(v) = obj.get(*key) {
            if let Some(b) = v.as_bool() {
                return Some(b);
            }
            if let Some(n) = v.as_i64() {
                return Some(n != 0);
            }
            if let Some(s) = v.as_str() {
                match s.trim().to_ascii_lowercase().as_str() {
                    "true" | "yes" | "1" => return Some(true),
                    "false" | "no" | "0" => return Some(false),
                    _ => {}
                }
            }
        }
    }
    None
}

/// UTF-16LE base64 encoding for `-EncodedCommand`.
pub fn encode_utf16le_base64(script: &str) -> String {
    let mut bytes = Vec::with_capacity(script.len() * 2);
    for unit in script.encode_utf16() {
        bytes.extend_from_slice(&unit.to_le_bytes());
    }
    base64_encode(&bytes)
}

/// Minimal standard base64 encoder (avoids an extra dependency).
pub fn base64_encode(input: &[u8]) -> String {
    const TABLE: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity((input.len() + 2) / 3 * 4);
    for chunk in input.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = *chunk.get(1).unwrap_or(&0) as u32;
        let b2 = *chunk.get(2).unwrap_or(&0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(TABLE[((triple >> 18) & 0x3F) as usize] as char);
        out.push(TABLE[((triple >> 12) & 0x3F) as usize] as char);
        if chunk.len() > 1 {
            out.push(TABLE[((triple >> 6) & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(TABLE[(triple & 0x3F) as usize] as char);
        } else {
            out.push('=');
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn base64_matches_rfc4648_vectors() {
        assert_eq!(base64_encode(b""), "");
        assert_eq!(base64_encode(b"f"), "Zg==");
        assert_eq!(base64_encode(b"fo"), "Zm8=");
        assert_eq!(base64_encode(b"foo"), "Zm9v");
        assert_eq!(base64_encode(b"foob"), "Zm9vYg==");
        assert_eq!(base64_encode(b"fooba"), "Zm9vYmE=");
        assert_eq!(base64_encode(b"foobar"), "Zm9vYmFy");
    }

    #[test]
    fn encoded_command_is_utf16le() {
        // "A" -> 0x41 0x00 -> "QQ=="
        assert_eq!(encode_utf16le_base64("A"), "QQ==");
    }

    #[test]
    fn as_array_normalizes() {
        let single = serde_json::json!({"a": 1});
        assert_eq!(as_array(&single).len(), 1);
        let many = serde_json::json!([{"a": 1}, {"a": 2}]);
        assert_eq!(as_array(&many).len(), 2);
        let null = serde_json::Value::Null;
        assert!(as_array(&null).is_empty());
    }

    #[test]
    fn field_extraction() {
        let v = serde_json::json!({"Name": "Wi-Fi", "Index": 3, "Enabled": true});
        assert_eq!(str_field(&v, &["Name"]), Some("Wi-Fi".into()));
        assert_eq!(u64_field(&v, &["Index"]), Some(3));
        assert_eq!(bool_field(&v, &["Enabled"]), Some(true));
        assert_eq!(str_field(&v, &["Missing"]), None);
    }
}
