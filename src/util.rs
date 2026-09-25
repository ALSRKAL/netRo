//! Shared utilities: process execution, PATH lookup, target validation, CIDR
//! math, formatting and redaction.
//!
//! Security note: netRo never invokes a shell. All external programs are
//! executed with explicit argument vectors. [`validate_host`] additionally
//! rejects inputs that begin with `-` (argument injection) or contain shell
//! metacharacters (defense in depth).

use crate::error::{invalid_target, timeout, ErrorCode, NetroError, Result};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

/// Output of an external program.
#[derive(Debug, Clone)]
pub struct CommandOutput {
    pub program: String,
    pub args: Vec<String>,
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub duration: Duration,
}

impl CommandOutput {
    pub fn success(&self) -> bool {
        self.status == Some(0)
    }

    pub fn combined(&self) -> String {
        let mut s = self.stdout.clone();
        if !self.stderr.trim().is_empty() {
            if !s.is_empty() && !s.ends_with('\n') {
                s.push('\n');
            }
            s.push_str(&self.stderr);
        }
        s
    }
}

/// Execute a program with an argument vector and a hard timeout.
///
/// Never uses a shell. Returns [`ErrorCode::DependencyMissing`] when the
/// program cannot be spawned because it does not exist.
pub fn run_command<S: AsRef<str>>(
    program: &str,
    args: &[S],
    timeout_duration: Duration,
) -> Result<CommandOutput> {
    let started = Instant::now();
    let mut cmd = Command::new(program);
    cmd.args(args.iter().map(|a| a.as_ref()))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());

    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        const CREATE_NO_WINDOW: u32 = 0x0800_0000;
        cmd.creation_flags(CREATE_NO_WINDOW);
    }

    let mut child = match cmd.spawn() {
        Ok(child) => child,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(NetroError::new(
                ErrorCode::DependencyMissing,
                format!("failed to execute '{program}': {e}"),
            ));
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(NetroError::new(
                ErrorCode::PermissionDenied,
                format!("failed to execute '{program}': {e}"),
            ));
        }
        Err(e) => return Err(e.into()),
    };

    let stdout_pipe = child.stdout.take();
    let stderr_pipe = child.stderr.take();

    let stdout_handle = stdout_pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
            buf
        })
    });
    let stderr_handle = stderr_pipe.map(|mut pipe| {
        std::thread::spawn(move || {
            let mut buf = Vec::new();
            let _ = std::io::Read::read_to_end(&mut pipe, &mut buf);
            buf
        })
    });

    let deadline = started + timeout_duration;
    let mut timed_out = false;
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) => {
                if Instant::now() >= deadline {
                    timed_out = true;
                    let _ = child.kill();
                    let _ = child.wait();
                    break None;
                }
                std::thread::sleep(Duration::from_millis(15));
            }
            Err(e) => return Err(e.into()),
        }
    };

    let stdout = stdout_handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();
    let stderr = stderr_handle
        .and_then(|h| h.join().ok())
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default();

    if timed_out {
        return Err(timeout(format!(
            "'{program}' did not finish within {}s",
            timeout_duration.as_secs_f64()
        )));
    }

    Ok(CommandOutput {
        program: program.to_string(),
        args: args.iter().map(|a| a.as_ref().to_string()).collect(),
        status: status.and_then(|s| s.code()),
        stdout,
        stderr,
        duration: started.elapsed(),
    })
}

/// Locate a program on `PATH`.
///
/// - On Unix the executable bit is required.
/// - On Windows `PATHEXT` extensions are tried.
pub fn which(program: &str) -> Option<PathBuf> {
    if program.is_empty() {
        return None;
    }
    let candidate = Path::new(program);
    if candidate.components().count() > 1 {
        return is_executable(candidate).then(|| candidate.to_path_buf());
    }
    let path_var = std::env::var_os("PATH")?;
    let exts = if cfg!(windows) {
        let pathext =
            std::env::var("PATHEXT").unwrap_or_else(|_| ".COM;.EXE;.BAT;.CMD;.PS1".to_string());
        pathext
            .split(';')
            .filter(|s| !s.is_empty())
            .map(|s| s.to_ascii_lowercase())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    for dir in std::env::split_paths(&path_var) {
        if dir.as_os_str().is_empty() {
            continue;
        }
        let direct = dir.join(program);
        if is_executable(&direct) {
            return Some(direct);
        }
        if cfg!(windows) {
            for ext in &exts {
                let with_ext = dir.join(format!("{program}{ext}"));
                if with_ext.is_file() {
                    return Some(with_ext);
                }
            }
        }
    }
    None
}

#[cfg(unix)]
fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    match std::fs::metadata(path) {
        Ok(meta) => meta.is_file() && (meta.permissions().mode() & 0o111) != 0,
        Err(_) => false,
    }
}

#[cfg(not(unix))]
fn is_executable(path: &Path) -> bool {
    path.is_file()
}

/// True when the program exists on `PATH`.
pub fn has_program(program: &str) -> bool {
    which(program).is_some()
}

/// Validate a host, IP or CIDR string that will be handed to network code or an
/// external tool as a single argument.
pub fn validate_host(input: &str) -> Result<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(invalid_target("empty host"));
    }
    if trimmed.len() > 253 {
        return Err(invalid_target("host name too long"));
    }
    if trimmed.starts_with('-') {
        return Err(invalid_target(
            "host must not start with '-' (argument injection protection)",
        ));
    }
    if let Some(bad) = trimmed
        .chars()
        .find(|c| c.is_whitespace() || ";&|$`'\"\\<>(){}!*\n\r".contains(*c))
    {
        return Err(invalid_target(format!(
            "host contains forbidden character {bad:?}"
        )));
    }
    if trimmed.parse::<IpAddr>().is_ok() {
        return Ok(trimmed.to_string());
    }
    if trimmed.contains('/') {
        if parse_cidr(trimmed).is_ok() {
            return Ok(trimmed.to_string());
        }
        return Err(invalid_target(format!("invalid CIDR: {trimmed}")));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some(host) = rest.strip_suffix(']') {
            if host.parse::<Ipv6Addr>().is_ok() {
                return Ok(trimmed.to_string());
            }
        }
        return Err(invalid_target(format!("invalid IPv6 literal: {trimmed}")));
    }
    if is_valid_hostname(trimmed) {
        return Ok(trimmed.to_string());
    }
    Err(invalid_target(format!("invalid host: {trimmed}")))
}

/// RFC 1123 hostname validation (also accepts a single label).
pub fn is_valid_hostname(host: &str) -> bool {
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.is_empty() || host.len() > 253 {
        return false;
    }
    host.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    })
}

/// Parse `IPv4/prefix` or `IPv6/prefix`, or a bare IP (host prefix).
pub fn parse_cidr(input: &str) -> Result<(IpAddr, u8)> {
    let trimmed = input.trim();
    let (addr_part, prefix_part) = match trimmed.split_once('/') {
        Some((a, p)) => (a, Some(p)),
        None => (trimmed, None),
    };
    let addr: IpAddr = addr_part
        .parse()
        .map_err(|_| invalid_target(format!("not an IP address: {addr_part}")))?;
    let max_prefix = if addr.is_ipv4() { 32 } else { 128 };
    let prefix = match prefix_part {
        None => max_prefix,
        Some(p) => {
            let value: u8 = p
                .parse()
                .map_err(|_| invalid_target(format!("invalid prefix length: {p}")))?;
            if value > max_prefix {
                return Err(invalid_target(format!(
                    "prefix {value} out of range for {}",
                    if addr.is_ipv4() { "IPv4" } else { "IPv6" }
                )));
            }
            value
        }
    };
    Ok((addr, prefix))
}

/// Network address for an IP/prefix pair.
pub fn network_address(addr: IpAddr, prefix: u8) -> IpAddr {
    match addr {
        IpAddr::V4(v4) => {
            let bits = u32::from(v4);
            let mask = if prefix == 0 {
                0
            } else {
                u32::MAX << (32 - prefix.min(32))
            };
            IpAddr::V4(Ipv4Addr::from(bits & mask))
        }
        IpAddr::V6(v6) => {
            let bits = u128::from(v6);
            let mask = if prefix == 0 {
                0
            } else {
                u128::MAX << (128 - prefix.min(128))
            };
            IpAddr::V6(Ipv6Addr::from(bits & mask))
        }
    }
}

/// Whether two addresses are in the same subnet.
pub fn same_subnet(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(_), IpAddr::V4(_)) | (IpAddr::V6(_), IpAddr::V6(_)) => {
            network_address(a, prefix) == network_address(b, prefix)
        }
        _ => false,
    }
}

/// Enumerate usable host addresses in a subnet, bounded by `limit`.
///
/// IPv4 `/31` and `/32` include all addresses (RFC 3021). Larger IPv6 prefixes
/// are sampled (first `limit` addresses after the network address).
pub fn subnet_hosts(addr: IpAddr, prefix: u8, limit: usize) -> Vec<IpAddr> {
    match addr {
        IpAddr::V4(v4) => {
            let total = if prefix >= 31 {
                1u64 << (32 - prefix)
            } else {
                (1u64 << (32 - prefix)) - 2
            };
            let network = u32::from(match network_address(IpAddr::V4(v4), prefix) {
                IpAddr::V4(n) => n,
                _ => unreachable!(),
            });
            let start = if prefix >= 31 { network } else { network + 1 };
            let count = (total as usize).min(limit);
            (0..count as u32)
                .map(|offset| {
                    let raw = if prefix >= 31 {
                        start.wrapping_add(offset)
                    } else {
                        start.saturating_add(offset)
                    };
                    IpAddr::V4(Ipv4Addr::from(raw))
                })
                .collect()
        }
        IpAddr::V6(v6) => {
            let network = match network_address(IpAddr::V6(v6), prefix) {
                IpAddr::V6(n) => u128::from(n),
                _ => unreachable!(),
            };
            let host_bits = 128 - prefix.min(128);
            let available: u128 = if host_bits >= 127 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            let max = host_bits.min(64);
            let count = (available.min(limit as u128) as u64).min(1u64 << max.min(63));
            (0..count)
                .map(|offset| IpAddr::V6(Ipv6Addr::from(network.wrapping_add(offset as u128 + 1))))
                .collect()
        }
    }
}

/// Sort key so that IP addresses order naturally.
pub fn ip_sort_key(ip: &IpAddr) -> (u8, u128) {
    match ip {
        IpAddr::V4(v4) => (4, u32::from(*v4) as u128),
        IpAddr::V6(v6) => (6, u128::from(*v6)),
    }
}

/// True for RFC1918 / RFC4193 private addresses.
pub fn is_private_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_private() || v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            (seg & 0xfe00) == 0xfc00 || (seg & 0xffc0) == 0xfe80
        }
    }
}

/// True for IPv4 169.254.0.0/16 and IPv6 fe80::/10 link-local addresses.
pub fn is_link_local_ip(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_link_local(),
        IpAddr::V6(v6) => {
            let seg = v6.segments()[0];
            (seg & 0xffc0) == 0xfe80
        }
    }
}

/// True when a target is inside the user's local scope (loopback or private).
pub fn is_local_scope(ip: &IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
        }
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.is_unspecified() || is_private_ip(&IpAddr::V6(*v6))
        }
    }
}

/// Resolve a validated target to IP addresses.
pub fn resolve_target(target: &str) -> Result<Vec<IpAddr>> {
    let validated = validate_host(target)?;
    if let Ok(ip) = validated.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    if let Some(rest) = validated.strip_prefix('[') {
        if let Some(host) = rest.strip_suffix(']') {
            if let Ok(ip) = host.parse::<IpAddr>() {
                return Ok(vec![ip]);
            }
        }
    }
    match (validated.as_str(), 0u16).to_socket_addrs() {
        Ok(iter) => {
            let mut addrs: Vec<IpAddr> = iter.map(|s| s.ip()).collect();
            addrs.sort_by_key(ip_sort_key);
            addrs.dedup();
            if addrs.is_empty() {
                Err(NetroError::new(
                    ErrorCode::NetworkDnsUnavailable,
                    format!("no addresses resolved for {validated}"),
                ))
            } else {
                Ok(addrs)
            }
        }
        Err(e) => Err(NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("failed to resolve {validated}: {e}"),
        )),
    }
}

/// Pretty byte size (SI units, matching disk-vendor conventions).
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KB", "MB", "GB", "TB", "PB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1000.0 && unit < UNITS.len() - 1 {
        value /= 1000.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

/// Pretty byte size using binary units.
pub fn human_bytes_binary(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}

pub fn human_duration(d: Duration) -> String {
    let secs = d.as_secs_f64();
    if secs < 1.0 {
        format!("{:.0}ms", secs * 1000.0)
    } else if secs < 60.0 {
        format!("{secs:.2}s")
    } else if secs < 3600.0 {
        format!("{}m {:.0}s", (secs / 60.0).floor(), secs % 60.0)
    } else {
        format!(
            "{}h {}m",
            (secs / 3600.0).floor(),
            ((secs % 3600.0) / 60.0).floor()
        )
    }
}

pub fn human_uptime(secs: u64) -> String {
    let days = secs / 86_400;
    let hours = (secs % 86_400) / 3_600;
    let minutes = (secs % 3_600) / 60;
    if days > 0 {
        format!("{days}d {hours}h {minutes}m")
    } else if hours > 0 {
        format!("{hours}h {minutes}m")
    } else {
        format!("{minutes}m")
    }
}

pub fn percent(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        (part as f64 / total as f64) * 100.0
    }
}

/// Redact likely secrets from a string before logging.
///
/// This is intentionally conservative: any `key=value`/`key: value` pair whose
/// key looks secret gets its value replaced.
pub fn redact(input: &str) -> String {
    const SENSITIVE: [&str; 8] = [
        "password",
        "passwd",
        "token",
        "secret",
        "api_key",
        "apikey",
        "private_key",
        "credential",
    ];
    let mut out = String::with_capacity(input.len());
    let mut redact_next = false;
    for token in input.split_inclusive(char::is_whitespace) {
        let had_space = token.ends_with(char::is_whitespace);
        if redact_next {
            out.push_str("<redacted>");
            if had_space {
                out.push(' ');
            }
            redact_next = false;
            continue;
        }
        let lowered = token.to_ascii_lowercase();
        let is_secret = SENSITIVE.iter().any(|k| lowered.contains(k));
        if is_secret {
            if let Some(sep_idx) = token.find(['=', ':']) {
                let (key, rest) = token.split_at(sep_idx + 1);
                out.push_str(key);
                let value = rest.trim_end();
                if value.is_empty() {
                    // "token: value" — the value is the next whitespace token.
                    redact_next = true;
                } else {
                    out.push_str("<redacted>");
                }
                if had_space {
                    out.push(' ');
                }
                continue;
            }
        }
        out.push_str(token);
    }
    out
}

/// RFC 4180 CSV escaping.
pub fn csv_escape(field: &str) -> String {
    if field.contains(',') || field.contains('"') || field.contains('\n') || field.contains('\r') {
        format!("\"{}\"", field.replace('"', "\"\""))
    } else {
        field.to_string()
    }
}

/// Make data received from an untrusted source (service banners, TLS
/// certificates, DNS answers) safe to print to a terminal.
///
/// ANSI escape sequences are removed and remaining control characters are
/// replaced by spaces, so a hostile peer cannot manipulate the user's
/// terminal. Runs of whitespace are collapsed and the result is trimmed.
pub fn sanitize_terminal(input: &str) -> String {
    let mut stripped = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(c) = chars.next() {
        if c == '\x1b' {
            match chars.peek() {
                Some('[') => {
                    // CSI: ESC [ parameters/intermediates final-byte (0x40-0x7E)
                    chars.next();
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if ('\x40'..='\x7e').contains(&next) {
                            break;
                        }
                    }
                }
                Some(']') => {
                    // OSC: ESC ] ... BEL or ESC \
                    chars.next();
                    while let Some(&next) = chars.peek() {
                        chars.next();
                        if next == '\x07' {
                            break;
                        }
                        if next == '\x1b' {
                            let _ = chars.next();
                            break;
                        }
                    }
                }
                _ => {
                    // Two-character escape (e.g. ESC c) — drop the introducer.
                    let _ = chars.next();
                }
            }
            stripped.push(' ');
            continue;
        }
        if c.is_control() {
            stripped.push(' ');
        } else {
            stripped.push(c);
        }
    }
    stripped.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Escape text for safe inclusion in HTML.
pub fn html_escape(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for c in input.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_ip_and_host() {
        assert!(validate_host("127.0.0.1").is_ok());
        assert!(validate_host("::1").is_ok());
        assert!(validate_host("example.com").is_ok());
        assert!(validate_host("sub.example.co.uk").is_ok());
        assert!(validate_host("[::1]").is_ok());
        assert!(validate_host("192.168.1.0/24").is_ok());
    }

    #[test]
    fn rejects_injection_attempts() {
        assert!(validate_host("-oN /tmp/x").is_err());
        assert!(validate_host("example.com;rm -rf /").is_err());
        assert!(validate_host("example.com && whoami").is_err());
        assert!(validate_host("host$(id)").is_err());
        assert!(validate_host("a`b`").is_err());
        assert!(validate_host("").is_err());
        assert!(validate_host("bad host").is_err());
    }

    #[test]
    fn rejects_invalid_hostnames() {
        assert!(validate_host("-bad.example.com").is_err());
        assert!(validate_host("bad-.example.com").is_err());
        assert!(validate_host(&"a".repeat(64)).is_err());
    }

    #[test]
    fn cidr_network_math() {
        let (addr, prefix) = parse_cidr("192.168.1.42/24").unwrap();
        assert_eq!(
            network_address(addr, prefix),
            "192.168.1.0".parse::<IpAddr>().unwrap()
        );
        let (addr, prefix) = parse_cidr("10.0.0.5/8").unwrap();
        assert_eq!(
            network_address(addr, prefix),
            "10.0.0.0".parse::<IpAddr>().unwrap()
        );
        let (addr, prefix) = parse_cidr("172.16.5.5/12").unwrap();
        assert_eq!(
            network_address(addr, prefix),
            "172.16.0.0".parse::<IpAddr>().unwrap()
        );
        let (addr, prefix) = parse_cidr("2001:db8::1/32").unwrap();
        assert_eq!(
            network_address(addr, prefix),
            "2001:db8::".parse::<IpAddr>().unwrap()
        );
    }

    #[test]
    fn cidr_rejects_bad_prefix() {
        assert!(parse_cidr("192.168.1.1/33").is_err());
        assert!(parse_cidr("192.168.1.1/abc").is_err());
        assert!(parse_cidr("not-an-ip/24").is_err());
    }

    #[test]
    fn subnet_hosts_v4() {
        let (addr, prefix) = parse_cidr("192.168.1.10/30").unwrap();
        let hosts = subnet_hosts(addr, prefix, 1000);
        assert_eq!(
            hosts,
            vec![
                "192.168.1.9".parse::<IpAddr>().unwrap(),
                "192.168.1.10".parse::<IpAddr>().unwrap()
            ]
        );
        let (addr, prefix) = parse_cidr("192.168.1.10/24").unwrap();
        let hosts = subnet_hosts(addr, prefix, 1000);
        assert_eq!(hosts.len(), 254);
        assert_eq!(hosts[0], "192.168.1.1".parse::<IpAddr>().unwrap());
        let hosts = subnet_hosts(addr, prefix, 10);
        assert_eq!(hosts.len(), 10);
    }

    #[test]
    fn subnet_hosts_v6_is_bounded() {
        let (addr, prefix) = parse_cidr("2001:db8::1/64").unwrap();
        let hosts = subnet_hosts(addr, prefix, 5);
        assert_eq!(hosts.len(), 5);
        assert_eq!(hosts[0], "2001:db8::1".parse::<IpAddr>().unwrap());
    }

    #[test]
    fn same_subnet_detection() {
        let a: IpAddr = "192.168.1.10".parse().unwrap();
        let b: IpAddr = "192.168.1.200".parse().unwrap();
        let c: IpAddr = "192.168.2.10".parse().unwrap();
        assert!(same_subnet(a, b, 24));
        assert!(!same_subnet(a, c, 24));
    }

    #[test]
    fn private_scope_detection() {
        assert!(is_private_ip(&"10.1.2.3".parse().unwrap()));
        assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
        assert!(is_private_ip(&"192.168.0.1".parse().unwrap()));
        assert!(is_private_ip(&"fe80::1".parse().unwrap()));
        assert!(is_private_ip(&"fd00::1".parse().unwrap()));
        assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
        assert!(is_local_scope(&"127.0.0.1".parse().unwrap()));
    }

    #[test]
    fn csv_escaping() {
        assert_eq!(csv_escape("plain"), "plain");
        assert_eq!(csv_escape("a,b"), "\"a,b\"");
        assert_eq!(csv_escape("say \"hi\""), "\"say \"\"hi\"\"\"");
        assert_eq!(csv_escape("line\nbreak"), "\"line\nbreak\"");
    }

    #[test]
    fn terminal_sanitization_blocks_escape_sequences() {
        let hostile = "\x1b[2J\x1b[31mEvil\x07 Server\r\n";
        let clean = sanitize_terminal(hostile);
        assert!(!clean.contains('\x1b'));
        assert!(!clean.contains('\x07'));
        assert!(!clean.contains('\r'));
        assert!(clean.contains("Evil"));
        assert!(clean.contains("Server"));
        assert_eq!(clean, "Evil Server");
        assert_eq!(sanitize_terminal("  normal banner  "), "normal banner");
        // Complete CSI sequences are removed, including their parameters.
        assert_eq!(sanitize_terminal("\x1b[1;31mred\x1b[0m"), "red");
        assert_eq!(sanitize_terminal("a\x1b]0;title\x07b"), "a b");
    }

    #[test]
    fn html_escaping() {
        assert_eq!(
            html_escape("<script>alert('x')</script>"),
            "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;"
        );
        assert_eq!(html_escape("a & b"), "a &amp; b");
    }

    #[test]
    fn redaction_hides_secret_values() {
        let redacted = redact("api_key=abc123 user=bob token: zzz");
        assert!(!redacted.contains("abc123"));
        assert!(!redacted.contains("zzz"));
        assert!(redacted.contains("user=bob"));
    }

    #[test]
    fn human_formats() {
        assert_eq!(human_bytes(999), "999 B");
        assert_eq!(human_bytes(1500), "1.5 KB");
        assert_eq!(human_bytes_binary(1024), "1.0 KiB");
        assert_eq!(human_duration(Duration::from_millis(250)), "250ms");
        assert_eq!(human_uptime(90_000), "1d 1h 0m");
    }

    #[test]
    fn ip_sort_order_is_numeric() {
        let mut ips: Vec<IpAddr> = ["192.168.1.10", "192.168.1.2", "10.0.0.1"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        ips.sort_by_key(ip_sort_key);
        let as_strings: Vec<String> = ips.iter().map(|i| i.to_string()).collect();
        assert_eq!(as_strings, vec!["10.0.0.1", "192.168.1.2", "192.168.1.10"]);
    }

    #[test]
    fn which_finds_sh_and_misses_nonsense() {
        assert!(which("sh").is_some() || which("sh.exe").is_some());
        assert!(which("definitely-not-a-real-binary-netro").is_none());
    }

    #[test]
    fn run_command_reports_missing_binary() {
        let err = run_command(
            "definitely-not-a-real-binary-netro",
            &["--x"],
            Duration::from_secs(1),
        )
        .unwrap_err();
        assert_eq!(err.code(), ErrorCode::DependencyMissing);
    }

    #[test]
    fn run_command_executes_without_shell() {
        let out = run_command("echo", &["hello"], Duration::from_secs(5)).unwrap();
        assert!(out.success());
        assert!(out.stdout.contains("hello"));
    }
}
