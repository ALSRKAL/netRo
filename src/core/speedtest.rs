//! Network speed test with a provider abstraction.
//!
//! Providers:
//! * `iperf3` — talks to a user-specified iperf3 server (TCP or UDP). Throughput,
//!   jitter and packet loss come from iperf3's JSON output.
//! * `http` — a minimal HTTP/1.1 client (chunked upload, streamed download)
//!   against a user-specified URL. HTTPS uses rustls when built with the `tls`
//!   feature.
//!
//! netRo never contacts a speed-test provider on its own: a server must be
//! configured or passed on the command line, and the provider/server is always
//! stated in the result.

use crate::error::{dependency_missing, ErrorCode, NetroError, Result};
use crate::util::{self, which};
use serde::{Deserialize, Serialize};
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Download,
    Upload,
    Both,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestOptions {
    pub provider: String,
    pub server: Option<String>,
    pub port: Option<u16>,
    pub duration: Duration,
    pub direction: Direction,
    pub udp: bool,
    pub timeout: Duration,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LatencySample {
    pub connect_ms: Option<f64>,
    pub first_byte_ms: Option<f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpeedTestResult {
    pub provider: String,
    pub server: String,
    pub direction: String,
    pub latency: Option<LatencySample>,
    pub download_mbps: Option<f64>,
    pub upload_mbps: Option<f64>,
    pub jitter_ms: Option<f64>,
    pub packet_loss_percent: Option<f64>,
    pub bytes_downloaded: Option<u64>,
    pub bytes_uploaded: Option<u64>,
    pub duration_secs: f64,
    pub note: String,
    pub error: Option<String>,
}

/// A speed-test provider. Implementations must perform real transfers; they
/// must never synthesize numbers.
pub trait SpeedTestProvider {
    fn name(&self) -> &'static str;
    fn run(&self, options: &SpeedTestOptions) -> Result<SpeedTestResult>;
}

pub fn provider_for(name: &str) -> Result<Box<dyn SpeedTestProvider>> {
    match name.to_ascii_lowercase().as_str() {
        "iperf3" => Ok(Box::new(Iperf3Provider)),
        "http" | "https" => Ok(Box::new(HttpProvider)),
        other => Err(NetroError::new(
            ErrorCode::ConfigError,
            format!("unknown speed test provider '{other}' (expected iperf3 or http)"),
        )),
    }
}

// ---------------------------------------------------------------------------
// iperf3
// ---------------------------------------------------------------------------

pub struct Iperf3Provider;

impl SpeedTestProvider for Iperf3Provider {
    fn name(&self) -> &'static str {
        "iperf3"
    }

    fn run(&self, options: &SpeedTestOptions) -> Result<SpeedTestResult> {
        let binary =
            which("iperf3").ok_or_else(|| dependency_missing("iperf3", "throughput testing"))?;
        let server = options.server.clone().ok_or_else(|| {
            NetroError::new(
                ErrorCode::ConfigError,
                "iperf3 requires a server (--server host or integrations.speedtest_server)",
            )
        })?;
        let port = options.port.unwrap_or(5201);
        let mut result = SpeedTestResult {
            provider: "iperf3".into(),
            server: format!("{server}:{port}"),
            direction: match options.direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
                Direction::Both => "both",
            }
            .into(),
            latency: None,
            download_mbps: None,
            upload_mbps: None,
            jitter_ms: None,
            packet_loss_percent: None,
            bytes_downloaded: None,
            bytes_uploaded: None,
            duration_secs: options.duration.as_secs_f64(),
            note: if options.udp {
                "UDP mode: jitter and loss are reported by iperf3; rate is not a capacity measurement".into()
            } else {
                "TCP mode: measured against the configured iperf3 server".into()
            },
            error: None,
        };

        let run_one = |reverse: bool| -> Result<IperfSummary> {
            let mut args: Vec<String> = vec![
                "-c".into(),
                server.clone(),
                "-p".into(),
                port.to_string(),
                "-t".into(),
                options.duration.as_secs().max(1).to_string(),
                "-J".into(),
                "--connect-timeout".into(),
                options.timeout.as_millis().max(1000).to_string(),
            ];
            if reverse {
                args.push("-R".into());
            }
            if options.udp {
                args.push("-u".into());
                args.push("-b".into());
                args.push("0".into());
            }
            let out = util::run_command(
                &binary.to_string_lossy(),
                &args,
                options.duration + Duration::from_secs(15),
            )?;
            if !out.success() {
                return Err(NetroError::new(
                    ErrorCode::NetworkUnreachable,
                    format!(
                        "iperf3 failed: {}",
                        out.stderr.trim().lines().next().unwrap_or("unknown error")
                    ),
                ));
            }
            parse_iperf3_json(&out.stdout)
        };

        match options.direction {
            Direction::Upload => {
                let summary = run_one(false)?;
                result.upload_mbps = summary
                    .sent_bps
                    .or(summary.received_bps)
                    .map(|b| b / 1_000_000.0);
                result.bytes_uploaded = summary.bytes;
                result.jitter_ms = summary.jitter_ms;
                result.packet_loss_percent = summary.lost_percent;
            }
            Direction::Download => {
                let summary = run_one(true)?;
                result.download_mbps = summary
                    .received_bps
                    .or(summary.sent_bps)
                    .map(|b| b / 1_000_000.0);
                result.bytes_downloaded = summary.bytes;
                result.jitter_ms = summary.jitter_ms;
                result.packet_loss_percent = summary.lost_percent;
            }
            Direction::Both => {
                let up = run_one(false)?;
                result.upload_mbps = up.sent_bps.or(up.received_bps).map(|b| b / 1_000_000.0);
                result.bytes_uploaded = up.bytes;
                let down = run_one(true)?;
                result.download_mbps = down.received_bps.or(down.sent_bps).map(|b| b / 1_000_000.0);
                result.bytes_downloaded = down.bytes;
                result.jitter_ms = up.jitter_ms.or(down.jitter_ms);
                result.packet_loss_percent = up.lost_percent.or(down.lost_percent);
            }
        }
        Ok(result)
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct IperfSummary {
    /// Sender-side throughput (upload when netro is the client).
    pub sent_bps: Option<f64>,
    /// Receiver-side throughput (download when netro is the client).
    pub received_bps: Option<f64>,
    pub bytes: Option<u64>,
    pub jitter_ms: Option<f64>,
    pub lost_percent: Option<f64>,
}

/// Parse `iperf3 -J` output.
pub fn parse_iperf3_json(text: &str) -> Result<IperfSummary> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|e| {
        NetroError::new(
            ErrorCode::ParseError,
            format!("iperf3 did not return valid JSON: {e}"),
        )
    })?;
    let end = value.get("end").unwrap_or(&value);
    let number =
        |v: &serde_json::Value, key: &str| -> Option<f64> { v.get(key).and_then(|x| x.as_f64()) };
    let mut summary = IperfSummary::default();

    if let Some(section) = end.get("sum_sent") {
        summary.sent_bps = number(section, "bits_per_second");
        if summary.bytes.is_none() {
            summary.bytes = section.get("bytes").and_then(|b| b.as_u64());
        }
    }
    if let Some(section) = end.get("sum_received") {
        summary.received_bps = number(section, "bits_per_second");
        if summary.bytes.is_none() {
            summary.bytes = section.get("bytes").and_then(|b| b.as_u64());
        }
    }
    // UDP tests report jitter/loss (and often a combined rate) under "sum".
    if let Some(section) = end.get("sum") {
        if summary.sent_bps.is_none() {
            summary.sent_bps = number(section, "bits_per_second");
        }
        if summary.received_bps.is_none() {
            summary.received_bps = number(section, "bits_per_second");
        }
        if summary.jitter_ms.is_none() {
            summary.jitter_ms = number(section, "jitter_ms");
        }
        if summary.lost_percent.is_none() {
            summary.lost_percent = number(section, "lost_percent");
        }
        if summary.bytes.is_none() {
            summary.bytes = section.get("bytes").and_then(|b| b.as_u64());
        }
    }
    if summary.sent_bps.is_none() && summary.received_bps.is_none() && summary.bytes.is_none() {
        return Err(NetroError::new(
            ErrorCode::ParseError,
            "iperf3 JSON contained no throughput summary",
        ));
    }
    Ok(summary)
}

// ---------------------------------------------------------------------------
// HTTP provider
// ---------------------------------------------------------------------------

pub struct HttpProvider;

#[derive(Debug, Clone, PartialEq)]
pub struct HttpUrl {
    pub https: bool,
    pub host: String,
    pub port: u16,
    pub path: String,
}

/// Parse an absolute HTTP(S) URL (no external dependency).
pub fn parse_http_url(url: &str) -> Result<HttpUrl> {
    let (https, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{url}' is not an absolute http:// or https:// URL"),
        ));
    };
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{path}")),
        None => (rest, "/".to_string()),
    };
    if authority.is_empty() {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{url}' has no host"),
        ));
    }
    let (host, port) = match authority.rsplit_once(':') {
        Some((host, port)) if port.chars().all(|c| c.is_ascii_digit()) => {
            let port: u16 = port.parse().map_err(|_| {
                NetroError::new(ErrorCode::InvalidTarget, format!("bad port in {url}"))
            })?;
            (host.to_string(), port)
        }
        _ => (authority.to_string(), if https { 443 } else { 80 }),
    };
    if host.is_empty() {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{url}' has no host"),
        ));
    }
    Ok(HttpUrl {
        https,
        host,
        port,
        path,
    })
}

impl SpeedTestProvider for HttpProvider {
    fn name(&self) -> &'static str {
        "http"
    }

    fn run(&self, options: &SpeedTestOptions) -> Result<SpeedTestResult> {
        let url = options.server.clone().ok_or_else(|| {
            NetroError::new(
                ErrorCode::ConfigError,
                "the http provider requires a URL (--server https://host/path or integrations.speedtest_server)",
            )
        })?;
        let parsed = parse_http_url(&url)?;
        let addr = resolve_addr(&parsed.host, parsed.port, options.timeout)?;

        let mut result = SpeedTestResult {
            provider: "http".into(),
            server: url.clone(),
            direction: match options.direction {
                Direction::Download => "download",
                Direction::Upload => "upload",
                Direction::Both => "both",
            }
            .into(),
            latency: None,
            download_mbps: None,
            upload_mbps: None,
            jitter_ms: None,
            packet_loss_percent: None,
            bytes_downloaded: None,
            bytes_uploaded: None,
            duration_secs: options.duration.as_secs_f64(),
            note: "HTTP throughput depends on the configured server and its capacity".into(),
            error: None,
        };

        if parsed.https {
            #[cfg(not(feature = "tls"))]
            {
                return Err(NetroError::new(
                    ErrorCode::PlatformUnsupported,
                    "HTTPS speed test requires a build with the 'tls' feature",
                ));
            }
        }

        // Each direction uses a fresh connection: HTTP keep-alive semantics are
        // not assumed, so a single request per connection is the only
        // defensible design.
        let mut connect_ms = None;
        let mut first_byte_ms = None;

        if matches!(options.direction, Direction::Download | Direction::Both) {
            let started = Instant::now();
            let stream = TcpStream::connect_timeout(&addr, options.timeout).map_err(|e| {
                NetroError::new(
                    ErrorCode::NetworkUnreachable,
                    format!("cannot connect to {addr}: {e}"),
                )
            })?;
            connect_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
            stream.set_read_timeout(Some(options.timeout)).ok();
            stream.set_write_timeout(Some(options.timeout)).ok();
            let (bytes, elapsed, first_byte) =
                http_download(stream, &parsed, options.duration, options.timeout)?;
            first_byte_ms = first_byte;
            result.download_mbps = Some(megabits(bytes, elapsed));
            result.bytes_downloaded = Some(bytes);
        }
        if matches!(options.direction, Direction::Upload | Direction::Both) {
            let started = Instant::now();
            let stream = TcpStream::connect_timeout(&addr, options.timeout).map_err(|e| {
                NetroError::new(
                    ErrorCode::NetworkUnreachable,
                    format!("cannot connect to {addr}: {e}"),
                )
            })?;
            if connect_ms.is_none() {
                connect_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
            }
            stream.set_read_timeout(Some(options.timeout)).ok();
            stream.set_write_timeout(Some(options.timeout)).ok();
            let (bytes, elapsed) = http_upload(stream, &parsed, options.duration, options.timeout)?;
            result.upload_mbps = Some(megabits(bytes, elapsed));
            result.bytes_uploaded = Some(bytes);
        }
        result.latency = Some(LatencySample {
            connect_ms,
            first_byte_ms,
        });
        Ok(result)
    }
}

fn megabits(bytes: u64, elapsed: Duration) -> f64 {
    if elapsed.as_secs_f64() <= 0.0 {
        return 0.0;
    }
    (bytes as f64 * 8.0) / elapsed.as_secs_f64() / 1_000_000.0
}

fn resolve_addr(host: &str, port: u16, timeout: Duration) -> Result<SocketAddr> {
    let addrs: Vec<SocketAddr> = (host, port)
        .to_socket_addrs()
        .map_err(|e| {
            NetroError::new(
                ErrorCode::NetworkDnsUnavailable,
                format!("cannot resolve {host}: {e}"),
            )
        })?
        .collect();
    let _ = timeout;
    addrs.into_iter().next().ok_or_else(|| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("no addresses for {host}"),
        )
    })
}

#[cfg(feature = "tls")]
struct MaybeTls {
    inner: Option<Box<rustls::StreamOwned<rustls::ClientConnection, TcpStream>>>,
    plain: Option<TcpStream>,
}

#[cfg(not(feature = "tls"))]
struct MaybeTls {
    plain: Option<TcpStream>,
}

#[cfg(feature = "tls")]
fn maybe_tls(stream: TcpStream, parsed: &HttpUrl) -> Result<MaybeTls> {
    if !parsed.https {
        return Ok(MaybeTls {
            inner: None,
            plain: Some(stream),
        });
    }
    use rustls::pki_types::ServerName;
    use std::sync::Arc;
    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();
    let server_name = ServerName::try_from(parsed.host.clone())
        .map_err(|e| NetroError::new(ErrorCode::InvalidTarget, format!("bad TLS name: {e}")))?;
    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| NetroError::new(ErrorCode::Io, format!("TLS setup failed: {e}")))?;
    let mut tls = rustls::StreamOwned::new(conn, stream);
    while tls.conn.is_handshaking() {
        tls.conn
            .complete_io(&mut tls.sock)
            .map_err(|e| NetroError::new(ErrorCode::Io, format!("TLS handshake failed: {e}")))?;
    }
    Ok(MaybeTls {
        inner: Some(Box::new(tls)),
        plain: None,
    })
}

#[cfg(not(feature = "tls"))]
fn maybe_tls(stream: TcpStream, parsed: &HttpUrl) -> Result<MaybeTls> {
    if parsed.https {
        return Err(NetroError::new(
            ErrorCode::PlatformUnsupported,
            "HTTPS requires a build with the 'tls' feature",
        ));
    }
    Ok(MaybeTls {
        plain: Some(stream),
    })
}

#[cfg(feature = "tls")]
impl Read for MaybeTls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        if let Some(tls) = self.inner.as_mut() {
            tls.read(buf)
        } else if let Some(plain) = self.plain.as_mut() {
            plain.read(buf)
        } else {
            Ok(0)
        }
    }
}

#[cfg(feature = "tls")]
impl Write for MaybeTls {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        if let Some(tls) = self.inner.as_mut() {
            tls.write(buf)
        } else if let Some(plain) = self.plain.as_mut() {
            plain.write(buf)
        } else {
            Ok(buf.len())
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        if let Some(tls) = self.inner.as_mut() {
            tls.flush()
        } else if let Some(plain) = self.plain.as_mut() {
            plain.flush()
        } else {
            Ok(())
        }
    }
}

#[cfg(not(feature = "tls"))]
impl Read for MaybeTls {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        match self.plain.as_mut() {
            Some(plain) => plain.read(buf),
            None => Ok(0),
        }
    }
}

#[cfg(not(feature = "tls"))]
impl Write for MaybeTls {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        match self.plain.as_mut() {
            Some(plain) => plain.write(buf),
            None => Ok(buf.len()),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> {
        match self.plain.as_mut() {
            Some(plain) => plain.flush(),
            None => Ok(()),
        }
    }
}

fn http_download(
    stream: TcpStream,
    parsed: &HttpUrl,
    duration: Duration,
    timeout: Duration,
) -> Result<(u64, Duration, Option<f64>)> {
    let mut stream = maybe_tls(stream, parsed)?;
    let request = format!(
        "GET {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netro/{}\r\nAccept: */*\r\nConnection: close\r\n\r\n",
        parsed.path,
        parsed.host,
        crate::version::VERSION
    );
    let started = Instant::now();
    stream
        .write_all(request.as_bytes())
        .map_err(|e| NetroError::new(ErrorCode::Io, format!("HTTP write failed: {e}")))?;
    stream.flush().ok();

    let mut buf = vec![0u8; 64 * 1024];
    let mut total = 0u64;
    let mut header_end: Option<usize> = None;
    let mut header_bytes: Vec<u8> = Vec::new();
    let mut first_byte_ms = None;
    let deadline = started + duration;
    loop {
        if Instant::now() >= deadline && total > 0 {
            break;
        }
        match stream.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => {
                if first_byte_ms.is_none() {
                    first_byte_ms = Some(started.elapsed().as_secs_f64() * 1000.0);
                }
                if header_end.is_none() {
                    header_bytes.extend_from_slice(&buf[..n]);
                    if header_bytes.len() > 64 * 1024 {
                        return Err(NetroError::new(
                            ErrorCode::ParseError,
                            "HTTP response headers exceed 64 KiB",
                        ));
                    }
                    if let Some(pos) = find_header_end(&header_bytes) {
                        let status = parse_http_status(&header_bytes[..pos]);
                        match status {
                            Some(code) if (200..300).contains(&code) => {}
                            Some(code) => {
                                return Err(NetroError::new(
                                    ErrorCode::NetworkUnreachable,
                                    format!(
                                        "speed test server returned HTTP {code}; refusing to \
                                         measure an error response"
                                    ),
                                ));
                            }
                            None => {
                                return Err(NetroError::new(
                                    ErrorCode::ParseError,
                                    "speed test server returned an invalid HTTP status line",
                                ));
                            }
                        }
                        header_end = Some(pos);
                        total += (n - pos) as u64;
                    }
                } else {
                    total += n as u64;
                }
                if Instant::now() >= deadline {
                    break;
                }
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                if total > 0 {
                    break;
                }
                return Err(NetroError::new(
                    ErrorCode::Timeout,
                    format!("no HTTP response within {:.1}s", timeout.as_secs_f64()),
                ));
            }
            Err(e) => {
                if total > 0 {
                    break;
                }
                return Err(NetroError::new(
                    ErrorCode::Io,
                    format!("HTTP read failed: {e}"),
                ));
            }
        }
    }
    Ok((total, started.elapsed(), first_byte_ms))
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
}

/// Extract the numeric status code from an HTTP/1.x status line.
pub fn parse_http_status(header: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(header);
    let first_line = text.lines().next()?;
    let mut parts = first_line.split_whitespace();
    let version = parts.next()?;
    if !version.starts_with("HTTP/") {
        return None;
    }
    parts.next()?.parse::<u16>().ok()
}

fn http_upload(
    stream: TcpStream,
    parsed: &HttpUrl,
    duration: Duration,
    _timeout: Duration,
) -> Result<(u64, Duration)> {
    let mut stream = maybe_tls(stream, parsed)?;
    let request = format!(
        "POST {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: netro/{}\r\nContent-Type: application/octet-stream\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
        parsed.path,
        parsed.host,
        crate::version::VERSION
    );
    stream
        .write_all(request.as_bytes())
        .map_err(|e| NetroError::new(ErrorCode::Io, format!("HTTP write failed: {e}")))?;

    let chunk = vec![0x5Au8; 64 * 1024];
    let chunk_prefix = format!("{:x}\r\n", chunk.len());
    let started = Instant::now();
    let mut sent = 0u64;
    let deadline = started + duration;
    let mut error: Option<NetroError> = None;
    while Instant::now() < deadline {
        if let Err(e) = stream.write_all(chunk_prefix.as_bytes()) {
            error = Some(NetroError::new(
                ErrorCode::Io,
                format!("HTTP upload failed: {e}"),
            ));
            break;
        }
        match stream.write_all(&chunk) {
            Ok(()) => sent += chunk.len() as u64,
            Err(e) => {
                error = Some(NetroError::new(
                    ErrorCode::Io,
                    format!("HTTP upload failed: {e}"),
                ));
                break;
            }
        }
        if stream.write_all(b"\r\n").is_err() {
            break;
        }
    }
    let _ = stream.write_all(b"0\r\n\r\n");
    let _ = stream.flush();
    if let Some(e) = error {
        if sent == 0 {
            return Err(e);
        }
    }
    Ok((sent, started.elapsed()))
}

/// Build options from the CLI and configuration, applying defaults and
/// producing actionable errors when nothing is configured.
pub fn resolve_options(
    provider: Option<&str>,
    server: Option<&str>,
    port: Option<u16>,
    duration_secs: f64,
    direction: Direction,
    udp: bool,
    config: &crate::config::Config,
) -> Result<SpeedTestOptions> {
    let server = server
        .map(|s| s.to_string())
        .or_else(|| config.integrations.speedtest_server.clone());
    let provider = provider
        .map(|s| s.to_string())
        .or_else(|| config.integrations.speedtest_provider.clone())
        .unwrap_or_else(|| {
            if util::has_program("iperf3") {
                "iperf3".to_string()
            } else {
                "http".to_string()
            }
        });
    if server.is_none() {
        return Err(
            NetroError::new(ErrorCode::ConfigError, "no speed test server configured").with_hint(
                "pass --server <host> (iperf3) or --server <https://url> (http), or run \
             `netro config set integrations.speedtest_server <value>`",
            ),
        );
    }
    Ok(SpeedTestOptions {
        provider,
        server,
        port,
        duration: Duration::from_secs_f64(duration_secs.clamp(1.0, 120.0)),
        direction,
        udp,
        timeout: Duration::from_secs(10),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn http_url_parsing() {
        let url = parse_http_url("https://speed.example.com/down?size=100").unwrap();
        assert!(url.https);
        assert_eq!(url.host, "speed.example.com");
        assert_eq!(url.port, 443);
        assert_eq!(url.path, "/down?size=100");

        let url = parse_http_url("http://10.0.0.5:8080/upload").unwrap();
        assert!(!url.https);
        assert_eq!(url.host, "10.0.0.5");
        assert_eq!(url.port, 8080);
        assert_eq!(url.path, "/upload");

        let url = parse_http_url("http://example.com").unwrap();
        assert_eq!(url.path, "/");
        assert_eq!(url.port, 80);
    }

    #[test]
    fn http_url_rejects_invalid() {
        assert!(parse_http_url("ftp://example.com").is_err());
        assert!(parse_http_url("example.com").is_err());
        assert!(parse_http_url("http://").is_err());
        assert!(parse_http_url("http://host:99999/").is_err());
    }

    #[test]
    fn iperf3_json_parsing_tcp() {
        let fixture = r#"{"end":{"sum_sent":{"start":0,"end":5,"seconds":5,"bytes":62500000,"bits_per_second":100000000,"retransmits":0},"sum_received":{"start":0,"end":5,"seconds":5,"bytes":62000000,"bits_per_second":99200000}}}"#;
        let summary = parse_iperf3_json(fixture).unwrap();
        assert_eq!(summary.sent_bps, Some(100000000.0));
        assert_eq!(summary.received_bps, Some(99200000.0));
        assert_eq!(summary.bytes, Some(62500000));
        assert!(summary.jitter_ms.is_none());
    }

    #[test]
    fn iperf3_json_parsing_udp_reports_jitter_and_loss() {
        let fixture = r#"{"end":{"sum":{"start":0,"end":5,"seconds":5,"bytes":1000000,"bits_per_second":1600000,"jitter_ms":0.45,"lost_packets":2,"packets":1000,"lost_percent":0.2,"sender":true},"sum_sent":{"bits_per_second":1600000}}}"#;
        let summary = parse_iperf3_json(fixture).unwrap();
        assert_eq!(summary.jitter_ms, Some(0.45));
        assert_eq!(summary.lost_percent, Some(0.2));
        assert_eq!(summary.sent_bps, Some(1600000.0));
    }

    #[test]
    fn http_status_parsing() {
        assert_eq!(
            parse_http_status(b"HTTP/1.1 200 OK\r\nServer: x\r\n"),
            Some(200)
        );
        assert_eq!(parse_http_status(b"HTTP/1.0 404 Not Found\r\n"), Some(404));
        assert_eq!(parse_http_status(b"HTTP/1.1 401 Unauthorized"), Some(401));
        assert_eq!(parse_http_status(b"garbage"), None);
        assert_eq!(parse_http_status(b""), None);
    }

    #[test]
    fn iperf3_json_rejects_non_json() {
        assert_eq!(
            parse_iperf3_json("iperf3: error - unable to connect")
                .unwrap_err()
                .code(),
            ErrorCode::ParseError
        );
    }

    #[test]
    fn unknown_provider_is_rejected() {
        let error = provider_for("speedtest.net")
            .err()
            .expect("unknown provider must fail");
        assert_eq!(error.code(), ErrorCode::ConfigError);
    }

    #[test]
    fn speedtest_requires_a_server() {
        let config = crate::config::Config::default();
        let err =
            resolve_options(None, None, None, 5.0, Direction::Both, false, &config).unwrap_err();
        assert_eq!(err.code(), ErrorCode::ConfigError);
        assert!(err.hint().unwrap_or("").contains("--server"));
    }
}
