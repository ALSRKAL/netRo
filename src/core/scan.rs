//! Port scanning engine.
//!
//! - TCP connect scan with bounded concurrency and per-connect timeouts.
//! - Service identification from a curated catalog plus live protocol probes
//!   (banners, HTTP `Server:` headers, TLS handshakes).
//! - UDP probing for a small set of well-defined services (DNS, NTP).
//! - Public targets require explicit authorization; private/loopback targets do
//!   not, but the CLI always prints the applicable-use notice.
//!
//! Everything reported is derived from an actual network exchange; when only a
//! port number is known the confidence is reported as `low`.

use crate::core::dns;
use crate::error::{invalid_target, ErrorCode, NetroError, Result};
use crate::model::*;
use crate::util;
use std::io::{Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream, UdpSocket};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub timeout: Duration,
    pub concurrency: usize,
    pub banner: bool,
    pub tls: bool,
    pub udp: bool,
    pub authorized: bool,
    /// Optional cooperative cancellation flag. Workers check it before each
    /// probe and stop promptly; partial results are returned with a note.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl ScanOptions {
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
}

/// Real scan progress: `completed` of `total` TCP probes finished.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ScanProgress {
    pub completed: usize,
    pub total: usize,
}

impl Default for ScanOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(1000),
            concurrency: 100,
            banner: true,
            tls: true,
            udp: false,
            authorized: false,
            cancel: None,
        }
    }
}

/// Ports scanned by `--ports common`.
pub const COMMON_PORTS: &[u16] = &[
    20, 21, 22, 23, 25, 53, 67, 68, 69, 80, 88, 110, 111, 123, 135, 137, 138, 139, 143, 161, 162,
    179, 389, 443, 445, 465, 500, 514, 515, 548, 587, 623, 631, 636, 873, 902, 989, 990, 993, 995,
    1080, 1194, 1433, 1521, 1701, 1723, 1883, 1900, 2049, 2082, 2083, 2181, 2222, 2375, 2376, 3128,
    3260, 3306, 3389, 4443, 4505, 4506, 5000, 5432, 5555, 5601, 5672, 5900, 5901, 5984, 5985, 5986,
    6379, 6443, 7001, 7077, 8000, 8008, 8080, 8081, 8086, 8443, 8888, 9000, 9090, 9092, 9200, 9300,
    9418, 9443, 10000, 10250, 11211, 15672, 27017, 27018, 50000,
];

/// Curated service catalog: (port, name, expects_tls_hint).
const CATALOG: &[(u16, &str, bool)] = &[
    (20, "ftp-data", false),
    (21, "ftp", false),
    (22, "ssh", false),
    (23, "telnet", false),
    (25, "smtp", false),
    (53, "dns", false),
    (67, "dhcp", false),
    (68, "dhcp", false),
    (69, "tftp", false),
    (80, "http", false),
    (88, "kerberos", false),
    (110, "pop3", false),
    (111, "rpcbind", false),
    (123, "ntp", false),
    (135, "msrpc", false),
    (137, "netbios-ns", false),
    (138, "netbios-dgm", false),
    (139, "netbios-ssn", false),
    (143, "imap", false),
    (161, "snmp", false),
    (162, "snmptrap", false),
    (179, "bgp", false),
    (389, "ldap", false),
    (443, "https", true),
    (445, "microsoft-ds", false),
    (465, "smtps", true),
    (500, "isakmp", false),
    (514, "syslog", false),
    (515, "printer", false),
    (548, "afp", false),
    (587, "submission", false),
    (623, "ipmi", false),
    (631, "ipp", false),
    (636, "ldaps", true),
    (873, "rsync", false),
    (902, "vmware-auth", false),
    (989, "ftps-data", true),
    (990, "ftps", true),
    (993, "imaps", true),
    (995, "pop3s", true),
    (1080, "socks", false),
    (1194, "openvpn", false),
    (1433, "ms-sql", false),
    (1521, "oracle", false),
    (1701, "l2tp", false),
    (1723, "pptp", false),
    (1883, "mqtt", false),
    (1900, "ssdp", false),
    (2049, "nfs", false),
    (2082, "cpanel", false),
    (2083, "cpanel-ssl", true),
    (2181, "zookeeper", false),
    (2222, "ssh-alt", false),
    (2375, "docker", false),
    (2376, "docker-tls", true),
    (3128, "squid", false),
    (3260, "iscsi", false),
    (3306, "mysql", false),
    (3389, "rdp", false),
    (4443, "https-alt", true),
    (4505, "salt-master", false),
    (4506, "salt-return", false),
    (5000, "http-alt", false),
    (5432, "postgresql", false),
    (5555, "adb/rtsp", false),
    (5601, "kibana", false),
    (5672, "amqp", false),
    (5900, "vnc", false),
    (5901, "vnc-alt", false),
    (5984, "couchdb", false),
    (5985, "winrm-http", false),
    (5986, "winrm-https", true),
    (6379, "redis", false),
    (6443, "kubernetes-api", true),
    (7001, "weblogic", false),
    (7077, "spark", false),
    (8000, "http-alt", false),
    (8008, "http-alt", false),
    (8080, "http-proxy", false),
    (8081, "http-alt", false),
    (8086, "influxdb", false),
    (8443, "https-alt", true),
    (8888, "http-alt", false),
    (9000, "http-alt", false),
    (9090, "prometheus", false),
    (9092, "kafka", false),
    (9200, "elasticsearch", false),
    (9300, "elasticsearch", false),
    (9418, "git", false),
    (9443, "https-alt", true),
    (10000, "webmin", false),
    (10250, "kubelet", true),
    (11211, "memcached", false),
    (15672, "rabbitmq-mgmt", false),
    (27017, "mongodb", false),
    (27018, "mongodb", false),
    (50000, "sap", false),
];

pub fn parse_ports(spec: &str) -> Result<Vec<u16>> {
    let trimmed = spec.trim().to_ascii_lowercase();
    let mut ports: Vec<u16> = Vec::new();
    match trimmed.as_str() {
        "common" | "top" => ports.extend_from_slice(COMMON_PORTS),
        "all" | "full" => ports.extend(1..=65535u16),
        "" => {
            return Err(NetroError::new(
                ErrorCode::InvalidTarget,
                "empty port specification",
            ))
        }
        _ => {
            for part in trimmed.split(',') {
                let part = part.trim();
                if part.is_empty() {
                    continue;
                }
                if let Some((start, end)) = part.split_once('-') {
                    let start: u16 = start.trim().parse().map_err(|_| {
                        invalid_target(format!("invalid port range start: {start}"))
                    })?;
                    let end: u16 = end
                        .trim()
                        .parse()
                        .map_err(|_| invalid_target(format!("invalid port range end: {end}")))?;
                    if start == 0 || start > end {
                        return Err(invalid_target(format!("invalid port range {start}-{end}")));
                    }
                    ports.extend(start..=end);
                } else {
                    let port: u16 = part
                        .parse()
                        .map_err(|_| invalid_target(format!("invalid port: {part}")))?;
                    if port == 0 {
                        return Err(invalid_target("port 0 is not scannable"));
                    }
                    ports.push(port);
                }
            }
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.is_empty() {
        return Err(invalid_target("no valid ports in specification"));
    }
    Ok(ports)
}

pub fn service_for_port(port: u16) -> Option<&'static str> {
    CATALOG
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(_, name, _)| *name)
}

fn likely_tls(port: u16) -> bool {
    CATALOG
        .iter()
        .find(|(p, _, _)| *p == port)
        .map(|(_, _, tls)| *tls)
        .unwrap_or(false)
}

/// Scan a single target.
pub fn scan(target: &str, ports: &[u16], options: &ScanOptions) -> Result<ScanReport> {
    scan_with(target, ports, options, &mut |_| {})
}

/// Scan with a progress observer. Progress reflects completed TCP probes, not
/// an estimate; cancellation returns partial results with `cancelled: true`
/// recorded in the note.
pub fn scan_with(
    target: &str,
    ports: &[u16],
    options: &ScanOptions,
    observer: &mut dyn FnMut(ScanProgress),
) -> Result<ScanReport> {
    let ips = crate::core::diagnostics::resolve(target)?;
    let public: Vec<IpAddr> = ips
        .iter()
        .cloned()
        .filter(|ip| !util::is_local_scope(ip))
        .collect();
    if !public.is_empty() && !options.authorized {
        return Err(NetroError::new(
            ErrorCode::UnauthorizedScan,
            format!(
                "target {target} resolves to public address(es): {}",
                public
                    .iter()
                    .map(|i| i.to_string())
                    .collect::<Vec<_>>()
                    .join(", ")
            ),
        )
        .with_hint("re-run with --authorized if you own or are authorized to test this system"));
    }

    let started = Instant::now();
    let started_epoch = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() as i64)
        .unwrap_or(0);

    let mut results: Vec<ScannedPort> = Vec::new();
    for ip in &ips {
        if options.is_cancelled() {
            break;
        }
        results.extend(scan_ip(*ip, ports, options, observer));
    }

    if options.udp && !options.is_cancelled() {
        if let Some(ip) = ips.first() {
            results.extend(scan_udp_ip(*ip, ports, options));
        }
    }

    results.sort_by_key(|p| (p.port, p.protocol.clone()));
    results.dedup_by(|a, b| a.port == b.port && a.protocol == b.protocol);

    Ok(ScanReport {
        target: target.to_string(),
        resolved: ips.iter().map(|i| i.to_string()).collect(),
        ports: results,
        started_epoch,
        duration_ms: started.elapsed().as_millis() as u64,
        concurrency: options.concurrency.max(1),
        timeout_ms: options.timeout.as_millis() as u64,
        scan_type: if options.udp {
            "tcp-connect + udp-probe".into()
        } else {
            "tcp-connect".into()
        },
        note: Some(if options.is_cancelled() {
            "scan cancelled: partial results shown; TCP connect scan requires a completed \
             handshake so results reflect actual responses"
                .into()
        } else {
            "TCP connect scan requires a completed handshake; results reflect actual responses"
                .into()
        }),
        cancelled: options.is_cancelled(),
    })
}

fn scan_ip(
    ip: IpAddr,
    ports: &[u16],
    options: &ScanOptions,
    observer: &mut dyn FnMut(ScanProgress),
) -> Vec<ScannedPort> {
    let workers = options.concurrency.clamp(1, 1024).min(ports.len().max(1));
    let next = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<ScannedPort>();
    let total = ports.len();

    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            scope.spawn(move || loop {
                if options.is_cancelled() {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                if index >= ports.len() {
                    break;
                }
                let port = ports[index];
                let result = probe_tcp_port(ip, port, options);
                if tx.send(result).is_err() {
                    break;
                }
            });
        }
        drop(tx);
        let mut collected = Vec::new();
        // Stream real completed counts to the observer; recv_timeout also lets
        // us notice cancellation while workers are still finishing probes.
        loop {
            match rx.recv_timeout(Duration::from_millis(80)) {
                Ok(item) => {
                    collected.push(item);
                    let completed = collected.len();
                    if completed == total || completed % 32 == 0 {
                        observer(ScanProgress { completed, total });
                    }
                }
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if options.is_cancelled() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        collected
    })
}

fn probe_tcp_port(ip: IpAddr, port: u16, options: &ScanOptions) -> ScannedPort {
    let addr = SocketAddr::new(ip, port);
    match TcpStream::connect_timeout(&addr, options.timeout) {
        Ok(_stream) => {
            let service = service_for_port(port).map(|s| s.to_string());
            let mut scanned = ScannedPort {
                port,
                protocol: "tcp".into(),
                state: PortState::Open,
                service: service.clone(),
                product: None,
                version: None,
                banner: None,
                tls: None,
                detection: Some(if service.is_some() {
                    "port catalog".into()
                } else {
                    "tcp handshake".into()
                }),
                confidence: if service.is_some() {
                    Confidence::Likely
                } else {
                    Confidence::Confirmed
                },
            };

            if options.tls && likely_tls(port) {
                scanned.tls = Some(tls_probe(ip, port, options.timeout));
                if scanned
                    .tls
                    .as_ref()
                    .map(|t| t.handshake_ok)
                    .unwrap_or(false)
                {
                    if let Some(tls) = &scanned.tls {
                        if tls.protocol_version.is_some() {
                            scanned.service = Some("https/tls".to_string());
                            scanned.detection = Some("tls handshake".into());
                            scanned.confidence = Confidence::Confirmed;
                        }
                    }
                }
            }

            if options.banner && scanned.tls.is_none() {
                if let Some(banner) = grab_banner(ip, port, service.as_deref(), options.timeout) {
                    let parsed = parse_banner(service.as_deref(), &banner);
                    scanned.product = parsed.0;
                    scanned.version = parsed.1;
                    if scanned.product.is_some() || scanned.version.is_some() {
                        scanned.confidence = Confidence::Confirmed;
                        scanned.detection = Some("banner/targeted probe".into());
                    }
                    scanned.banner = Some(summarize_banner(&banner));
                }
            }
            scanned
        }
        Err(e) => {
            let state = match e.kind() {
                std::io::ErrorKind::ConnectionRefused => PortState::Closed,
                std::io::ErrorKind::TimedOut => PortState::Filtered,
                _ => match e.raw_os_error() {
                    Some(111) | Some(10061) => PortState::Closed,
                    Some(110) | Some(10060) => PortState::Filtered,
                    _ => PortState::Closed,
                },
            };
            ScannedPort {
                port,
                protocol: "tcp".into(),
                state,
                service: service_for_port(port).map(|s| s.to_string()),
                product: None,
                version: None,
                banner: None,
                tls: None,
                detection: Some("tcp connect error".into()),
                confidence: Confidence::Confirmed,
            }
        }
    }
}

/// Read a service banner, sending a protocol-appropriate request when the
/// service does not speak first.
fn grab_banner(ip: IpAddr, port: u16, service: Option<&str>, timeout: Duration) -> Option<String> {
    let addr = SocketAddr::new(ip, port);
    let mut stream = TcpStream::connect_timeout(&addr, timeout).ok()?;
    stream.set_read_timeout(Some(timeout)).ok();
    stream.set_write_timeout(Some(timeout)).ok();

    if let Some(service) = service {
        let request: Option<String> = match service {
            "http" | "http-alt" | "http-proxy" | "elasticsearch" | "prometheus" | "kibana"
            | "influxdb" | "couchdb" | "webmin" | "rabbitmq-mgmt" => Some(format!(
                "HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: netro/{}\r\n\r\n",
                crate::version::VERSION
            )),
            "redis" => Some("PING\r\n".to_string()),
            "memcached" => Some("version\r\n".to_string()),
            "mongodb" | "mysql" | "postgresql" | "smtp" | "submission" | "pop3" | "imap"
            | "ssh" | "ftp" | "telnet" | "vnc" | "rdp" => None,
            _ => None,
        };
        if let Some(request) = request {
            let _ = stream.write_all(request.as_bytes());
        }
    }

    let mut buf = [0u8; 512];
    match stream.read(&mut buf) {
        Ok(0) => None,
        Ok(n) => Some(String::from_utf8_lossy(&buf[..n]).to_string()),
        Err(_) => None,
    }
}

fn summarize_banner(banner: &str) -> String {
    let first = banner.lines().find(|l| !l.trim().is_empty()).unwrap_or("");
    let cleaned = crate::util::sanitize_terminal(first);
    let mut s: String = cleaned.chars().take(200).collect();
    if cleaned.chars().count() > 200 {
        s.push('…');
    }
    s
}

/// Extract (product, version) from a banner/headers, only when evidence is
/// present.
pub fn parse_banner(service: Option<&str>, banner: &str) -> (Option<String>, Option<String>) {
    // Remote data: sanitize line by line (keeping the line structure that
    // protocol parsing depends on) so extracted fields can never carry
    // terminal escape sequences.
    let banner = banner
        .lines()
        .map(crate::util::sanitize_terminal)
        .collect::<Vec<_>>()
        .join("\n");
    let banner = banner.as_str();
    let lower = banner.to_ascii_lowercase();
    // HTTP Server header.
    for line in banner.lines() {
        if let Some(value) = line.split_once(':').and_then(|(k, v)| {
            if k.trim().eq_ignore_ascii_case("server") {
                Some(v.trim())
            } else {
                None
            }
        }) {
            let (product, version) = split_product_version(value);
            return (product, version);
        }
    }
    // SSH identification string.
    if lower.starts_with("ssh-") {
        let rest = banner.trim().strip_prefix("SSH-").unwrap_or(banner.trim());
        let rest = rest.split('-').skip(1).collect::<Vec<_>>().join("-");
        let (product, version) = split_product_version(&rest);
        return (product.or_else(|| Some("ssh".into())), version);
    }
    // FTP / SMTP greetings.
    if let Some(rest) = banner.trim().strip_prefix("220 ") {
        let (product, version) = split_product_version(rest);
        return (product, version);
    }
    if service == Some("redis") && lower.contains("pong") {
        return (Some("redis".into()), None);
    }
    (None, None)
}

fn split_product_version(text: &str) -> (Option<String>, Option<String>) {
    let cleaned = text.trim().trim_matches(|c| c == '(' || c == ')');
    let mut words = cleaned.split_whitespace();
    let first = words.next().unwrap_or("");
    // Handle "nginx/1.24.0" and "OpenSSH_9.6p1" style tokens first.
    let embedded = first.split_once('/').or_else(|| first.split_once('_'));
    if let Some((product, version)) = embedded {
        let version = version.trim_end_matches(';');
        return (
            (!product.is_empty()).then(|| product.to_string()),
            version
                .chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
                .then(|| version.to_string()),
        );
    }
    let product = (!first.is_empty()).then(|| first.to_string());
    let version = words
        .next()
        .map(|s| s.trim_end_matches(';').to_string())
        .filter(|s| {
            s.chars()
                .next()
                .map(|c| c.is_ascii_digit())
                .unwrap_or(false)
        });
    (product, version)
}

// ---------------------------------------------------------------------------
// TLS probing
// ---------------------------------------------------------------------------

#[cfg(feature = "tls")]
fn tls_probe(ip: IpAddr, port: u16, timeout: Duration) -> TlsInfo {
    match tls_probe_inner(ip, port, timeout) {
        Ok(info) => info,
        Err(e) => TlsInfo {
            handshake_ok: false,
            error: Some(e),
            protocol_version: None,
            cipher_suite: None,
            subject: None,
            issuer: None,
            not_before: None,
            not_after: None,
            days_remaining: None,
            san: Vec::new(),
            self_signed: None,
        },
    }
}

#[cfg(feature = "tls")]
fn tls_probe_inner(
    ip: IpAddr,
    port: u16,
    timeout: Duration,
) -> std::result::Result<TlsInfo, String> {
    use rustls::pki_types::ServerName;
    use std::sync::Arc;

    let root_store = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.to_vec(),
    };
    let config = rustls::ClientConfig::builder()
        .with_root_certificates(root_store)
        .with_no_client_auth();

    let server_name = match ip {
        IpAddr::V4(v4) => ServerName::IpAddress(v4.into()),
        IpAddr::V6(v6) => ServerName::IpAddress(v6.into()),
    };

    let conn = rustls::ClientConnection::new(Arc::new(config), server_name)
        .map_err(|e| format!("TLS setup failed: {e}"))?;
    let addr = SocketAddr::new(ip, port);
    let sock = TcpStream::connect_timeout(&addr, timeout)
        .map_err(|e| format!("TCP connect failed: {e}"))?;
    sock.set_read_timeout(Some(timeout)).ok();
    sock.set_write_timeout(Some(timeout)).ok();

    let mut tls = rustls::StreamOwned::new(conn, sock);
    // Drive the handshake explicitly so errors are attributable.
    while tls.conn.is_handshaking() {
        match tls.conn.complete_io(&mut tls.sock) {
            Ok(_) => {}
            Err(e) => return Err(format!("TLS handshake failed: {e}")),
        }
    }

    let protocol_version = tls.conn.protocol_version().map(|v| format!("{v:?}"));
    let cipher_suite = tls
        .conn
        .negotiated_cipher_suite()
        .map(|s| format!("{:?}", s.suite()));

    let certs = tls.conn.peer_certificates().unwrap_or(&[]);
    let mut info = TlsInfo {
        handshake_ok: true,
        error: None,
        protocol_version,
        cipher_suite,
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        days_remaining: None,
        san: Vec::new(),
        self_signed: None,
    };
    if let Some(leaf) = certs.first() {
        match x509_parser::parse_x509_certificate(leaf.as_ref()) {
            Ok((_, cert)) => {
                info.subject = Some(format_name(cert.subject()));
                info.issuer = Some(format_name(cert.issuer()));
                info.not_before = Some(cert.validity().not_before.to_string());
                info.not_after = Some(cert.validity().not_after.to_string());
                let now = chrono::Utc::now().timestamp();
                info.days_remaining = Some((cert.validity().not_after.timestamp() - now) / 86_400);
                if let Ok(Some(san)) = cert.subject_alternative_name() {
                    info.san = san
                        .value
                        .general_names
                        .iter()
                        .filter_map(|name| match name {
                            x509_parser::extensions::GeneralName::DNSName(d) => {
                                Some(crate::util::sanitize_terminal(d))
                            }
                            x509_parser::extensions::GeneralName::IPAddress(bytes) => {
                                match bytes.len() {
                                    4 => Some(
                                        IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]])
                                            .to_string(),
                                    ),
                                    16 => {
                                        let mut arr = [0u8; 16];
                                        arr.copy_from_slice(bytes);
                                        Some(IpAddr::from(arr).to_string())
                                    }
                                    _ => None,
                                }
                            }
                            _ => None,
                        })
                        .take(20)
                        .collect();
                }
                info.self_signed = Some(cert.subject() == cert.issuer());
            }
            Err(e) => {
                info.error = Some(format!("certificate parse failed: {e}"));
            }
        }
    }
    Ok(info)
}

#[cfg(feature = "tls")]
fn format_name(name: &x509_parser::x509::X509Name<'_>) -> String {
    let mut parts = Vec::new();
    for attr in name.iter_attributes() {
        let key = attr.attr_type().to_id_string();
        let short = match key.as_str() {
            "2.5.4.3" => "CN",
            "2.5.4.10" => "O",
            "2.5.4.11" => "OU",
            "2.5.4.6" => "C",
            "2.5.4.7" => "L",
            "2.5.4.8" => "ST",
            _ => key.as_str(),
        };
        let value = attr
            .as_str()
            .map(|s| s.to_string())
            .unwrap_or_else(|_| String::from_utf8_lossy(attr.as_slice()).to_string());
        parts.push(format!(
            "{short}={}",
            crate::util::sanitize_terminal(&value)
        ));
    }
    parts.join(", ")
}

#[cfg(not(feature = "tls"))]
fn tls_probe(_ip: IpAddr, _port: u16, _timeout: Duration) -> TlsInfo {
    TlsInfo {
        handshake_ok: false,
        error: Some(
            "netro was built without TLS support (--no-default-features); rebuild with --features tls"
                .into(),
        ),
        protocol_version: None,
        cipher_suite: None,
        subject: None,
        issuer: None,
        not_before: None,
        not_after: None,
        days_remaining: None,
        san: Vec::new(),
        self_signed: None,
    }
}

// ---------------------------------------------------------------------------
// UDP probing
// ---------------------------------------------------------------------------

fn scan_udp_ip(ip: IpAddr, ports: &[u16], options: &ScanOptions) -> Vec<ScannedPort> {
    let mut out = Vec::new();
    for &port in ports {
        let payload: Vec<u8> = match port {
            53 => {
                let id = 0x4E52u16;
                // A query for example.com A.
                dns::encode_query(id, "example.com", dns::RecordType::A, true).unwrap_or_default()
            }
            123 => {
                let mut ntp = vec![0u8; 48];
                ntp[0] = 0x1B; // client mode v3
                ntp
            }
            _ => Vec::new(),
        };
        let result = udp_probe(ip, port, &payload, options.timeout);
        out.push(result);
    }
    out
}

fn udp_probe(ip: IpAddr, port: u16, payload: &[u8], timeout: Duration) -> ScannedPort {
    let bind_addr = if ip.is_ipv6() { "[::]:0" } else { "0.0.0.0:0" };
    let socket = match UdpSocket::bind(bind_addr) {
        Ok(s) => s,
        Err(_) => {
            return ScannedPort {
                port,
                protocol: "udp".into(),
                state: PortState::Filtered,
                service: service_for_port(port).map(|s| s.to_string()),
                product: None,
                version: None,
                banner: None,
                tls: None,
                detection: Some("udp socket unavailable".into()),
                confidence: Confidence::Confirmed,
            }
        }
    };
    socket.set_read_timeout(Some(timeout)).ok();
    let addr = SocketAddr::new(ip, port);
    if socket.send_to(payload, addr).is_err() {
        return ScannedPort {
            port,
            protocol: "udp".into(),
            state: PortState::Filtered,
            service: service_for_port(port).map(|s| s.to_string()),
            product: None,
            version: None,
            banner: None,
            tls: None,
            detection: Some("udp send failed".into()),
            confidence: Confidence::Likely,
        };
    }
    let mut buf = [0u8; 1024];
    match socket.recv_from(&mut buf) {
        Ok((n, _)) => {
            let banner = if port == 53 && n >= 12 {
                match dns::parse_response(&buf[..n]) {
                    Ok(parsed) => {
                        if parsed.rcode == 0 && !parsed.answers.is_empty() {
                            Some(format!(
                                "dns response: {} answer(s), first {}",
                                parsed.answers.len(),
                                parsed.answers[0].value
                            ))
                        } else {
                            Some(format!("dns response rcode={}", parsed.rcode))
                        }
                    }
                    Err(_) => None,
                }
            } else if port == 123 && n >= 48 {
                Some("ntp response".into())
            } else {
                Some(format!("{n} bytes response"))
            };
            ScannedPort {
                port,
                protocol: "udp".into(),
                state: PortState::Open,
                service: service_for_port(port).map(|s| s.to_string()),
                product: None,
                version: None,
                banner,
                tls: None,
                detection: Some("udp request/response".into()),
                confidence: Confidence::Confirmed,
            }
        }
        Err(_) => ScannedPort {
            port,
            protocol: "udp".into(),
            state: PortState::OpenOrFiltered,
            service: service_for_port(port).map(|s| s.to_string()),
            product: None,
            version: None,
            banner: None,
            tls: None,
            detection: Some("no udp response (open|filtered)".into()),
            confidence: Confidence::Confirmed,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn port_spec_parsing() {
        assert_eq!(parse_ports("22,80,443").unwrap(), vec![22, 80, 443]);
        assert_eq!(parse_ports("80-83").unwrap(), vec![80, 81, 82, 83]);
        assert_eq!(parse_ports("80,80").unwrap(), vec![80]);
        let common = parse_ports("common").unwrap();
        assert!(common.contains(&22) && common.contains(&443));
        assert!(common.len() > 50);
    }

    #[test]
    fn port_spec_rejects_bad_input() {
        assert!(parse_ports("").is_err());
        assert!(parse_ports("80-").is_err());
        assert!(parse_ports("100-50").is_err());
        assert!(parse_ports("abc").is_err());
        assert!(parse_ports("0").is_err());
        assert!(parse_ports("70000").is_err());
    }

    #[test]
    fn all_ports_is_full_range() {
        let all = parse_ports("all").unwrap();
        assert_eq!(all.len(), 65535);
        assert_eq!(all[0], 1);
        assert_eq!(all[all.len() - 1], 65535);
    }

    #[test]
    fn catalog_lookup() {
        assert_eq!(service_for_port(22), Some("ssh"));
        assert_eq!(service_for_port(443), Some("https"));
        assert_eq!(service_for_port(5432), Some("postgresql"));
        assert_eq!(service_for_port(1), None);
        assert!(likely_tls(443));
        assert!(likely_tls(993));
        assert!(!likely_tls(80));
    }

    #[test]
    fn banner_product_extraction() {
        let (product, version) = parse_banner(
            Some("http"),
            "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0\r\nContent-Length: 0\r\n",
        );
        assert_eq!(product.as_deref(), Some("nginx"));
        assert_eq!(version.as_deref(), Some("1.24.0"));

        let (product, version) = parse_banner(Some("ssh"), "SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n");
        assert_eq!(product.as_deref(), Some("OpenSSH"));
        assert_eq!(version.as_deref(), Some("9.6p1"));

        let (product, _) = parse_banner(Some("ftp"), "220 ProFTPD 1.3.5 Server ready\r\n");
        assert_eq!(product.as_deref(), Some("ProFTPD"));
    }

    #[test]
    fn banner_parse_strips_terminal_escapes() {
        let hostile = "HTTP/1.1 200 OK\r\nServer: \x1b[31mEvil\x1b[0m 9.9\r\n\r\n";
        let (product, version) = parse_banner(Some("http"), hostile);
        let product = product.unwrap_or_default();
        assert!(!product.contains('\x1b'), "escape leaked: {product:?}");
        assert_eq!(product, "Evil");
        assert_eq!(version.as_deref(), Some("9.9"));
        let summary = summarize_banner(hostile);
        assert!(!summary.contains('\x1b'));
    }

    #[test]
    fn banner_never_claims_without_evidence() {
        let (product, version) = parse_banner(Some("http"), "garbage\r\n");
        assert!(product.is_none() && version.is_none());
    }

    #[test]
    fn banner_summary_is_bounded_and_sanitized() {
        let long = "a".repeat(500);
        let summary = summarize_banner(&long);
        assert!(summary.chars().count() <= 201);
        let ctrl = summarize_banner("hello\x07\x08world\nsecond line");
        assert!(!ctrl.contains('\x07'));
        assert_eq!(ctrl, "hello world");
    }

    #[test]
    fn scan_public_target_requires_authorization() {
        let options = ScanOptions {
            timeout: Duration::from_millis(100),
            concurrency: 4,
            ..ScanOptions::default()
        };
        let err = scan("1.1.1.1", &[443], &options).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnauthorizedScan);
    }

    #[test]
    fn scan_localhost_closed_port_reports_closed_not_open() {
        let options = ScanOptions {
            timeout: Duration::from_millis(500),
            concurrency: 2,
            banner: false,
            tls: false,
            ..ScanOptions::default()
        };
        // Port 1 on loopback is privileged and almost certainly closed.
        let report = scan("127.0.0.1", &[1], &options).unwrap();
        assert_eq!(report.ports.len(), 1);
        assert_ne!(report.ports[0].state, PortState::Open);
    }

    #[test]
    fn scan_localhost_open_listener_is_detected() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let options = ScanOptions {
            timeout: Duration::from_millis(800),
            concurrency: 4,
            banner: false,
            tls: false,
            ..ScanOptions::default()
        };
        let report = scan("127.0.0.1", &[port], &options).unwrap();
        assert_eq!(report.ports[0].state, PortState::Open);
        assert_eq!(report.ports[0].port, port);
    }
}
