//! Network diagnostics: latency, connectivity, traceroute.
//!
//! ICMP is performed through the platform `ping` utility (which every target OS
//! ships and which handles the raw-socket privilege question itself). A pure
//! TCP-connect latency probe is available as a fallback and is always labelled
//! as `tcp_connect` so results are never confused with ICMP.

use crate::config::Config;
use crate::core::dns;
use crate::error::{dependency_missing, unsupported, ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::{platform, shared};
use crate::util::{self, validate_host, which};
use socket2::{Domain, Protocol, Socket, Type};
use std::net::{IpAddr, SocketAddr, TcpStream, ToSocketAddrs};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PingMethod {
    Auto,
    Icmp,
    Tcp,
}

impl PingMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(PingMethod::Auto),
            "icmp" => Some(PingMethod::Icmp),
            "tcp" => Some(PingMethod::Tcp),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct PingOptions {
    pub count: u32,
    pub timeout: Duration,
    pub tcp_port: u16,
}

impl Default for PingOptions {
    fn default() -> Self {
        Self {
            count: 4,
            timeout: Duration::from_secs(5),
            tcp_port: 443,
        }
    }
}

/// Resolve a target to addresses, returning a structured error on failure.
pub fn resolve(target: &str) -> Result<Vec<IpAddr>> {
    let validated = validate_host(target)?;
    if let Ok(ip) = validated.parse::<IpAddr>() {
        return Ok(vec![ip]);
    }
    let addrs: Vec<SocketAddr> = (validated.as_str(), 0)
        .to_socket_addrs()
        .map_err(|e| {
            NetroError::new(
                ErrorCode::NetworkDnsUnavailable,
                format!("cannot resolve {validated}: {e}"),
            )
        })?
        .collect();
    let mut ips: Vec<IpAddr> = addrs.into_iter().map(|s| s.ip()).collect();
    ips.sort_by_key(util::ip_sort_key);
    ips.dedup();
    if ips.is_empty() {
        return Err(NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("no addresses returned for {validated}"),
        ));
    }
    Ok(ips)
}

/// Measure latency to a target.
pub fn ping(target: &str, method: PingMethod, options: &PingOptions) -> PingResult {
    let ips = match resolve(target) {
        Ok(ips) => ips,
        Err(e) => return PingResult::failed(target, method_to_probe(method), e.to_string()),
    };
    let ip = ips[0];

    let use_icmp = match method {
        PingMethod::Icmp => true,
        PingMethod::Tcp => false,
        PingMethod::Auto => which("ping").is_some(),
    };

    let result = if use_icmp {
        match icmp_ping(ip, options) {
            Ok(mut result) => {
                result.target = target.to_string();
                result.resolved = ips.iter().map(|i| i.to_string()).collect();
                result
            }
            Err(e) => {
                if method == PingMethod::Icmp {
                    let mut failed = PingResult::failed(target, ProbeMethod::Icmp, e.to_string());
                    failed.resolved = ips.iter().map(|i| i.to_string()).collect();
                    return failed;
                }
                tcp_ping(ip, options)
            }
        }
    } else {
        tcp_ping(ip, options)
    };

    let mut result = result;
    result.target = target.to_string();
    result.resolved = ips.iter().map(|i| i.to_string()).collect();
    result
}

fn method_to_probe(method: PingMethod) -> ProbeMethod {
    match method {
        PingMethod::Icmp => ProbeMethod::Icmp,
        PingMethod::Tcp => ProbeMethod::TcpConnect,
        PingMethod::Auto => ProbeMethod::SystemUtility,
    }
}

/// ICMP ping via the platform `ping` utility, parsing real output.
pub fn icmp_ping(ip: IpAddr, options: &PingOptions) -> Result<PingResult> {
    let ping = which("ping").ok_or_else(|| dependency_missing("ping", "ICMP latency tests"))?;
    let count = options.count.max(1);
    let timeout_secs = options.timeout.as_secs_f64().max(1.0).ceil() as u64;
    let host = ip.to_string();
    let host_for_args = host.clone();

    let args: Vec<String> = if cfg!(windows) {
        vec![
            "-n".into(),
            count.to_string(),
            "-w".into(),
            (options.timeout.as_millis().max(1000)).to_string(),
            host_for_args,
        ]
    } else if cfg!(target_os = "macos") {
        vec![
            "-c".into(),
            count.to_string(),
            "-W".into(),
            (options.timeout.as_millis().max(1000)).to_string(),
            host_for_args,
        ]
    } else {
        vec![
            "-c".into(),
            count.to_string(),
            "-W".into(),
            timeout_secs.to_string(),
            host_for_args,
        ]
    };

    let out = util::run_command(
        &ping.to_string_lossy(),
        &args,
        options.timeout + Duration::from_secs(count as u64 + 2),
    )?;

    let parsed = if cfg!(windows) {
        parse_ping_windows(&out.combined())
    } else {
        parse_ping_unix(&out.combined())
    };

    match parsed {
        Some(result) => {
            let (min, avg, max, jitter) = rtt_stats(&result.rtts);
            Ok(PingResult {
                target: host,
                resolved: vec![ip.to_string()],
                method: ProbeMethod::Icmp,
                transmitted: result.transmitted,
                received: result.received,
                loss_percent: result.loss_percent,
                min_ms: result.min.or(min),
                avg_ms: result.avg.or(avg),
                max_ms: result.max.or(max),
                jitter_ms: jitter,
                rtts: result.rtts,
                error: None,
            })
        }
        None => Err(NetroError::new(
            ErrorCode::ParseError,
            "could not parse ping output (localized system output?)",
        )
        .with_hint("use --method tcp for a language-independent measurement")),
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct ParsedPing {
    pub transmitted: u32,
    pub received: u32,
    pub loss_percent: f64,
    pub min: Option<f64>,
    pub avg: Option<f64>,
    pub max: Option<f64>,
    pub rtts: Vec<f64>,
}

/// Parse iputils/macOS ping output.
pub fn parse_ping_unix(text: &str) -> Option<ParsedPing> {
    let mut result = ParsedPing::default();
    for line in text.lines() {
        // "64 bytes from 1.1.1.1: icmp_seq=1 ttl=57 time=11.2 ms"
        if let Some(time_pos) = line.find("time=") {
            let rest = &line[time_pos + 5..];
            let num: String = rest
                .chars()
                .take_while(|c| c.is_ascii_digit() || *c == '.')
                .collect();
            if let Ok(v) = num.parse::<f64>() {
                result.rtts.push(v);
            }
        }
        // "3 packets transmitted, 3 received, 0% packet loss"
        if line.contains("packets transmitted") || line.contains("packet transmitted") {
            for (index, token) in line.split_whitespace().enumerate() {
                if token.contains("transmitted") || token.contains("received") {
                    continue;
                }
                let _ = index;
            }
            let cleaned = line.replace(',', " ");
            let words: Vec<&str> = cleaned.split_whitespace().collect();
            let preceding_number = |pos: usize| -> Option<u32> {
                words[..pos]
                    .iter()
                    .rev()
                    .find_map(|w| w.parse::<u32>().ok())
            };
            if let Some(pos) = words.iter().position(|w| w.starts_with("transmitted")) {
                result.transmitted = preceding_number(pos).unwrap_or(0);
            }
            if let Some(pos) = words.iter().position(|w| w.starts_with("received")) {
                result.received = preceding_number(pos).unwrap_or(0);
            }
            if let Some(pos) = words
                .iter()
                .position(|w| w.contains("packet") && w.contains("loss"))
            {
                let loss = words
                    .get(pos.saturating_sub(1))
                    .map(|s| s.trim_end_matches('%'))
                    .and_then(|s| s.parse::<f64>().ok());
                if let Some(loss) = loss {
                    result.loss_percent = loss;
                }
            } else if let Some(pos) = words.iter().position(|w| w.ends_with('%')) {
                if let Ok(loss) = words[pos].trim_end_matches('%').parse::<f64>() {
                    result.loss_percent = loss;
                }
            }
        }
        // "rtt min/avg/max/mdev = 1.1/1.2/1.3/0.1 ms"
        if line.starts_with("rtt ") || line.starts_with("round-trip ") {
            if let Some(eq) = line.find('=') {
                let values: Vec<&str> = line[eq + 1..]
                    .split('/')
                    .map(|s| s.split_whitespace().next().unwrap_or(""))
                    .collect();
                if values.len() >= 3 {
                    result.min = values[0].parse().ok();
                    result.avg = values[1].parse().ok();
                    result.max = values[2].parse().ok();
                }
            }
        }
    }
    if result.rtts.is_empty() && result.transmitted == 0 {
        return None;
    }
    if result.transmitted == 0 {
        result.transmitted = result.rtts.len() as u32;
    }
    if result.received == 0 && !result.rtts.is_empty() {
        result.received = result.rtts.len() as u32;
    }
    if result.loss_percent == 0.0 && result.transmitted > 0 && result.received < result.transmitted
    {
        result.loss_percent =
            (result.transmitted - result.received) as f64 / result.transmitted as f64 * 100.0;
    }
    Some(result)
}

/// Parse Windows ping output.
pub fn parse_ping_windows(text: &str) -> Option<ParsedPing> {
    let mut result = ParsedPing::default();
    for line in text.lines() {
        let lower = line.to_ascii_lowercase();
        if lower.contains("time=") || lower.contains("time<") {
            let marker = if lower.contains("time<") {
                "time<"
            } else {
                "time="
            };
            if let Some(pos) = lower.find(marker) {
                let rest = &line[pos + marker.len()..];
                let num: String = rest
                    .chars()
                    .take_while(|c| c.is_ascii_digit() || *c == '.')
                    .collect();
                if let Ok(v) = num.parse::<f64>() {
                    result.rtts.push(v);
                }
            }
        }
        if lower.contains("packets:") {
            let cleaned = line.replace(',', " ");
            let words: Vec<&str> = cleaned.split_whitespace().collect();
            let value_after = |label: &str| -> Option<u32> {
                let pos = words
                    .iter()
                    .position(|w| w.trim_end_matches(':').eq_ignore_ascii_case(label))?;
                words[pos + 1..]
                    .iter()
                    .find_map(|w| w.trim_start_matches('=').parse::<u32>().ok())
            };
            if let Some(sent) = value_after("sent") {
                result.transmitted = sent;
            }
            if let Some(received) = value_after("received") {
                result.received = received;
            }
            if let Some(lost) = value_after("lost") {
                if result.transmitted > 0 {
                    result.loss_percent = lost as f64 / result.transmitted as f64 * 100.0;
                }
            }
            if let Some(pct_pos) = line.find('%') {
                let before = &line[..pct_pos];
                let digits: String = before
                    .chars()
                    .rev()
                    .take_while(|c| c.is_ascii_digit())
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                    .collect();
                if let Ok(pct) = digits.parse::<f64>() {
                    result.loss_percent = pct;
                }
            }
        }
        if lower.contains("minimum") && lower.contains("maximum") {
            let numbers: Vec<f64> = line
                .split('=')
                .filter_map(|chunk| {
                    chunk
                        .split("ms")
                        .next()
                        .map(|s| s.trim())
                        .and_then(|s| s.parse::<f64>().ok())
                })
                .collect();
            if numbers.len() >= 3 {
                result.min = Some(numbers[0]);
                result.max = Some(numbers[1]);
                result.avg = Some(numbers[2]);
            }
        }
    }
    if result.transmitted == 0 && result.rtts.is_empty() {
        return None;
    }
    if result.transmitted == 0 {
        result.transmitted = result.rtts.len() as u32;
    }
    if result.received == 0 && !result.rtts.is_empty() {
        result.received = result.rtts.len() as u32;
    }
    Some(result)
}

/// TCP-connect latency probe (works without any external utility).
pub fn tcp_ping(ip: IpAddr, options: &PingOptions) -> PingResult {
    let count = options.count.max(1);
    let mut rtts = Vec::new();
    let mut received = 0u32;
    let mut errors = Vec::new();
    let addr = SocketAddr::new(ip, options.tcp_port);
    for _ in 0..count {
        let started = Instant::now();
        match TcpStream::connect_timeout(&addr, options.timeout) {
            Ok(_) => {
                received += 1;
                rtts.push(started.elapsed().as_secs_f64() * 1000.0);
            }
            Err(e) => {
                if errors.len() < 3 {
                    errors.push(e.to_string());
                }
            }
        }
    }
    let (min, avg, max, jitter) = rtt_stats(&rtts);
    PingResult {
        target: ip.to_string(),
        resolved: vec![ip.to_string()],
        method: ProbeMethod::TcpConnect,
        transmitted: count,
        received,
        loss_percent: (count - received) as f64 / count as f64 * 100.0,
        min_ms: min,
        avg_ms: avg,
        max_ms: max,
        jitter_ms: jitter,
        rtts,
        error: if received == 0 && !errors.is_empty() {
            Some(format!(
                "TCP connect to {}:{} failed: {}",
                ip,
                options.tcp_port,
                errors.join("; ")
            ))
        } else {
            None
        },
    }
}

// ---------------------------------------------------------------------------
// Connectivity
// ---------------------------------------------------------------------------

pub struct ConnectivityOptions {
    pub timeout: Duration,
    pub dns_query_name: String,
    pub ipv6: bool,
}

impl Default for ConnectivityOptions {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(3),
            dns_query_name: "example.com".to_string(),
            ipv6: true,
        }
    }
}

pub fn connectivity(options: &ConnectivityOptions) -> ConnectivityReport {
    let mut checks = Vec::new();

    // Loopback: bind a listener on 127.0.0.1 and truly connect to it.
    let (loopback_ok, loopback_error) = match loopback_probe() {
        Ok(()) => (true, None),
        Err(e) => (false, Some(e)),
    };
    checks.push(ConnectivityCheck {
        name: "loopback".into(),
        target: "127.0.0.1".into(),
        method: ProbeMethod::TcpConnect,
        ok: loopback_ok,
        latency_ms: None,
        error: loopback_error,
        note: Some("local IP stack responds without external dependencies".into()),
    });

    // Gateway.
    let gateway = platform()
        .routes()
        .ok()
        .and_then(|routes| shared::default_gateway(&routes, "ipv4"));
    match gateway {
        Some(gw) => {
            let result = ping(
                &gw,
                PingMethod::Auto,
                &PingOptions {
                    count: 2,
                    timeout: options.timeout.max(Duration::from_secs(2)),
                    tcp_port: 80,
                },
            );
            checks.push(ConnectivityCheck {
                name: "gateway".into(),
                target: gw,
                method: result.method,
                ok: result.received > 0,
                latency_ms: result.avg_ms,
                error: result.error.clone(),
                note: Some("default IPv4 gateway reachability".into()),
            });
        }
        None => checks.push(ConnectivityCheck {
            name: "gateway".into(),
            target: "n/a".into(),
            method: ProbeMethod::Icmp,
            ok: false,
            latency_ms: None,
            error: Some("no default IPv4 gateway in the routing table".into()),
            note: None,
        }),
    }

    // DNS resolution through configured resolvers.
    let dns_result = dns::resolve_via_system(
        &options.dns_query_name,
        dns::RecordType::A,
        options.timeout.max(Duration::from_secs(2)),
    );
    checks.push(match &dns_result {
        Ok(response) => ConnectivityCheck {
            name: "dns".into(),
            target: format!("{} via {}", options.dns_query_name, response.server),
            method: ProbeMethod::Dns,
            ok: response.rcode == 0 && !response.answers.is_empty(),
            latency_ms: Some(response.rtt_ms),
            error: (response.rcode != 0).then(|| format!("rcode {}", response.rcode_name)),
            note: Some(format!("query type {}", response.record_type)),
        },
        Err(e) => ConnectivityCheck {
            name: "dns".into(),
            target: options.dns_query_name.clone(),
            method: ProbeMethod::Dns,
            ok: false,
            latency_ms: None,
            error: Some(e.to_string()),
            note: None,
        },
    });

    // IPv4 internet reachability: TCP to well-known anycast addresses.
    let ipv4_target: IpAddr = "1.1.1.1".parse().unwrap();
    let ipv4 = tcp_connect_check(
        "internet_ipv4",
        ipv4_target,
        443,
        options.timeout,
        "TCP to 1.1.1.1:443 (Cloudflare anycast)",
    );
    checks.push(ipv4.clone());

    // IPv6 internet reachability.
    let ipv6_configured = platform()
        .interfaces()
        .map(|ifaces| {
            ifaces.iter().any(|i| {
                i.up && i.ipv6.iter().any(|a| {
                    a.addr
                        .parse::<IpAddr>()
                        .map(|ip| !ip.is_loopback() && !ip.is_unspecified())
                        .unwrap_or(false)
                })
            })
        })
        .unwrap_or(false);
    let ipv6 = if options.ipv6 && ipv6_configured {
        let target: IpAddr = "2606:4700:4700::1111".parse().unwrap();
        tcp_connect_check(
            "internet_ipv6",
            target,
            443,
            options.timeout,
            "TCP to [2606:4700:4700::1111]:443 (Cloudflare anycast)",
        )
    } else {
        ConnectivityCheck {
            name: "internet_ipv6".into(),
            target: "n/a".into(),
            method: ProbeMethod::TcpConnect,
            ok: false,
            latency_ms: None,
            error: None,
            note: Some(if options.ipv6 {
                "no non-loopback IPv6 address configured; IPv6 check skipped".into()
            } else {
                "IPv6 checks disabled".into()
            }),
        }
    };
    checks.push(ipv6);

    let gateway_reachable = checks.iter().find(|c| c.name == "gateway").map(|c| c.ok);
    let dns_working = checks
        .iter()
        .find(|c| c.name == "dns")
        .map(|c| c.ok)
        .unwrap_or(false);
    let ipv4_available = checks
        .iter()
        .find(|c| c.name == "internet_ipv4")
        .map(|c| c.ok)
        .unwrap_or(false);
    let ipv6_available = checks
        .iter()
        .find(|c| c.name == "internet_ipv6")
        .map(|c| c.ok)
        .unwrap_or(false);

    ConnectivityReport {
        internet_reachable: ipv4_available || ipv6_available,
        checks,
        ipv4_available,
        ipv6_available,
        dns_working,
        gateway_reachable,
    }
}

/// Bind and connect to a loopback listener, proving the local IP stack works.
fn loopback_probe() -> std::result::Result<(), String> {
    let listener = std::net::TcpListener::bind("127.0.0.1:0")
        .map_err(|e| format!("cannot bind loopback listener: {e}"))?;
    let addr = listener
        .local_addr()
        .map_err(|e| format!("cannot read loopback address: {e}"))?;
    let handle = std::thread::spawn(move || listener.accept().map(|_| ()));
    let connect = TcpStream::connect_timeout(&addr, Duration::from_millis(500));
    let result = match connect {
        Ok(_) => Ok(()),
        Err(e) => Err(format!("cannot connect to loopback listener: {e}")),
    };
    let _ = handle.join();
    result
}

fn tcp_connect_check(
    name: &str,
    ip: IpAddr,
    port: u16,
    timeout_duration: Duration,
    note: &str,
) -> ConnectivityCheck {
    let addr = SocketAddr::new(ip, port);
    let started = Instant::now();
    match TcpStream::connect_timeout(&addr, timeout_duration) {
        Ok(_) => ConnectivityCheck {
            name: name.into(),
            target: format!("{ip}:{port}"),
            method: ProbeMethod::TcpConnect,
            ok: true,
            latency_ms: Some(started.elapsed().as_secs_f64() * 1000.0),
            error: None,
            note: Some(note.into()),
        },
        Err(e) => ConnectivityCheck {
            name: name.into(),
            target: format!("{ip}:{port}"),
            method: ProbeMethod::TcpConnect,
            ok: false,
            latency_ms: None,
            error: Some(e.to_string()),
            note: Some(note.into()),
        },
    }
}

// ---------------------------------------------------------------------------
// Traceroute
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceMethod {
    Auto,
    Icmp,
    Tcp,
}

impl TraceMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(TraceMethod::Auto),
            "icmp" => Some(TraceMethod::Icmp),
            "tcp" => Some(TraceMethod::Tcp),
            _ => None,
        }
    }
}

pub struct TraceOptions {
    pub max_hops: u8,
    pub timeout: Duration,
    pub tcp_port: u16,
}

impl Default for TraceOptions {
    fn default() -> Self {
        Self {
            max_hops: 30,
            timeout: Duration::from_secs(2),
            tcp_port: 443,
        }
    }
}

pub fn traceroute(
    target: &str,
    method: TraceMethod,
    options: &TraceOptions,
) -> Result<TraceResult> {
    let ips = resolve(target)?;
    let ip = ips[0];

    let use_system = match method {
        TraceMethod::Icmp => true,
        TraceMethod::Tcp => false,
        TraceMethod::Auto => which("traceroute").is_some() || which("tracert").is_some(),
    };

    if use_system {
        match system_traceroute(ip, options) {
            Ok(mut result) => {
                result.target = target.to_string();
                return Ok(result);
            }
            Err(e) if method == TraceMethod::Icmp => return Err(e),
            Err(_) => {}
        }
    }

    if ip.is_ipv6() {
        return Err(unsupported(
            "native TCP traceroute is IPv4-only; install traceroute/tracert for IPv6",
        ));
    }
    tcp_traceroute(target, ip, options)
}

fn system_traceroute(ip: IpAddr, options: &TraceOptions) -> Result<TraceResult> {
    let (program, args): (String, Vec<String>) = if let Some(p) = which("traceroute") {
        (
            p.to_string_lossy().to_string(),
            vec![
                "-n".into(),
                "-m".into(),
                options.max_hops.to_string(),
                "-w".into(),
                options.timeout.as_secs().max(1).to_string(),
                ip.to_string(),
            ],
        )
    } else if let Some(p) = which("tracert") {
        (
            p.to_string_lossy().to_string(),
            vec![
                "-d".into(),
                "-h".into(),
                options.max_hops.to_string(),
                "-w".into(),
                (options.timeout.as_millis().max(1000)).to_string(),
                ip.to_string(),
            ],
        )
    } else {
        return Err(dependency_missing(
            "traceroute",
            "ICMP traceroute (use --method tcp for the built-in tracer)",
        ));
    };

    let out = util::run_command(
        &program,
        &args,
        options.timeout * (options.max_hops as u32) + Duration::from_secs(5),
    )?;

    let hops = if cfg!(windows) {
        parse_tracert_windows(&out.stdout)
    } else {
        parse_traceroute_unix(&out.stdout)
    };
    if hops.is_empty() {
        return Err(NetroError::new(
            ErrorCode::ParseError,
            "could not parse traceroute output (localized system output?)",
        )
        .with_hint("use --method tcp for the built-in tracer"));
    }
    let reached = hops
        .last()
        .and_then(|h| h.address.as_ref())
        .map(|addr| addr.parse::<IpAddr>().map(|a| a == ip).unwrap_or(false))
        .unwrap_or(false);
    Ok(TraceResult {
        target: ip.to_string(),
        method: ProbeMethod::SystemUtility,
        hops,
        reached,
        note: Some(format!("using {program} (no packet payload analysis)")),
    })
}

/// Native TCP traceroute: discovers hop distance by setting the TTL on TCP
/// SYNs. It reports hop latency but cannot report intermediate hop addresses
/// without raw ICMP sockets, which is stated in the result note.
pub fn tcp_traceroute(target: &str, ip: IpAddr, options: &TraceOptions) -> Result<TraceResult> {
    if ip.is_ipv6() {
        return Err(unsupported("TCP traceroute currently supports IPv4 only"));
    }
    let mut hops = Vec::new();
    let mut reached = false;

    for ttl in 1..=options.max_hops {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(Protocol::TCP))
            .map_err(|e| NetroError::new(ErrorCode::Io, format!("socket creation failed: {e}")))?;
        socket
            .set_ttl_v4(ttl as u32)
            .map_err(|e| NetroError::new(ErrorCode::Io, format!("set TTL failed: {e}")))?;
        let _ = socket.set_nonblocking(true);
        let addr = SocketAddr::new(ip, options.tcp_port);
        let sockaddr = socket2::SockAddr::from(addr);

        let started = Instant::now();
        let connect_result = socket.connect(&sockaddr);
        let mut status = match connect_result {
            Ok(()) => HopOutcome::Connected,
            Err(e)
                if e.kind() == std::io::ErrorKind::WouldBlock
                    || e.raw_os_error() == Some(115)
                    || e.raw_os_error() == Some(10035) =>
            {
                HopOutcome::Pending
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::ConnectionRefused
                    || e.raw_os_error() == Some(111) =>
            {
                HopOutcome::Refused
            }
            Err(e)
                if e.kind() == std::io::ErrorKind::HostUnreachable
                    || e.kind() == std::io::ErrorKind::NetworkUnreachable =>
            {
                HopOutcome::Unreachable
            }
            Err(_) => HopOutcome::Pending,
        };

        if status == HopOutcome::Pending {
            let deadline = started + options.timeout;
            loop {
                std::thread::sleep(Duration::from_millis(20));
                match socket.take_error() {
                    Ok(Some(err)) => {
                        status = classify_error(&err);
                        break;
                    }
                    Ok(None) => {
                        if socket.peer_addr().is_ok() {
                            status = HopOutcome::Connected;
                            break;
                        }
                    }
                    Err(_) => {}
                }
                if Instant::now() >= deadline {
                    status = HopOutcome::Timeout;
                    break;
                }
            }
        }

        let rtt = started.elapsed().as_secs_f64() * 1000.0;
        match status {
            HopOutcome::Connected => {
                hops.push(TraceHop {
                    hop: ttl,
                    address: Some(ip.to_string()),
                    hostname: None,
                    rtt_ms: vec![rtt],
                    timeout: false,
                });
                reached = true;
                break;
            }
            HopOutcome::Refused => {
                // RST from the target means the host is reached.
                hops.push(TraceHop {
                    hop: ttl,
                    address: Some(ip.to_string()),
                    hostname: None,
                    rtt_ms: vec![rtt],
                    timeout: false,
                });
                reached = true;
                break;
            }
            HopOutcome::Timeout | HopOutcome::Unreachable | HopOutcome::Pending => {
                hops.push(TraceHop {
                    hop: ttl,
                    address: None,
                    hostname: None,
                    rtt_ms: vec![],
                    timeout: true,
                });
            }
        }
    }

    Ok(TraceResult {
        target: target.to_string(),
        method: ProbeMethod::TcpConnect,
        hops,
        reached,
        note: Some(
            "built-in TCP tracer reports hop distance and latency; intermediate addresses require \
             raw ICMP sockets and are shown as '*'"
                .into(),
        ),
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum HopOutcome {
    Connected,
    Refused,
    Unreachable,
    Timeout,
    Pending,
}

fn classify_error(err: &std::io::Error) -> HopOutcome {
    match err.kind() {
        std::io::ErrorKind::ConnectionRefused => HopOutcome::Refused,
        std::io::ErrorKind::HostUnreachable | std::io::ErrorKind::NetworkUnreachable => {
            HopOutcome::Unreachable
        }
        _ => match err.raw_os_error() {
            Some(111) => HopOutcome::Refused,
            Some(113) | Some(101) => HopOutcome::Unreachable,
            _ => HopOutcome::Timeout,
        },
    }
}

/// Parse Unix `traceroute` output.
pub fn parse_traceroute_unix(text: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with("traceroute to") {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        let hop: u8 = match cols[0].parse() {
            Ok(h) => h,
            Err(_) => continue,
        };
        let mut address = None;
        let mut hostname = None;
        let mut rtts = Vec::new();
        let mut i = 1;
        while i < cols.len() {
            let token = cols[i];
            if token == "*" {
                i += 1;
                continue;
            }
            // "0.512" followed by "ms" (or the combined "0.512ms")
            let next_is_ms = cols.get(i + 1).map(|n| *n == "ms").unwrap_or(false);
            if token.ends_with("ms") {
                if let Ok(v) = token.trim_end_matches("ms").parse::<f64>() {
                    rtts.push(v);
                }
                i += 1;
                continue;
            }
            if next_is_ms {
                if let Ok(v) = token.parse::<f64>() {
                    rtts.push(v);
                }
                i += 2;
                continue;
            }
            if token == "ms" {
                i += 1;
                continue;
            }
            if token.starts_with('(') && token.ends_with(')') {
                address = Some(token.trim_matches(|c| c == '(' || c == ')').to_string());
                i += 1;
                continue;
            }
            if token.parse::<IpAddr>().is_ok() {
                address = Some(token.to_string());
                i += 1;
                continue;
            }
            // A hostname is a non-numeric label containing a dot but not
            // starting with a digit.
            if token.contains('.')
                && !token.starts_with(|c: char| c.is_ascii_digit())
                && hostname.is_none()
            {
                hostname = Some(token.to_string());
            }
            i += 1;
        }
        let timeout = address.is_none() && rtts.is_empty();
        hops.push(TraceHop {
            hop,
            address,
            hostname,
            rtt_ms: rtts,
            timeout,
        });
    }
    hops
}

/// Parse Windows `tracert` output.
pub fn parse_tracert_windows(text: &str) -> Vec<TraceHop> {
    let mut hops = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty()
            || trimmed.starts_with("Tracing route")
            || trimmed.starts_with("over a maximum")
            || trimmed.starts_with("Trace complete")
        {
            continue;
        }
        let cols: Vec<&str> = trimmed.split_whitespace().collect();
        if cols.is_empty() {
            continue;
        }
        let hop: u8 = match cols[0].parse() {
            Ok(h) => h,
            Err(_) => continue,
        };
        let mut rtts = Vec::new();
        let mut address = None;
        for token in &cols[1..] {
            if token.eq_ignore_ascii_case("ms") {
                continue;
            }
            if *token == "*" || token.eq_ignore_ascii_case("Request") {
                continue;
            }
            if let Ok(v) = token.parse::<f64>() {
                rtts.push(v);
                continue;
            }
            if *token == "<1" {
                rtts.push(1.0);
                continue;
            }
            if let Ok(ip) = token
                .trim_matches(|c| c == '[' || c == ']')
                .parse::<IpAddr>()
            {
                address = Some(ip.to_string());
            }
        }
        let timeout = address.is_none() && rtts.is_empty();
        hops.push(TraceHop {
            hop,
            address,
            hostname: None,
            rtt_ms: rtts,
            timeout,
        });
    }
    hops
}

/// Apply traceroute-related configuration defaults (kept here so the CLI only
/// needs to pass options through).
pub fn trace_options_from_config(config: &Config) -> TraceOptions {
    TraceOptions {
        timeout: Duration::from_millis(config.scan.timeout_ms.max(500)),
        ..TraceOptions::default()
    }
}

/// Convenience wrapper: ping a target using the given count.
pub fn ping_count(target: &str, count: u32) -> PingResult {
    ping(
        target,
        PingMethod::Auto,
        &PingOptions {
            count,
            ..PingOptions::default()
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_unix_ping_output() {
        let fixture = "PING example.com (93.184.216.34) 56(84) bytes of data.\n\
64 bytes from 93.184.216.34: icmp_seq=1 ttl=56 time=11.2 ms\n\
64 bytes from 93.184.216.34: icmp_seq=2 ttl=56 time=11.9 ms\n\
64 bytes from 93.184.216.34: icmp_seq=3 ttl=56 time=11.4 ms\n\
\n--- example.com ping statistics ---\n\
3 packets transmitted, 3 received, 0% packet loss, time 2003ms\n\
rtt min/avg/max/mdev = 11.106/11.254/11.489/0.181 ms\n";
        let parsed = parse_ping_unix(fixture).unwrap();
        assert_eq!(parsed.transmitted, 3);
        assert_eq!(parsed.received, 3);
        assert_eq!(parsed.loss_percent, 0.0);
        assert_eq!(parsed.rtts.len(), 3);
        assert_eq!(parsed.min, Some(11.106));
        assert_eq!(parsed.avg, Some(11.254));
        assert_eq!(parsed.max, Some(11.489));
    }

    #[test]
    fn parse_unix_ping_with_loss() {
        let fixture = "PING 10.0.0.1 (10.0.0.1) 56(84) bytes of data.\n\
64 bytes from 10.0.0.1: icmp_seq=1 ttl=64 time=0.5 ms\n\
\n--- 10.0.0.1 ping statistics ---\n\
4 packets transmitted, 1 received, 75% packet loss, time 3000ms\n";
        let parsed = parse_ping_unix(fixture).unwrap();
        assert_eq!(parsed.transmitted, 4);
        assert_eq!(parsed.received, 1);
        assert_eq!(parsed.loss_percent, 75.0);
    }

    #[test]
    fn parse_windows_ping_output() {
        let fixture = "Pinging example.com [93.184.216.34] with 32 bytes of data:\n\
Reply from 93.184.216.34: bytes=32 time=11ms TTL=56\n\
Reply from 93.184.216.34: bytes=32 time=12ms TTL=56\n\
Request timed out.\n\
\nPing statistics for 93.184.216.34:\n\
    Packets: Sent = 3, Received = 2, Lost = 1 (33% loss),\n\
Approximate round trip times in milli-seconds:\n\
    Minimum = 11ms, Maximum = 12ms, Average = 11ms\n";
        let parsed = parse_ping_windows(fixture).unwrap();
        assert_eq!(parsed.transmitted, 3);
        assert_eq!(parsed.received, 2);
        assert_eq!(parsed.loss_percent, 33.0);
        assert_eq!(parsed.rtts, vec![11.0, 12.0]);
    }

    #[test]
    fn parse_unparseable_ping_returns_none() {
        assert!(parse_ping_unix("PING: transmit failed. General failure.").is_none());
    }

    #[test]
    fn parse_unix_traceroute() {
        let fixture = "traceroute to example.com (93.184.216.34), 30 hops max, 60 byte packets\n\
 1  _gateway (192.168.1.1)  0.512 ms  0.487 ms  0.476 ms\n\
 2  * * *\n\
 3  10.0.0.1 (10.0.0.1)  5.1 ms  5.2 ms *\n";
        let hops = parse_traceroute_unix(fixture);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].rtt_ms.len(), 3);
        assert!(hops[1].timeout);
        assert_eq!(hops[2].address.as_deref(), Some("10.0.0.1"));
    }

    #[test]
    fn parse_windows_tracert() {
        let fixture = "Tracing route to example.com [93.184.216.34]\nover a maximum of 30 hops:\n\n  1     1 ms     1 ms     1 ms  192.168.1.1\n  2     *        *        *     Request timed out.\n  3    11 ms    12 ms    11 ms  93.184.216.34\n\nTrace complete.\n";
        let hops = parse_tracert_windows(fixture);
        assert_eq!(hops.len(), 3);
        assert_eq!(hops[0].address.as_deref(), Some("192.168.1.1"));
        assert_eq!(hops[0].rtt_ms, vec![1.0, 1.0, 1.0]);
        assert!(hops[1].timeout);
        assert_eq!(hops[2].address.as_deref(), Some("93.184.216.34"));
    }

    #[test]
    fn resolve_localhost() {
        let ips = resolve("127.0.0.1").unwrap();
        assert_eq!(ips, vec!["127.0.0.1".parse::<IpAddr>().unwrap()]);
        assert!(resolve("-bad").is_err());
    }

    #[test]
    fn tcp_ping_to_closed_local_port_reports_loss_not_panic() {
        let result = tcp_ping(
            "127.0.0.1".parse().unwrap(),
            &PingOptions {
                count: 1,
                timeout: Duration::from_millis(200),
                tcp_port: 1,
            },
        );
        assert_eq!(result.transmitted, 1);
        assert!(result.received <= 1);
        assert!(!result.target.is_empty());
    }
}
