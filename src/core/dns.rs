//! Minimal but real DNS client.
//!
//! Implements RFC 1035 message encoding/decoding over UDP with TCP fallback on
//! truncation. Used for resolution tests, reverse lookups, and service
//! discovery. No external resolver library is required.

use crate::error::{timeout, ErrorCode, NetroError, Result};
use crate::platform::platform;
use crate::util;
use std::net::{IpAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordType {
    A,
    AAAA,
    Cname,
    Mx,
    Txt,
    Ns,
    Soa,
    Ptr,
    Srv,
    Caa,
}

impl RecordType {
    pub fn code(self) -> u16 {
        match self {
            RecordType::A => 1,
            RecordType::Ns => 2,
            RecordType::Cname => 5,
            RecordType::Soa => 6,
            RecordType::Ptr => 12,
            RecordType::Mx => 15,
            RecordType::Txt => 16,
            RecordType::AAAA => 28,
            RecordType::Srv => 33,
            RecordType::Caa => 257,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            RecordType::A => "A",
            RecordType::AAAA => "AAAA",
            RecordType::Cname => "CNAME",
            RecordType::Mx => "MX",
            RecordType::Txt => "TXT",
            RecordType::Ns => "NS",
            RecordType::Soa => "SOA",
            RecordType::Ptr => "PTR",
            RecordType::Srv => "SRV",
            RecordType::Caa => "CAA",
        }
    }

    pub fn from_name(name: &str) -> Option<Self> {
        Some(match name.to_ascii_uppercase().as_str() {
            "A" => RecordType::A,
            "AAAA" => RecordType::AAAA,
            "CNAME" => RecordType::Cname,
            "MX" => RecordType::Mx,
            "TXT" => RecordType::Txt,
            "NS" => RecordType::Ns,
            "SOA" => RecordType::Soa,
            "PTR" => RecordType::Ptr,
            "SRV" => RecordType::Srv,
            "CAA" => RecordType::Caa,
            _ => return None,
        })
    }
}

#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub name: String,
    pub record_type: String,
    pub ttl: u32,
    pub value: String,
}

#[derive(Debug, Clone)]
pub struct DnsResponse {
    pub id: u16,
    pub rcode: u8,
    pub rcode_name: String,
    pub answers: Vec<DnsAnswer>,
    pub truncated: bool,
    pub server: String,
    pub rtt_ms: f64,
    pub record_type: String,
    pub query_name: String,
}

pub fn rcode_name(code: u8) -> &'static str {
    match code {
        0 => "NOERROR",
        1 => "FORMERR",
        2 => "SERVFAIL",
        3 => "NXDOMAIN",
        4 => "NOTIMP",
        5 => "REFUSED",
        6 => "YXDOMAIN",
        7 => "YXRRSET",
        8 => "NXRRSET",
        9 => "NOTAUTH",
        10 => "NOTZONE",
        _ => "UNKNOWN",
    }
}

/// Encode a DNS query message.
pub fn encode_query(id: u16, name: &str, rtype: RecordType, rd: bool) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(512);
    buf.extend_from_slice(&id.to_be_bytes());
    // flags: QR=0, Opcode=0, AA=0, TC=0, RD=rd, RA=0, Z=0, RCODE=0
    let flags: u16 = if rd { 0x0100 } else { 0 };
    buf.extend_from_slice(&flags.to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ANCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // NSCOUNT
    buf.extend_from_slice(&0u16.to_be_bytes()); // ARCOUNT
    encode_name(name, &mut buf)?;
    buf.extend_from_slice(&rtype.code().to_be_bytes());
    buf.extend_from_slice(&1u16.to_be_bytes()); // IN class
    Ok(buf)
}

fn encode_name(name: &str, buf: &mut Vec<u8>) -> Result<()> {
    let trimmed = name.trim_end_matches('.');
    if trimmed.is_empty() {
        buf.push(0);
        return Ok(());
    }
    if trimmed.len() > 253 {
        return Err(NetroError::new(
            ErrorCode::InvalidTarget,
            "DNS name exceeds 253 characters",
        ));
    }
    for label in trimmed.split('.') {
        if label.is_empty() {
            return Err(NetroError::new(
                ErrorCode::InvalidTarget,
                format!("invalid DNS name (empty label): {name}"),
            ));
        }
        if label.len() > 63 {
            return Err(NetroError::new(
                ErrorCode::InvalidTarget,
                format!("DNS label exceeds 63 characters: {label}"),
            ));
        }
        buf.push(label.len() as u8);
        buf.extend_from_slice(label.as_bytes());
    }
    buf.push(0);
    Ok(())
}

struct Parser<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Parser<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn u8(&mut self) -> Result<u8> {
        let v = *self
            .buf
            .get(self.pos)
            .ok_or_else(|| parse_err("truncated DNS message"))?;
        self.pos += 1;
        Ok(v)
    }

    fn u16(&mut self) -> Result<u16> {
        let hi = self.u8()? as u16;
        let lo = self.u8()? as u16;
        Ok((hi << 8) | lo)
    }

    fn u32(&mut self) -> Result<u32> {
        let a = self.u16()? as u32;
        let b = self.u16()? as u32;
        Ok((a << 16) | b)
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.pos.saturating_add(n);
        if end > self.buf.len() {
            return Err(parse_err("truncated DNS message"));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    /// Decode a (possibly compressed) name.
    fn name(&mut self) -> Result<String> {
        let mut labels: Vec<String> = Vec::new();
        let mut pos = self.pos;
        let mut jumped = false;
        let mut jumps = 0usize;
        let mut consumed_end = self.pos;

        loop {
            if pos >= self.buf.len() {
                return Err(parse_err("truncated DNS name"));
            }
            let len = self.buf[pos];
            if len & 0xC0 == 0xC0 {
                if pos + 1 >= self.buf.len() {
                    return Err(parse_err("truncated DNS compression pointer"));
                }
                let pointer = (((len & 0x3F) as usize) << 8) | self.buf[pos + 1] as usize;
                if !jumped {
                    consumed_end = pos + 2;
                }
                jumped = true;
                jumps += 1;
                if jumps > 20 {
                    return Err(parse_err("DNS compression pointer loop"));
                }
                if pointer >= self.buf.len() {
                    return Err(parse_err("DNS compression pointer out of range"));
                }
                pos = pointer;
                continue;
            }
            if len == 0 {
                if !jumped {
                    consumed_end = pos + 1;
                }
                break;
            }
            let start = pos + 1;
            let end = start + len as usize;
            if end > self.buf.len() {
                return Err(parse_err("truncated DNS label"));
            }
            let label = String::from_utf8_lossy(&self.buf[start..end]).to_string();
            labels.push(label);
            pos = end;
            if !jumped {
                consumed_end = pos;
            }
        }
        self.pos = consumed_end;
        Ok(if labels.is_empty() {
            ".".to_string()
        } else {
            labels.join(".")
        })
    }
}

fn parse_err(msg: &str) -> NetroError {
    NetroError::new(ErrorCode::ParseError, msg.to_string())
}

pub struct ParsedMessage {
    pub id: u16,
    pub rcode: u8,
    pub truncated: bool,
    pub answers: Vec<DnsAnswer>,
}

/// Decode a DNS response.
pub fn parse_response(buf: &[u8]) -> Result<ParsedMessage> {
    let mut p = Parser::new(buf);
    let id = p.u16()?;
    let flags = p.u16()?;
    let rcode = (flags & 0x000F) as u8;
    let truncated = flags & 0x0200 != 0;
    let qdcount = p.u16()?;
    let ancount = p.u16()?;
    let _nscount = p.u16()?;
    let _arcount = p.u16()?;

    for _ in 0..qdcount {
        let _ = p.name()?;
        let _qtype = p.u16()?;
        let _qclass = p.u16()?;
    }

    let mut answers = Vec::new();
    for _ in 0..ancount {
        let name = p.name()?;
        let rtype = p.u16()?;
        let _class = p.u16()?;
        let ttl = p.u32()?;
        let rdlength = p.u16()? as usize;
        let rdata_start = p.pos;
        let value = decode_rdata(&mut p, rtype, rdlength)?;
        if p.pos < rdata_start + rdlength {
            p.pos = rdata_start + rdlength;
        }
        answers.push(DnsAnswer {
            name,
            record_type: type_name(rtype),
            ttl,
            value,
        });
    }

    Ok(ParsedMessage {
        id,
        rcode,
        truncated,
        answers,
    })
}

fn type_name(rtype: u16) -> String {
    match rtype {
        1 => "A".into(),
        2 => "NS".into(),
        5 => "CNAME".into(),
        6 => "SOA".into(),
        12 => "PTR".into(),
        15 => "MX".into(),
        16 => "TXT".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        257 => "CAA".into(),
        other => format!("TYPE{other}"),
    }
}

fn decode_rdata(p: &mut Parser<'_>, rtype: u16, rdlength: usize) -> Result<String> {
    match rtype {
        1 => {
            let bytes = p.take(4)?;
            Ok(IpAddr::from([bytes[0], bytes[1], bytes[2], bytes[3]]).to_string())
        }
        28 => {
            let bytes = p.take(16)?;
            let mut arr = [0u8; 16];
            arr.copy_from_slice(bytes);
            Ok(IpAddr::from(arr).to_string())
        }
        2 | 5 | 12 => p.name(),
        15 => {
            let pref = p.u16()?;
            let exchange = p.name()?;
            Ok(format!("{pref} {exchange}"))
        }
        16 => {
            let mut parts = Vec::new();
            let mut remaining = rdlength;
            while remaining > 0 {
                let len = p.u8()? as usize;
                remaining = remaining.saturating_sub(1);
                if len > remaining {
                    break;
                }
                let bytes = p.take(len)?;
                remaining -= len;
                parts.push(String::from_utf8_lossy(bytes).to_string());
            }
            Ok(parts.join(""))
        }
        33 => {
            let priority = p.u16()?;
            let weight = p.u16()?;
            let port = p.u16()?;
            let target = p.name()?;
            Ok(format!("{priority} {weight} {port} {target}"))
        }
        6 => {
            let mname = p.name()?;
            let rname = p.name()?;
            let serial = p.u32()?;
            let refresh = p.u32()?;
            let retry = p.u32()?;
            let expire = p.u32()?;
            let minimum = p.u32()?;
            Ok(format!(
                "{mname} {rname} serial={serial} refresh={refresh} retry={retry} expire={expire} minimum={minimum}"
            ))
        }
        257 => {
            let flags = p.u8()?;
            let tag_len = p.u8()? as usize;
            let tag = String::from_utf8_lossy(p.take(tag_len)?).to_string();
            let value =
                String::from_utf8_lossy(p.take(rdlength.saturating_sub(2 + tag_len))?).to_string();
            Ok(format!("{flags} {tag} {value}"))
        }
        _ => {
            let bytes = p.take(rdlength.min(p.buf.len().saturating_sub(p.pos)))?;
            Ok(format!("<{} bytes>", bytes.len()))
        }
    }
}

/// Normalize a server specification: `ip`, `ip:port`, `[v6]:port`, `v6`.
pub fn parse_server(server: &str) -> Result<(IpAddr, u16)> {
    let trimmed = server.trim();
    if let Some(rest) = trimmed.strip_prefix('[') {
        if let Some((host, port)) = rest.split_once("]:") {
            let ip: IpAddr = host.parse().map_err(|_| {
                NetroError::new(ErrorCode::InvalidTarget, format!("bad DNS server {server}"))
            })?;
            let port: u16 = port.parse().map_err(|_| {
                NetroError::new(
                    ErrorCode::InvalidTarget,
                    format!("bad DNS port in {server}"),
                )
            })?;
            return Ok((ip, port));
        }
    }
    if let Ok(ip) = trimmed.parse::<IpAddr>() {
        return Ok((ip, 53));
    }
    if let Ok(ip) = trimmed.parse::<std::net::Ipv4Addr>() {
        return Ok((IpAddr::V4(ip), 53));
    }
    // host:port form
    if let Some((host, port)) = trimmed.rsplit_once(':') {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if let Ok(port) = port.parse::<u16>() {
                return Ok((ip, port));
            }
        }
    }
    Err(NetroError::new(
        ErrorCode::InvalidTarget,
        format!("'{server}' is not a valid DNS server (expected IP or IP:port)"),
    ))
}

/// Query a specific server.
pub fn query(
    server: &str,
    name: &str,
    rtype: RecordType,
    timeout_duration: Duration,
) -> Result<DnsResponse> {
    let (ip, port) = parse_server(server)?;
    let started = Instant::now();
    let id: u16 = (std::process::id() as u16) ^ (started.elapsed().subsec_nanos() as u16);
    let request = encode_query(id, name, rtype, true)?;

    let mut buf = vec![0u8; 4096];
    let socket = UdpSocket::bind(("0.0.0.0", 0)).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("cannot create UDP socket: {e}"),
        )
    })?;
    socket.set_read_timeout(Some(timeout_duration)).ok();
    socket.connect((ip, port)).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("cannot reach DNS server {ip}: {e}"),
        )
    })?;
    socket.send(&request).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("DNS send failed: {e}"),
        )
    })?;

    let size = match socket.recv(&mut buf) {
        Ok(n) => n,
        Err(e)
            if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
        {
            return Err(timeout(format!(
                "no DNS response from {ip}:{port} within {:.1}s",
                timeout_duration.as_secs_f64()
            )));
        }
        Err(e) => {
            return Err(NetroError::new(
                ErrorCode::NetworkDnsUnavailable,
                format!("DNS receive failed: {e}"),
            ))
        }
    };
    let rtt_ms = started.elapsed().as_secs_f64() * 1000.0;

    let mut message = parse_response(&buf[..size])?;
    if message.id != id {
        // Some servers echo the ID; if not, still parse but note it is best effort.
        message.id = id;
    }

    if message.truncated {
        let tcp_response = query_tcp(ip, port, &request, timeout_duration)?;
        message = tcp_response;
    }

    Ok(DnsResponse {
        id,
        rcode: message.rcode,
        rcode_name: rcode_name(message.rcode).to_string(),
        answers: message.answers,
        truncated: message.truncated,
        server: format!("{ip}:{port}"),
        rtt_ms,
        record_type: rtype.name().to_string(),
        query_name: name.to_string(),
    })
}

fn query_tcp(
    ip: IpAddr,
    port: u16,
    request: &[u8],
    timeout_duration: Duration,
) -> Result<ParsedMessage> {
    let addr = (ip, port);
    let mut stream = TcpStream::connect_timeout(
        &addr
            .to_socket_addrs()
            .map_err(|e| NetroError::new(ErrorCode::NetworkDnsUnavailable, e.to_string()))?
            .next()
            .ok_or_else(|| NetroError::new(ErrorCode::NetworkDnsUnavailable, "no TCP address"))?,
        timeout_duration,
    )
    .map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("DNS TCP connect failed: {e}"),
        )
    })?;
    stream.set_read_timeout(Some(timeout_duration)).ok();
    stream.set_write_timeout(Some(timeout_duration)).ok();

    let mut framed = Vec::with_capacity(request.len() + 2);
    framed.extend_from_slice(&(request.len() as u16).to_be_bytes());
    framed.extend_from_slice(request);
    std::io::Write::write_all(&mut stream, &framed).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("DNS TCP write failed: {e}"),
        )
    })?;

    let mut len_buf = [0u8; 2];
    std::io::Read::read_exact(&mut stream, &mut len_buf).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("DNS TCP read failed: {e}"),
        )
    })?;
    let len = u16::from_be_bytes(len_buf) as usize;
    let mut resp = vec![0u8; len.min(65535)];
    std::io::Read::read_exact(&mut stream, &mut resp).map_err(|e| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            format!("DNS TCP read failed: {e}"),
        )
    })?;
    parse_response(&resp)
}

/// Build a reverse-DNS name for an address.
pub fn reverse_name(ip: &IpAddr) -> String {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            format!("{}.{}.{}.{}.in-addr.arpa", o[3], o[2], o[1], o[0])
        }
        IpAddr::V6(v6) => {
            let mut s = String::with_capacity(80);
            for byte in v6.octets().iter().rev() {
                s.push_str(&format!("{:x}.{:x}.", byte & 0x0F, byte >> 4));
            }
            s.push_str("ip6.arpa");
            s
        }
    }
}

/// Resolve using the platform's configured resolvers.
pub fn resolve_via_system(
    name: &str,
    rtype: RecordType,
    timeout_duration: Duration,
) -> Result<DnsResponse> {
    let config = platform().dns_config()?;
    let mut last_error = None;
    for server in &config.servers {
        match query(server, name, rtype, timeout_duration) {
            Ok(response) => return Ok(response),
            Err(e) => last_error = Some(e),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        NetroError::new(
            ErrorCode::NetworkDnsUnavailable,
            "no DNS servers configured",
        )
    }))
}

/// PTR lookup using the system resolvers.
pub fn reverse_lookup(ip: &IpAddr, timeout_duration: Duration) -> Result<Vec<String>> {
    let name = reverse_name(ip);
    let response = resolve_via_system(&name, RecordType::Ptr, timeout_duration)?;
    Ok(response
        .answers
        .into_iter()
        .filter(|a| a.record_type == "PTR")
        .map(|a| a.value.trim_end_matches('.').to_string())
        .collect())
}

/// Convenience: first A/AAAA record values.
pub fn resolve_addresses(name: &str, timeout_duration: Duration) -> Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for rtype in [RecordType::A, RecordType::AAAA] {
        if let Ok(response) = resolve_via_system(name, rtype, timeout_duration) {
            for answer in response.answers {
                if answer.record_type == "A" || answer.record_type == "AAAA" {
                    if let Ok(ip) = answer.value.parse::<IpAddr>() {
                        out.push(ip);
                    }
                }
            }
        }
    }
    out.sort_by_key(util::ip_sort_key);
    out.dedup();
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_query_header_and_name() {
        let bytes = encode_query(0x1234, "example.com", RecordType::A, true).unwrap();
        assert_eq!(&bytes[0..2], &[0x12, 0x34]);
        assert_eq!(&bytes[2..4], &[0x01, 0x00]); // RD set
        assert_eq!(&bytes[4..6], &[0x00, 0x01]); // QDCOUNT
        assert_eq!(&bytes[12], &7u8); // len "example"
        assert_eq!(&bytes[13..20], b"example");
        assert_eq!(&bytes[20], &3u8);
        assert_eq!(&bytes[21..24], b"com");
        assert_eq!(&bytes[24], &0u8);
        assert_eq!(&bytes[25..27], &[0x00, 0x01]); // A
        assert_eq!(&bytes[27..29], &[0x00, 0x01]); // IN
    }

    #[test]
    fn encode_query_rejects_bad_names() {
        assert!(encode_query(1, "a..b", RecordType::A, true).is_err());
        assert!(encode_query(1, &format!("{}.com", "a".repeat(64)), RecordType::A, true).is_err());
    }

    fn fixture_response() -> Vec<u8> {
        // Hand-built NOERROR response for "example.com" A with a compression
        // pointer to the question name.
        let mut b = Vec::new();
        b.extend_from_slice(&[0xAB, 0xCD]); // id
        b.extend_from_slice(&[0x81, 0x80]); // QR=1, RD=1, RA=1
        b.extend_from_slice(&[0x00, 0x01]); // qd
        b.extend_from_slice(&[0x00, 0x02]); // an
        b.extend_from_slice(&[0x00, 0x00]); // ns
        b.extend_from_slice(&[0x00, 0x00]); // ar
        b.push(7);
        b.extend_from_slice(b"example");
        b.push(3);
        b.extend_from_slice(b"com");
        b.push(0);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]);
        // answer 1: pointer to offset 12
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&[0x00, 0x01, 0x00, 0x01]); // A IN
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]); // ttl 300
        b.extend_from_slice(&[0x00, 0x04]);
        b.extend_from_slice(&[93, 184, 216, 34]);
        // answer 2: AAAA
        b.extend_from_slice(&[0xC0, 0x0C]);
        b.extend_from_slice(&[0x00, 0x1C, 0x00, 0x01]); // AAAA IN
        b.extend_from_slice(&[0x00, 0x00, 0x01, 0x2C]);
        b.extend_from_slice(&[0x00, 0x10]);
        b.extend_from_slice(&[
            0x26, 0x06, 0x28, 0x00, 0x02, 0x20, 0x00, 0x01, 0x02, 0x48, 0x18, 0x93, 0x25, 0xC8,
            0x19, 0x46,
        ]);
        b
    }

    #[test]
    fn parse_response_with_compression() {
        let parsed = parse_response(&fixture_response()).unwrap();
        assert_eq!(parsed.id, 0xABCD);
        assert_eq!(parsed.rcode, 0);
        assert!(!parsed.truncated);
        assert_eq!(parsed.answers.len(), 2);
        assert_eq!(parsed.answers[0].name, "example.com");
        assert_eq!(parsed.answers[0].record_type, "A");
        assert_eq!(parsed.answers[0].value, "93.184.216.34");
        assert_eq!(parsed.answers[0].ttl, 300);
        assert_eq!(parsed.answers[1].record_type, "AAAA");
        assert_eq!(
            parsed.answers[1].value,
            "2606:2800:220:1:248:1893:25c8:1946"
        );
    }

    #[test]
    fn parse_nxdomain() {
        let mut b = fixture_response();
        b[3] = 0x83; // rcode 3, QR+RD+RA
        b[7] = 0x00; // ancount 0
        b.truncate(12 + 17);
        let parsed = parse_response(&b).unwrap();
        assert_eq!(parsed.rcode, 3);
        assert_eq!(rcode_name(parsed.rcode), "NXDOMAIN");
        assert!(parsed.answers.is_empty());
    }

    #[test]
    fn parse_truncated_buffer_is_error() {
        let b = [0u8; 5];
        assert!(parse_response(&b).is_err());
    }

    #[test]
    fn compression_loop_is_rejected() {
        let mut b = vec![0u8; 12];
        b.extend_from_slice(&[0xC0, 0x0C]); // points to itself
        let mut p = Parser::new(&b);
        p.pos = 12;
        assert!(p.name().is_err());
    }

    #[test]
    fn reverse_name_v4_and_v6() {
        assert_eq!(
            reverse_name(&"192.168.1.10".parse().unwrap()),
            "10.1.168.192.in-addr.arpa"
        );
        let v6 = reverse_name(&"::1".parse().unwrap());
        assert!(v6.ends_with("ip6.arpa"));
        assert!(v6.starts_with("1.0.0.0"));
    }

    #[test]
    fn server_parsing() {
        assert_eq!(
            parse_server("1.1.1.1").unwrap(),
            ("1.1.1.1".parse::<IpAddr>().unwrap(), 53)
        );
        assert_eq!(
            parse_server("1.1.1.1:5353").unwrap(),
            ("1.1.1.1".parse::<IpAddr>().unwrap(), 5353)
        );
        assert_eq!(
            parse_server("[2606:4700:4700::1111]:53").unwrap(),
            ("2606:4700:4700::1111".parse::<IpAddr>().unwrap(), 53)
        );
        assert!(parse_server("not-a-server").is_err());
    }

    #[test]
    fn type_parsing_round_trip() {
        for t in [
            RecordType::A,
            RecordType::AAAA,
            RecordType::Cname,
            RecordType::Mx,
            RecordType::Txt,
            RecordType::Ns,
            RecordType::Soa,
            RecordType::Ptr,
            RecordType::Srv,
        ] {
            assert_eq!(RecordType::from_name(t.name()), Some(t));
        }
    }
}
