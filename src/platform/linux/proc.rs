//! Pure parsers for Linux `/proc` and `/etc` data.
//!
//! Keeping these as pure functions (input string -> structured data) makes them
//! unit-testable with fixtures, independently of the host state.

use crate::model::*;
use std::collections::HashMap;
use std::net::{Ipv4Addr, Ipv6Addr};

/// Parse one `/proc/net/route` or `/proc/net/ipv6_route` style table.
///
/// `/proc/net/route` columns:
/// `Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT`
fn parse_hex_u32(field: &str) -> u32 {
    let trimmed = field.trim();
    let trimmed = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    u32::from_str_radix(trimmed, 16).unwrap_or(0)
}

pub fn parse_proc_route(content: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 8 {
            continue;
        }
        let iface = cols[0];
        let destination = match parse_hex_ipv4(cols[1]) {
            Some(ip) => ip,
            None => continue,
        };
        let gateway_raw = parse_hex_ipv4(cols[2]);
        let flags = parse_hex_u32(cols[3]);
        let metric = cols[6].parse::<u32>().ok();
        let mask = parse_hex_ipv4(cols[7]).unwrap_or(Ipv4Addr::UNSPECIFIED);
        let prefix = mask_to_prefix_v4(mask);
        let is_default = destination == Ipv4Addr::UNSPECIFIED && prefix == 0;
        let gateway = gateway_raw.filter(|g| *g != Ipv4Addr::UNSPECIFIED);
        routes.push(Route {
            family: "ipv4".into(),
            destination: destination.to_string(),
            prefix,
            gateway: gateway.map(|g| g.to_string()),
            interface: Some(iface.to_string()),
            metric,
            flags: decode_route_flags(flags),
            is_default,
        });
    }
    routes
}

/// `/proc/net/ipv6_route` fixed-width columns:
/// `dest(32) destlen(2) src(32) srclen(2) nexthop(32) metric(8) refcnt(8) use(8) flags(8) iface`
pub fn parse_proc_ipv6_route(content: &str) -> Vec<Route> {
    let mut routes = Vec::new();
    for line in content.lines() {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let dest = match parse_hex_ipv6_network_order(cols[0]) {
            Some(ip) => ip,
            None => continue,
        };
        let prefix = u8::from_str_radix(cols[1], 16).unwrap_or(0);
        let nexthop = parse_hex_ipv6_network_order(cols[4]).unwrap_or(Ipv6Addr::UNSPECIFIED);
        let metric = u32::from_str_radix(cols[5], 16).ok();
        let flags = parse_hex_u32(cols[8]);
        let iface = cols[9];
        let is_default = dest == Ipv6Addr::UNSPECIFIED && prefix == 0;
        let gateway = if nexthop == Ipv6Addr::UNSPECIFIED {
            None
        } else {
            Some(nexthop.to_string())
        };
        routes.push(Route {
            family: "ipv6".into(),
            destination: dest.to_string(),
            prefix,
            gateway,
            interface: Some(iface.to_string()),
            metric,
            flags: decode_route_flags(flags),
            is_default,
        });
    }
    routes
}

pub fn decode_route_flags(flags: u32) -> Vec<String> {
    // From include/uapi/linux/route.h (RTF_*).
    let table = [
        (0x0001, "UP"),
        (0x0002, "GATEWAY"),
        (0x0004, "HOST"),
        (0x0008, "REINSTATE"),
        (0x0010, "DYNAMIC"),
        (0x0020, "MODIFIED"),
        (0x0040, "MTU"),
        (0x0080, "WINDOW"),
        (0x0100, "IRTT"),
        (0x0200, "REJECT"),
        (0x0400, "STATIC"),
    ];
    table
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, name)| name.to_string())
        .collect()
}

/// Parse an IPv4 in `/proc` hexadecimal form (`0100007F` -> `127.0.0.1`).
pub fn parse_hex_ipv4(hex: &str) -> Option<Ipv4Addr> {
    let value = u32::from_str_radix(hex.trim(), 16).ok()?;
    // The kernel prints the address in host byte order; on little-endian
    // systems `from_le_bytes` reconstructs network order.
    let bytes = if cfg!(target_endian = "little") {
        value.to_le_bytes()
    } else {
        value.to_be_bytes()
    };
    Some(Ipv4Addr::from(bytes))
}

/// Parse an IPv6 address from `/proc/net/ipv6_route`, which prints the raw
/// address bytes in network order (unlike `/proc/net/tcp6`, which prints
/// host-order 32-bit words).
pub fn parse_hex_ipv6_network_order(hex: &str) -> Option<Ipv6Addr> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(2).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        bytes[index] = u8::from_str_radix(s, 16).ok()?;
    }
    Some(Ipv6Addr::from(bytes))
}

/// Parse an IPv6 in `/proc/net/tcp6` hexadecimal form (four host-order 32-bit
/// words, i.e. each word is little-endian on little-endian hosts).
pub fn parse_hex_ipv6(hex: &str) -> Option<Ipv6Addr> {
    let hex = hex.trim();
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (word_index, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let s = std::str::from_utf8(chunk).ok()?;
        let word = u32::from_str_radix(s, 16).ok()?;
        let word_bytes = if cfg!(target_endian = "little") {
            word.to_le_bytes()
        } else {
            word.to_be_bytes()
        };
        bytes[word_index * 4..word_index * 4 + 4].copy_from_slice(&word_bytes);
    }
    Some(Ipv6Addr::from(bytes))
}

/// Convert an IPv4 netmask to a prefix length. Returns 0 for non-contiguous
/// masks (which are invalid in practice).
pub fn mask_to_prefix_v4(mask: Ipv4Addr) -> u8 {
    let bits = u32::from(mask);
    if bits == 0 {
        return 0;
    }
    let ones = bits.leading_ones() as u8;
    let expected = if ones == 0 {
        0
    } else {
        u32::MAX << (32 - ones)
    };
    if expected == bits {
        ones
    } else {
        0
    }
}

/// `/proc/net/arp` columns:
/// `IPaddress HWtype Flags HWaddress Mask Device`
pub fn parse_proc_arp(content: &str) -> Vec<Neighbor> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 6 {
            continue;
        }
        let flags = parse_hex_u32(cols[2]);
        let mac = cols[3];
        if flags & 0x2 == 0 || mac == "00:00:00:00:00:00" {
            continue;
        }
        out.push(Neighbor {
            ip: cols[0].to_string(),
            mac: Some(mac.to_ascii_lowercase()),
            interface: Some(cols[5].to_string()),
            state: Some(if flags & 0x2 != 0 {
                "reachable".into()
            } else {
                "incomplete".into()
            }),
            vendor: None,
            hostname: None,
        });
    }
    out
}

/// A socket row from `/proc/net/tcp`, `tcp6`, `udp`, `udp6`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcSocket {
    pub local_addr: String,
    pub local_port: u16,
    pub remote_addr: Option<String>,
    pub remote_port: Option<u16>,
    pub state: String,
    pub uid: u32,
    pub inode: u64,
}

/// TCP state codes from `include/net/tcp_states.h`.
pub fn tcp_state_name(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x02 => "SYN_SENT",
        0x03 => "SYN_RECV",
        0x04 => "FIN_WAIT1",
        0x05 => "FIN_WAIT2",
        0x06 => "TIME_WAIT",
        0x07 => "CLOSE",
        0x08 => "CLOSE_WAIT",
        0x09 => "LAST_ACK",
        0x0A => "LISTEN",
        0x0B => "CLOSING",
        0x0C => "NEW_SYN_RECV",
        0x0D => "UNKNOWN",
        0x0E => "UNKNOWN",
        0x0F => "UNKNOWN",
        _ => "UNKNOWN",
    }
}

/// UDP state codes: the kernel reports `07` (CLOSE/UNCONNECTED) for bound
/// sockets and `01` for connected ones.
pub fn udp_state_name(code: u8) -> &'static str {
    match code {
        0x01 => "ESTABLISHED",
        0x07 => "UNCONNECTED",
        other => tcp_state_name(other),
    }
}

/// Parse `/proc/net/tcp*` or `/proc/net/udp*`.
///
/// IPv6 tables are detected by the 32-character address column and parsed with
/// [`parse_hex_ipv6`]; IPv4 uses [`parse_hex_ipv4`].
pub fn parse_proc_sockets(content: &str, udp: bool) -> Vec<ProcSocket> {
    let mut out = Vec::new();
    for line in content.lines().skip(1) {
        let cols: Vec<&str> = line.split_whitespace().collect();
        if cols.len() < 10 {
            continue;
        }
        let (local_addr, local_port) = match parse_proc_sockaddr(cols[1]) {
            Some(v) => v,
            None => continue,
        };
        let remote = parse_proc_sockaddr(cols[2]).filter(|(addr, port)| {
            *port != 0
                || addr
                    .parse::<std::net::IpAddr>()
                    .map(|ip| !ip.is_unspecified())
                    .unwrap_or(true)
        });
        let state_code = u8::from_str_radix(cols[3], 16).unwrap_or(0xFF);
        let state = if udp {
            udp_state_name(state_code)
        } else {
            tcp_state_name(state_code)
        };
        let uid = cols[7].parse::<u32>().unwrap_or(0);
        let inode = cols[9].parse::<u64>().unwrap_or(0);
        out.push(ProcSocket {
            local_addr,
            local_port,
            remote_addr: remote.as_ref().map(|(a, _)| a.clone()),
            remote_port: remote.as_ref().map(|(_, p)| *p),
            state: state.to_string(),
            uid,
            inode,
        });
    }
    out
}

fn parse_proc_sockaddr(field: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if addr_hex.len() == 32 {
        parse_hex_ipv6(addr_hex)?.to_string()
    } else if addr_hex.len() == 8 {
        parse_hex_ipv4(addr_hex)?.to_string()
    } else {
        return None;
    };
    Some((addr, port))
}

/// Map socket inode -> (pid, process name) by scanning `/proc/<pid>/fd`.
///
/// Only the requested inodes are resolved, and the scan stops as soon as all of
/// them are found. This keeps the cost proportional to the number of sockets
/// netRo actually reports instead of to the size of the process table. Only
/// processes owned by the current user (or all, when root) can be read;
/// unreadable entries are skipped deliberately.
pub fn inode_process_map_for(targets: &[u64]) -> HashMap<u64, (u32, String)> {
    let mut remaining: std::collections::HashSet<u64> = targets
        .iter()
        .copied()
        .filter(|inode| *inode != 0)
        .collect();
    let mut map = HashMap::new();
    if remaining.is_empty() {
        return map;
    }
    let proc_dir = match std::fs::read_dir("/proc") {
        Ok(d) => d,
        Err(_) => return map,
    };
    for entry in proc_dir.flatten() {
        if remaining.is_empty() {
            break;
        }
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: u32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };
        let fd_dir = format!("/proc/{pid}/fd");
        let fds = match std::fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue,
        };
        let mut comm: Option<String> = None;
        for fd in fds.flatten() {
            if let Ok(target) = std::fs::read_link(fd.path()) {
                let t = target.to_string_lossy();
                if let Some(inner) = t.strip_prefix("socket:[") {
                    if let Some(inode_str) = inner.strip_suffix(']') {
                        if let Ok(inode) = inode_str.parse::<u64>() {
                            if remaining.remove(&inode) {
                                let name = comm.get_or_insert_with(|| {
                                    std::fs::read_to_string(format!("/proc/{pid}/comm"))
                                        .map(|s| s.trim().to_string())
                                        .unwrap_or_default()
                                });
                                map.insert(inode, (pid, name.clone()));
                                if remaining.is_empty() {
                                    break;
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    map
}

// ---------------------------------------------------------------------------
// /etc accounts
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct PasswdEntry {
    pub name: String,
    pub uid: u32,
    pub gid: u32,
    pub home: String,
    pub shell: String,
}

pub fn parse_passwd(content: &str) -> Vec<PasswdEntry> {
    content
        .lines()
        .filter(|l| !l.trim_start().starts_with('#') && !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 7 {
                return None;
            }
            Some(PasswdEntry {
                name: parts[0].to_string(),
                uid: parts[2].parse().ok()?,
                gid: parts[3].parse().ok()?,
                home: parts[5].to_string(),
                shell: parts[6].to_string(),
            })
        })
        .collect()
}

#[derive(Debug, Clone)]
pub struct ShadowEntry {
    pub name: String,
    pub hash: String,
    pub last_change: Option<u64>,
    pub min_days: Option<u64>,
    pub max_days: Option<u64>,
    pub warn_days: Option<u64>,
    pub inactive_days: Option<u64>,
    pub expire_days: Option<u64>,
}

pub fn parse_shadow(content: &str) -> Vec<ShadowEntry> {
    content
        .lines()
        .filter(|l| !l.trim().is_empty())
        .filter_map(|line| {
            let parts: Vec<&str> = line.split(':').collect();
            if parts.len() < 9 {
                return None;
            }
            let num = |s: &str| s.parse::<u64>().ok();
            Some(ShadowEntry {
                name: parts[0].to_string(),
                hash: parts[1].to_string(),
                last_change: num(parts[2]),
                min_days: num(parts[3]),
                max_days: num(parts[4]),
                warn_days: num(parts[5]),
                inactive_days: num(parts[6]),
                expire_days: num(parts[7]),
            })
        })
        .collect()
}

/// Classify an `/etc/shadow` hash field.
pub fn classify_password_hash(hash: &str) -> PasswordStatus {
    if hash.is_empty() {
        return PasswordStatus::Empty;
    }
    if hash.starts_with('!') || hash.starts_with('*') {
        return PasswordStatus::Locked;
    }
    PasswordStatus::Set
}

/// Parse `/etc/group` into group name -> members.
pub fn parse_groups(content: &str) -> HashMap<String, Vec<String>> {
    let mut map: HashMap<String, Vec<String>> = HashMap::new();
    for line in content.lines() {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() < 4 {
            continue;
        }
        let members: Vec<String> = parts[3]
            .split(',')
            .map(|s| s.trim().to_string())
            .filter(|s| !s.is_empty())
            .collect();
        map.insert(parts[0].to_string(), members);
    }
    map
}

/// A user is privileged when they are uid 0 or a member of a well-known
/// administrative group. This is evidence-based, not a heuristic guess.
pub fn is_privileged_account(entry: &PasswdEntry, groups: &HashMap<String, Vec<String>>) -> bool {
    if entry.uid == 0 {
        return true;
    }
    const ADMIN_GROUPS: [&str; 5] = ["sudo", "wheel", "admin", "root", "sudoers"];
    ADMIN_GROUPS.iter().any(|g| {
        groups
            .get(*g)
            .map(|members| members.iter().any(|m| m == &entry.name))
            .unwrap_or(false)
    })
}

/// Shells that indicate a non-interactive service account.
pub fn is_login_shell(shell: &str) -> bool {
    let s = shell.trim();
    !s.is_empty()
        && !s.ends_with("/nologin")
        && !s.ends_with("/false")
        && s != "/bin/sync"
        && s != "/sbin/shutdown"
        && s != "/sbin/halt"
}

/// Parse `/etc/login.defs` password-aging defaults.
pub fn parse_login_defs(content: &str) -> HashMap<String, u32> {
    let mut map = HashMap::new();
    for line in content.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once(char::is_whitespace) {
            if let Ok(v) = value.trim().parse::<u32>() {
                map.insert(key.trim().to_string(), v);
            }
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::*;

    const ROUTE_FIXTURE: &str =
        "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
eth0\t00000000\t0101A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
eth0\t0001A8C0\t00000000\t0001\t0\t0\t100\t00FFFFFF\t0\t0\t0\n";

    #[test]
    fn proc_route_parses_default_route() {
        let routes = parse_proc_route(ROUTE_FIXTURE);
        assert_eq!(routes.len(), 2);
        let default = routes.iter().find(|r| r.is_default).unwrap();
        assert_eq!(default.gateway.as_deref(), Some("192.168.1.1"));
        assert_eq!(default.interface.as_deref(), Some("eth0"));
        assert_eq!(default.metric, Some(100));
        assert!(default.flags.contains(&"UP".to_string()));
        assert!(default.flags.contains(&"GATEWAY".to_string()));
        let local = routes.iter().find(|r| !r.is_default).unwrap();
        assert_eq!(local.destination, "192.168.1.0");
        assert_eq!(local.prefix, 24);
    }

    #[test]
    fn ipv6_route_parses_default() {
        let line = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 00000000000000000000000000000000 00000100 00000001 00000000 00000003 eth0";
        let routes = parse_proc_ipv6_route(line);
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_default);
        assert_eq!(routes[0].destination, "::");
        assert_eq!(routes[0].prefix, 0);
    }

    #[test]
    fn hex_ipv4_parsing() {
        assert_eq!(
            parse_hex_ipv4("0100007F"),
            Some("127.0.0.1".parse().unwrap())
        );
        assert_eq!(
            parse_hex_ipv4("0101A8C0"),
            Some("192.168.1.1".parse().unwrap())
        );
        assert_eq!(parse_hex_ipv4("zzzz"), None);
    }

    #[test]
    fn hex_ipv6_parsing_tcp6_host_order_words() {
        let v6 = parse_hex_ipv6("00000000000000000000000001000000").unwrap();
        assert_eq!(v6, "::1".parse::<Ipv6Addr>().unwrap());
        let v6 = parse_hex_ipv6("000080FE000000000000000000000000").unwrap();
        assert_eq!(v6, "fe80::".parse::<Ipv6Addr>().unwrap());
        assert!(parse_hex_ipv6("short").is_none());
    }

    #[test]
    fn hex_ipv6_parsing_network_order() {
        let v6 = parse_hex_ipv6_network_order("00000000000000000000000000000001").unwrap();
        assert_eq!(v6, "::1".parse::<Ipv6Addr>().unwrap());
        let v6 = parse_hex_ipv6_network_order("fe80000000000000f6cae7fffed9b0dc").unwrap();
        assert_eq!(v6, "fe80::f6ca:e7ff:fed9:b0dc".parse::<Ipv6Addr>().unwrap());
        assert!(parse_hex_ipv6_network_order("nope").is_none());
    }

    #[test]
    fn ipv6_route_gateway_parsing() {
        let line = "00000000000000000000000000000000 00 00000000000000000000000000000000 00 fe80000000000000f6cae7fffed9b0dc 00000100 00000001 00000000 00000001 wlp3s0";
        let routes = parse_proc_ipv6_route(line);
        assert_eq!(routes.len(), 1);
        assert!(routes[0].is_default);
        assert_eq!(
            routes[0].gateway.as_deref(),
            Some("fe80::f6ca:e7ff:fed9:b0dc")
        );
    }

    #[test]
    fn mask_to_prefix() {
        assert_eq!(mask_to_prefix_v4("255.255.255.0".parse().unwrap()), 24);
        assert_eq!(mask_to_prefix_v4("255.255.255.255".parse().unwrap()), 32);
        assert_eq!(mask_to_prefix_v4("0.0.0.0".parse().unwrap()), 0);
        assert_eq!(mask_to_prefix_v4("255.255.0.255".parse().unwrap()), 0);
    }

    #[test]
    fn arp_parsing_skips_incomplete() {
        let content =
            "IP address       HW type     Flags       HW address            Mask     Device\n\
192.168.1.1      0x1         0x2         aa:bb:cc:dd:ee:ff     *        eth0\n\
192.168.1.50     0x1         0x0         00:00:00:00:00:00     *        eth0\n";
        let neighbors = parse_proc_arp(content);
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].ip, "192.168.1.1");
        assert_eq!(neighbors[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
    }

    #[test]
    fn proc_socket_parsing_v4() {
        let content = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 0100007F:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 ffff 0\n";
        let sockets = parse_proc_sockets(content, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_addr, "127.0.0.1");
        assert_eq!(sockets[0].local_port, 22);
        assert_eq!(sockets[0].state, "LISTEN");
        assert_eq!(sockets[0].inode, 12345);
        assert!(sockets[0].remote_addr.is_none());
    }

    #[test]
    fn proc_socket_parsing_v6_established() {
        let content = "  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
   0: 00000000000000000000000001000000:1F90 00000000000000000000000000000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 999 1 ffff 0\n";
        let sockets = parse_proc_sockets(content, false);
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].local_addr, "::1");
        assert_eq!(sockets[0].local_port, 8080);
        assert_eq!(sockets[0].state, "LISTEN");
    }

    #[test]
    fn passwd_parsing() {
        let content = "root:x:0:0:root:/root:/bin/bash\n\
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n\
alice:x:1000:1000:Alice:/home/alice:/bin/bash\n";
        let entries = parse_passwd(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].uid, 0);
        assert_eq!(entries[2].name, "alice");
        assert!(is_login_shell(&entries[0].shell));
        assert!(!is_login_shell(&entries[1].shell));
    }

    #[test]
    fn shadow_parsing_and_classification() {
        let content = "root:$6$abc:19000:0:99999:7:::\n\
lockeduser:!$6$def:19000:0:99999:7:::\n\
nopass::19000:0:99999:7:::\n";
        let entries = parse_shadow(content);
        assert_eq!(entries.len(), 3);
        assert_eq!(
            classify_password_hash(&entries[0].hash),
            PasswordStatus::Set
        );
        assert_eq!(
            classify_password_hash(&entries[1].hash),
            PasswordStatus::Locked
        );
        assert_eq!(
            classify_password_hash(&entries[2].hash),
            PasswordStatus::Empty
        );
    }

    #[test]
    fn privileged_account_detection() {
        let groups = parse_groups("sudo:x:27:alice,bob\nwheel:x:10:carol\n");
        let alice = PasswdEntry {
            name: "alice".into(),
            uid: 1000,
            gid: 1000,
            home: String::new(),
            shell: "/bin/bash".into(),
        };
        assert!(is_privileged_account(&alice, &groups));
        let root = PasswdEntry {
            name: "root".into(),
            uid: 0,
            gid: 0,
            home: String::new(),
            shell: "/bin/bash".into(),
        };
        assert!(is_privileged_account(&root, &groups));
        let dave = PasswdEntry {
            name: "dave".into(),
            uid: 1001,
            gid: 1001,
            home: String::new(),
            shell: "/bin/bash".into(),
        };
        assert!(!is_privileged_account(&dave, &groups));
    }

    #[test]
    fn login_defs_parsing() {
        let content = "# comment\nPASS_MAX_DAYS\t99999\nPASS_MIN_DAYS 0\nPASS_WARN_AGE 7\n";
        let map = parse_login_defs(content);
        assert_eq!(map.get("PASS_MAX_DAYS"), Some(&99999));
        assert_eq!(map.get("PASS_WARN_AGE"), Some(&7));
    }
}
