//! Safe local-network discovery.
//!
//! Discovery is layered and evidence-based:
//! 1. The OS neighbor (ARP/NDP) table — instant and always available.
//! 2. Optional ICMP sweep through the platform `ping` utility.
//! 3. Optional TCP probes to a small set of common service ports.
//! 4. Optional `nmap -sn` when installed (parsed, never required).
//!
//! Discovery is restricted to the machine's own subnets (or an explicitly
//! provided one); public ranges require `--authorized`.

use crate::core::diagnostics::{ping, PingMethod, PingOptions};
use crate::core::oui;
use crate::error::{dependency_missing, ErrorCode, NetroError, Result};
use crate::model::*;
use crate::platform::platform;
use crate::util::{self, parse_cidr};
use std::collections::BTreeMap;
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoveryMethod {
    Auto,
    Neighbors,
    Icmp,
    Tcp,
    Nmap,
}

impl DiscoveryMethod {
    pub fn parse(value: &str) -> Option<Self> {
        match value.to_ascii_lowercase().as_str() {
            "auto" => Some(DiscoveryMethod::Auto),
            "neighbors" | "arp" => Some(DiscoveryMethod::Neighbors),
            "icmp" | "ping" => Some(DiscoveryMethod::Icmp),
            "tcp" => Some(DiscoveryMethod::Tcp),
            "nmap" => Some(DiscoveryMethod::Nmap),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct DiscoveryOptions {
    pub interface: Option<String>,
    pub target: Option<String>,
    pub method: DiscoveryMethod,
    pub max_hosts: usize,
    pub tcp_ports: Vec<u16>,
    pub resolve_hostnames: bool,
    pub vendor_lookup: bool,
    pub oui_file: Option<PathBuf>,
    pub concurrency: usize,
    pub timeout: Duration,
    /// Optional cooperative cancellation flag; the sweep stops promptly and
    /// partial results are returned.
    pub cancel: Option<Arc<AtomicBool>>,
}

impl DiscoveryOptions {
    pub fn is_cancelled(&self) -> bool {
        self.cancel
            .as_ref()
            .map(|flag| flag.load(Ordering::Relaxed))
            .unwrap_or(false)
    }
}

/// Real discovery progress: `probed` of `total` probes in the current `phase`,
/// with `found` hosts discovered so far.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryProgress {
    pub phase: &'static str,
    pub probed: usize,
    pub total: usize,
    pub found: usize,
}

impl Default for DiscoveryOptions {
    fn default() -> Self {
        Self {
            interface: None,
            target: None,
            method: DiscoveryMethod::Auto,
            max_hosts: 256,
            tcp_ports: vec![22, 80, 443, 445, 139, 8080],
            resolve_hostnames: true,
            vendor_lookup: true,
            oui_file: None,
            concurrency: 64,
            timeout: Duration::from_millis(800),
            cancel: None,
        }
    }
}

pub fn discover(options: &DiscoveryOptions) -> Result<DiscoveryReport> {
    discover_with(options, &mut |_| {})
}

pub fn discover_with(
    options: &DiscoveryOptions,
    observer: &mut dyn FnMut(DiscoveryProgress),
) -> Result<DiscoveryReport> {
    let started = Instant::now();
    let subnets = collect_subnets(options)?;
    if subnets.is_empty() {
        return Err(NetroError::new(
            ErrorCode::NetworkUnreachable,
            "no usable IPv4 subnet found on any active interface",
        )
        .with_hint("specify --target <cidr> or check interface configuration"));
    }

    // Build the address set, honoring max_hosts across all subnets.
    let mut host_list: Vec<IpAddr> = Vec::new();
    let mut truncated = false;
    for (addr, prefix) in &subnets {
        let remaining = options.max_hosts.saturating_sub(host_list.len());
        if remaining == 0 {
            truncated = true;
            break;
        }
        let hosts = util::subnet_hosts(*addr, *prefix, remaining);
        if hosts.len() == remaining
            && util::subnet_hosts(*addr, *prefix, remaining + 1).len() > remaining
        {
            truncated = true;
        }
        host_list.extend(hosts);
    }
    host_list.sort_by_key(util::ip_sort_key);
    host_list.dedup();
    observer(DiscoveryProgress {
        phase: "preparing",
        probed: 0,
        total: host_list.len(),
        found: 0,
    });

    let mut hosts: BTreeMap<IpAddr, DiscoveredHost> = BTreeMap::new();
    let mut methods_used: Vec<String> = Vec::new();
    let mut cancelled = options.is_cancelled();

    // 1. Neighbor table.
    if matches!(
        options.method,
        DiscoveryMethod::Auto | DiscoveryMethod::Neighbors
    ) {
        if let Ok(neighbors) = platform().neighbors() {
            for neighbor in neighbors {
                if let Ok(ip) = neighbor.ip.parse::<IpAddr>() {
                    if !ip.is_ipv4() || ip.is_loopback() {
                        continue;
                    }
                    if !in_subnets(&ip, &subnets) && options.target.is_none() {
                        continue;
                    }
                    let entry = hosts.entry(ip).or_insert_with(|| new_host(ip));
                    if entry.mac.is_none() {
                        entry.mac = neighbor.mac.clone();
                    }
                    if entry.response_ms.is_none() {
                        entry.response_ms = Some(0.0);
                    }
                    add_source(entry, "neighbor-table");
                }
            }
            methods_used.push("neighbor-table".into());
        }
        observer(DiscoveryProgress {
            phase: "neighbors",
            probed: host_list.len(),
            total: host_list.len(),
            found: hosts.len(),
        });
    }

    // 2. ICMP sweep.
    let icmp_available = crate::util::has_program("ping");
    let want_icmp = matches!(
        options.method,
        DiscoveryMethod::Auto | DiscoveryMethod::Icmp
    );
    if want_icmp && icmp_available && !options.is_cancelled() {
        let alive = icmp_sweep(&host_list, options, &mut |probed, total, found| {
            observer(DiscoveryProgress {
                phase: "icmp",
                probed,
                total,
                found,
            })
        });
        for (ip, rtt) in &alive {
            let entry = hosts.entry(*ip).or_insert_with(|| new_host(*ip));
            if entry.response_ms.is_none() || entry.response_ms == Some(0.0) {
                entry.response_ms = Some(*rtt);
            }
            add_source(entry, "icmp");
        }
        methods_used.push("icmp".into());
    } else if want_icmp && options.method == DiscoveryMethod::Icmp && !options.is_cancelled() {
        return Err(dependency_missing("ping", "ICMP discovery"));
    }

    // 3. TCP probe.
    let want_tcp = match options.method {
        DiscoveryMethod::Tcp => true,
        DiscoveryMethod::Auto => {
            // Probe hosts we know about; if nothing is known, sweep everything.
            hosts.is_empty() || hosts.len() < 2
        }
        DiscoveryMethod::Icmp => false,
        _ => false,
    };
    if want_tcp && !options.is_cancelled() {
        let probe_all = hosts.is_empty();
        let targets: Vec<IpAddr> = if probe_all {
            host_list.clone()
        } else {
            hosts.keys().cloned().collect()
        };
        let results = tcp_probe(
            &targets,
            &options.tcp_ports,
            options,
            &mut |probed, total, found| {
                observer(DiscoveryProgress {
                    phase: "tcp",
                    probed,
                    total,
                    found,
                })
            },
        );
        for (ip, open_ports, rtt) in results {
            let entry = hosts.entry(ip).or_insert_with(|| new_host(ip));
            for port in open_ports {
                if !entry.open_ports.contains(&port) {
                    entry.open_ports.push(port);
                }
            }
            entry.open_ports.sort_unstable();
            if entry.response_ms.is_none() || entry.response_ms == Some(0.0) {
                entry.response_ms = Some(rtt);
            }
            add_source(entry, "tcp-probe");
        }
        methods_used.push("tcp-probe".into());
    }

    // 4. nmap.
    if options.method == DiscoveryMethod::Nmap && !options.is_cancelled() {
        observer(DiscoveryProgress {
            phase: "nmap",
            probed: 0,
            total: host_list.len(),
            found: hosts.len(),
        });
        let nmap_hosts = nmap_discovery(&subnets, options)?;
        for host in nmap_hosts {
            let ip = match host.ip.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => continue,
            };
            let entry = hosts.entry(ip).or_insert_with(|| new_host(ip));
            if entry.mac.is_none() {
                entry.mac = host.mac.clone();
            }
            if entry.hostname.is_none() {
                entry.hostname = host.hostname.clone();
            }
            if let Some(vendor) = host.vendor {
                entry.vendor = Some(vendor);
            }
            if entry.response_ms.is_none() {
                entry.response_ms = Some(0.0);
            }
            add_source(entry, "nmap");
        }
        methods_used.push("nmap".into());
    }

    // Enrich: vendor and reverse DNS.
    let enrich_total = hosts.len();
    let mut enrich_done = 0usize;
    for host in hosts.values_mut() {
        if options.is_cancelled() {
            cancelled = true;
            break;
        }
        enrich_done += 1;
        if enrich_done % 16 == 0 {
            observer(DiscoveryProgress {
                phase: "enrich",
                probed: enrich_done,
                total: enrich_total,
                found: enrich_total,
            });
        }
        if options.vendor_lookup {
            if let Some(mac) = &host.mac {
                if host.vendor.is_none() {
                    host.vendor = oui::vendor_for_mac_with_file(mac, options.oui_file.as_deref());
                }
            }
        }
        if options.resolve_hostnames
            && host.hostname.is_none()
            && platform().id() != PlatformId::Unknown
        {
            if let Ok(ip) = host.ip.parse::<IpAddr>() {
                if let Ok(names) = crate::core::dns::reverse_lookup(&ip, Duration::from_millis(600))
                {
                    host.hostname = names
                        .into_iter()
                        .next()
                        .map(|name| util::sanitize_terminal(&name))
                        .filter(|name| !name.is_empty());
                }
            }
        }
    }

    if options.is_cancelled() {
        cancelled = true;
    }
    let found_count = hosts.len();
    let host_vec: Vec<DiscoveredHost> = hosts.into_values().collect();
    let note = if cancelled {
        Some(format!(
            "discovery cancelled: partial results for {found_count} host(s)"
        ))
    } else if truncated {
        Some(format!(
            "scan truncated to {} hosts; raise --max-hosts for a larger sweep",
            options.max_hosts
        ))
    } else {
        None
    };

    Ok(DiscoveryReport {
        subnets: subnets.iter().map(|(ip, p)| format!("{ip}/{p}")).collect(),
        method: methods_used.join("+"),
        scanned: host_list.len(),
        hosts: host_vec,
        duration_ms: started.elapsed().as_millis() as u64,
        note,
        cancelled,
    })
}

fn new_host(ip: IpAddr) -> DiscoveredHost {
    DiscoveredHost {
        ip: ip.to_string(),
        mac: None,
        vendor: None,
        hostname: None,
        response_ms: None,
        open_ports: Vec::new(),
        discovery_sources: Vec::new(),
    }
}

fn add_source(host: &mut DiscoveredHost, source: &str) {
    if !host.discovery_sources.iter().any(|s| s == source) {
        host.discovery_sources.push(source.to_string());
    }
}

fn collect_subnets(options: &DiscoveryOptions) -> Result<Vec<(IpAddr, u8)>> {
    if let Some(target) = &options.target {
        let (addr, prefix) = parse_cidr(target)?;
        if !addr.is_ipv4() {
            return Err(NetroError::new(
                ErrorCode::PlatformUnsupported,
                "IPv4 CIDR required for discovery (IPv6 sweeps are not supported)",
            ));
        }
        if !util::is_local_scope(&addr) {
            return Err(NetroError::new(
                ErrorCode::UnauthorizedScan,
                format!("{target} is not a private/local network"),
            )
            .with_hint("only scan networks you own or are authorized to test"));
        }
        return Ok(vec![(addr, prefix)]);
    }

    let interfaces = platform().interfaces()?;
    let mut subnets: Vec<(IpAddr, u8)> = Vec::new();
    for iface in interfaces {
        if !iface.up || iface.kind == InterfaceKind::Loopback {
            continue;
        }
        if let Some(only) = &options.interface {
            if &iface.name != only {
                continue;
            }
        }
        for network in &iface.ipv4 {
            if let Ok(addr) = network.addr.parse::<IpAddr>() {
                if addr.is_loopback() || addr.is_unspecified() || util::is_link_local_ip(&addr) {
                    continue;
                }
                let entry = (util::network_address(addr, network.prefix), network.prefix);
                if !subnets.contains(&entry) {
                    subnets.push(entry);
                }
            }
        }
    }
    if options.interface.is_some() && subnets.is_empty() {
        return Err(NetroError::new(
            ErrorCode::NotFound,
            format!(
                "interface {} has no IPv4 address or does not exist",
                options.interface.clone().unwrap_or_default()
            ),
        ));
    }
    Ok(subnets)
}

fn in_subnets(ip: &IpAddr, subnets: &[(IpAddr, u8)]) -> bool {
    subnets
        .iter()
        .any(|(network, prefix)| util::same_subnet(*ip, *network, *prefix))
}

fn icmp_sweep(
    hosts: &[IpAddr],
    options: &DiscoveryOptions,
    progress: &mut dyn FnMut(usize, usize, usize),
) -> Vec<(IpAddr, f64)> {
    let workers = options.concurrency.clamp(1, 256).min(hosts.len().max(1));
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<(IpAddr, f64)>();
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            let done = &done;
            scope.spawn(move || loop {
                if options.is_cancelled() {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                if index >= hosts.len() {
                    break;
                }
                let ip = hosts[index];
                let result = ping(
                    &ip.to_string(),
                    PingMethod::Icmp,
                    &PingOptions {
                        count: 1,
                        timeout: options.timeout.max(Duration::from_millis(500)),
                        tcp_port: 443,
                    },
                );
                done.fetch_add(1, Ordering::SeqCst);
                if result.received > 0 {
                    let rtt = result.avg_ms.unwrap_or(0.0);
                    let _ = tx.send((ip, rtt));
                }
            });
        }
        drop(tx);
        let mut found = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(80)) {
                Ok(item) => found.push(item),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    progress(done.load(Ordering::SeqCst), hosts.len(), found.len());
                    if options.is_cancelled() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        progress(done.load(Ordering::SeqCst), hosts.len(), found.len());
        found
    })
}

fn tcp_probe(
    hosts: &[IpAddr],
    ports: &[u16],
    options: &DiscoveryOptions,
    progress: &mut dyn FnMut(usize, usize, usize),
) -> Vec<(IpAddr, Vec<u16>, f64)> {
    let mut work: Vec<(IpAddr, u16)> = Vec::new();
    for ip in hosts {
        for port in ports {
            work.push((*ip, *port));
        }
    }
    let workers = options.concurrency.clamp(1, 256).min(work.len().max(1));
    let next = AtomicUsize::new(0);
    let done = AtomicUsize::new(0);
    let (tx, rx) = mpsc::channel::<(IpAddr, u16, Option<f64>)>();
    let work_ref = &work;
    std::thread::scope(|scope| {
        for _ in 0..workers {
            let tx = tx.clone();
            let next = &next;
            let done = &done;
            scope.spawn(move || loop {
                if options.is_cancelled() {
                    break;
                }
                let index = next.fetch_add(1, Ordering::SeqCst);
                if index >= work_ref.len() {
                    break;
                }
                let (ip, port) = work_ref[index];
                let started = Instant::now();
                let addr = SocketAddr::new(ip, port);
                let ok = TcpStream::connect_timeout(&addr, options.timeout).is_ok();
                done.fetch_add(1, Ordering::SeqCst);
                let rtt = ok.then(|| started.elapsed().as_secs_f64() * 1000.0);
                let _ = tx.send((ip, port, rtt));
            });
        }
        drop(tx);
        let mut found = Vec::new();
        loop {
            match rx.recv_timeout(Duration::from_millis(80)) {
                Ok(item) => found.push(item),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    let open_hosts = found
                        .iter()
                        .filter(|(_, _, rtt)| rtt.is_some())
                        .map(|(ip, _, _)| *ip)
                        .collect::<std::collections::BTreeSet<_>>()
                        .len();
                    progress(done.load(Ordering::SeqCst), work_ref.len(), open_hosts);
                    if options.is_cancelled() {
                        break;
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => break,
            }
        }
        found
    })
    .into_iter()
    .fold(
        BTreeMap::<IpAddr, (Vec<u16>, f64)>::new(),
        |mut acc, (ip, port, rtt)| {
            let entry = acc.entry(ip).or_insert((Vec::new(), f64::MAX));
            if let Some(rtt) = rtt {
                entry.0.push(port);
                if rtt < entry.1 {
                    entry.1 = rtt;
                }
            }
            acc
        },
    )
    .into_iter()
    .filter(|(_, (ports, _))| !ports.is_empty())
    .map(|(ip, (mut ports, rtt))| {
        ports.sort_unstable();
        (ip, ports, if rtt == f64::MAX { 0.0 } else { rtt })
    })
    .collect()
}

fn nmap_discovery(
    subnets: &[(IpAddr, u8)],
    options: &DiscoveryOptions,
) -> Result<Vec<DiscoveredHost>> {
    let nmap =
        util::which("nmap").ok_or_else(|| dependency_missing("nmap", "nmap-based discovery"))?;
    let mut hosts = Vec::new();
    for (addr, prefix) in subnets {
        let target = format!("{addr}/{prefix}");
        let out = util::run_command(
            &nmap.to_string_lossy(),
            &["-sn", "-oG", "-", &target],
            Duration::from_secs(120).max(options.timeout * (options.max_hosts as u32).min(600) / 8),
        )?;
        hosts.extend(parse_nmap_grepable(&out.stdout));
    }
    Ok(hosts)
}

/// Parse `nmap -oG -` (grepable) discovery output.
pub fn parse_nmap_grepable(text: &str) -> Vec<DiscoveredHost> {
    let mut hosts = Vec::new();
    let mut pending: BTreeMap<String, DiscoveredHost> = BTreeMap::new();
    let mut order: Vec<String> = Vec::new();
    for line in text.lines() {
        if !line.starts_with("Host:") {
            continue;
        }
        let cols: Vec<&str> = line.split('\t').collect();
        let mut ip = String::new();
        let mut hostname = None;
        let mut mac = None;
        let mut vendor = None;
        let mut status_up = false;
        for col in &cols {
            let col = col.trim();
            if let Some(rest) = col.strip_prefix("Host:") {
                let rest = rest.trim();
                if let Some((addr, name)) = rest.split_once('(') {
                    ip = addr.trim().to_string();
                    hostname = Some(util::sanitize_terminal(name.trim_end_matches(')').trim()))
                        .filter(|name| !name.is_empty());
                } else {
                    ip = rest.to_string();
                }
            } else if let Some(rest) = col.strip_prefix("Status:") {
                status_up = rest.trim().eq_ignore_ascii_case("Up");
            } else if let Some(rest) = col.strip_prefix("MAC Address:") {
                let rest = rest.trim();
                if let Some((mac_part, vendor_part)) = rest.split_once('(') {
                    mac = Some(mac_part.trim().to_ascii_lowercase());
                    vendor = Some(util::sanitize_terminal(
                        vendor_part.trim_end_matches(')').trim(),
                    ));
                } else {
                    mac = Some(rest.to_ascii_lowercase());
                }
            }
        }
        let known = pending.contains_key(&ip);
        if ip.is_empty() || (!status_up && !known) {
            continue;
        }
        if !known {
            order.push(ip.clone());
            pending.insert(
                ip.clone(),
                DiscoveredHost {
                    ip: ip.clone(),
                    mac: None,
                    vendor: None,
                    hostname: None,
                    response_ms: Some(0.0),
                    open_ports: Vec::new(),
                    discovery_sources: vec!["nmap".into()],
                },
            );
        }
        if let Some(entry) = pending.get_mut(&ip) {
            if mac.is_some() {
                entry.mac = mac;
            }
            if vendor.is_some() {
                entry.vendor = vendor;
            }
            if let Some(name) = hostname.filter(|h| !h.is_empty()) {
                entry.hostname = Some(name);
            }
        }
    }
    for ip in order {
        if let Some(host) = pending.remove(&ip) {
            hosts.push(host);
        }
    }
    hosts
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nmap_grepable_parsing() {
        let fixture = "Host: 192.168.1.1 (router.lan)\tStatus: Up\n\
Host: 192.168.1.1 (router.lan)\tPorts: 80/open/tcp//http///\tIgnored State: closed (999)\tMAC Address: AA:BB:CC:DD:EE:FF (Netgear)\n\
Host: 192.168.1.9\tStatus: Down\n\
Host: 192.168.1.20 ()\tStatus: Up\n\
Host: 192.168.1.20 ()\tMAC Address: 00:0C:29:11:22:33 (VMware)\n";
        let hosts = parse_nmap_grepable(fixture);
        assert_eq!(hosts.len(), 2);
        assert_eq!(hosts[0].ip, "192.168.1.1");
        assert_eq!(hosts[0].hostname.as_deref(), Some("router.lan"));
        assert_eq!(hosts[0].mac.as_deref(), Some("aa:bb:cc:dd:ee:ff"));
        assert_eq!(hosts[0].vendor.as_deref(), Some("Netgear"));
        assert_eq!(hosts[1].ip, "192.168.1.20");
        assert_eq!(hosts[1].hostname, None);
    }

    #[test]
    fn subnet_membership() {
        let subnets = vec![("192.168.1.0".parse().unwrap(), 24)];
        assert!(in_subnets(&"192.168.1.50".parse().unwrap(), &subnets));
        assert!(!in_subnets(&"10.0.0.1".parse().unwrap(), &subnets));
    }

    #[test]
    fn discovery_rejects_public_explicit_target() {
        let options = DiscoveryOptions {
            target: Some("8.8.8.0/24".into()),
            ..DiscoveryOptions::default()
        };
        let err = discover(&options).unwrap_err();
        assert_eq!(err.code(), ErrorCode::UnauthorizedScan);
    }

    #[test]
    fn discovery_on_localhost_finds_at_least_subnet() {
        // Localhost has no non-loopback IPv4; discovery should report an error
        // rather than fabricate hosts, unless an explicit loopback target is
        // given (which is local scope and allowed).
        let options = DiscoveryOptions {
            target: Some("127.0.0.0/30".into()),
            method: DiscoveryMethod::Tcp,
            max_hosts: 4,
            tcp_ports: vec![1],
            timeout: Duration::from_millis(100),
            concurrency: 4,
            resolve_hostnames: false,
            ..DiscoveryOptions::default()
        };
        let report = discover(&options).unwrap();
        assert_eq!(report.subnets, vec!["127.0.0.0/30"]);
        assert!(report.scanned <= 4);
        // Port 1 on loopback is not a real service; no host should be invented.
        assert!(report.hosts.iter().all(|h| !h.discovery_sources.is_empty()));
    }
}
