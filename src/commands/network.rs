//! `netro network ...`

use crate::cli::{
    ConnectivityArgs, DiscoverArgs, DnsArgs, LatencyArgs, NetworkArgs, NetworkCommand, ScanArgs,
    SpeedTestArgs, TraceArgs,
};
use crate::commands::{boolean, emit_table, envelope, format_opt, opt, Context};
use crate::core::{diagnostics, discovery, dns, scan, speedtest};
use crate::error::{ErrorCode, NetroError, Result};
use crate::model::*;
use crate::output::OutputFormat;
use crate::platform::platform;
use crate::util;
use std::time::Duration;

pub fn run(args: NetworkArgs, ctx: &Context) -> Result<()> {
    match args.command {
        NetworkCommand::Interfaces => interfaces(ctx),
        NetworkCommand::Routes => routes(ctx),
        NetworkCommand::Dns(args) => dns_cmd(args, ctx),
        NetworkCommand::Discover(args) => discover(args, ctx),
        NetworkCommand::Scan(args) => scan_cmd(args, ctx),
        NetworkCommand::Latency(args) => latency(args, ctx),
        NetworkCommand::Connectivity(args) => connectivity(args, ctx),
        NetworkCommand::Trace(args) => trace(args, ctx),
        NetworkCommand::Speedtest(args) => speedtest_cmd(args, ctx),
    }
}

fn speedtest_cmd(args: SpeedTestArgs, ctx: &Context) -> Result<()> {
    let direction = match args.direction.to_ascii_lowercase().as_str() {
        "download" | "down" => speedtest::Direction::Download,
        "upload" | "up" => speedtest::Direction::Upload,
        "both" => speedtest::Direction::Both,
        other => {
            return Err(NetroError::new(
                ErrorCode::InvalidTarget,
                format!("unknown direction '{other}' (expected download, upload or both)"),
            ))
        }
    };
    let options = speedtest::resolve_options(
        args.provider.as_deref(),
        args.server.as_deref(),
        args.port,
        args.duration,
        direction,
        args.udp,
        &ctx.config,
    )?;
    let provider = speedtest::provider_for(&options.provider)?;
    ctx.note(&format!(
        "note: measuring {} against {} using {}",
        match direction {
            speedtest::Direction::Download => "download",
            speedtest::Direction::Upload => "upload",
            speedtest::Direction::Both => "download and upload",
        },
        options.server.clone().unwrap_or_default(),
        provider.name()
    ));
    let result = provider.run(&options)?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.speedtest", &result));
    }
    println!("provider: {}", result.provider);
    println!("server:   {}", result.server);
    println!("direction:{}", result.direction);
    if let Some(latency) = &result.latency {
        println!(
            "latency:  connect {}  first byte {}",
            format_opt(latency.connect_ms, " ms"),
            format_opt(latency.first_byte_ms, " ms")
        );
    }
    if let Some(down) = result.download_mbps {
        println!(
            "download: {down:.2} Mbit/s ({} transferred)",
            result
                .bytes_downloaded
                .map(util::human_bytes)
                .unwrap_or_else(|| "-".into())
        );
    }
    if let Some(up) = result.upload_mbps {
        println!(
            "upload:   {up:.2} Mbit/s ({} transferred)",
            result
                .bytes_uploaded
                .map(util::human_bytes)
                .unwrap_or_else(|| "-".into())
        );
    }
    if let Some(jitter) = result.jitter_ms {
        println!("jitter:   {jitter:.2} ms");
    }
    if let Some(loss) = result.packet_loss_percent {
        println!("loss:     {loss:.2}%");
    }
    println!("note: {}", result.note);
    Ok(())
}

fn interfaces(ctx: &Context) -> Result<()> {
    let interfaces = platform().interfaces()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.interfaces", &interfaces));
    }
    let rows: Vec<Vec<String>> = interfaces
        .iter()
        .map(|iface| {
            let addrs: Vec<String> = iface
                .ipv4
                .iter()
                .map(|a| format!("{}/{}", a.addr, a.prefix))
                .chain(
                    iface
                        .ipv6
                        .iter()
                        .map(|a| format!("{}/{}", a.addr, a.prefix)),
                )
                .collect();
            vec![
                iface.name.clone(),
                format!("{:?}", iface.kind).to_lowercase(),
                if iface.up { "up" } else { "down" }.to_string(),
                iface.mac.clone().unwrap_or_else(|| "-".into()),
                addrs.join(" "),
                iface
                    .speed_mbps
                    .map(|s| format!("{s} Mbps"))
                    .unwrap_or_else(|| "-".into()),
                iface
                    .mtu
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".into()),
                iface.dhcp.map(boolean).unwrap_or("unknown").to_string(),
                iface.default_route.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Interface",
            "Kind",
            "State",
            "MAC",
            "Addresses",
            "Speed",
            "MTU",
            "DHCP",
            "Gateway",
        ],
        &rows,
        None,
    )
}

fn routes(ctx: &Context) -> Result<()> {
    let routes = platform().routes()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.routes", &routes));
    }
    let rows: Vec<Vec<String>> = routes
        .iter()
        .map(|route| {
            vec![
                route.family.clone(),
                format!("{}/{}", route.destination, route.prefix),
                route.gateway.clone().unwrap_or_else(|| "-".into()),
                route.interface.clone().unwrap_or_else(|| "-".into()),
                route
                    .metric
                    .map(|m| m.to_string())
                    .unwrap_or_else(|| "-".into()),
                route.flags.join(","),
                if route.is_default { "yes" } else { "" }.to_string(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Family",
            "Destination",
            "Gateway",
            "Interface",
            "Metric",
            "Flags",
            "Default",
        ],
        &rows,
        None,
    )
}

fn dns_cmd(args: DnsArgs, ctx: &Context) -> Result<()> {
    let timeout = Duration::from_secs(5);

    if args.reverse {
        let name = args.name.ok_or_else(|| {
            NetroError::new(ErrorCode::InvalidTarget, "--reverse requires an IP address")
        })?;
        let ip: std::net::IpAddr = name.parse().map_err(|_| {
            NetroError::new(
                ErrorCode::InvalidTarget,
                format!("'{name}' is not an IP address"),
            )
        })?;
        let queries = if let Some(server) = &args.server {
            let reverse = dns::reverse_name(&ip);
            vec![dns::query(server, &reverse, dns::RecordType::Ptr, timeout)?]
        } else {
            let reverse = dns::reverse_name(&ip);
            let response = dns::resolve_via_system(&reverse, dns::RecordType::Ptr, timeout)?;
            vec![response]
        };
        return print_dns_results(&queries, ctx);
    }

    match args.name {
        None => {
            let config = platform().dns_config()?;
            if ctx.output.is_json() {
                return crate::output::emit_json(&envelope("network.dns.config", &config));
            }
            println!("DNS configuration");
            println!("  source:        {}", config.source);
            println!("  servers:       {}", config.servers.join(", "));
            if !config.search_domains.is_empty() {
                println!("  search:        {}", config.search_domains.join(" "));
            }
            if config.systemd_resolved_stub {
                println!("  note:          resolver is the systemd-resolved stub");
            }
            if let Some(note) = &config.note {
                println!("  note:          {note}");
            }
            Ok(())
        }
        Some(name) => {
            let rtype = dns::RecordType::from_name(&args.r#type).ok_or_else(|| {
                NetroError::new(
                    ErrorCode::InvalidTarget,
                    format!(
                        "unknown record type '{}' (expected A, AAAA, CNAME, MX, TXT, NS, SOA, PTR or SRV)",
                        args.r#type
                    ),
                )
            })?;
            let response = if let Some(server) = &args.server {
                dns::query(server, &name, rtype, timeout)?
            } else {
                dns::resolve_via_system(&name, rtype, timeout)?
            };
            print_dns_results(&[response], ctx)
        }
    }
}

fn print_dns_results(responses: &[dns::DnsResponse], ctx: &Context) -> Result<()> {
    if ctx.output.is_json() {
        let payload: Vec<serde_json::Value> = responses
            .iter()
            .map(|r| {
                serde_json::json!({
                    "name": r.query_name,
                    "type": r.record_type,
                    "server": r.server,
                    "rcode": r.rcode,
                    "rcode_name": r.rcode_name,
                    "rtt_ms": r.rtt_ms,
                    "truncated": r.truncated,
                    "answers": r.answers.iter().map(|a| serde_json::json!({
                        "name": a.name,
                        "type": a.record_type,
                        "ttl": a.ttl,
                        "value": a.value,
                    })).collect::<Vec<_>>(),
                })
            })
            .collect();
        return crate::output::emit_json(&envelope("network.dns.query", payload));
    }
    for response in responses {
        println!(
            "{}/{} via {} -> {} in {:.0} ms",
            response.query_name,
            response.record_type,
            response.server,
            response.rcode_name,
            response.rtt_ms
        );
        if response.answers.is_empty() {
            println!("  (no answers)");
        }
        for answer in &response.answers {
            // Values come from a (possibly hostile) DNS server.
            println!(
                "  {:<28} {:<6} TTL {:>5}  {}",
                util::sanitize_terminal(&answer.name),
                answer.record_type,
                answer.ttl,
                util::sanitize_terminal(&answer.value)
            );
        }
    }
    Ok(())
}

fn discover(args: DiscoverArgs, ctx: &Context) -> Result<()> {
    let method = discovery::DiscoveryMethod::parse(&args.method).ok_or_else(|| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!(
                "unknown discovery method '{}' (expected auto, neighbors, icmp, tcp or nmap)",
                args.method
            ),
        )
    })?;
    let options = discovery::DiscoveryOptions {
        interface: args.interface,
        target: args.target,
        method,
        max_hosts: args.max_hosts.max(1),
        tcp_ports: args.ports,
        resolve_hostnames: !args.no_dns && ctx.config.privacy.reverse_dns,
        vendor_lookup: !args.no_vendor && ctx.config.privacy.vendor_lookup,
        oui_file: ctx
            .config
            .integrations
            .oui_file
            .as_ref()
            .map(std::path::PathBuf::from),
        concurrency: args.concurrency.max(1),
        timeout: Duration::from_millis(args.timeout_ms.max(50)),
        cancel: None,
    };
    ctx.note("note: only discover networks you own or are authorized to test.");
    let report = discovery::discover(&options)?;

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.discover", &report));
    }
    println!(
        "subnets: {}  method: {}  scanned: {}  hosts found: {}  duration: {}",
        report.subnets.join(", "),
        report.method,
        report.scanned,
        report.hosts.len(),
        util::human_duration(Duration::from_millis(report.duration_ms))
    );
    if let Some(note) = &report.note {
        println!("note: {note}");
    }
    let rows: Vec<Vec<String>> = report
        .hosts
        .iter()
        .map(|host| {
            vec![
                host.ip.clone(),
                host.hostname.clone().unwrap_or_else(|| "-".into()),
                host.mac.clone().unwrap_or_else(|| "-".into()),
                host.vendor.clone().unwrap_or_else(|| "unknown".into()),
                format_opt(host.response_ms, " ms"),
                if host.open_ports.is_empty() {
                    "-".into()
                } else {
                    host.open_ports
                        .iter()
                        .map(|p| p.to_string())
                        .collect::<Vec<_>>()
                        .join(",")
                },
                host.discovery_sources.join("+"),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "IP",
            "Hostname",
            "MAC",
            "Vendor",
            "RTT",
            "Open ports",
            "Sources",
        ],
        &rows,
        None,
    )
}

fn scan_cmd(args: ScanArgs, ctx: &Context) -> Result<()> {
    let port_spec = args
        .ports
        .clone()
        .unwrap_or_else(|| ctx.config.scan.ports.clone());
    let ports = scan::parse_ports(&port_spec)?;
    let options = scan::ScanOptions {
        timeout: Duration::from_millis(
            args.timeout_ms
                .unwrap_or(ctx.config.scan.timeout_ms)
                .max(50),
        ),
        concurrency: args
            .concurrency
            .unwrap_or(ctx.config.scan.concurrency)
            .clamp(1, 1024),
        banner: !args.no_banner && ctx.config.scan.banner_grab,
        tls: !args.no_tls && ctx.config.scan.tls_probe,
        udp: args.udp,
        authorized: args.authorized,
        cancel: None,
    };

    if ctx.output.format == OutputFormat::Text {
        crate::output::authorization_notice(ctx.quiet);
        if !ctx.quiet {
            eprintln!(
                "scanning {} port(s) on {} (timeout {} ms, concurrency {})",
                ports.len(),
                args.target,
                options.timeout.as_millis(),
                options.concurrency
            );
        }
    }

    let mut report = scan::scan(&args.target, &ports, &options)?;
    if args.open_only {
        report
            .ports
            .retain(|p| matches!(p.state, PortState::Open | PortState::OpenOrFiltered));
    }

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.scan", &report));
    }

    let closed_count = report
        .ports
        .iter()
        .filter(|p| p.state == PortState::Closed)
        .count();
    let filtered_count = report
        .ports
        .iter()
        .filter(|p| p.state == PortState::Filtered)
        .count();
    println!(
        "target: {} ({})  scan: {}  duration: {}",
        report.target,
        report.resolved.join(", "),
        report.scan_type,
        util::human_duration(Duration::from_millis(report.duration_ms))
    );
    // In text mode, hide closed ports by default and summarize them; CSV/JSON
    // always carry the full result set.
    let visible: Vec<&ScannedPort> = if ctx.output.format == OutputFormat::Text {
        report
            .ports
            .iter()
            .filter(|p| p.state != PortState::Closed)
            .collect()
    } else {
        report.ports.iter().collect()
    };
    if visible.is_empty() {
        println!("no open ports found ({closed_count} closed, {filtered_count} filtered)");
        return Ok(());
    }
    let rows: Vec<Vec<String>> = visible
        .iter()
        .map(|port| {
            let service = match (&port.service, &port.product, &port.version) {
                (Some(service), Some(product), Some(version)) => {
                    format!("{service} ({product} {version})")
                }
                (Some(service), Some(product), None) => format!("{service} ({product})"),
                (Some(service), None, _) => service.clone(),
                _ => "-".into(),
            };
            let tls = port
                .tls
                .as_ref()
                .map(|t| {
                    if t.handshake_ok {
                        let mut s = t.protocol_version.clone().unwrap_or_else(|| "TLS".into());
                        if let Some(subject) = &t.subject {
                            s.push_str(&format!(" subject={subject}"));
                        }
                        if let Some(days) = t.days_remaining {
                            s.push_str(&format!(" expires_in={days}d"));
                        }
                        s
                    } else {
                        format!("failed: {}", t.error.clone().unwrap_or_default())
                    }
                })
                .unwrap_or_else(|| "-".into());
            vec![
                port.port.to_string(),
                port.protocol.clone(),
                port.state.as_str().to_string(),
                service,
                port.banner.clone().unwrap_or_else(|| "-".into()),
                tls,
                format!("{:?}", port.confidence).to_lowercase(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Port",
            "Proto",
            "State",
            "Service",
            "Banner",
            "TLS",
            "Confidence",
        ],
        &rows,
        None,
    )?;
    if ctx.output.format == OutputFormat::Text {
        println!(
            "{} open/open|filtered shown; {closed_count} closed, {filtered_count} filtered hidden (use --json for the full result)",
            visible.len()
        );
    }
    Ok(())
}

fn latency(args: LatencyArgs, ctx: &Context) -> Result<()> {
    let method = diagnostics::PingMethod::parse(&args.method).ok_or_else(|| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!(
                "unknown method '{}' (expected auto, icmp or tcp)",
                args.method
            ),
        )
    })?;
    let result = diagnostics::ping(
        &args.target,
        method,
        &diagnostics::PingOptions {
            count: args.count,
            timeout: Duration::from_millis(args.timeout_ms.max(50)),
            tcp_port: args.port,
        },
    );
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.latency", &result));
    }
    println!(
        "{} ({}) via {:?}",
        result.target,
        if result.resolved.is_empty() {
            "unresolved".into()
        } else {
            result.resolved.join(", ")
        },
        result.method
    );
    if let Some(error) = &result.error {
        println!("error: {error}");
    }
    println!(
        "{}/{} packets received, {:.0}% loss",
        result.received, result.transmitted, result.loss_percent
    );
    if !result.rtts.is_empty() {
        println!(
            "rtt min/avg/max/jitter = {}/{}/{}/{} ms",
            format_opt(result.min_ms, ""),
            format_opt(result.avg_ms, ""),
            format_opt(result.max_ms, ""),
            format_opt(result.jitter_ms, ""),
        );
    }
    Ok(())
}

fn connectivity(args: ConnectivityArgs, ctx: &Context) -> Result<()> {
    let report = diagnostics::connectivity(&diagnostics::ConnectivityOptions {
        timeout: Duration::from_millis(args.timeout_ms.max(200)),
        ipv6: !args.no_ipv6,
        ..diagnostics::ConnectivityOptions::default()
    });
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.connectivity", &report));
    }
    let rows: Vec<Vec<String>> = report
        .checks
        .iter()
        .map(|check| {
            vec![
                check.name.clone(),
                check.target.clone(),
                if check.ok { "ok" } else { "failed" }.to_string(),
                format_opt(check.latency_ms, " ms"),
                check
                    .error
                    .clone()
                    .or_else(|| check.note.clone())
                    .unwrap_or_default(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &["Check", "Target", "Result", "Latency", "Detail"],
        &rows,
        None,
    )?;
    if !ctx.output.is_json() {
        println!(
            "internet: {} | ipv4: {} | ipv6: {} | dns: {} | gateway: {}",
            boolean(report.internet_reachable),
            boolean(report.ipv4_available),
            boolean(report.ipv6_available),
            boolean(report.dns_working),
            report.gateway_reachable.map(boolean).unwrap_or("unknown")
        );
    }
    Ok(())
}

fn trace(args: TraceArgs, ctx: &Context) -> Result<()> {
    let method = diagnostics::TraceMethod::parse(&args.method).ok_or_else(|| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!(
                "unknown method '{}' (expected auto, icmp or tcp)",
                args.method
            ),
        )
    })?;
    let result = diagnostics::traceroute(
        &args.target,
        method,
        &diagnostics::TraceOptions {
            max_hops: args.max_hops.clamp(1, 64),
            timeout: Duration::from_millis(args.timeout_ms.max(200)),
            tcp_port: args.port,
        },
    )?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("network.trace", &result));
    }
    println!(
        "traceroute to {} ({}) reached={}",
        result.target,
        match result.method {
            ProbeMethod::Icmp => "icmp".to_string(),
            ProbeMethod::SystemUtility => "system traceroute".to_string(),
            ProbeMethod::TcpConnect => "built-in tcp".to_string(),
            ProbeMethod::Dns => "dns".to_string(),
        },
        boolean(result.reached)
    );
    if let Some(note) = &result.note {
        println!("note: {note}");
    }
    for hop in &result.hops {
        let address = hop.address.clone().unwrap_or_else(|| "*".into());
        let hostname = opt(&hop.hostname);
        let rtts = if hop.rtt_ms.is_empty() {
            "*".to_string()
        } else {
            hop.rtt_ms
                .iter()
                .map(|r| format!("{r:.1} ms"))
                .collect::<Vec<_>>()
                .join("  ")
        };
        println!(
            "{:>2}  {:<40} {:<20} {}",
            hop.hop,
            address,
            if hostname == "-" {
                String::new()
            } else {
                hostname
            },
            rtts
        );
    }
    Ok(())
}
