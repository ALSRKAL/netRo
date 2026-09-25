//! Shared fixtures for TUI tests.
//!
//! All fixture data is deterministic so rendering snapshots are stable. These
//! are *rendering* fixtures only; they never replace real runtime checks.

#![allow(dead_code)]

use netro::config::Config;
use netro::core::security::SecurityAudit;
use netro::core::snapshot::{Snapshot, SnapshotDiff};
use netro::model::*;
use netro::tui::app::{App, TuiOptions};
use netro::tui::caps::{Caps, ColorMode};
use netro::tui::state::Fresh;
use netro::tui::theme::ThemeKind;
use ratatui::backend::TestBackend;
use ratatui::buffer::Buffer;
use ratatui::Terminal;

pub fn test_caps(width: u16, height: u16) -> Caps {
    Caps {
        width,
        height,
        colors: ColorMode::Ansi16,
        unicode: false,
        mouse: false,
        interactive: true,
    }
}

pub fn fixture_app(width: u16, height: u16) -> App {
    let caps = test_caps(width, height);
    let mut app = App::new(
        caps,
        Config::default(),
        TuiOptions {
            mouse: false,
            theme: Some(ThemeKind::Dark),
        },
    );
    populate(&mut app);
    app.state.tick = 3;
    app
}

pub fn empty_app(width: u16, height: u16) -> App {
    let caps = test_caps(width, height);
    App::new(
        caps,
        Config::default(),
        TuiOptions {
            mouse: false,
            theme: Some(ThemeKind::Dark),
        },
    )
}

fn os_info() -> OsInfo {
    OsInfo {
        name: Some("Ubuntu".into()),
        long_name: Some("Ubuntu 24.04".into()),
        version: Some("24.04".into()),
        kernel: Some("6.8.0-88-generic".into()),
        arch: "x86_64".into(),
        hostname: Some("zbook".into()),
        distro_id: Some("ubuntu".into()),
        uptime_secs: 4 * 86_400 + 8 * 3_600,
        boot_time_epoch: Some(1_700_000_000),
        virtualization: None,
        platform: PlatformId::Linux,
        note: None,
    }
}

fn system_snapshot() -> SystemSnapshot {
    SystemSnapshot {
        generated_at_epoch: 1_700_000_000,
        platform: PlatformId::Linux,
        os: os_info(),
        cpu: CpuInfo {
            model: Some("Intel(R) Core(TM) i7-6820HQ CPU @ 2.70GHz".into()),
            vendor: Some("GenuineIntel".into()),
            arch: "x86_64".into(),
            logical_cores: 8,
            physical_cores: Some(4),
            usage_percent: Some(42.0),
            per_core_usage: vec![40.0, 44.0, 41.0, 43.0, 45.0, 39.0, 42.0, 44.0],
            frequency_mhz: Some(2700),
            load_average: Some([1.2, 1.1, 0.9]),
            temperatures_c: vec![Temperature {
                label: "Package id 0".into(),
                current_c: 51.0,
                max_c: Some(100.0),
                critical_c: Some(100.0),
            }],
            note: None,
        },
        memory: MemoryInfo {
            total_bytes: 16 * 1024 * 1024 * 1024,
            used_bytes: 8 * 1024 * 1024 * 1024,
            available_bytes: 7 * 1024 * 1024 * 1024,
            free_bytes: 6 * 1024 * 1024 * 1024,
            utilization_percent: 51.0,
            swap_total_bytes: 2 * 1024 * 1024 * 1024,
            swap_used_bytes: 200 * 1024 * 1024,
            swap_free_bytes: 1_800 * 1024 * 1024,
            swap_utilization_percent: 10.0,
        },
        disks: vec![
            DiskInfo {
                device: "/dev/nvme0n1p2".into(),
                mount_point: "/".into(),
                file_system: "ext4".into(),
                total_bytes: 500 * 1024 * 1024 * 1024,
                used_bytes: 410 * 1024 * 1024 * 1024,
                free_bytes: 90 * 1024 * 1024 * 1024,
                utilization_percent: 82.0,
                read_only: false,
                removable: false,
                kind: Some("SSD".into()),
                note: None,
            },
            DiskInfo {
                device: "/dev/nvme0n1p3".into(),
                mount_point: "/home".into(),
                file_system: "ext4".into(),
                total_bytes: 400 * 1024 * 1024 * 1024,
                used_bytes: 190 * 1024 * 1024 * 1024,
                free_bytes: 210 * 1024 * 1024 * 1024,
                utilization_percent: 48.0,
                read_only: false,
                removable: false,
                kind: Some("SSD".into()),
                note: None,
            },
        ],
        gpus: vec![GpuInfo {
            vendor: Some("NVIDIA".into()),
            model: Some("Quadro M1000M".into()),
            vram_bytes: Some(2 * 1024 * 1024 * 1024),
            driver: Some("550.90".into()),
            utilization_percent: Some(14.0),
            temperature_c: Some(51.0),
            power_watts: Some(12.0),
            compute_backend: Some("CUDA".into()),
            source: "nvidia-smi".into(),
            note: None,
        }],
        warnings: Vec::new(),
    }
}

fn interfaces() -> Vec<Interface> {
    vec![
        Interface {
            name: "wlp3s0".into(),
            kind: InterfaceKind::Wifi,
            mac: Some("34:f3:9a:c2:6e:4c".into()),
            ipv4: vec![IpWithPrefix {
                addr: "192.168.1.20".into(),
                prefix: 24,
            }],
            ipv6: vec![IpWithPrefix {
                addr: "fe80::7100:1025:750e:52d9".into(),
                prefix: 64,
            }],
            up: true,
            oper_state: Some("up".into()),
            speed_mbps: None,
            mtu: Some(1500),
            dhcp: Some(true),
            dhcp_source: Some("NetworkManager (nmcli)".into()),
            default_route: Some("192.168.1.1".into()),
            note: None,
        },
        Interface {
            name: "docker0".into(),
            kind: InterfaceKind::Docker,
            mac: Some("02:42:aa:bb:cc:dd".into()),
            ipv4: vec![IpWithPrefix {
                addr: "172.17.0.1".into(),
                prefix: 16,
            }],
            ipv6: Vec::new(),
            up: true,
            oper_state: Some("up".into()),
            speed_mbps: Some(10000),
            mtu: Some(1500),
            dhcp: Some(false),
            dhcp_source: None,
            default_route: None,
            note: None,
        },
    ]
}

fn routes() -> Vec<Route> {
    vec![
        Route {
            family: "ipv4".into(),
            destination: "0.0.0.0".into(),
            prefix: 0,
            gateway: Some("192.168.1.1".into()),
            interface: Some("wlp3s0".into()),
            metric: Some(600),
            flags: vec!["UP".into(), "GATEWAY".into()],
            is_default: true,
        },
        Route {
            family: "ipv4".into(),
            destination: "192.168.1.0".into(),
            prefix: 24,
            gateway: None,
            interface: Some("wlp3s0".into()),
            metric: Some(600),
            flags: vec!["UP".into()],
            is_default: false,
        },
    ]
}

fn dns_config() -> DnsConfig {
    DnsConfig {
        servers: vec!["1.1.1.1".into(), "192.168.1.1".into()],
        search_domains: vec!["lan".into()],
        source: "/etc/resolv.conf".into(),
        systemd_resolved_stub: false,
        note: None,
    }
}

fn connectivity() -> ConnectivityReport {
    ConnectivityReport {
        checks: vec![
            ConnectivityCheck {
                name: "loopback".into(),
                target: "127.0.0.1".into(),
                method: ProbeMethod::TcpConnect,
                ok: true,
                latency_ms: None,
                error: None,
                note: None,
            },
            ConnectivityCheck {
                name: "gateway".into(),
                target: "192.168.1.1".into(),
                method: ProbeMethod::Icmp,
                ok: true,
                latency_ms: Some(2.0),
                error: None,
                note: None,
            },
            ConnectivityCheck {
                name: "dns".into(),
                target: "example.com via 1.1.1.1:53".into(),
                method: ProbeMethod::Dns,
                ok: true,
                latency_ms: Some(18.0),
                error: None,
                note: None,
            },
            ConnectivityCheck {
                name: "internet_ipv4".into(),
                target: "1.1.1.1:443".into(),
                method: ProbeMethod::TcpConnect,
                ok: true,
                latency_ms: Some(21.0),
                error: None,
                note: None,
            },
            ConnectivityCheck {
                name: "internet_ipv6".into(),
                target: "n/a".into(),
                method: ProbeMethod::TcpConnect,
                ok: false,
                latency_ms: None,
                error: None,
                note: Some("no non-loopback IPv6 address configured".into()),
            },
        ],
        ipv4_available: true,
        ipv6_available: false,
        internet_reachable: true,
        dns_working: true,
        gateway_reachable: Some(true),
    }
}

fn audit() -> SecurityAudit {
    let findings = vec![
        Finding::new(
            "exposure.ssh",
            Severity::Info,
            "exposure",
            "SSH is listening on all interfaces",
        )
        .with_evidence("tcp 0.0.0.0:22 LISTEN (process: sshd)")
        .with_impact("Remote access is available from reachable networks.")
        .with_recommendation("Restrict SSH exposure if not required."),
        Finding::new(
            "firewall.disabled",
            Severity::High,
            "firewall",
            "Host firewall appears disabled",
        )
        .with_evidence("ufw reported inactive (ufw status verbose)")
        .with_impact("Inbound traffic is not filtered by the host.")
        .with_recommendation("Enable the platform firewall."),
    ];
    let score = netro::core::security::score_findings(&findings);
    SecurityAudit {
        generated_at_epoch: 1_700_000_000,
        platform: PlatformId::Linux,
        hostname: Some("zbook".into()),
        elevated: false,
        findings,
        score,
        listening: listening(),
        exposed_ports: 2,
        accounts: accounts(),
        accounts_total: 2,
        privileged_accounts: vec!["root".into()],
        locked_accounts: 1,
        password_policy: None,
        firewall: FirewallStatus {
            enabled: Some(false),
            backends: vec![FirewallBackend {
                name: "ufw".into(),
                active: Some(false),
                detail: Some("Status: inactive".into()),
                via: "ufw status verbose".into(),
            }],
            notes: vec!["rule inspection may be incomplete without root privileges".into()],
            error: None,
        },
        services: Vec::new(),
        external_tools: vec![netro::core::security::ExternalToolResult {
            tool: "rkhunter".into(),
            installed: false,
            ran: false,
            summary: None,
            error: None,
            source: EvidenceSource::ExternalTool,
            note: Some("not installed".into()),
        }],
        limitations: vec!["password policy could not be read on this platform".into()],
    }
}

fn accounts() -> Vec<Account> {
    vec![
        Account {
            name: "root".into(),
            uid: Some(0),
            gid: Some(0),
            home: Some("/root".into()),
            shell: Some("/bin/bash".into()),
            privileged: true,
            is_system: false,
            login_shell: true,
            password: PasswordStatus::Set,
            groups: vec!["root".into()],
            note: None,
        },
        Account {
            name: "daemon".into(),
            uid: Some(1),
            gid: Some(1),
            home: Some("/usr/sbin".into()),
            shell: Some("/usr/sbin/nologin".into()),
            privileged: false,
            is_system: true,
            login_shell: false,
            password: PasswordStatus::Locked,
            groups: Vec::new(),
            note: None,
        },
    ]
}

fn listening() -> Vec<ListeningPort> {
    vec![
        ListeningPort {
            protocol: "tcp".into(),
            address: "0.0.0.0".into(),
            port: 22,
            scope: ExposureScope::All,
            state: "LISTEN".into(),
            pid: Some(842),
            process: Some("sshd".into()),
        },
        ListeningPort {
            protocol: "tcp".into(),
            address: "127.0.0.1".into(),
            port: 631,
            scope: ExposureScope::Local,
            state: "LISTEN".into(),
            pid: Some(1200),
            process: Some("cupsd".into()),
        },
    ]
}

fn doctor_report() -> DoctorReport {
    let audit = audit();
    let checks = vec![
        CheckResult::new("system", "System", CheckStatus::Pass)
            .with_summary("Ubuntu 24.04 (x86_64)")
            .with_evidence("kernel: 6.8.0-88-generic"),
        CheckResult::new("cpu", "CPU", CheckStatus::Pass).with_summary("42.0% used"),
        CheckResult::new("memory", "Memory", CheckStatus::Pass).with_summary("51.0% used"),
        CheckResult::new("storage", "Storage", CheckStatus::Warning)
            .with_summary("/ is 82.0% full")
            .with_findings(vec![Finding::new(
                "health.storage.low-space",
                Severity::Medium,
                "configuration",
                "Low disk space on a mounted filesystem",
            )
            .with_evidence("/ is 82.0% full (90.0 GB free of 500.0 GB)")]),
        CheckResult::new("gpu", "GPU", CheckStatus::Pass).with_summary("1 GPU(s) detected"),
        CheckResult::new("network", "Network", CheckStatus::Pass).with_summary("2 interface(s) up"),
        CheckResult::new("routes", "Routes", CheckStatus::Pass).with_summary("2 route(s)"),
        CheckResult::new("dns", "DNS", CheckStatus::Pass).with_summary("resolution via 1.1.1.1"),
        CheckResult::new("internet", "Internet", CheckStatus::Pass)
            .with_summary("internet reachable"),
        CheckResult::new("firewall", "Firewall", CheckStatus::Warning)
            .with_summary("host firewall appears disabled"),
        CheckResult::new("processes", "Processes", CheckStatus::Pass).with_summary("210 processes"),
        CheckResult::new("security", "Security", CheckStatus::Fail)
            .with_summary("score 88/100 (grade B), 2 finding(s)")
            .with_findings(audit.findings.clone()),
    ];
    let findings = audit.findings.clone();
    DoctorReport {
        generated_at_epoch: 1_700_000_000,
        platform: PlatformId::Linux,
        hostname: Some("zbook".into()),
        checks,
        findings,
        summary: DoctorSummary {
            passed: 9,
            warnings: 2,
            failed: 1,
            unsupported: 0,
            skipped: 0,
            recommendations: vec![
                "Enable the platform firewall and allow only required ports.".into(),
                "Free space or extend the filesystem.".into(),
            ],
            score: Some(audit.score.clone()),
        },
        dependencies: Vec::new(),
        note: Some("CPU/memory values are point-in-time samples".into()),
    }
}

fn processes() -> Vec<ProcessInfo> {
    vec![
        ProcessInfo {
            pid: 2134,
            ppid: Some(1),
            name: "firefox".into(),
            exe: Some("/usr/lib/firefox/firefox".into()),
            cmdline: Some("firefox".into()),
            user: Some("mohammed".into()),
            uid: Some(1000),
            cpu_percent: 18.4,
            memory_bytes: 1_800 * 1024 * 1024,
            virtual_memory_bytes: 3_000 * 1024 * 1024,
            start_time_epoch: 1_700_000_000,
            run_time_secs: 3_600,
            status: "Run".into(),
            note: None,
        },
        ProcessInfo {
            pid: 1032,
            ppid: Some(1),
            name: "code".into(),
            exe: Some("/usr/share/code/code".into()),
            cmdline: Some("code".into()),
            user: Some("mohammed".into()),
            uid: Some(1000),
            cpu_percent: 11.2,
            memory_bytes: 1_200 * 1024 * 1024,
            virtual_memory_bytes: 2_000 * 1024 * 1024,
            start_time_epoch: 1_700_000_000,
            run_time_secs: 7_200,
            status: "Run".into(),
            note: None,
        },
    ]
}

fn connections() -> Vec<Connection> {
    vec![
        Connection {
            protocol: "tcp".into(),
            local_addr: "127.0.0.1".into(),
            local_port: 3000,
            remote_addr: None,
            remote_port: None,
            state: "LISTEN".into(),
            pid: Some(1032),
            process: Some("code".into()),
        },
        Connection {
            protocol: "tcp".into(),
            local_addr: "192.168.1.20".into(),
            local_port: 443,
            remote_addr: Some("104.18.32.7".into()),
            remote_port: Some(443),
            state: "ESTABLISHED".into(),
            pid: Some(2134),
            process: Some("firefox".into()),
        },
    ]
}

fn scan_report() -> ScanReport {
    ScanReport {
        target: "127.0.0.1".into(),
        resolved: vec!["127.0.0.1".into()],
        ports: vec![
            ScannedPort {
                port: 22,
                protocol: "tcp".into(),
                state: PortState::Open,
                service: Some("ssh".into()),
                product: Some("OpenSSH".into()),
                version: Some("9.6p1".into()),
                banner: Some("SSH-2.0-OpenSSH_9.6p1 Ubuntu".into()),
                tls: None,
                detection: Some("banner/targeted probe".into()),
                confidence: Confidence::Confirmed,
            },
            ScannedPort {
                port: 443,
                protocol: "tcp".into(),
                state: PortState::Open,
                service: Some("https/tls".into()),
                product: Some("nginx".into()),
                version: Some("1.24.0".into()),
                banner: None,
                tls: Some(TlsInfo {
                    handshake_ok: true,
                    error: None,
                    protocol_version: Some("TLSv1.3".into()),
                    cipher_suite: Some("TLS13_AES_256_GCM_SHA384".into()),
                    subject: Some("CN=localhost".into()),
                    issuer: Some("CN=localhost".into()),
                    not_before: Some("2026-01-01".into()),
                    not_after: Some("2027-01-01".into()),
                    days_remaining: Some(300),
                    san: vec!["localhost".into()],
                    self_signed: Some(true),
                }),
                detection: Some("tls handshake".into()),
                confidence: Confidence::Confirmed,
            },
        ],
        started_epoch: 1_700_000_000,
        duration_ms: 420,
        concurrency: 100,
        timeout_ms: 1000,
        scan_type: "tcp-connect".into(),
        note: None,
        cancelled: false,
    }
}

pub fn fixture_discovery_report() -> DiscoveryReport {
    DiscoveryReport {
        subnets: vec!["192.168.1.0/24".into()],
        method: "neighbor-table+icmp".into(),
        hosts: vec![
            DiscoveredHost {
                ip: "192.168.1.1".into(),
                mac: Some("aa:bb:cc:dd:ee:ff".into()),
                vendor: Some("Netgear".into()),
                hostname: Some("router".into()),
                response_ms: Some(2.0),
                open_ports: vec![80, 443],
                discovery_sources: vec!["neighbor-table".into(), "icmp".into()],
            },
            DiscoveredHost {
                ip: "192.168.1.10".into(),
                mac: Some("28:cf:e9:00:00:00".into()),
                vendor: Some("Apple".into()),
                hostname: Some("laptop".into()),
                response_ms: Some(3.0),
                open_ports: Vec::new(),
                discovery_sources: vec!["icmp".into()],
            },
        ],
        scanned: 254,
        duration_ms: 8_200,
        note: None,
        cancelled: false,
    }
}

fn monitor_sample() -> MonitorSample {
    MonitorSample {
        timestamp_epoch: 1_700_000_000,
        uptime_secs: 4 * 86_400 + 8 * 3_600,
        cpu_usage_percent: 42.0,
        per_core_usage: vec![40.0, 44.0],
        load_average: Some([1.2, 1.1, 0.9]),
        memory_used_bytes: 8 * 1024 * 1024 * 1024,
        memory_total_bytes: 16 * 1024 * 1024 * 1024,
        memory_utilization_percent: 51.0,
        swap_used_bytes: 200 * 1024 * 1024,
        swap_total_bytes: 2 * 1024 * 1024 * 1024,
        network: vec![NetRate {
            interface: "wlp3s0".into(),
            rx_bytes_per_sec: 12_400_000.0,
            tx_bytes_per_sec: 1_800_000.0,
            rx_total_bytes: 1_000_000_000,
            tx_total_bytes: 100_000_000,
        }],
        temperatures: vec![Temperature {
            label: "Package id 0".into(),
            current_c: 51.0,
            max_c: Some(100.0),
            critical_c: None,
        }],
        top_cpu: processes(),
        top_memory: processes(),
    }
}

fn snapshot(epoch: i64, label: &str) -> Snapshot {
    Snapshot {
        schema_version: 1,
        created_epoch: epoch,
        hostname: Some("zbook".into()),
        platform: PlatformId::Linux,
        label: Some(label.into()),
        os_summary: "Ubuntu 24.04 (x86_64)".into(),
        interfaces: interfaces(),
        routes: routes(),
        listening: listening(),
        privileged_accounts: vec!["root".into()],
        firewall_enabled: Some(true),
        findings: vec![netro::core::snapshot::SnapshotFinding {
            id: "firewall.disabled".into(),
            severity: Severity::High,
            title: "Host firewall appears disabled".into(),
        }],
        note: None,
    }
}

pub fn fixture_diff() -> SnapshotDiff {
    SnapshotDiff {
        from: "baseline 2026-09-20 09:14".into(),
        to: "current 2026-09-25 23:11".into(),
        added_ports: vec!["tcp 0.0.0.0:8080".into()],
        removed_ports: vec!["tcp 0.0.0.0:22".into()],
        added_interfaces: vec!["wlan0".into()],
        removed_interfaces: Vec::new(),
        route_changes: vec!["ipv4 0.0.0.0/0 via 192.168.1.254 dev wlp3s0".into()],
        firewall_change: Some("firewall enabled changed: yes -> no".into()),
        new_findings: vec!["firewall.disabled".into()],
        resolved_findings: Vec::new(),
        account_changes: vec!["admin".into()],
        note: None,
    }
}

fn populate(app: &mut App) {
    app.state.caches.os = Some(Fresh::new(os_info()));
    app.state.caches.system = Some(Fresh::new(system_snapshot()));
    app.state.caches.interfaces = Some(Fresh::new(interfaces()));
    app.state.caches.routes = Some(Fresh::new(routes()));
    app.state.caches.dns = Some(Fresh::new(dns_config()));
    app.state.caches.connectivity = Some(Fresh::new(connectivity()));
    app.state.caches.audit = Some(Fresh::new(audit()));
    app.state.caches.doctor = Some(Fresh::new(doctor_report()));
    app.state.caches.processes = Some(Fresh::new(processes()));
    app.state.caches.connections = Some(Fresh::new(connections()));
    app.state.caches.listening = Some(Fresh::new(listening()));
    app.state.caches.firewall = Some(Fresh::new(FirewallStatus {
        enabled: Some(false),
        backends: vec![FirewallBackend {
            name: "ufw".into(),
            active: Some(false),
            detail: Some("Status: inactive".into()),
            via: "ufw status verbose".into(),
        }],
        notes: Vec::new(),
        error: None,
    }));
    app.state.caches.rules = Some(Fresh::new(vec![FirewallRule {
        backend: "ufw".into(),
        chain: None,
        action: "ALLOW".into(),
        source: None,
        destination: None,
        ports: Some("22".into()),
        protocol: Some("tcp".into()),
        raw: "22/tcp ALLOW Anywhere".into(),
    }]));
    app.state.caches.baseline = Some(netro::model::IntegrityBaseline {
        schema_version: 1,
        created_epoch: 1_700_000_000,
        hostname: "zbook".into(),
        platform: PlatformId::Linux,
        paths: vec!["/etc/passwd".into(), "/etc/ssh/sshd_config".into()],
        entries: Vec::new(),
    });
    app.state.caches.integrity_report = Some(Fresh::new(netro::model::IntegrityReport {
        baseline_created_epoch: Some(1_700_000_000),
        scanned_epoch: 1_700_000_100,
        changes: vec![netro::model::IntegrityChange {
            path: "/etc/ssh/sshd_config".into(),
            status: IntegrityStatus::Modified,
            details: vec!["content hash changed".into()],
        }],
        unchanged: 1,
        note: None,
    }));
    app.state.caches.external_tools = Some(Fresh::new(vec![
        netro::core::security::ExternalToolResult {
            tool: "rkhunter".into(),
            installed: false,
            ran: false,
            summary: None,
            error: None,
            source: EvidenceSource::ExternalTool,
            note: Some("not installed".into()),
        },
        netro::core::security::ExternalToolResult {
            tool: "lynis".into(),
            installed: true,
            ran: false,
            summary: None,
            error: None,
            source: EvidenceSource::ExternalTool,
            note: Some("installed but not run (use --run-external)".into()),
        },
    ]));
    app.state.doctor.report = Some(doctor_report());
    app.state.discovery.report = Some(fixture_discovery_report());
    app.state.discovery.target = "192.168.1.0/24".into();
    app.state.scanner.report = Some(scan_report());
    app.state.scanner.target = "127.0.0.1".into();
    app.state.scanner.authorized = true;
    app.state.network.latency = Some(PingResult {
        target: "1.1.1.1".into(),
        resolved: vec!["1.1.1.1".into()],
        method: ProbeMethod::Icmp,
        transmitted: 4,
        received: 4,
        loss_percent: 0.0,
        min_ms: Some(17.0),
        avg_ms: Some(18.0),
        max_ms: Some(19.0),
        jitter_ms: Some(0.6),
        rtts: vec![17.0, 18.0, 19.0, 18.0],
        error: None,
    });
    app.state.network.latency_target = "1.1.1.1".into();
    app.state.network.trace = Some(TraceResult {
        target: "1.1.1.1".into(),
        method: ProbeMethod::SystemUtility,
        hops: vec![
            TraceHop {
                hop: 1,
                address: Some("192.168.1.1".into()),
                hostname: None,
                rtt_ms: vec![1.0, 1.0, 1.0],
                timeout: false,
            },
            TraceHop {
                hop: 2,
                address: None,
                hostname: None,
                rtt_ms: Vec::new(),
                timeout: true,
            },
            TraceHop {
                hop: 3,
                address: Some("1.1.1.1".into()),
                hostname: None,
                rtt_ms: vec![18.0],
                timeout: false,
            },
        ],
        reached: true,
        note: None,
    });
    app.state.network.trace_target = "1.1.1.1".into();
    app.state.network.dns_name = "example.com".into();
    app.state.monitor.push_sample(monitor_sample());
    app.state.snapshots.list = vec![
        (
            std::path::PathBuf::from("/tmp/1.json"),
            snapshot(1_700_000_000, "Baseline"),
        ),
        (
            std::path::PathBuf::from("/tmp/2.json"),
            snapshot(1_700_100_000, "Current"),
        ),
    ];
    app.state.snapshots.loaded = true;
}

pub fn buffer_to_string(buffer: &Buffer) -> String {
    let mut out = String::new();
    for y in 0..buffer.area.height {
        let mut line = String::new();
        for x in 0..buffer.area.width {
            line.push_str(buffer[(x, y)].symbol());
        }
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

pub fn render_app(app: &mut App, width: u16, height: u16) -> String {
    let backend = TestBackend::new(width, height);
    let mut terminal = Terminal::new(backend).expect("test terminal");
    terminal
        .draw(|frame| app.render(frame))
        .expect("render to test backend");
    buffer_to_string(terminal.backend().buffer())
}
