//! Command-line interface definition.
//!
//! The CLI is fully scriptable: every command is non-interactive by default,
//! machines can consume `--json`, and destructive operations require `--yes`
//! (or an interactive confirmation).

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Debug, Parser)]
#[command(
    name = "netro",
    version = crate::version::VERSION,
    about = "Cross-platform system, network, diagnostics and security-audit tool",
    long_about = "netro performs real system, network, diagnostics, monitoring and \
security-audit checks across Linux, Windows and macOS. Output is available as text, \
JSON or CSV. Optional external tools are detected but never required for core \
functionality.",
    propagate_version = true,
    disable_help_subcommand = true,
    after_help = "EXAMPLES:\n  \
        netro                           launch the interactive TUI (on a terminal)\n  \
        netro doctor                    full health check with evidence\n  \
        netro doctor --json             machine-readable health report\n  \
        netro system --json             OS/CPU/memory/storage/GPU\n  \
        netro network interfaces        interface inventory\n  \
        netro network scan 127.0.0.1    scan localhost (authorized automatically)\n  \
        netro network scan 10.0.0.5 --ports common --authorized\n  \
        netro network discover --method auto\n  \
        netro connections --state ESTABLISHED\n  \
        netro security audit --json\n  \
        netro integrity baseline create && netro integrity scan\n  \
        netro monitor --interval 2 --count 10\n  \
        netro report --html report.html\n\n\
        Scanning: only test systems you own or are explicitly authorized to test."
)]
pub struct Cli {
    /// Output format: text, json, csv
    #[arg(long, global = true, value_name = "FORMAT")]
    pub format: Option<String>,

    /// Shorthand for --format json
    #[arg(long, global = true)]
    pub json: bool,

    /// Color output: auto, always, never
    #[arg(long, global = true, default_value = "auto", value_name = "WHEN")]
    pub color: String,

    /// Increase log verbosity (-v, -vv)
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    /// Suppress informational stderr messages
    #[arg(long, global = true)]
    pub quiet: bool,

    /// Log level: debug, info, warn, error
    #[arg(long, global = true, value_name = "LEVEL")]
    pub log_level: Option<String>,

    /// Write logs to this file
    #[arg(long, global = true, value_name = "PATH")]
    pub log_file: Option<PathBuf>,

    /// Assume "yes" for confirmation prompts (required in non-interactive use)
    #[arg(long, global = true)]
    pub yes: bool,

    #[command(subcommand)]
    pub command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// System information (OS, CPU, memory, storage, GPU)
    System(SystemArgs),

    /// Network information and diagnostics
    Network(NetworkArgs),

    /// Active network connections with owning process
    Connections(ConnectionsArgs),

    /// Process diagnostics
    Processes(ProcessesArgs),

    /// Security audit: accounts, exposure, firewall, policy
    Security(SecurityArgs),

    /// Firewall status and controlled block/unblock
    Firewall(FirewallArgs),

    /// File integrity baselines and comparison
    Integrity(IntegrityArgs),

    /// Full health check with findings, severity and transparent score
    Doctor(DoctorArgs),

    /// Live system and network monitoring
    Monitor(MonitorArgs),

    /// Interactive terminal user interface
    Tui(TuiArgs),

    /// Generate a report (text/json/csv/html)
    Report(ReportArgs),

    /// Configuration management
    Config(ConfigArgs),

    /// Detect optional external dependencies
    Dependencies(DependenciesArgs),

    /// Version and build information
    Version,
}

#[derive(Debug, Args)]
pub struct TuiArgs {
    /// Disable mouse capture (keyboard-only operation)
    #[arg(long)]
    pub no_mouse: bool,
    /// Theme: auto, dark, light, contrast, none
    #[arg(long, value_name = "KIND")]
    pub theme: Option<String>,
}

#[derive(Debug, Args)]
pub struct SystemArgs {
    /// Only show CPU information
    #[arg(long)]
    pub cpu: bool,
    /// Only show memory information
    #[arg(long)]
    pub memory: bool,
    /// Only show storage information
    #[arg(long)]
    pub storage: bool,
    /// Only show GPU information
    #[arg(long)]
    pub gpu: bool,
}

#[derive(Debug, Args)]
pub struct NetworkArgs {
    #[command(subcommand)]
    pub command: NetworkCommand,
}

#[derive(Debug, Subcommand)]
pub enum NetworkCommand {
    /// List interfaces with addresses, type and state
    Interfaces,
    /// Show the routing table
    Routes,
    /// Show resolver configuration, or query a name
    Dns(DnsArgs),
    /// Discover hosts on local subnets
    Discover(DiscoverArgs),
    /// TCP/UDP port scan with service detection
    Scan(ScanArgs),
    /// Measure latency (ICMP via system ping, or TCP)
    Latency(LatencyArgs),
    /// Run connectivity checks (gateway, DNS, internet, IPv4/IPv6)
    Connectivity(ConnectivityArgs),
    /// Trace the path to a target
    Trace(TraceArgs),
    /// Measure throughput against a configured server (no implicit third parties)
    Speedtest(SpeedTestArgs),
}

#[derive(Debug, Args)]
pub struct SpeedTestArgs {
    /// Provider: iperf3 or http
    #[arg(long)]
    pub provider: Option<String>,
    /// iperf3 host, or an http(s) URL
    #[arg(long)]
    pub server: Option<String>,
    /// iperf3 port (default 5201)
    #[arg(long)]
    pub port: Option<u16>,
    /// Test duration in seconds
    #[arg(long, default_value_t = 5.0)]
    pub duration: f64,
    /// Direction: download, upload or both
    #[arg(long, default_value = "both")]
    pub direction: String,
    /// Use UDP (iperf3 only); reports jitter and loss
    #[arg(long)]
    pub udp: bool,
}

#[derive(Debug, Args)]
pub struct DnsArgs {
    /// Name to resolve (omit to show resolver configuration)
    pub name: Option<String>,
    /// DNS server to query (IP or IP:port)
    #[arg(long)]
    pub server: Option<String>,
    /// Record type: A, AAAA, CNAME, MX, TXT, NS, SOA, PTR, SRV
    #[arg(long, default_value = "A")]
    pub r#type: String,
    /// Perform a reverse lookup for an IP address
    #[arg(long)]
    pub reverse: bool,
}

#[derive(Debug, Args)]
pub struct DiscoverArgs {
    /// Discovery method: auto, neighbors, icmp, tcp, nmap
    #[arg(long, default_value = "auto")]
    pub method: String,
    /// Restrict to one interface
    #[arg(long)]
    pub interface: Option<String>,
    /// Explicit local CIDR (e.g. 192.168.1.0/24)
    #[arg(long)]
    pub target: Option<String>,
    /// Maximum number of hosts to sweep
    #[arg(long, default_value_t = 256)]
    pub max_hosts: usize,
    /// TCP ports probed during discovery
    #[arg(long, value_delimiter = ',', default_value = "22,80,443,445,139,8080")]
    pub ports: Vec<u16>,
    /// Do not resolve hostnames
    #[arg(long)]
    pub no_dns: bool,
    /// Do not look up MAC vendors
    #[arg(long)]
    pub no_vendor: bool,
    /// Concurrency for sweep probes
    #[arg(long, default_value_t = 64)]
    pub concurrency: usize,
    /// Per-probe timeout in milliseconds
    #[arg(long, default_value_t = 800)]
    pub timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct ScanArgs {
    /// Target IP address or hostname (use `network discover` for CIDR sweeps)
    pub target: String,
    /// Ports: common, all, 22,80,443, 1-1024
    #[arg(long)]
    pub ports: Option<String>,
    /// Per-connect timeout in milliseconds
    #[arg(long)]
    pub timeout_ms: Option<u64>,
    /// Concurrent connection workers
    #[arg(long)]
    pub concurrency: Option<usize>,
    /// Do not attempt banner/service detection
    #[arg(long)]
    pub no_banner: bool,
    /// Do not perform TLS probes
    #[arg(long)]
    pub no_tls: bool,
    /// Also perform UDP probes for known services
    #[arg(long)]
    pub udp: bool,
    /// Only print open ports
    #[arg(long)]
    pub open_only: bool,
    /// Confirm you own or are authorized to test the target (required for public targets)
    #[arg(long)]
    pub authorized: bool,
}

#[derive(Debug, Args)]
pub struct LatencyArgs {
    /// Host or IP to measure
    pub target: String,
    /// Number of probes
    #[arg(long, default_value_t = 4)]
    pub count: u32,
    /// Method: auto, icmp, tcp
    #[arg(long, default_value = "auto")]
    pub method: String,
    /// TCP port used by the TCP fallback
    #[arg(long, default_value_t = 443)]
    pub port: u16,
    /// Per-probe timeout in milliseconds
    #[arg(long, default_value_t = 2000)]
    pub timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct ConnectivityArgs {
    /// Do not test IPv6
    #[arg(long)]
    pub no_ipv6: bool,
    /// Timeout per check in milliseconds
    #[arg(long, default_value_t = 3000)]
    pub timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct TraceArgs {
    /// Host or IP to trace
    pub target: String,
    /// Maximum number of hops
    #[arg(long, default_value_t = 30)]
    pub max_hops: u8,
    /// Method: auto, icmp, tcp
    #[arg(long, default_value = "auto")]
    pub method: String,
    /// TCP port used by the built-in TCP tracer
    #[arg(long, default_value_t = 443)]
    pub port: u16,
    /// Per-hop timeout in milliseconds
    #[arg(long, default_value_t = 2000)]
    pub timeout_ms: u64,
}

#[derive(Debug, Args)]
pub struct ConnectionsArgs {
    /// Filter by state (e.g. ESTABLISHED, LISTEN)
    #[arg(long)]
    pub state: Option<String>,
    /// Filter by process name (substring, case-insensitive)
    #[arg(long)]
    pub process: Option<String>,
    /// Filter by local or remote port
    #[arg(long)]
    pub port: Option<u16>,
    /// Filter by remote address (substring)
    #[arg(long)]
    pub remote: Option<String>,
    /// Filter by protocol: tcp or udp
    #[arg(long)]
    pub protocol: Option<String>,
    /// Show only listening sockets
    #[arg(long)]
    pub listen: bool,
    /// Maximum rows
    #[arg(long, default_value_t = 200)]
    pub limit: usize,
}

#[derive(Debug, Args)]
pub struct ProcessesArgs {
    /// Sort by: cpu, memory, pid, recent, name
    #[arg(long, default_value = "cpu")]
    pub sort: String,
    /// Maximum rows
    #[arg(long, default_value_t = 25)]
    pub limit: usize,
    /// Filter by PID
    #[arg(long)]
    pub pid: Option<u32>,
    /// Filter by process name (substring, case-insensitive)
    #[arg(long)]
    pub name: Option<String>,
    /// Only show processes with network connections
    #[arg(long)]
    pub network: bool,
}

#[derive(Debug, Args)]
pub struct SecurityArgs {
    #[command(subcommand)]
    pub command: Option<SecurityCommand>,
    /// Run optional external scanners (rkhunter/chkrootkit/lynis) — slow
    #[arg(long)]
    pub run_external: bool,
}

#[derive(Debug, Subcommand)]
pub enum SecurityCommand {
    /// Full audit with findings and score
    Audit {
        /// Run optional external scanners (slow)
        #[arg(long)]
        run_external: bool,
    },
    /// Local accounts and password status
    Accounts,
    /// Listening sockets with exposure classification
    Listening,
}

#[derive(Debug, Args)]
pub struct FirewallArgs {
    #[command(subcommand)]
    pub command: FirewallCommand,
}

#[derive(Debug, Subcommand)]
pub enum FirewallCommand {
    /// Show firewall backends and state
    Status,
    /// Show active rules
    Rules {
        /// Maximum rules to display
        #[arg(long, default_value_t = 50)]
        limit: usize,
    },
    /// Block an IP address on this host
    Block {
        /// IP address to block
        ip: String,
        /// Show the exact commands without executing them
        #[arg(long)]
        dry_run: bool,
    },
    /// Remove a block previously created by netro
    Unblock {
        /// IP address to unblock
        ip: String,
        /// Show the exact commands without executing them
        #[arg(long)]
        dry_run: bool,
    },
}

#[derive(Debug, Args)]
pub struct IntegrityArgs {
    #[command(subcommand)]
    pub command: IntegrityCommand,
}

#[derive(Debug, Subcommand)]
pub enum IntegrityCommand {
    /// Create a new cryptographic baseline
    Baseline {
        /// Paths to include (defaults to platform-critical files)
        #[arg(long, value_delimiter = ',')]
        paths: Vec<String>,
        /// Maximum file size to hash, in megabytes
        #[arg(long)]
        max_size_mb: Option<u64>,
    },
    /// Compare current state against the baseline
    Scan {
        /// Maximum file size to hash, in megabytes
        #[arg(long)]
        max_size_mb: Option<u64>,
        /// Show unchanged files as well
        #[arg(long)]
        all: bool,
    },
    /// Show baseline metadata
    Show,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Run optional external scanners (slow)
    #[arg(long)]
    pub run_external: bool,
    /// Skip internet connectivity checks
    #[arg(long)]
    pub no_internet: bool,
    /// Only list optional external dependencies
    #[arg(long)]
    pub dependencies: bool,
}

#[derive(Debug, Args)]
pub struct MonitorArgs {
    /// Sample interval in seconds
    #[arg(long)]
    pub interval: Option<f64>,
    /// Number of samples (omit for continuous)
    #[arg(long)]
    pub count: Option<u64>,
    /// Total duration in seconds (alternative to --count)
    #[arg(long)]
    pub duration: Option<f64>,
    /// Number of top processes to display
    #[arg(long)]
    pub top: Option<usize>,
    /// Do not show processes
    #[arg(long)]
    pub no_processes: bool,
    /// Show network rate only for interfaces with traffic
    #[arg(long)]
    pub active_net: bool,
}

#[derive(Debug, Args)]
pub struct ReportArgs {
    /// Write an HTML report to this path
    #[arg(long, value_name = "PATH")]
    pub html: Option<PathBuf>,
    /// Write the selected format to this path instead of stdout
    #[arg(long, value_name = "PATH")]
    pub out: Option<PathBuf>,
    /// Skip connectivity/Internet checks
    #[arg(long)]
    pub no_internet: bool,
    /// Skip the security section
    #[arg(long)]
    pub no_security: bool,
    /// Skip system information
    #[arg(long)]
    pub no_system: bool,
}

#[derive(Debug, Args)]
pub struct ConfigArgs {
    #[command(subcommand)]
    pub command: Option<ConfigCommand>,
}

#[derive(Debug, Subcommand)]
pub enum ConfigCommand {
    /// Print the effective configuration
    Show,
    /// Print the configuration file path
    Path,
    /// Write a default configuration if none exists
    Init,
    /// Set a configuration value (dotted path)
    Set {
        /// e.g. scan.timeout_ms, monitor.interval_secs, output.format
        key: String,
        value: String,
    },
}

#[derive(Debug, Args)]
pub struct DependenciesArgs {
    /// Only show dependencies that are missing
    #[arg(long)]
    pub missing: bool,
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;

    #[test]
    fn cli_definition_is_valid() {
        Cli::command().debug_assert();
    }

    #[test]
    fn parses_json_flag() {
        let cli = Cli::try_parse_from(["netro", "doctor", "--json"]).unwrap();
        assert!(cli.json);
        assert!(matches!(cli.command, Some(Commands::Doctor(_))));
    }

    #[test]
    fn parses_network_scan() {
        let cli = Cli::try_parse_from([
            "netro",
            "network",
            "scan",
            "127.0.0.1",
            "--ports",
            "22,80",
            "--authorized",
        ])
        .unwrap();
        match cli.command {
            Some(Commands::Network(args)) => match args.command {
                NetworkCommand::Scan(scan) => {
                    assert_eq!(scan.target, "127.0.0.1");
                    assert!(scan.authorized);
                }
                _ => panic!("wrong subcommand"),
            },
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn parses_firewall_block_with_dry_run() {
        let cli = Cli::try_parse_from(["netro", "firewall", "block", "203.0.113.5", "--dry-run"])
            .unwrap();
        match cli.command {
            Some(Commands::Firewall(args)) => match args.command {
                FirewallCommand::Block { ip, dry_run } => {
                    assert_eq!(ip, "203.0.113.5");
                    assert!(dry_run);
                }
                _ => panic!("wrong subcommand"),
            },
            _ => panic!("wrong command"),
        }
    }

    #[test]
    fn rejects_unknown_flags() {
        assert!(Cli::try_parse_from(["netro", "doctor", "--nope"]).is_err());
    }
}
