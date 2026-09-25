//! UI text abstraction.
//!
//! All user-facing UI strings live here so localization can be added later
//! without touching component code. Technical identifiers, command names,
//! error codes and protocol names are intentionally not translated.

macro_rules! define_text {
    ($($name:ident => $value:literal),* $(,)?) => {
        /// UI strings. English is the only shipped locale for now; components
        /// read every visible label from here.
        pub struct Text {
            $(pub $name: &'static str),*
        }
        pub static T: Text = Text {
            $($name: $value),*
        };
    };
}

define_text! {
    // Application chrome
    app_name => "netRo",
    app_tagline => "System & Network Diagnostics",
    nav_title => "NAVIGATION",
    status_panel => "LIVE STATUS",
    hint_navigate => "Navigate",
    hint_open => "Open",
    hint_back => "Back",
    hint_refresh => "Refresh",
    hint_search => "Search",
    hint_help => "Help",
    hint_quit => "Quit",
    hint_palette => "Palette",
    hint_cancel => "Cancel",
    hint_details => "Details",
    hint_export => "Export",
    hint_run => "Run",
    hint_toggle => "Toggle",
    loading => "Loading...",
    cancelled => "Cancelled",
    running => "Running",
    updated => "Updated",
    stale => "Stale",
    never => "never",
    retry_hint => "Press r to retry",
    no_data => "No data available",
    unsupported => "Unsupported on this platform",
    permission_required => "Requires administrator/root privileges",
    cancelled_note => "Cancelled by user; partial results below",

    // Screens
    screen_dashboard => "Dashboard",
    screen_system => "System",
    screen_network => "Network",
    screen_discovery => "Discovery",
    screen_scanner => "Scanner",
    screen_security => "Security",
    screen_monitor => "Monitor",
    screen_doctor => "Doctor",
    screen_reports => "Reports",
    screen_snapshots => "Snapshots",
    screen_settings => "Settings",

    // Dashboard
    dash_overview => "OVERVIEW",
    dash_health => "HEALTH",
    dash_network => "NETWORK",
    dash_resources => "RESOURCES",
    dash_findings => "FINDINGS",
    dash_host => "Host",
    dash_os => "OS",
    dash_kernel => "Kernel",
    dash_uptime => "Uptime",
    dash_interface => "Interface",
    dash_address => "Address",
    dash_gateway => "Gateway",
    dash_dns => "DNS",
    dash_internet => "Internet",
    dash_latency => "Latency",
    dash_overall => "Overall Health",
    dash_last_scan => "Last scan",
    dash_no_findings => "No findings from the checks that ran",
    dash_checks_running => "Running checks...",

    // System
    sys_cpu => "CPU",
    sys_memory => "MEMORY",
    sys_storage => "STORAGE",
    sys_gpu => "GPU",
    sys_processes => "PROCESSES",
    sys_model => "Model",
    sys_cores => "Cores",
    sys_usage => "Usage",
    sys_frequency => "Frequency",
    sys_load => "Load average",
    sys_temperature => "Temperature",
    sys_total => "Total",
    sys_used => "Used",
    sys_available => "Available",
    sys_swap => "Swap",
    sys_mount => "Mount",
    sys_free => "Free",
    sys_driver => "Driver",
    sys_utilization => "Utilization",
    sys_power => "Power",
    sys_backend => "Backend",
    sys_source => "Source",

    // Network
    net_internet => "Internet",
    net_gateway => "Gateway",
    net_ipv4 => "IPv4",
    net_ipv6 => "IPv6",
    net_packet_loss => "Packet loss",
    net_connected => "CONNECTED",
    net_disconnected => "NOT REACHABLE",
    net_no_interface => "No active network interface detected.",
    tab_overview => "Overview",
    tab_interfaces => "Interfaces",
    tab_routes => "Routes",
    tab_dns => "DNS",
    tab_connectivity => "Connectivity",
    tab_latency => "Latency",
    tab_trace => "Trace",
    tab_connections => "Connections",
    net_target => "Target",
    net_query => "Name",
    net_resolver => "Resolver",
    net_result => "Result",

    // Discovery
    disc_title => "NETWORK DISCOVERY",
    disc_target => "Scan",
    disc_method => "Method",
    disc_hosts_found => "Hosts found",
    disc_probed => "Probed",
    disc_start => "Start discovery",
    disc_ip => "IP",
    disc_hostname => "Hostname",
    disc_vendor => "Vendor",
    disc_rtt => "RTT",
    disc_ports => "Open ports",
    disc_local_only => "Discovery runs only on local subnets (private/loopback).",

    // Scanner
    scan_title => "PORT SCANNER",
    scan_new => "NEW SCAN",
    scan_target => "Target",
    scan_profile => "Profile",
    scan_authorization => "Authorization",
    scan_authorization_text => "I am authorized to scan this target.",
    scan_start => "Start scan",
    scan_suggest => "Suggestion: scan localhost or your own network.",
    scan_port => "Port",
    scan_state => "State",
    scan_service => "Service",
    scan_banner => "Banner",
    scan_tls => "TLS",
    scan_open => "open",
    scan_closed => "closed",
    scan_filtered => "filtered",
    scan_public_warning => "Public targets require explicit authorization.",
    tab_port_scan => "Port scan",
    tab_host_scan => "Host scan",
    tab_nmap => "Nmap",

    // Security
    sec_score => "Security score",
    sec_findings => "Security findings",
    sec_evidence => "Evidence",
    sec_impact => "Why it matters",
    sec_recommendation => "Recommendation",
    sec_severity => "Severity",
    sec_category => "Category",
    sec_confidence => "Confidence",
    sec_source => "Source",
    sec_score_impact => "Score impact",
    sec_good => "No findings from the checks that ran.",
    tab_findings => "Findings",
    tab_accounts => "Accounts",
    tab_listening => "Listening Services",
    tab_firewall => "Firewall",
    tab_integrity => "Integrity",
    tab_external => "External Tools",
    sec_account => "Account",
    sec_privileged => "Privileged",
    sec_password => "Password",
    sec_groups => "Groups",
    sec_scope => "Scope",
    sec_process => "Process",
    fw_block => "Block IP",
    fw_unblock => "Remove netro block",
    fw_this_machine => "This machine",
    fw_scope_warning => "This changes the firewall of THIS machine only. It does NOT disconnect the device from the router.",
    integ_baseline => "Baseline",
    integ_create => "Create baseline",
    integ_scan => "Scan against baseline",
    integ_no_baseline => "No baseline yet. Press c to create one.",
    integ_paths => "Paths",
    integ_entries => "Entries",

    // Doctor
    doc_title => "NETRO DOCTOR",
    doc_summary => "HEALTH SUMMARY",
    doc_problems => "PROBLEMS FOUND",
    doc_recommendations => "RECOMMENDATIONS",
    doc_checks => "Checks",
    doc_passed => "passed",
    doc_warnings => "warnings",
    doc_failed => "failed",
    doc_unsupported => "unsupported",
    doc_running => "Doctor is already running.",
    doc_started => "Running diagnostics...",

    // Monitor
    mon_cpu => "CPU",
    mon_memory => "Memory",
    mon_network => "Network",
    mon_download => "Down",
    mon_upload => "Up",
    mon_temperatures => "Temperatures",
    mon_top_cpu => "TOP CPU",
    mon_top_memory => "TOP MEMORY",
    mon_paused => "PAUSED",
    mon_history => "history",
    mon_interval => "Interval",

    // Reports
    rep_title => "REPORTS",
    rep_format => "Format",
    rep_scope => "Scope",
    rep_output => "Output file",
    rep_generate => "Generate report",
    rep_scope_full => "Full",
    rep_scope_system => "System",
    rep_scope_network => "Network",
    rep_scope_security => "Security",
    rep_reuse_note => "Fresh cached results are reused; presses g to regenerate.",
    rep_written => "Report written",

    // Snapshots
    snap_title => "SNAPSHOTS",
    snap_create => "Create snapshot",
    snap_view => "View",
    snap_compare => "Compare",
    snap_delete => "Delete",
    snap_export => "Export",
    snap_mark => "Mark for comparison",
    snap_none => "No snapshots yet. Press c to create one.",
    snap_created => "Snapshot created",
    snap_label_prompt => "Snapshot label (optional)",
    snap_diff_title => "SNAPSHOT DIFF",
    snap_added_ports => "NEW LISTENING PORT",
    snap_removed_ports => "CLOSED PORT",
    snap_added_interfaces => "NEW INTERFACE",
    snap_removed_interfaces => "REMOVED INTERFACE",
    snap_route_changes => "ROUTE CHANGE",
    snap_findings => "NEW FINDING",
    snap_resolved => "RESOLVED FINDING",
    snap_accounts => "ACCOUNT CHANGE",
    snap_firewall => "FIREWALL",
    snap_no_diff => "No stable differences detected.",

    // Settings
    set_title => "SETTINGS",
    set_appearance => "Appearance",
    set_monitoring => "Monitoring",
    set_scan => "Scan defaults",
    set_network => "Network",
    set_privacy => "Privacy",
    set_integrations => "Integrations",
    set_theme => "Theme",
    set_colors => "Color mode",
    set_unicode => "Unicode",
    set_refresh => "Dashboard refresh",
    set_monitor_interval => "Monitor interval",
    set_discovery_method => "Discovery method",
    set_scan_ports => "Scan ports",
    set_scan_timeout => "Scan timeout (ms)",
    set_scan_concurrency => "Scan concurrency",
    set_reverse_dns => "Reverse DNS",
    set_vendor_lookup => "Vendor lookup",
    set_oui_file => "OUI file",
    set_speedtest_server => "Speedtest server",
    set_save => "Save configuration",
    set_saved => "Configuration saved",
    set_invalid => "Invalid value",

    // Overlays
    overlay_help => "KEYBOARD SHORTCUTS",
    overlay_palette => "COMMAND PALETTE",
    overlay_confirm => "CONFIRM",
    overlay_error => "ERROR",
    overlay_details => "DETAILS",
    palette_query => "Type to filter commands",
    palette_empty => "No matching commands",
    confirm_continue => "Continue?",
    error_reason => "Reason",
    error_required => "Required",
    error_details_hint => "Enter for technical details, Esc to close",
    detail_close => "Esc Close",

    // Empty / degraded states
    empty_no_processes => "No processes reported.",
    empty_no_connections => "No active connections.",
    empty_no_listening => "No listening sockets reported.",
    empty_no_hosts => "No hosts discovered. Press r to retry.",
    empty_no_accounts => "No accounts available.",
    empty_no_snapshots => "No snapshots stored yet.",
    empty_filtered => "No rows match the current filter.",
    too_small => "Terminal too small",
    too_small_hint => "Resize to at least 40x12, or press q to quit.",
    offline_note => "Internet unavailable; local diagnostics remain available.",
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_screen_titles_are_present() {
        for title in [
            T.screen_dashboard,
            T.screen_system,
            T.screen_network,
            T.screen_discovery,
            T.screen_scanner,
            T.screen_security,
            T.screen_monitor,
            T.screen_doctor,
            T.screen_reports,
            T.screen_snapshots,
            T.screen_settings,
        ] {
            assert!(!title.is_empty());
        }
    }

    #[test]
    fn no_text_contains_terminal_escapes() {
        // Guards against accidental escape sequences in UI strings.
        let strings = [
            T.app_name,
            T.app_tagline,
            T.fw_scope_warning,
            T.too_small_hint,
            T.disc_local_only,
        ];
        for s in strings {
            assert!(!s.contains('\x1b'));
        }
    }
}
