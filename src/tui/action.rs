//! Typed UI actions.
//!
//! The command palette and confirmation dialogs produce `Action` values; the
//! application translates them into core calls. No shell strings are ever
//! constructed.

use crate::tui::state::{NetworkTab, Screen, SecurityTab};

#[derive(Debug, Clone, PartialEq)]
pub enum Action {
    Quit,
    Back,
    OpenScreen(Screen, Option<usize>),
    RefreshCurrent,
    RefreshAll,

    // Diagnostics
    RunDoctor,
    RunAudit,
    RunConnectivity,
    RunInterfaces,
    RunRoutes,
    RunDnsConfig,
    RunListening,
    RunFirewallStatus,
    RunIntegrityScan,
    RunExternalTools,
    RunLatency(String),
    RunTrace(String),
    RunDnsQuery(String, String),
    RunSpeedtest(String),

    // Discovery / scanning
    StartDiscovery,
    StartScan,
    CancelTask,

    // Monitoring
    StartMonitor,
    StopMonitor,
    TogglePause,
    MonitorIntervalDelta(i32),

    // Snapshots
    CreateSnapshot(Option<String>),
    DeleteSnapshot(usize),
    ExportSnapshot(usize, String),
    CompareSnapshots(usize, usize),

    // Reports
    GenerateReport(String, String, String),

    // Settings
    SaveSettings,

    // Firewall (destructive; always routed through confirmation)
    FirewallBlock(String),
    FirewallUnblock(String),

    // Navigation sugar used by the command palette
    SwitchNetworkTab(NetworkTab),
    SwitchSecurityTab(SecurityTab),
}

impl Action {
    /// Destructive actions must never run without an explicit confirmation.
    pub fn is_destructive(&self) -> bool {
        matches!(
            self,
            Action::FirewallBlock(_) | Action::FirewallUnblock(_) | Action::DeleteSnapshot(_)
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn destructive_actions_are_classified() {
        assert!(Action::FirewallBlock("203.0.113.1".into()).is_destructive());
        assert!(Action::FirewallUnblock("203.0.113.1".into()).is_destructive());
        assert!(Action::DeleteSnapshot(0).is_destructive());
        assert!(!Action::RunDoctor.is_destructive());
        assert!(!Action::StartScan.is_destructive());
    }
}
