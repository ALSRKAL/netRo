//! Background task scheduling.
//!
//! Every potentially slow diagnostic runs in a worker thread and reports a
//! typed result back to the UI thread. The render loop never performs IO.
//! Tasks support cooperative cancellation and real progress reporting.

use crate::core::discovery::DiscoveryProgress;
use crate::core::security::{ExternalToolResult, SecurityAudit};
use crate::core::snapshot::{Snapshot, SnapshotDiff};
use crate::core::speedtest::SpeedTestResult;
use crate::core::{dns::DnsResponse, scan::ScanProgress};
use crate::error::NetroError;
use crate::model::*;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::Arc;
use std::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TaskKind {
    System,
    NetworkBasics,
    Connectivity,
    Audit,
    Doctor,
    Connections,
    Processes,
    Listening,
    FirewallStatus,
    FirewallRules,
    Discovery,
    Scan,
    Monitor,
    SnapshotCreate,
    IntegrityBaseline,
    IntegrityScan,
    ExternalTools,
    Report,
    FirewallChange,
    Latency,
    Trace,
    DnsQuery,
    Speedtest,
    ConfigSave,
    ExportScan,
}

impl TaskKind {
    pub fn label(self) -> &'static str {
        match self {
            TaskKind::System => "collecting system information",
            TaskKind::NetworkBasics => "collecting network information",
            TaskKind::Connectivity => "checking connectivity",
            TaskKind::Audit => "running security audit",
            TaskKind::Doctor => "running diagnostics",
            TaskKind::Connections => "listing connections",
            TaskKind::Processes => "collecting process data",
            TaskKind::Listening => "enumerating listening sockets",
            TaskKind::FirewallStatus => "inspecting firewall",
            TaskKind::FirewallRules => "reading firewall rules",
            TaskKind::Discovery => "discovering network hosts",
            TaskKind::Scan => "scanning ports",
            TaskKind::Monitor => "monitoring",
            TaskKind::SnapshotCreate => "creating snapshot",
            TaskKind::IntegrityBaseline => "creating integrity baseline",
            TaskKind::IntegrityScan => "scanning file integrity",
            TaskKind::ExternalTools => "running external security tools",
            TaskKind::Report => "generating report",
            TaskKind::FirewallChange => "applying firewall change",
            TaskKind::Latency => "measuring latency",
            TaskKind::Trace => "tracing route",
            TaskKind::DnsQuery => "resolving name",
            TaskKind::Speedtest => "measuring throughput",
            TaskKind::ConfigSave => "saving configuration",
            TaskKind::ExportScan => "exporting scan results",
        }
    }

    /// Tasks that must not run concurrently with themselves.
    pub fn is_exclusive(self) -> bool {
        matches!(
            self,
            TaskKind::Scan
                | TaskKind::Discovery
                | TaskKind::Doctor
                | TaskKind::Monitor
                | TaskKind::Report
                | TaskKind::ExternalTools
                | TaskKind::IntegrityScan
        )
    }

    /// Tasks the user can cancel with Esc (long-running or continuous).
    pub fn is_cancellable(self) -> bool {
        self.is_exclusive() || self.is_expensive()
    }

    pub fn is_expensive(self) -> bool {
        matches!(
            self,
            TaskKind::Scan
                | TaskKind::Discovery
                | TaskKind::Doctor
                | TaskKind::Report
                | TaskKind::ExternalTools
        )
    }
}

/// Typed task payloads. No `Any`/downcasts: the compiler checks the wiring
/// between workers, state updates and components.
pub enum TaskResult {
    Os(Box<OsInfo>),
    System(Box<SystemSnapshot>),
    Interfaces(Vec<Interface>),
    Routes(Vec<Route>),
    DnsConfig(Box<DnsConfig>),
    Connectivity(Box<ConnectivityReport>),
    Audit(Box<SecurityAudit>),
    Doctor(Box<DoctorReport>),
    Connections(Vec<Connection>),
    Processes(Vec<ProcessInfo>),
    Listening(Vec<ListeningPort>),
    Firewall(Box<FirewallStatus>),
    FirewallRules(Vec<FirewallRule>),
    Discovery(Box<DiscoveryReport>),
    Scan(Box<ScanReport>),
    MonitorStopped,
    SnapshotCreated(PathBuf, Box<Snapshot>),
    IntegrityBaseline(Box<IntegrityBaseline>),
    IntegrityReport(Box<IntegrityReport>),
    ExternalTools(Vec<ExternalToolResult>),
    ReportWritten(PathBuf, String),
    FirewallChanged(Box<FirewallChange>),
    Latency(Box<PingResult>),
    Trace(Box<TraceResult>),
    DnsQuery(Box<DnsResponse>),
    Speedtest(Box<SpeedTestResult>),
    ConfigSaved(PathBuf),
    BaselineMissing,
    SnapshotDiff(Box<SnapshotDiff>),
    Exported(PathBuf),
}

#[derive(Debug)]
pub enum TaskProgress {
    Check(Box<CheckResult>),
    Scan(ScanProgress),
    Discovery(DiscoveryProgress),
    Monitor(Box<MonitorSample>),
    Message(String),
}

pub enum TaskPayload {
    Progress(TaskProgress),
    Done(Box<TaskResult>),
    Failed(NetroError),
}

pub struct TaskEvent {
    pub task: u64,
    pub kind: TaskKind,
    pub payload: TaskPayload,
}

struct RunningTask {
    id: u64,
    kind: TaskKind,
    cancel: Arc<AtomicBool>,
    started: Instant,
}

/// Context handed to worker closures: cooperative cancellation plus a typed
/// progress reporter. Cloning is cheap and safe.
#[derive(Clone)]
pub struct TaskContext {
    cancel: Arc<AtomicBool>,
    reporter: Arc<dyn Fn(TaskProgress) + Send + Sync>,
}

impl TaskContext {
    pub fn is_cancelled(&self) -> bool {
        self.cancel.load(Ordering::Relaxed)
    }

    pub fn cancel_flag(&self) -> Arc<AtomicBool> {
        self.cancel.clone()
    }

    pub fn progress(&self, progress: TaskProgress) {
        (self.reporter)(progress);
    }
}

pub struct TaskManager {
    next_id: u64,
    running: Vec<RunningTask>,
    tx: Sender<TaskEvent>,
    rx: Receiver<TaskEvent>,
}

impl Default for TaskManager {
    fn default() -> Self {
        Self::new()
    }
}

impl TaskManager {
    pub fn new() -> Self {
        let (tx, rx) = channel();
        Self {
            next_id: 1,
            running: Vec::new(),
            tx,
            rx,
        }
    }

    pub fn spawn<F>(&mut self, kind: TaskKind, work: F) -> u64
    where
        F: FnOnce(TaskContext) -> Result<TaskResult, NetroError> + Send + 'static,
    {
        let id = self.next_id;
        self.next_id += 1;
        let cancel = Arc::new(AtomicBool::new(false));
        self.running.push(RunningTask {
            id,
            kind,
            cancel: cancel.clone(),
            started: Instant::now(),
        });

        let tx = self.tx.clone();
        std::thread::spawn(move || {
            let reporter_tx = tx.clone();
            let reporter = Arc::new(move |progress: TaskProgress| {
                let _ = reporter_tx.send(TaskEvent {
                    task: id,
                    kind,
                    payload: TaskPayload::Progress(progress),
                });
            });
            let context = TaskContext {
                cancel: cancel.clone(),
                reporter: reporter.clone(),
            };
            let payload = match work(context) {
                Ok(result) => TaskPayload::Done(Box::new(result)),
                Err(error) => TaskPayload::Failed(error),
            };
            let _ = tx.send(TaskEvent {
                task: id,
                kind,
                payload,
            });
        });
        id
    }

    /// Collect all pending events; finished tasks are dropped from the running
    /// set here (and only here) so `is_running` stays accurate.
    pub fn drain(&mut self) -> Vec<TaskEvent> {
        let mut events = Vec::new();
        while let Ok(event) = self.rx.try_recv() {
            if matches!(event.payload, TaskPayload::Done(_) | TaskPayload::Failed(_)) {
                self.running.retain(|t| t.id != event.task);
            }
            events.push(event);
        }
        events
    }

    pub fn is_running(&self, kind: TaskKind) -> bool {
        self.running.iter().any(|t| t.kind == kind)
    }

    pub fn running_kinds(&self) -> Vec<(TaskKind, u64)> {
        self.running.iter().map(|t| (t.kind, t.id)).collect()
    }

    pub fn oldest_expensive(&self) -> Option<(TaskKind, u64)> {
        self.running
            .iter()
            .filter(|t| t.kind.is_cancellable())
            .min_by_key(|t| t.started)
            .map(|t| (t.kind, t.id))
    }

    pub fn cancel(&mut self, id: u64) {
        if let Some(task) = self.running.iter().find(|t| t.id == id) {
            task.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn cancel_kind(&mut self, kind: TaskKind) {
        for task in self.running.iter().filter(|t| t.kind == kind) {
            task.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn cancel_all(&mut self) {
        for task in &self.running {
            task.cancel.store(true, Ordering::Relaxed);
        }
    }

    pub fn active_count(&self) -> usize {
        self.running.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tasks_report_results_and_clear_running_state() {
        let mut manager = TaskManager::new();
        let id = manager.spawn(TaskKind::Connectivity, |_ctx| {
            Ok(TaskResult::Interfaces(Vec::new()))
        });
        assert!(manager.is_running(TaskKind::Connectivity));
        assert!(manager.running_kinds().iter().any(|(_, t)| *t == id));

        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut done = false;
        while Instant::now() < deadline {
            for event in manager.drain() {
                if matches!(event.payload, TaskPayload::Done(_)) {
                    done = true;
                }
            }
            if done {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(done, "task never finished");
        assert!(!manager.is_running(TaskKind::Connectivity));
    }

    #[test]
    fn cancellation_flag_is_visible_to_worker() {
        let mut manager = TaskManager::new();
        let id = manager.spawn(TaskKind::Scan, |ctx| {
            let deadline = Instant::now() + std::time::Duration::from_secs(2);
            while !ctx.is_cancelled() {
                if Instant::now() > deadline {
                    return Err(NetroError::new(
                        crate::error::ErrorCode::Timeout,
                        "not cancelled in time",
                    ));
                }
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Ok(TaskResult::MonitorStopped)
        });
        manager.cancel(id);
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut finished = false;
        while Instant::now() < deadline {
            for event in manager.drain() {
                if matches!(event.payload, TaskPayload::Done(_)) {
                    finished = true;
                }
            }
            if finished {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(finished);
    }

    #[test]
    fn failures_are_reported_not_swallowed() {
        let mut manager = TaskManager::new();
        let _ = manager.spawn(TaskKind::Audit, |_ctx| {
            Err(NetroError::new(
                crate::error::ErrorCode::PermissionDenied,
                "nope",
            ))
        });
        let deadline = Instant::now() + std::time::Duration::from_secs(5);
        let mut error = None;
        while Instant::now() < deadline {
            for event in manager.drain() {
                if let TaskPayload::Failed(e) = event.payload {
                    error = Some(e);
                }
            }
            if error.is_some() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let error = error.expect("failure event missing");
        assert_eq!(error.code(), crate::error::ErrorCode::PermissionDenied);
    }

    #[test]
    fn exclusivity_classification() {
        assert!(TaskKind::Scan.is_exclusive());
        assert!(TaskKind::Doctor.is_exclusive());
        assert!(!TaskKind::Processes.is_exclusive());
        assert!(TaskKind::Report.is_expensive());
        assert!(!TaskKind::Connections.is_expensive());
    }
}
