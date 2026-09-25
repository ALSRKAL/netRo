//! Real-time monitoring with bounded overhead.
//!
//! Holds one `sysinfo::System` instance so that per-process CPU deltas are
//! computed correctly between samples. Network rates are derived from
//! cumulative counters and elapsed time.

use crate::model::*;
use crate::platform::shared;
use std::collections::HashMap;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sysinfo::{Components, Networks, ProcessesToUpdate, System};

#[derive(Debug, Clone)]
pub struct MonitorOptions {
    pub interval: Duration,
    /// `None` means run until interrupted.
    pub iterations: Option<u64>,
    pub top_n: usize,
    pub show_temperatures: bool,
    pub include_processes: bool,
}

impl Default for MonitorOptions {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(2),
            iterations: None,
            top_n: 5,
            show_temperatures: true,
            include_processes: true,
        }
    }
}

pub struct Monitor {
    system: System,
    networks: Networks,
    components: Components,
    last_net: HashMap<String, (u64, u64)>,
    last_net_time: Instant,
    top_n: usize,
    show_temperatures: bool,
    include_processes: bool,
}

impl Monitor {
    pub fn new(options: &MonitorOptions) -> Self {
        // Deliberately not `System::new_all()`: enumerating every process at
        // startup is expensive and unnecessary (prime() refreshes what is
        // actually sampled).
        let mut system = System::new();
        system.refresh_memory();
        system.refresh_cpu_all();
        let mut networks = Networks::new_with_refreshed_list();
        networks.refresh(true);
        let components = if options.show_temperatures {
            Components::new_with_refreshed_list()
        } else {
            Components::new()
        };
        let last_net = networks
            .list()
            .iter()
            .map(|(name, data)| {
                (
                    name.clone(),
                    (data.total_received(), data.total_transmitted()),
                )
            })
            .collect();
        Self {
            system,
            networks,
            components,
            last_net,
            last_net_time: Instant::now(),
            top_n: options.top_n,
            show_temperatures: options.show_temperatures,
            include_processes: options.include_processes,
        }
    }

    /// Take a fresh sample. This is a blocking CPU sampling window of ~250 ms
    /// on the first call (sysinfo requirement) and refresh-only afterwards.
    pub fn sample(&mut self) -> MonitorSample {
        self.system.refresh_cpu_usage();
        self.system.refresh_memory();
        // The process table is only refreshed when process metrics were
        // requested; it is by far the most expensive part of a sample.
        if self.include_processes {
            self.system.refresh_processes(ProcessesToUpdate::All, true);
        }
        self.networks.refresh(true);
        if self.show_temperatures {
            self.components.refresh(true);
        }

        let elapsed = self.last_net_time.elapsed().as_secs_f64().max(0.001);
        let mut network = Vec::new();
        for (name, data) in self.networks.list() {
            let rx = data.total_received();
            let tx = data.total_transmitted();
            let (prev_rx, prev_tx) = self.last_net.get(name).copied().unwrap_or((rx, tx));
            network.push(NetRate {
                interface: name.clone(),
                rx_bytes_per_sec: rx.saturating_sub(prev_rx) as f64 / elapsed,
                tx_bytes_per_sec: tx.saturating_sub(prev_tx) as f64 / elapsed,
                rx_total_bytes: rx,
                tx_total_bytes: tx,
            });
            self.last_net.insert(name.clone(), (rx, tx));
        }
        self.last_net_time = Instant::now();
        network.sort_by(|a, b| {
            (b.rx_bytes_per_sec + b.tx_bytes_per_sec)
                .partial_cmp(&(a.rx_bytes_per_sec + a.tx_bytes_per_sec))
                .unwrap_or(std::cmp::Ordering::Equal)
        });

        let temperatures = if self.show_temperatures {
            shared::temperatures()
        } else {
            Vec::new()
        };

        let (top_cpu, top_memory) = if self.include_processes {
            let mut by_cpu = shared::processes(&self.system, shared::ProcessSort::Cpu);
            by_cpu.truncate(self.top_n);
            let mut by_memory = shared::processes(&self.system, shared::ProcessSort::Memory);
            by_memory.truncate(self.top_n);
            (by_cpu, by_memory)
        } else {
            (Vec::new(), Vec::new())
        };

        let load = System::load_average();
        let has_load = load.one > 0.0 || load.five > 0.0 || load.fifteen > 0.0;

        MonitorSample {
            timestamp_epoch: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_secs() as i64)
                .unwrap_or(0),
            uptime_secs: System::uptime(),
            cpu_usage_percent: self.system.global_cpu_usage(),
            per_core_usage: self.system.cpus().iter().map(|c| c.cpu_usage()).collect(),
            load_average: has_load.then_some([load.one, load.five, load.fifteen]),
            memory_used_bytes: self.system.used_memory(),
            memory_total_bytes: self.system.total_memory(),
            memory_utilization_percent: crate::util::percent(
                self.system.used_memory(),
                self.system.total_memory(),
            ),
            swap_used_bytes: self.system.used_swap(),
            swap_total_bytes: self.system.total_swap(),
            network,
            temperatures,
            top_cpu,
            top_memory,
        }
    }

    /// Prime process CPU accounting. Call once, then sleep ~250 ms before the
    /// first sample for meaningful process percentages.
    pub fn prime(&mut self) {
        if !self.include_processes {
            // CPU-only mode: the sampling window inside the first `sample()`
            // is sufficient; no process scan is performed at all.
            self.system.refresh_cpu_all();
            std::thread::sleep(shared::CPU_SAMPLE_INTERVAL);
            self.system.refresh_cpu_usage();
            return;
        }
        self.system.refresh_processes(ProcessesToUpdate::All, true);
        std::thread::sleep(shared::CPU_SAMPLE_INTERVAL);
        self.system.refresh_cpu_usage();
        self.system.refresh_processes(ProcessesToUpdate::All, true);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn monitor_produces_real_samples() {
        let options = MonitorOptions {
            top_n: 3,
            ..MonitorOptions::default()
        };
        let mut monitor = Monitor::new(&options);
        monitor.prime();
        let sample = monitor.sample();
        assert!(sample.cpu_usage_percent >= 0.0);
        assert!(sample.memory_total_bytes > 0);
        assert!(!sample.per_core_usage.is_empty());
        assert!(sample.timestamp_epoch > 0);
        assert!(sample.top_cpu.len() <= 3);
        assert!(sample.top_memory.len() <= 3);
    }

    #[test]
    fn network_totals_are_cumulative_and_non_decreasing() {
        let options = MonitorOptions {
            include_processes: false,
            show_temperatures: false,
            ..MonitorOptions::default()
        };
        let mut monitor = Monitor::new(&options);
        let first = monitor.sample();
        std::thread::sleep(Duration::from_millis(50));
        let second = monitor.sample();
        for rate in &second.network {
            if let Some(previous) = first.network.iter().find(|r| r.interface == rate.interface) {
                assert!(rate.rx_total_bytes >= previous.rx_total_bytes);
                assert!(rate.tx_total_bytes >= previous.tx_total_bytes);
                assert!(rate.rx_bytes_per_sec >= 0.0);
                assert!(rate.tx_bytes_per_sec >= 0.0);
            }
        }
    }
}
