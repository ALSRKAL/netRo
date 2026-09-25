//! `netro monitor` and `netro tui`

use crate::cli::MonitorArgs;
use crate::commands::{envelope, rate, Context};
use crate::core::monitoring;
use crate::error::{ErrorCode, NetroError, Result};
use crate::output::OutputFormat;
use crate::util;
use std::io::IsTerminal;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub fn run(args: MonitorArgs, ctx: &Context) -> Result<()> {
    let interval_secs = args.interval.unwrap_or(ctx.config.monitor.interval_secs);
    if !(0.2..=3600.0).contains(&interval_secs) {
        return Err(NetroError::new(
            ErrorCode::ConfigError,
            format!("interval {interval_secs}s is out of range (0.2 - 3600)"),
        ));
    }
    let interval = Duration::from_secs_f64(interval_secs);
    let top_n = args.top.unwrap_or(ctx.config.monitor.top_n).max(1);

    let iterations = match (args.count, args.duration) {
        (Some(count), None) => Some(count.max(1)),
        (None, Some(duration)) => {
            if duration <= 0.0 {
                return Err(NetroError::new(
                    ErrorCode::ConfigError,
                    "duration must be positive",
                ));
            }
            Some((duration / interval_secs).ceil().max(1.0) as u64)
        }
        (Some(count), Some(_)) => Some(count.max(1)),
        (None, None) => None,
    };

    let options = monitoring::MonitorOptions {
        interval,
        iterations,
        top_n,
        show_temperatures: ctx.config.monitor.show_temperatures,
        include_processes: !args.no_processes,
    };

    let stop = Arc::new(AtomicBool::new(false));
    {
        let stop = stop.clone();
        let _ = ctrlc::set_handler(move || {
            stop.store(true, Ordering::SeqCst);
        });
    }

    let mut monitor = monitoring::Monitor::new(&options);
    let continuous = iterations.is_none();
    if ctx.output.format == OutputFormat::Text && !ctx.quiet {
        eprintln!(
            "netro monitor: interval {:.1}s{}{} — press Ctrl-C to stop",
            interval_secs,
            iterations
                .map(|n| format!(", {n} sample(s)"))
                .unwrap_or_default(),
            if continuous { " (continuous)" } else { "" }
        );
    }

    // Prime CPU accounting so the first sample is meaningful.
    monitor.prime();

    let mut count = 0u64;
    loop {
        if stop.load(Ordering::SeqCst) {
            break;
        }
        if let Some(limit) = iterations {
            if count >= limit {
                break;
            }
        }

        let started = Instant::now();
        let sample = monitor.sample();
        count += 1;

        if ctx.output.is_json() {
            crate::output::emit_json_line(&envelope("monitor", &sample))?;
        } else if ctx.output.format == OutputFormat::Csv {
            println!(
                "{},{:.1},{:.1},{},{},{},{},{:.1},{:.1}",
                sample.timestamp_epoch,
                sample.cpu_usage_percent,
                sample.memory_utilization_percent,
                sample.memory_used_bytes,
                sample.memory_total_bytes,
                sample.swap_used_bytes,
                sample.swap_total_bytes,
                sample
                    .network
                    .iter()
                    .map(|n| n.rx_bytes_per_sec)
                    .sum::<f64>(),
                sample
                    .network
                    .iter()
                    .map(|n| n.tx_bytes_per_sec)
                    .sum::<f64>()
            );
        } else {
            render_text(&sample, ctx, &args, count, iterations);
        }

        // Account for time spent sampling to keep the cadence close to the
        // requested interval without busy-waiting.
        let elapsed = started.elapsed();
        if elapsed < interval {
            let mut remaining = interval - elapsed;
            while remaining > Duration::ZERO && !stop.load(Ordering::SeqCst) {
                let step = remaining.min(Duration::from_millis(100));
                std::thread::sleep(step);
                remaining = remaining.saturating_sub(step);
            }
        }
    }

    if ctx.output.format == OutputFormat::Text && !ctx.quiet {
        eprintln!("monitor stopped after {count} sample(s)");
    }
    Ok(())
}

fn render_text(
    sample: &crate::model::MonitorSample,
    ctx: &Context,
    args: &MonitorArgs,
    count: u64,
    iterations: Option<u64>,
) {
    let clear = std::io::stdout().is_terminal() && !ctx.quiet;
    if clear {
        print!("\x1b[2J\x1b[H");
    }
    let progress = iterations
        .map(|n| format!("sample {count}/{n}"))
        .unwrap_or_else(|| format!("sample {count}"));
    println!(
        "netro monitor  {}  uptime {}",
        progress,
        util::human_uptime(sample.uptime_secs)
    );
    println!(
        "CPU    {:>5.1}%{}",
        sample.cpu_usage_percent,
        sample
            .load_average
            .map(|l| format!("   load {:.2} {:.2} {:.2}", l[0], l[1], l[2]))
            .unwrap_or_default()
    );
    if sample.per_core_usage.len() <= 16 && !sample.per_core_usage.is_empty() {
        let cores: Vec<String> = sample
            .per_core_usage
            .iter()
            .enumerate()
            .map(|(i, v)| format!("c{:<2}{:>5.1}%", i, v))
            .collect();
        println!("       {}", cores.join(" "));
    }
    println!(
        "MEM    {:>5.1}%  {} / {}",
        sample.memory_utilization_percent,
        util::human_bytes(sample.memory_used_bytes),
        util::human_bytes(sample.memory_total_bytes)
    );
    if sample.swap_total_bytes > 0 {
        println!(
            "SWAP   {:>5.1}%  {} / {}",
            util::percent(sample.swap_used_bytes, sample.swap_total_bytes),
            util::human_bytes(sample.swap_used_bytes),
            util::human_bytes(sample.swap_total_bytes)
        );
    }
    if !sample.network.is_empty() {
        println!("NET");
        let mut shown = 0;
        for net in &sample.network {
            if args.active_net && net.rx_bytes_per_sec < 1.0 && net.tx_bytes_per_sec < 1.0 {
                continue;
            }
            println!(
                "  {:<16} rx {:>12}  tx {:>12}",
                net.interface,
                rate(net.rx_bytes_per_sec),
                rate(net.tx_bytes_per_sec)
            );
            shown += 1;
            if shown >= 8 {
                break;
            }
        }
        if shown == 0 {
            println!("  (no active traffic)");
        }
    }
    if !sample.temperatures.is_empty() {
        let temps: Vec<String> = sample
            .temperatures
            .iter()
            .take(4)
            .map(|t| format!("{} {:.0}C", t.label, t.current_c))
            .collect();
        println!("TEMP   {}", temps.join(", "));
    }
    if !sample.top_cpu.is_empty() {
        println!("TOP CPU");
        for process in &sample.top_cpu {
            println!(
                "  {:<12} pid {:<7} {:>6.1}%  {}",
                truncate(&process.name, 12),
                process.pid,
                process.cpu_percent,
                util::human_bytes(process.memory_bytes)
            );
        }
    }
    if !sample.top_memory.is_empty() {
        println!("TOP MEMORY");
        for process in &sample.top_memory {
            println!(
                "  {:<12} pid {:<7} {:>8}  {:.1}% cpu",
                truncate(&process.name, 12),
                process.pid,
                util::human_bytes(process.memory_bytes),
                process.cpu_percent
            );
        }
    }
}

fn truncate(value: &str, max: usize) -> String {
    if value.chars().count() <= max {
        value.to_string()
    } else {
        let mut s: String = value.chars().take(max.saturating_sub(1)).collect();
        s.push('…');
        s
    }
}
