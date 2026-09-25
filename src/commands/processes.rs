//! `netro processes`

use crate::cli::ProcessesArgs;
use crate::commands::{emit_table, envelope, Context};
use crate::error::{ErrorCode, NetroError, Result};
use crate::platform::platform;
use crate::util;

pub fn run(args: ProcessesArgs, ctx: &Context) -> Result<()> {
    let mut processes = platform().processes()?;

    let sort = args.sort.to_ascii_lowercase();
    match sort.as_str() {
        "cpu" => processes.sort_by(|a, b| {
            b.cpu_percent
                .partial_cmp(&a.cpu_percent)
                .unwrap_or(std::cmp::Ordering::Equal)
        }),
        "memory" | "mem" => processes.sort_by(|a, b| b.memory_bytes.cmp(&a.memory_bytes)),
        "pid" => processes.sort_by_key(|p| p.pid),
        "recent" | "start" => processes.sort_by(|a, b| b.start_time_epoch.cmp(&a.start_time_epoch)),
        "name" => processes.sort_by(|a, b| a.name.cmp(&b.name)),
        other => {
            return Err(NetroError::new(
                ErrorCode::InvalidTarget,
                format!("unknown sort '{other}' (expected cpu, memory, pid, recent or name)"),
            ))
        }
    }

    if let Some(pid) = args.pid {
        processes.retain(|p| p.pid == pid);
    }
    if let Some(name) = &args.name {
        let needle = name.to_ascii_lowercase();
        processes.retain(|p| {
            p.name.to_ascii_lowercase().contains(&needle)
                || p.cmdline
                    .as_deref()
                    .map(|c| c.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
        });
    }

    let mut network_note = None;
    if args.network {
        match platform().connections() {
            Ok(connections) => {
                let active: std::collections::BTreeSet<u32> =
                    connections.iter().filter_map(|c| c.pid).collect();
                processes.retain(|p| active.contains(&p.pid));
                network_note = Some(format!(
                    "{} process(es) with active connections",
                    processes.len()
                ));
            }
            Err(e) => {
                network_note = Some(format!("network mapping unavailable: {e}"));
                processes.clear();
            }
        }
    }

    processes.truncate(args.limit);

    if ctx.output.is_json() {
        let mut envelope_value = envelope("processes", &processes);
        if let Some(note) = &network_note {
            envelope_value["note"] = serde_json::Value::String(note.clone());
        }
        return crate::output::emit_json(&envelope_value);
    }

    if let Some(note) = &network_note {
        ctx.note(note);
    }
    let rows: Vec<Vec<String>> = processes
        .iter()
        .map(|p| {
            vec![
                p.pid.to_string(),
                p.ppid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                p.name.clone(),
                p.user.clone().unwrap_or_else(|| "-".into()),
                format!("{:.1}", p.cpu_percent),
                util::human_bytes(p.memory_bytes),
                util::human_uptime(p.run_time_secs),
                p.status.clone(),
                p.exe.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "PID",
            "PPID",
            "Name",
            "User",
            "CPU%",
            "Memory",
            "Runtime",
            "Status",
            "Executable",
        ],
        &rows,
        None,
    )
}
