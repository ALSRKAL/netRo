//! `netro system`

use crate::cli::SystemArgs;
use crate::commands::{envelope, Context};
use crate::error::Result;
use crate::output::OutputFormat;
use crate::platform::platform;
use crate::util;
use serde_json::json;

pub fn run(args: SystemArgs, ctx: &Context) -> Result<()> {
    let selective = args.cpu || args.memory || args.storage || args.gpu;
    let want_cpu = !selective || args.cpu;
    let want_memory = !selective || args.memory;
    let want_storage = !selective || args.storage;
    let want_gpu = !selective || args.gpu;

    // Only fetch what is requested: CPU/memory sampling costs a measuring
    // window each.
    let os = platform().os_info()?;
    let cpu = if want_cpu {
        Some(platform().cpu_info()?)
    } else {
        None
    };
    let memory = if want_memory {
        Some(platform().memory_info()?)
    } else {
        None
    };
    let disks = if want_storage {
        Some(platform().disks()?)
    } else {
        None
    };
    let gpus = if want_gpu {
        Some(platform().gpu_info()?)
    } else {
        None
    };

    if ctx.output.is_json() {
        let mut data = serde_json::Map::new();
        data.insert("platform".into(), json!(platform().id()));
        data.insert(
            "generated_at_epoch".into(),
            json!(chrono::Utc::now().timestamp()),
        );
        data.insert("os".into(), serde_json::to_value(&os)?);
        data.insert(
            "cpu".into(),
            cpu.as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        );
        data.insert(
            "memory".into(),
            memory
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        );
        data.insert(
            "disks".into(),
            disks
                .as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        );
        data.insert(
            "gpus".into(),
            gpus.as_ref()
                .map(serde_json::to_value)
                .transpose()?
                .unwrap_or(serde_json::Value::Null),
        );
        return crate::output::emit_json(&envelope("system", serde_json::Value::Object(data)));
    }

    if ctx.output.is_csv() {
        let mut rows: Vec<Vec<String>> = Vec::new();
        rows.push(vec![
            "os".into(),
            os.long_name.clone().or(os.name.clone()).unwrap_or_default(),
            os.version.clone().unwrap_or_default(),
            os.arch.clone(),
        ]);
        rows.push(vec![
            "host".into(),
            os.hostname.clone().unwrap_or_default(),
            os.kernel.clone().unwrap_or_default(),
            util::human_uptime(os.uptime_secs),
        ]);
        if let Some(cpu) = &cpu {
            rows.push(vec![
                "cpu".into(),
                cpu.model.clone().unwrap_or_default(),
                format!("{}", cpu.logical_cores),
                format!("{:.1}%", cpu.usage_percent.unwrap_or(0.0)),
            ]);
        }
        if let Some(memory) = &memory {
            rows.push(vec![
                "memory".into(),
                util::human_bytes(memory.total_bytes),
                util::human_bytes(memory.used_bytes),
                format!("{:.1}%", memory.utilization_percent),
            ]);
        }
        if let Some(disks) = &disks {
            for disk in disks {
                rows.push(vec![
                    "disk".into(),
                    disk.mount_point.clone(),
                    util::human_bytes(disk.used_bytes),
                    format!("{:.1}%", disk.utilization_percent),
                ]);
            }
        }
        if let Some(gpus) = &gpus {
            for gpu in gpus {
                rows.push(vec![
                    "gpu".into(),
                    gpu.model.clone().unwrap_or_default(),
                    gpu.vendor.clone().unwrap_or_default(),
                    gpu.source.clone(),
                ]);
            }
        }
        return crate::output::emit_csv(&["section", "name", "detail", "value"], &rows);
    }

    println!("System");
    println!(
        "  os:         {} {}",
        os.long_name
            .clone()
            .or(os.name.clone())
            .unwrap_or_else(|| "unknown".into()),
        os.version.clone().unwrap_or_default()
    );
    println!(
        "  kernel:     {}",
        os.kernel.clone().unwrap_or_else(|| "unknown".into())
    );
    println!("  arch:       {}", os.arch);
    println!(
        "  hostname:   {}",
        os.hostname.clone().unwrap_or_else(|| "unknown".into())
    );
    println!("  uptime:     {}", util::human_uptime(os.uptime_secs));
    if let Some(virt) = &os.virtualization {
        println!("  virt:       {virt}");
    }
    println!();

    if let Some(cpu) = &cpu {
        println!("CPU");
        println!(
            "  model:        {}",
            cpu.model.clone().unwrap_or_else(|| "unknown".into())
        );
        println!(
            "  architecture: {} ({} logical, {} physical)",
            cpu.arch,
            cpu.logical_cores,
            cpu.physical_cores
                .map(|c| c.to_string())
                .unwrap_or_else(|| "unknown".into())
        );
        println!("  usage:        {:.1}%", cpu.usage_percent.unwrap_or(0.0));
        if let Some(freq) = cpu.frequency_mhz {
            println!("  frequency:    {freq} MHz");
        }
        if let Some(load) = cpu.load_average {
            println!(
                "  load average: {:.2} {:.2} {:.2}",
                load[0], load[1], load[2]
            );
        }
        if !cpu.temperatures_c.is_empty() {
            println!("  temperatures:");
            for temp in &cpu.temperatures_c {
                println!(
                    "    {:<24} {:.1} C{}",
                    temp.label,
                    temp.current_c,
                    temp.critical_c
                        .map(|c| format!(" (critical {c:.0} C)"))
                        .unwrap_or_default()
                );
            }
        }
        println!();
    }

    if let Some(memory) = &memory {
        println!("Memory");
        println!("  total:     {}", util::human_bytes(memory.total_bytes));
        println!(
            "  used:      {} ({:.1}%)",
            util::human_bytes(memory.used_bytes),
            memory.utilization_percent
        );
        println!("  available: {}", util::human_bytes(memory.available_bytes));
        if memory.swap_total_bytes > 0 {
            println!(
                "  swap:      {} of {} ({:.1}%)",
                util::human_bytes(memory.swap_used_bytes),
                util::human_bytes(memory.swap_total_bytes),
                memory.swap_utilization_percent
            );
        }
        println!();
    }

    if let Some(disks) = &disks {
        if !disks.is_empty() {
            println!("Storage");
            let mut table = crate::output::Table::new(&[
                "Mount",
                "Filesystem",
                "Total",
                "Used",
                "Free",
                "Use%",
                "Flags",
            ]);
            for disk in disks {
                table.row(&[
                    disk.mount_point.clone(),
                    disk.file_system.clone(),
                    util::human_bytes(disk.total_bytes),
                    util::human_bytes(disk.used_bytes),
                    util::human_bytes(disk.free_bytes),
                    format!("{:.1}", disk.utilization_percent),
                    format!(
                        "{}{}{}",
                        if disk.read_only { "read-only " } else { "" },
                        if disk.removable { "removable " } else { "" },
                        disk.kind.clone().unwrap_or_default()
                    ),
                ]);
            }
            print!("{}", table.render());
            println!();
        }
    }

    if let Some(gpus) = &gpus {
        if !gpus.is_empty() {
            println!("GPU");
            let mut table = crate::output::Table::new(&[
                "Vendor", "Model", "VRAM", "Driver", "Util%", "Temp", "Power", "Backend", "Source",
            ]);
            for gpu in gpus {
                table.row(&[
                    gpu.vendor.clone().unwrap_or_else(|| "-".into()),
                    gpu.model.clone().unwrap_or_else(|| "-".into()),
                    gpu.vram_bytes
                        .map(util::human_bytes)
                        .unwrap_or_else(|| "-".into()),
                    gpu.driver.clone().unwrap_or_else(|| "-".into()),
                    gpu.utilization_percent
                        .map(|v| format!("{v:.0}"))
                        .unwrap_or_else(|| "-".into()),
                    gpu.temperature_c
                        .map(|v| format!("{v:.0}"))
                        .unwrap_or_else(|| "-".into()),
                    gpu.power_watts
                        .map(|v| format!("{v:.0}W"))
                        .unwrap_or_else(|| "-".into()),
                    gpu.compute_backend.clone().unwrap_or_else(|| "-".into()),
                    gpu.source.clone(),
                ]);
            }
            print!("{}", table.render());
            for gpu in gpus {
                if let Some(note) = &gpu.note {
                    println!("note: {note}");
                }
            }
            println!();
        } else if ctx.output.format == OutputFormat::Text {
            println!("GPU: none detected");
        }
    }
    Ok(())
}
