//! System screen: OS/CPU/memory/storage/GPU plus the live process table.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::text::T;
use crate::tui::widgets::truncate;
use crate::util;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    if area.width >= 96 {
        let columns = Layout::default()
            .direction(Direction::Horizontal)
            .constraints([Constraint::Percentage(46), Constraint::Percentage(54)])
            .split(area);
        render_hardware(ui, frame, columns[0]);
        render_processes(ui, frame, columns[1]);
    } else {
        let rows = Layout::default()
            .direction(Direction::Vertical)
            .constraints([Constraint::Percentage(52), Constraint::Percentage(48)])
            .split(area);
        render_hardware(ui, frame, rows[0]);
        render_processes(ui, frame, rows[1]);
    }
}

fn render_hardware(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(
            format!(" {} ", T.screen_system),
            ui.theme.muted,
        ));
    let mut lines: Vec<Line> = Vec::new();
    let Some(system) = &ui.state.caches.system else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)).block(block),
            area,
        );
        return;
    };
    let system = &system.value;

    lines.push(Line::styled(T.sys_cpu.to_string(), ui.theme.muted));
    if let Some(model) = &system.cpu.model {
        lines.push(Line::styled(format!(" {model}"), ui.theme.text));
    }
    lines.push(Line::styled(
        format!(
            " {} logical / {} physical",
            system.cpu.logical_cores,
            system
                .cpu
                .physical_cores
                .map(|c| c.to_string())
                .unwrap_or_else(|| "?".into())
        ),
        ui.theme.muted,
    ));
    lines.push(Line::from(vec![
        Span::styled(format!(" {:<12}", T.sys_usage), ui.theme.muted),
        Span::styled(
            format!("{:.1}%", system.cpu.usage_percent.unwrap_or(0.0)),
            ui.theme.text,
        ),
    ]));
    if let Some(frequency) = system.cpu.frequency_mhz {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", T.sys_frequency), ui.theme.muted),
            Span::styled(format!("{frequency} MHz"), ui.theme.text),
        ]));
    }
    if let Some(load) = system.cpu.load_average {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", T.sys_load), ui.theme.muted),
            Span::styled(
                format!("{:.2} {:.2} {:.2}", load[0], load[1], load[2]),
                ui.theme.text,
            ),
        ]));
    }
    for temperature in system.cpu.temperatures_c.iter().take(3) {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<12}", truncate(&temperature.label, 12, ui.theme)),
                ui.theme.muted,
            ),
            Span::styled(format!("{:.0} C", temperature.current_c), ui.theme.text),
        ]));
    }
    lines.push(Line::from(""));

    lines.push(Line::styled(T.sys_memory.to_string(), ui.theme.muted));
    for (label, value) in [
        (T.sys_total, util::human_bytes(system.memory.total_bytes)),
        (T.sys_used, util::human_bytes(system.memory.used_bytes)),
        (
            T.sys_available,
            util::human_bytes(system.memory.available_bytes),
        ),
        (
            T.sys_swap,
            if system.memory.swap_total_bytes > 0 {
                format!(
                    "{} / {}",
                    util::human_bytes(system.memory.swap_used_bytes),
                    util::human_bytes(system.memory.swap_total_bytes)
                )
            } else {
                "not configured".into()
            },
        ),
    ] {
        lines.push(Line::from(vec![
            Span::styled(format!(" {:<12}", label), ui.theme.muted),
            Span::styled(value, ui.theme.text),
        ]));
    }
    lines.push(Line::from(""));

    lines.push(Line::styled(T.sys_storage.to_string(), ui.theme.muted));
    for disk in system.disks.iter().take(5) {
        lines.push(Line::from(vec![
            Span::styled(
                format!(" {:<16}", truncate(&disk.mount_point, 16, ui.theme)),
                ui.theme.muted,
            ),
            Span::styled(
                format!(
                    "{:>5.1}%  {} free",
                    disk.utilization_percent,
                    util::human_bytes(disk.free_bytes)
                ),
                if disk.utilization_percent >= 90.0 {
                    ui.theme.error
                } else if disk.utilization_percent >= 80.0 {
                    ui.theme.warning
                } else {
                    ui.theme.text
                },
            ),
        ]));
    }
    if system.disks.len() > 5 {
        lines.push(Line::styled(
            format!(" ... {} more", system.disks.len() - 5),
            ui.theme.muted,
        ));
    }

    if !system.gpus.is_empty() {
        lines.push(Line::from(""));
        lines.push(Line::styled(T.sys_gpu.to_string(), ui.theme.muted));
        for gpu in system.gpus.iter().take(3) {
            lines.push(Line::styled(
                format!(
                    " {} {}",
                    gpu.vendor.clone().unwrap_or_default(),
                    gpu.model.clone().unwrap_or_else(|| "unknown".into())
                ),
                ui.theme.text,
            ));
            let mut details = Vec::new();
            if let Some(driver) = &gpu.driver {
                details.push(format!("{} {driver}", T.sys_driver));
            }
            if let Some(utilization) = gpu.utilization_percent {
                details.push(format!(
                    "{:.0}% {}",
                    utilization,
                    T.sys_utilization.to_lowercase()
                ));
            }
            if let Some(temperature) = gpu.temperature_c {
                details.push(format!("{temperature:.0} C"));
            }
            if let Some(power) = gpu.power_watts {
                details.push(format!("{power:.0} W"));
            }
            if details.is_empty() {
                details.push(gpu.source.clone());
            }
            lines.push(Line::styled(
                format!("  {}", details.join("  ")),
                ui.theme.muted,
            ));
        }
    }
    frame.render_widget(Paragraph::new(lines).block(block), area);
}

fn render_processes(ui: &Ui, frame: &mut Frame, area: Rect) {
    let title = if ui.state.filtering {
        format!(" {} — filter: {}_ ", T.sys_processes, ui.state.filter)
    } else if !ui.state.filter.is_empty() {
        format!(" {} — filter: {} ", T.sys_processes, ui.state.filter)
    } else {
        format!(" {} ", T.sys_processes)
    };
    let block = Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(title, ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let processes = match &ui.state.caches.processes {
        Some(fresh) => fresh,
        None => {
            frame.render_widget(
                Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
                inner,
            );
            return;
        }
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = processes
        .value
        .iter()
        .filter(|process| {
            filter.is_empty()
                || process.name.to_ascii_lowercase().contains(&filter)
                || process
                    .user
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
        })
        .take(inner.height as usize)
        .map(|process| {
            vec![
                process.pid.to_string(),
                truncate(&process.name, 18, ui.theme),
                format!("{:.1}", process.cpu_percent),
                util::human_bytes(process.memory_bytes),
                process.user.clone().unwrap_or_else(|| "-".into()),
                util::human_uptime(process.run_time_secs),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                T.empty_no_processes.to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    let table = list_table(
        ui,
        &["PID", "Process", "CPU%", "Memory", "User", "Runtime"],
        rows,
        Some(ui.state.system_selected),
        &[
            Constraint::Length(7),
            Constraint::Min(12),
            Constraint::Length(6),
            Constraint::Length(9),
            Constraint::Length(10),
            Constraint::Length(8),
        ],
    );
    frame.render_widget(table, inner);
}
