//! `netro integrity ...`

use crate::cli::{IntegrityArgs, IntegrityCommand};
use crate::commands::{emit_table, envelope, Context};
use crate::core::integrity;
use crate::error::Result;
use crate::model::IntegrityStatus;
use crate::output::OutputFormat;
use crate::platform::platform;

fn effective_paths(ctx: &Context, override_paths: &[String]) -> Vec<String> {
    if !override_paths.is_empty() {
        return override_paths.to_vec();
    }
    if !ctx.config.integrity.paths.is_empty() {
        return ctx.config.integrity.paths.clone();
    }
    platform().default_integrity_paths()
}

fn max_size(ctx: &Context, override_mb: Option<u64>) -> u64 {
    let mb = override_mb.unwrap_or(ctx.config.integrity.max_file_size_mb.max(64));
    mb * 1024 * 1024
}

pub fn run(args: IntegrityArgs, ctx: &Context) -> Result<()> {
    match args.command {
        IntegrityCommand::Baseline { paths, max_size_mb } => baseline(&paths, max_size_mb, ctx),
        IntegrityCommand::Scan { max_size_mb, all } => scan(max_size_mb, all, ctx),
        IntegrityCommand::Show => show(ctx),
    }
}

fn baseline(paths: &[String], max_size_mb: Option<u64>, ctx: &Context) -> Result<()> {
    let paths = effective_paths(ctx, paths);
    let baseline = integrity::create_baseline(&paths, max_size(ctx, max_size_mb))?;
    let path = integrity::save_baseline(&baseline)?;
    let hashed = baseline
        .entries
        .iter()
        .filter(|e| e.sha256.is_some())
        .count();
    let skipped = baseline.entries.len() - hashed;

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope(
            "integrity.baseline.create",
            serde_json::json!({
                "baseline_path": path.display().to_string(),
                "created_epoch": baseline.created_epoch,
                "hostname": baseline.hostname,
                "paths": baseline.paths,
                "files": baseline.entries.len(),
                "hashed": hashed,
                "skipped": skipped,
            }),
        ));
    }
    println!("baseline created at {}", path.display());
    println!(
        "{} path(s), {} file(s): {} hashed, {} skipped (unreadable or too large)",
        baseline.paths.len(),
        baseline.entries.len(),
        hashed,
        skipped
    );
    for entry in &baseline.entries {
        if let Some(error) = &entry.error {
            eprintln!("skipped {}: {error}", entry.path);
        }
    }
    Ok(())
}

fn scan(max_size_mb: Option<u64>, all: bool, ctx: &Context) -> Result<()> {
    let baseline = integrity::load_baseline()?;
    let report = integrity::scan_baseline(&baseline, max_size(ctx, max_size_mb))?;

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("integrity.scan", &report));
    }
    if ctx.output.format == OutputFormat::Csv {
        let rows: Vec<Vec<String>> = report
            .changes
            .iter()
            .map(|c| {
                vec![
                    c.path.clone(),
                    format!("{:?}", c.status).to_uppercase(),
                    c.details.join("; "),
                ]
            })
            .collect();
        return emit_table(ctx, &["Path", "Status", "Details"], &rows, None);
    }

    let changed: Vec<_> = report
        .changes
        .iter()
        .filter(|c| c.status != IntegrityStatus::Unchanged)
        .collect();
    for change in &changed {
        println!("{}", format!("{:?}", change.status).to_uppercase());
        println!("{}", change.path);
        for detail in &change.details {
            println!("  - {detail}");
        }
        println!();
    }
    if all {
        // `--all` is only meaningful with a full listing; unchanged files are
        // not part of `changes`, so report the count explicitly.
        println!("{} unchanged file(s)", report.unchanged);
    }
    println!(
        "{} change(s); {} unchanged",
        changed.len(),
        report.unchanged
    );
    if let Some(note) = &report.note {
        println!("note: {note}");
    }
    println!(
        "baseline from {}",
        report
            .baseline_created_epoch
            .map(crate::core::reporting::format_epoch)
            .unwrap_or_else(|| "unknown".into())
    );
    Ok(())
}

fn show(ctx: &Context) -> Result<()> {
    let baseline = integrity::load_baseline()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("integrity.baseline.show", &baseline));
    }
    println!(
        "baseline created: {}",
        crate::core::reporting::format_epoch(baseline.created_epoch)
    );
    println!("hostname:         {}", baseline.hostname);
    println!("platform:         {}", baseline.platform);
    println!("paths:            {}", baseline.paths.join(", "));
    println!("entries:          {}", baseline.entries.len());
    println!(
        "path:             {}",
        crate::config::baseline_file().display()
    );
    Ok(())
}
