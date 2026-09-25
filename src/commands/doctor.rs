//! `netro doctor`

use crate::cli::DoctorArgs;
use crate::commands::{emit_table, envelope, Context};
use crate::core::health;
use crate::error::Result;
use crate::model::CheckStatus;
use crate::output::{status_color, OutputFormat};
use crate::platform::platform;

pub fn run(args: DoctorArgs, ctx: &Context) -> Result<()> {
    if args.dependencies {
        return dependencies(ctx);
    }
    let report = health::run(&health::DoctorOptions {
        run_external: args.run_external,
        skip_internet: args.no_internet,
        ..health::DoctorOptions::default()
    });

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("doctor", &report));
    }

    if ctx.output.format == OutputFormat::Csv {
        let rows: Vec<Vec<String>> = report
            .checks
            .iter()
            .map(|c| {
                vec![
                    c.id.clone(),
                    c.label.clone(),
                    c.status.as_str().to_string(),
                    c.summary.clone(),
                    c.evidence.join(" | "),
                    c.duration_ms.to_string(),
                ]
            })
            .collect();
        return emit_table(
            ctx,
            &[
                "ID",
                "Check",
                "Status",
                "Summary",
                "Evidence",
                "Duration ms",
            ],
            &rows,
            None,
        );
    }

    let color = ctx.output.color;
    println!("NETRO DOCTOR");
    println!(
        "host: {}  platform: {}  time: {}",
        report.hostname.clone().unwrap_or_else(|| "unknown".into()),
        report.platform,
        crate::core::reporting::format_epoch(report.generated_at_epoch)
    );
    println!();

    let mut table = crate::output::Table::new(&["Check", "Status", "Summary"]);
    for check in &report.checks {
        table.row(&[
            check.label.clone(),
            crate::output::paint(color, status_color(check.status), check.status.as_str()),
            check.summary.clone(),
        ]);
    }
    print!("{}", table.render());

    println!();
    let mut summary_line = format!(
        "{} passed, {} warnings, {} failed",
        report.summary.passed, report.summary.warnings, report.summary.failed
    );
    if report.summary.unsupported > 0 {
        summary_line.push_str(&format!(", {} unsupported", report.summary.unsupported));
    }
    if report.summary.skipped > 0 {
        summary_line.push_str(&format!(", {} skipped", report.summary.skipped));
    }
    println!("{summary_line}");
    println!();

    if let Some(score) = &report.summary.score {
        println!(
            "Security score: {}/{} (grade {})",
            score.total, score.max, score.grade
        );
        for category in &score.categories {
            if category.deductions.is_empty() {
                println!(
                    "  {:<14} {}/{}",
                    category.category, category.score, category.max
                );
            } else {
                println!(
                    "  {:<14} {}/{} (-{} points)",
                    category.category,
                    category.score,
                    category.max,
                    category.max - category.score
                );
                for deduction in &category.deductions {
                    println!(
                        "      -{} {} ({})",
                        deduction.points, deduction.reason, deduction.finding_id
                    );
                }
            }
        }
        println!("  methodology: {}", score.methodology);
        println!();
    }

    if !report.findings.is_empty() {
        println!("PROBLEMS FOUND");
        for finding in &report.findings {
            println!(
                "  [{}] {}",
                crate::output::paint(
                    color,
                    status_color(status_for(finding.severity)),
                    finding.severity.as_str()
                ),
                finding.title
            );
            for evidence in finding.evidence.iter().take(3) {
                println!("         evidence: {evidence}");
            }
            if !finding.recommendation.is_empty() {
                println!("         action:   {}", finding.recommendation);
            }
        }
        println!();
    }

    if !report.summary.recommendations.is_empty() {
        println!("RECOMMENDATIONS");
        for recommendation in &report.summary.recommendations {
            println!("  - {recommendation}");
        }
        println!();
    }

    if let Some(note) = &report.note {
        if !note.is_empty() {
            println!("notes: {note}");
        }
    }

    let failed = report.summary.failed;
    let warnings = report.summary.warnings;
    if failed > 0 {
        println!("result: {failed} failing check(s), {warnings} warning(s)");
    } else if warnings > 0 {
        println!("result: healthy with {warnings} warning(s)");
    } else {
        println!("result: all executed checks passed");
    }
    Ok(())
}

fn status_for(severity: crate::model::Severity) -> CheckStatus {
    use crate::model::Severity::*;
    match severity {
        Critical | High => CheckStatus::Fail,
        Medium => CheckStatus::Warning,
        Low | Info => CheckStatus::Pass,
    }
}

fn dependencies(ctx: &Context) -> Result<()> {
    let mut dependencies = platform().dependencies();
    dependencies.sort_by(|a, b| a.name.cmp(&b.name));
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("doctor.dependencies", &dependencies));
    }
    let rows: Vec<Vec<String>> = dependencies
        .iter()
        .map(|d| {
            vec![
                d.name.clone(),
                d.binary.clone(),
                if d.installed { "installed" } else { "missing" }.to_string(),
                d.version.clone().unwrap_or_default(),
                if d.required { "required" } else { "optional" }.to_string(),
                d.purpose.clone(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &["Tool", "Binary", "State", "Version", "Need", "Purpose"],
        &rows,
        None,
    )
}
