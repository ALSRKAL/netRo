//! `netro security ...`

use crate::cli::{SecurityArgs, SecurityCommand};
use crate::commands::{emit_table, envelope, Context};
use crate::core::security;
use crate::error::Result;
use crate::model::Severity;
use crate::output::{severity_color, OutputFormat};
use crate::platform::platform;

pub fn run(args: SecurityArgs, ctx: &Context) -> Result<()> {
    match args.command {
        Some(SecurityCommand::Accounts) => accounts(ctx),
        Some(SecurityCommand::Listening) => listening(ctx),
        Some(SecurityCommand::Audit { run_external }) => audit(run_external, ctx),
        None => audit(args.run_external, ctx),
    }
}

fn audit(run_external: bool, ctx: &Context) -> Result<()> {
    let result = security::audit(run_external);

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("security.audit", &result));
    }

    if ctx.output.is_csv() {
        let rows: Vec<Vec<String>> = result
            .findings
            .iter()
            .map(|f| {
                vec![
                    f.id.clone(),
                    f.severity.as_str().to_string(),
                    f.category.clone(),
                    f.title.clone(),
                    f.evidence.join(" | "),
                    f.recommendation.clone(),
                    f.score_impact.to_string(),
                ]
            })
            .collect();
        return emit_table(
            ctx,
            &[
                "ID",
                "Severity",
                "Category",
                "Title",
                "Evidence",
                "Recommendation",
                "Impact",
            ],
            &rows,
            None,
        );
    }

    let color = ctx.output.color;
    println!(
        "security audit on {} ({}){}",
        result
            .hostname
            .clone()
            .unwrap_or_else(|| "unknown host".into()),
        result.platform,
        if result.elevated {
            " [elevated]"
        } else {
            " [unprivileged: some checks limited]"
        }
    );
    println!();
    for finding in &result.findings {
        println!(
            "{} {}",
            crate::output::paint(
                color,
                severity_color(finding.severity),
                finding.severity.as_str()
            ),
            finding.title
        );
        println!("  id:       {}", finding.id);
        println!("  category: {}", finding.category);
        for evidence in &finding.evidence {
            println!("  evidence: {evidence}");
        }
        if !finding.impact.is_empty() {
            println!("  impact:   {}", finding.impact);
        }
        if !finding.recommendation.is_empty() {
            println!("  action:   {}", finding.recommendation);
        }
        println!(
            "  source:   {:?}, confidence: {:?}, score impact: -{}",
            finding.source, finding.confidence, finding.score_impact
        );
        println!();
    }
    if result.findings.is_empty() {
        println!("No findings from the checks that ran.");
        println!();
    }

    println!(
        "score: {}/{} (grade {})",
        result.score.total, result.score.max, result.score.grade
    );
    for category in &result.score.categories {
        println!(
            "  {:<14} {}/{}",
            category.category, category.score, category.max
        );
    }
    println!();
    println!("methodology: {}", result.score.methodology);

    if !result.limitations.is_empty() {
        println!("\nlimitations:");
        for limitation in &result.limitations {
            println!("  - {limitation}");
        }
    }
    if !result.external_tools.is_empty() {
        println!("\nexternal tools:");
        for tool in &result.external_tools {
            println!(
                "  {:<12} installed={} ran={} {}",
                tool.tool,
                tool.installed,
                tool.ran,
                tool.summary
                    .clone()
                    .or(tool.error.clone())
                    .or(tool.note.clone())
                    .unwrap_or_default()
            );
        }
    }
    let worst = result.findings.iter().map(|f| f.severity).max();
    if worst == Some(Severity::Critical) {
        println!("\ncritical findings require immediate attention");
    }
    let _ = OutputFormat::Text;
    Ok(())
}

fn accounts(ctx: &Context) -> Result<()> {
    let accounts = platform().accounts()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("security.accounts", &accounts));
    }
    let rows: Vec<Vec<String>> = accounts
        .iter()
        .map(|a| {
            vec![
                a.name.clone(),
                a.uid.map(|u| u.to_string()).unwrap_or_else(|| "-".into()),
                if a.privileged { "yes" } else { "-" }.to_string(),
                if a.is_system { "yes" } else { "-" }.to_string(),
                if a.login_shell { "yes" } else { "no" }.to_string(),
                format!("{:?}", a.password).to_lowercase(),
                a.groups.join(","),
                a.note.clone().unwrap_or_default(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Account",
            "UID",
            "Privileged",
            "System",
            "Login shell",
            "Password",
            "Groups",
            "Note",
        ],
        &rows,
        None,
    )
}

fn listening(ctx: &Context) -> Result<()> {
    let ports = platform().listening_ports()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("security.listening", &ports));
    }
    let rows: Vec<Vec<String>> = ports
        .iter()
        .map(|p| {
            vec![
                format!("{}:{}", p.address, p.port),
                p.protocol.clone(),
                format!("{:?}", p.scope).to_lowercase(),
                p.state.clone(),
                p.pid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                p.process.clone().unwrap_or_else(|| "-".into()),
                if p.scope == crate::model::ExposureScope::All {
                    "exposed"
                } else if p.scope == crate::model::ExposureScope::Local {
                    "local-only"
                } else {
                    ""
                }
                .to_string(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Address", "Proto", "Scope", "State", "PID", "Process", "Reach",
        ],
        &rows,
        None,
    )?;
    Ok(())
}
