//! `netro firewall ...`

use crate::cli::{FirewallArgs, FirewallCommand};
use crate::commands::{emit_table, envelope, Context};
use crate::error::{ErrorCode, NetroError, Result};
use crate::model::FirewallChange;
use crate::platform::platform;

pub fn run(args: FirewallArgs, ctx: &Context) -> Result<()> {
    match args.command {
        FirewallCommand::Status => status(ctx),
        FirewallCommand::Rules { limit } => rules(limit, ctx),
        FirewallCommand::Block { ip, dry_run } => block(&ip, dry_run, ctx),
        FirewallCommand::Unblock { ip, dry_run } => unblock(&ip, dry_run, ctx),
    }
}

fn status(ctx: &Context) -> Result<()> {
    let status = platform().firewall_status()?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("firewall.status", &status));
    }
    let state = match status.enabled {
        Some(true) => "enabled",
        Some(false) => "disabled",
        None => "unknown",
    };
    println!("firewall: {state}");
    if !status.backends.is_empty() {
        let rows: Vec<Vec<String>> = status
            .backends
            .iter()
            .map(|b| {
                vec![
                    b.name.clone(),
                    match b.active {
                        Some(true) => "active",
                        Some(false) => "inactive",
                        None => "unknown",
                    }
                    .to_string(),
                    b.detail.clone().unwrap_or_default(),
                    b.via.clone(),
                ]
            })
            .collect();
        emit_table(
            ctx,
            &["Backend", "State", "Detail", "Checked via"],
            &rows,
            None,
        )?;
    }
    for note in &status.notes {
        println!("note: {note}");
    }
    Ok(())
}

fn rules(limit: usize, ctx: &Context) -> Result<()> {
    let rules = platform().firewall_rules(limit)?;
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("firewall.rules", &rules));
    }
    let rows: Vec<Vec<String>> = rules
        .iter()
        .map(|r| {
            vec![
                r.backend.clone(),
                r.chain.clone().unwrap_or_default(),
                r.action.clone(),
                r.raw.clone(),
            ]
        })
        .collect();
    emit_table(ctx, &["Backend", "Chain", "Action", "Rule"], &rows, None)
}

fn block(ip: &str, dry_run: bool, ctx: &Context) -> Result<()> {
    let ip: std::net::IpAddr = ip.parse().map_err(|_| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{ip}' is not an IP address"),
        )
    })?;
    if !dry_run {
        ctx.confirm(&format!(
            "add a host firewall rule to block inbound traffic from {ip}?"
        ))?;
    }
    let change = platform().block_ip(&ip.to_string(), dry_run)?;
    print_change(&change, ctx)
}

fn unblock(ip: &str, dry_run: bool, ctx: &Context) -> Result<()> {
    let ip: std::net::IpAddr = ip.parse().map_err(|_| {
        NetroError::new(
            ErrorCode::InvalidTarget,
            format!("'{ip}' is not an IP address"),
        )
    })?;
    if !dry_run {
        ctx.confirm(&format!(
            "remove the netro firewall block for inbound traffic from {ip}?"
        ))?;
    }
    let change = platform().unblock_ip(&ip.to_string(), dry_run)?;
    print_change(&change, ctx)
}

fn print_change(change: &FirewallChange, ctx: &Context) -> Result<()> {
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("firewall.change", change));
    }
    println!(
        "{} {} via {}{}",
        change.action,
        change.ip,
        change.backend,
        if change.applied {
            " [applied]"
        } else {
            " [not applied]"
        }
    );
    println!("commands:");
    for command in &change.commands {
        println!("  {command}");
    }
    if !change.rollback.is_empty() {
        println!("rollback:");
        for command in &change.rollback {
            println!("  {command}");
        }
    }
    if let Some(output) = &change.output {
        if !output.trim().is_empty() {
            println!("output:\n{}", output.trim());
        }
    }
    if let Some(note) = &change.note {
        println!("note: {note}");
    }
    if change.applied && change.rollback.is_empty() {
        println!("note: netro did not record rollback commands for this backend");
    }
    Ok(())
}
