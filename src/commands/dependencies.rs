//! `netro dependencies`

use crate::cli::DependenciesArgs;
use crate::commands::{emit_table, envelope, Context};
use crate::error::Result;
use crate::platform::platform;

pub fn run(args: DependenciesArgs, ctx: &Context) -> Result<()> {
    let mut dependencies = platform().dependencies();
    if args.missing {
        dependencies.retain(|d| !d.installed);
    }
    dependencies.sort_by(|a, b| a.name.cmp(&b.name));

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("dependencies", &dependencies));
    }

    let missing_required: Vec<&str> = dependencies
        .iter()
        .filter(|d| d.required && !d.installed)
        .map(|d| d.name.as_str())
        .collect();

    let rows: Vec<Vec<String>> = dependencies
        .iter()
        .map(|d| {
            vec![
                d.name.clone(),
                d.binary.clone(),
                if d.installed { "installed" } else { "missing" }.to_string(),
                d.version.clone().unwrap_or_default(),
                if d.required { "required" } else { "optional" }.to_string(),
                d.path.clone().unwrap_or_default(),
                d.purpose.clone(),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &[
            "Tool", "Binary", "State", "Version", "Need", "Path", "Purpose",
        ],
        &rows,
        None,
    )?;

    if !missing_required.is_empty() {
        eprintln!(
            "warning: required dependencies missing: {}",
            missing_required.join(", ")
        );
    }
    Ok(())
}
