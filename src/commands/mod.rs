//! Command dispatch and shared command context.

mod config_cmd;
mod connections;
mod dependencies;
mod doctor;
mod firewall;
mod integrity;
mod monitor;
mod network;
mod processes;
mod report_cmd;
mod security;
mod system;

use crate::cli::Cli;
use crate::config::Config;
use crate::error::{ErrorCode, NetroError, Result};
use crate::output::{OutputFormat, OutputOptions};
use crate::util;
use clap::CommandFactory;
use std::io::IsTerminal;

pub struct Context {
    pub output: OutputOptions,
    pub config: Config,
    pub quiet: bool,
    pub assume_yes: bool,
}

impl Context {
    /// Require explicit confirmation for a destructive operation.
    pub fn confirm(&self, description: &str) -> Result<()> {
        if self.assume_yes {
            return Ok(());
        }
        if !std::io::stdin().is_terminal() {
            return Err(NetroError::new(
                ErrorCode::ConfirmationRequired,
                format!("{description} requires confirmation"),
            )
            .with_hint("pass --yes to confirm non-interactively"));
        }
        eprint!("{description} [y/N] ");
        let mut line = String::new();
        std::io::stdin().read_line(&mut line)?;
        if line.trim().eq_ignore_ascii_case("y") || line.trim().eq_ignore_ascii_case("yes") {
            Ok(())
        } else {
            Err(NetroError::new(ErrorCode::Cancelled, "cancelled by user"))
        }
    }

    pub fn note(&self, message: &str) {
        if !self.quiet {
            eprintln!("{message}");
        }
    }
}

pub fn run(cli: Cli) -> Result<()> {
    let output = resolve_output(&cli)?;
    let (config, warnings) = Config::load();
    if output.format == OutputFormat::Text && !cli.quiet {
        for warning in warnings {
            eprintln!("warning: {warning}");
        }
    }
    let context = Context {
        output,
        config,
        quiet: cli.quiet,
        assume_yes: cli.yes,
    };

    let command = match cli.command {
        Some(command) => command,
        None => return run_default(&cli, &context),
    };
    match command {
        crate::cli::Commands::System(args) => system::run(args, &context),
        crate::cli::Commands::Network(args) => network::run(args, &context),
        crate::cli::Commands::Connections(args) => connections::run(args, &context),
        crate::cli::Commands::Processes(args) => processes::run(args, &context),
        crate::cli::Commands::Security(args) => security::run(args, &context),
        crate::cli::Commands::Firewall(args) => firewall::run(args, &context),
        crate::cli::Commands::Integrity(args) => integrity::run(args, &context),
        crate::cli::Commands::Doctor(args) => doctor::run(args, &context),
        crate::cli::Commands::Monitor(args) => monitor::run(args, &context),
        crate::cli::Commands::Tui(args) => {
            let theme = args.theme.as_deref().map(parse_theme).transpose()?;
            crate::tui::run(crate::tui::TuiOptions {
                mouse: !args.no_mouse,
                theme,
            })
        }
        crate::cli::Commands::Report(args) => report_cmd::run(args, &context),
        crate::cli::Commands::Config(args) => config_cmd::run(args, &context),
        crate::cli::Commands::Dependencies(args) => dependencies::run(args, &context),
        crate::cli::Commands::Version => {
            let info = crate::version::version_info();
            if context.output.is_json() {
                crate::output::emit_json(&info)?;
            } else {
                println!("{info}");
            }
            Ok(())
        }
    }
}

fn parse_theme(value: &str) -> Result<crate::tui::theme::ThemeKind> {
    use crate::tui::theme::ThemeKind;
    match value.to_ascii_lowercase().as_str() {
        "auto" => Ok(ThemeKind::Auto),
        "dark" => Ok(ThemeKind::Dark),
        "light" => Ok(ThemeKind::Light),
        "contrast" | "high-contrast" | "highcontrast" => Ok(ThemeKind::HighContrast),
        "none" | "no-color" | "nocolor" => Ok(ThemeKind::NoColor),
        other => Err(NetroError::new(
            ErrorCode::ConfigError,
            format!("unknown theme '{other}' (expected auto, dark, light, contrast or none)"),
        )),
    }
}

/// `netro` with no subcommand: launch the TUI on a terminal, otherwise print
/// help (never hang waiting for input in scripts or pipes).
fn run_default(cli: &Cli, context: &Context) -> Result<()> {
    let terminal = std::io::IsTerminal::is_terminal(&std::io::stdout())
        && std::io::IsTerminal::is_terminal(&std::io::stdin());
    if terminal && !cli.json && cli.format.is_none() {
        return crate::tui::run(crate::tui::TuiOptions {
            mouse: true,
            theme: None,
        });
    }
    if !context.quiet {
        Cli::command().print_help().ok();
        println!();
    }
    Ok(())
}

pub fn resolve_output(cli: &Cli) -> Result<OutputOptions> {
    let format = if cli.json {
        OutputFormat::Json
    } else {
        match &cli.format {
            Some(value) => OutputFormat::parse(value).ok_or_else(|| {
                NetroError::new(
                    ErrorCode::ConfigError,
                    format!("unknown output format '{value}' (expected text, json or csv)"),
                )
            })?,
            None => OutputFormat::Text,
        }
    };
    let color = match cli.color.as_str() {
        "auto" | "always" | "never" => cli.color.clone(),
        other => {
            return Err(NetroError::new(
                ErrorCode::ConfigError,
                format!("invalid --color value '{other}' (expected auto, always or never)"),
            ))
        }
    };
    Ok(OutputOptions::new(format, &color))
}

/// JSON envelope helper: every command emits an object with a `command` field
/// so consumers can identify the payload.
pub fn envelope<T: serde::Serialize>(command: &str, payload: T) -> serde_json::Value {
    serde_json::json!({
        "command": command,
        "schema_version": crate::model::MODEL_SCHEMA_VERSION,
        "netro_version": crate::version::VERSION,
        "generated_at_epoch": chrono::Utc::now().timestamp(),
        "data": payload,
    })
}

/// Print a table in text mode or emit CSV when requested.
pub fn emit_table(
    ctx: &Context,
    headers: &[&str],
    rows: &[Vec<String>],
    title: Option<&str>,
) -> Result<()> {
    match ctx.output.format {
        OutputFormat::Text => {
            if let Some(title) = title {
                println!("{title}");
            }
            if rows.is_empty() {
                println!("(no data)");
                return Ok(());
            }
            let mut table = crate::output::Table::new(headers);
            for row in rows {
                table.row(row);
            }
            print!("{}", table.render());
            Ok(())
        }
        OutputFormat::Csv => crate::output::emit_csv(headers, rows),
        OutputFormat::Json => {
            // Callers should emit structured JSON instead; this fallback keeps
            // the contract valid rather than printing human text.
            let items: Vec<serde_json::Value> = rows
                .iter()
                .map(|row| {
                    let mut map = serde_json::Map::new();
                    for (index, header) in headers.iter().enumerate() {
                        map.insert(
                            (*header).to_string(),
                            serde_json::Value::String(row.get(index).cloned().unwrap_or_default()),
                        );
                    }
                    serde_json::Value::Object(map)
                })
                .collect();
            crate::output::emit_json(&serde_json::json!({
                "schema_version": crate::model::MODEL_SCHEMA_VERSION,
                "data": items,
            }))
        }
    }
}

pub fn boolean(value: bool) -> &'static str {
    if value {
        "yes"
    } else {
        "no"
    }
}

pub fn opt(value: &Option<String>) -> String {
    value.clone().unwrap_or_else(|| "-".to_string())
}

pub fn format_opt(value: Option<f64>, unit: &str) -> String {
    value
        .map(|v| format!("{v:.1}{unit}"))
        .unwrap_or_else(|| "-".to_string())
}

pub fn rate(bytes_per_sec: f64) -> String {
    format!("{}/s", util::human_bytes(bytes_per_sec.max(0.0) as u64))
}
