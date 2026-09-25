//! `netro config ...`

use crate::cli::{ConfigArgs, ConfigCommand};
use crate::commands::{envelope, Context};
use crate::config::Config;
use crate::error::{ErrorCode, NetroError, Result};

pub fn run(args: ConfigArgs, ctx: &Context) -> Result<()> {
    match args.command.unwrap_or(ConfigCommand::Show) {
        ConfigCommand::Show => show(ctx),
        ConfigCommand::Path => {
            if ctx.output.is_json() {
                crate::output::emit_json(&serde_json::json!({
                    "config_file": Config::config_path_string(),
                    "config_dir": crate::config::config_dir().display().to_string(),
                    "data_dir": crate::config::data_dir().display().to_string(),
                    "cache_dir": crate::config::cache_dir().display().to_string(),
                    "log_dir": crate::config::log_dir().display().to_string(),
                }))
            } else {
                println!("{}", Config::config_path_string());
                Ok(())
            }
        }
        ConfigCommand::Init => {
            let (path, created) = Config::init_if_missing()?;
            if ctx.output.is_json() {
                crate::output::emit_json(&serde_json::json!({
                    "config_file": path.display().to_string(),
                    "created": created,
                }))
            } else {
                if created {
                    println!("wrote default configuration to {}", path.display());
                } else {
                    println!("configuration already exists at {}", path.display());
                }
                Ok(())
            }
        }
        ConfigCommand::Set { key, value } => set(&key, &value, ctx),
    }
}

fn show(ctx: &Context) -> Result<()> {
    let (config, warnings) = Config::load();
    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope(
            "config.show",
            serde_json::json!({
                "config_file": Config::config_path_string(),
                "config": config,
                "warnings": warnings,
            }),
        ));
    }
    for warning in &warnings {
        eprintln!("warning: {warning}");
    }
    println!("config file: {}", Config::config_path_string());
    println!();
    let text = serde_json::to_string_pretty(&config)?;
    println!("{text}");
    Ok(())
}

fn set(key: &str, value: &str, ctx: &Context) -> Result<()> {
    let (mut config, _) = Config::load();
    let normalized = key.trim().to_ascii_lowercase();

    let parse_u64 = || {
        value.parse::<u64>().map_err(|_| {
            NetroError::new(
                ErrorCode::ConfigError,
                format!("'{value}' is not a valid number for {key}"),
            )
        })
    };
    let parse_usize = || {
        value.parse::<usize>().map_err(|_| {
            NetroError::new(
                ErrorCode::ConfigError,
                format!("'{value}' is not a valid number for {key}"),
            )
        })
    };
    let parse_f64 = || {
        value.parse::<f64>().map_err(|_| {
            NetroError::new(
                ErrorCode::ConfigError,
                format!("'{value}' is not a valid number for {key}"),
            )
        })
    };
    let parse_bool = || match value.to_ascii_lowercase().as_str() {
        "true" | "yes" | "1" | "on" => Ok(true),
        "false" | "no" | "0" | "off" => Ok(false),
        _ => Err(NetroError::new(
            ErrorCode::ConfigError,
            format!("'{value}' is not a boolean for {key}"),
        )),
    };

    match normalized.as_str() {
        "scan.ports" => {
            // Validate against the real parser so a typo cannot silently break
            // every future scan.
            crate::core::scan::parse_ports(value).map_err(|e| {
                NetroError::new(
                    ErrorCode::ConfigError,
                    format!("invalid scan.ports value '{value}': {}", e.message()),
                )
            })?;
            config.scan.ports = value.to_string();
        }
        "scan.timeout_ms" => config.scan.timeout_ms = parse_u64()?,
        "scan.concurrency" => config.scan.concurrency = parse_usize()?.clamp(1, 1024),
        "scan.banner_grab" => config.scan.banner_grab = parse_bool()?,
        "scan.tls_probe" => config.scan.tls_probe = parse_bool()?,
        "scan.confirm_public_targets" => config.scan.confirm_public_targets = parse_bool()?,
        "monitor.interval_secs" => config.monitor.interval_secs = parse_f64()?,
        "monitor.top_n" => config.monitor.top_n = parse_usize()?.clamp(1, 100),
        "monitor.show_temperatures" => config.monitor.show_temperatures = parse_bool()?,
        "output.format" => {
            let format = value.to_ascii_lowercase();
            if crate::output::OutputFormat::parse(&format).is_none() {
                return Err(NetroError::new(
                    ErrorCode::ConfigError,
                    "output.format must be text, json or csv",
                ));
            }
            config.output.format = format;
        }
        "output.color" => {
            let color = value.to_ascii_lowercase();
            if !["auto", "always", "never"].contains(&color.as_str()) {
                return Err(NetroError::new(
                    ErrorCode::ConfigError,
                    "output.color must be auto, always or never",
                ));
            }
            config.output.color = color;
        }
        "output.table_width" => config.output.table_width = parse_usize()?,
        "integrity.max_file_size_mb" => config.integrity.max_file_size_mb = parse_u64()?,
        "discovery.method" => {
            let method = value.to_ascii_lowercase();
            if crate::core::discovery::DiscoveryMethod::parse(&method).is_none() {
                return Err(NetroError::new(
                    ErrorCode::ConfigError,
                    "discovery.method must be auto, neighbors, icmp, tcp or nmap",
                ));
            }
            config.discovery.method = method;
        }
        "discovery.max_hosts" => config.discovery.max_hosts = parse_usize()?.clamp(1, 65_536),
        "discovery.resolve_hostnames" => config.discovery.resolve_hostnames = parse_bool()?,
        "integrations.nmap_path" => config.integrations.nmap_path = non_empty(value),
        "integrations.iperf3_path" => config.integrations.iperf3_path = non_empty(value),
        "integrations.traceroute_path" => config.integrations.traceroute_path = non_empty(value),
        "integrations.ping_path" => config.integrations.ping_path = non_empty(value),
        "integrations.oui_file" => config.integrations.oui_file = non_empty(value),
        "integrations.speedtest_provider" => {
            config.integrations.speedtest_provider = non_empty(value)
        }
        "integrations.speedtest_server" => config.integrations.speedtest_server = non_empty(value),
        "privacy.telemetry" => {
            config.privacy.telemetry = parse_bool()?;
            if config.privacy.telemetry {
                eprintln!(
                    "warning: telemetry is reserved in this version and has no effect; \
                     netro never sends telemetry"
                );
            }
        }
        "privacy.resolve_hostnames" => config.privacy.resolve_hostnames = parse_bool()?,
        "privacy.vendor_lookup" => config.privacy.vendor_lookup = parse_bool()?,
        "privacy.reverse_dns" => config.privacy.reverse_dns = parse_bool()?,
        other => {
            return Err(NetroError::new(
                ErrorCode::ConfigError,
                format!("unknown configuration key '{other}'"),
            )
            .with_hint("run `netro config show` to see the configuration schema"));
        }
    }

    let path = config.save()?;
    if ctx.output.is_json() {
        crate::output::emit_json(&serde_json::json!({
            "config_file": path.display().to_string(),
            "key": key,
            "value": value,
            "saved": true,
        }))
    } else {
        println!("set {key} = {value} in {}", path.display());
        Ok(())
    }
}

fn non_empty(value: &str) -> Option<String> {
    let trimmed = value.trim();
    if trimmed.is_empty() || trimmed.eq_ignore_ascii_case("none") {
        None
    } else {
        Some(trimmed.to_string())
    }
}
