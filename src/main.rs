use clap::Parser;
use netro::cli::Cli;
use netro::commands;
use netro::logging::{self, LogLevel};

fn main() {
    // Standard CLI behavior: die quietly when stdout is closed (e.g. | head).
    #[cfg(unix)]
    unsafe {
        libc::signal(libc::SIGPIPE, libc::SIG_DFL);
    }

    let cli = Cli::parse();

    let level = match &cli.log_level {
        Some(value) => match LogLevel::parse(value) {
            Some(level) => level,
            None => {
                eprintln!(
                    "error: invalid --log-level '{value}' (expected debug, info, warn, error)"
                );
                std::process::exit(2);
            }
        },
        None => {
            if cli.verbose >= 2 {
                LogLevel::Debug
            } else {
                LogLevel::Info
            }
        }
    };
    logging::init(level, cli.log_file.clone(), cli.verbose >= 1 && !cli.quiet);

    netro::log_info!(
        "netro {} starting ({})",
        netro::version::VERSION,
        netro::version::BUILD_TARGET
    );

    let json_output = cli.json;
    match commands::run(cli) {
        Ok(()) => {}
        Err(error) => {
            netro::log_error!("command failed: {error}");
            if json_output {
                let payload = serde_json::json!({
                    "command": "error",
                    "error": {
                        "code": error.code().as_str(),
                        "message": error.message(),
                        "hint": error.hint(),
                    }
                });
                let _ = netro::output::emit_json(&payload);
            } else {
                eprintln!("error: {error}");
            }
            std::process::exit(error.code().exit_code());
        }
    }
}
