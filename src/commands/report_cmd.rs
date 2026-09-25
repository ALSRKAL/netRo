//! `netro report`

use crate::cli::ReportArgs;
use crate::commands::{envelope, Context};
use crate::core::reporting;
use crate::error::Result;
use crate::output::OutputFormat;
use std::time::Duration;

pub fn run(args: ReportArgs, ctx: &Context) -> Result<()> {
    let options = reporting::ReportOptions {
        include_system: !args.no_system,
        include_network: true,
        include_connectivity: !args.no_internet,
        include_security: !args.no_security,
        include_doctor: true,
        internet_timeout: Duration::from_secs(3),
    };
    let report = reporting::build(&options);

    if let Some(path) = &args.html {
        let html = reporting::render_html(&report);
        reporting::write_file(path, &html)?;
        ctx.note(&format!("HTML report written to {}", path.display()));
        if args.out.is_none() && ctx.output.format == OutputFormat::Text {
            // Also show a short text summary so the command is useful.
            print!("{}", reporting::render_text(&report));
        }
    }

    match ctx.output.format {
        OutputFormat::Text => {
            if args.html.is_none() {
                print!("{}", reporting::render_text(&report));
            }
        }
        OutputFormat::Json => {
            let value = envelope("report", &report);
            if let Some(out) = &args.out {
                reporting::write_file(out, &serde_json::to_string_pretty(&value)?)?;
                ctx.note(&format!("JSON report written to {}", out.display()));
            } else {
                crate::output::emit_json(&value)?;
            }
        }
        OutputFormat::Csv => {
            let csv = reporting::render_csv(&report);
            if let Some(out) = &args.out {
                reporting::write_file(out, &csv)?;
                ctx.note(&format!("CSV report written to {}", out.display()));
            } else {
                print!("{csv}");
            }
        }
    }
    Ok(())
}
