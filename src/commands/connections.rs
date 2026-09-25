//! `netro connections`

use crate::cli::ConnectionsArgs;
use crate::commands::{emit_table, envelope, Context};
use crate::error::Result;
use crate::platform::platform;

pub fn run(args: ConnectionsArgs, ctx: &Context) -> Result<()> {
    if args.listen {
        let mut ports = platform().listening_ports()?;
        if let Some(port) = args.port {
            ports.retain(|p| p.port == port);
        }
        if let Some(process) = &args.process {
            let needle = process.to_ascii_lowercase();
            ports.retain(|p| {
                p.process
                    .as_deref()
                    .map(|name| name.to_ascii_lowercase().contains(&needle))
                    .unwrap_or(false)
            });
        }
        if let Some(protocol) = &args.protocol {
            let needle = protocol.to_ascii_lowercase();
            ports.retain(|p| p.protocol == needle);
        }
        ports.truncate(args.limit);
        if ctx.output.is_json() {
            return crate::output::emit_json(&envelope("connections.listen", &ports));
        }
        let rows: Vec<Vec<String>> = ports
            .iter()
            .map(|p| {
                vec![
                    p.protocol.clone(),
                    format!("{}:{}", p.address, p.port),
                    format!("{:?}", p.scope).to_lowercase(),
                    p.state.clone(),
                    p.pid.map(|v| v.to_string()).unwrap_or_else(|| "-".into()),
                    p.process.clone().unwrap_or_else(|| "-".into()),
                ]
            })
            .collect();
        return emit_table(
            ctx,
            &["Proto", "Local", "Scope", "State", "PID", "Process"],
            &rows,
            None,
        );
    }

    let mut connections = platform().connections()?;
    if let Some(state) = &args.state {
        let needle = state.to_ascii_uppercase();
        connections.retain(|c| c.state.to_ascii_uppercase() == needle);
    }
    if let Some(process) = &args.process {
        let needle = process.to_ascii_lowercase();
        connections.retain(|c| {
            c.process
                .as_deref()
                .map(|name| name.to_ascii_lowercase().contains(&needle))
                .unwrap_or(false)
        });
    }
    if let Some(port) = args.port {
        connections.retain(|c| c.local_port == port || c.remote_port == Some(port));
    }
    if let Some(remote) = &args.remote {
        connections.retain(|c| {
            c.remote_addr
                .as_deref()
                .map(|addr| addr.contains(remote.as_str()))
                .unwrap_or(false)
        });
    }
    if let Some(protocol) = &args.protocol {
        let needle = protocol.to_ascii_lowercase();
        connections.retain(|c| c.protocol == needle);
    }
    connections.truncate(args.limit);

    if ctx.output.is_json() {
        return crate::output::emit_json(&envelope("connections", &connections));
    }
    let rows: Vec<Vec<String>> = connections
        .iter()
        .map(|c| {
            vec![
                c.protocol.clone(),
                format!("{}:{}", c.local_addr, c.local_port),
                c.remote_addr
                    .as_ref()
                    .map(|addr| {
                        format!(
                            "{}:{}",
                            addr,
                            c.remote_port
                                .map(|p| p.to_string())
                                .unwrap_or_else(|| "-".into())
                        )
                    })
                    .unwrap_or_else(|| "-".into()),
                c.state.clone(),
                c.pid.map(|p| p.to_string()).unwrap_or_else(|| "-".into()),
                c.process.clone().unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    emit_table(
        ctx,
        &["Proto", "Local", "Remote", "State", "PID", "Process"],
        &rows,
        None,
    )
}
