//! Security screen with tabs: Overview, Findings, Accounts, Listening,
//! Firewall, Integrity and External tools.

use crate::tui::app::Ui;
use crate::tui::components::list_table;
use crate::tui::components::status_badge;
use crate::tui::state::SecurityTab;
use crate::tui::text::T;
use crate::tui::theme::UiStatus;
use crate::tui::widgets::{gauge_line, truncate};
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph, Wrap};
use ratatui::Frame;

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(1), Constraint::Min(3)])
        .split(area);
    render_tabs(ui, frame, rows[0]);
    match ui.state.security_tab {
        SecurityTab::Overview => overview(ui, frame, rows[1]),
        SecurityTab::Findings => findings(ui, frame, rows[1]),
        SecurityTab::Accounts => accounts(ui, frame, rows[1]),
        SecurityTab::Listening => listening(ui, frame, rows[1]),
        SecurityTab::Firewall => firewall(ui, frame, rows[1]),
        SecurityTab::Integrity => integrity(ui, frame, rows[1]),
        SecurityTab::External => external(ui, frame, rows[1]),
    }
}

fn render_tabs(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    for tab in SecurityTab::ALL {
        let selected = tab == ui.state.security_tab;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        spans.push(Span::styled(
            format!("{marker} {} ", tab.label()),
            if selected {
                ui.theme.selected
            } else {
                ui.theme.muted
            },
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn panel(ui: &Ui, title: &str) -> Block<'static> {
    Block::default()
        .borders(Borders::ALL)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {title} "), ui.theme.muted))
}

fn overview(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.audit {
        Some(audit) => {
            let audit = &audit.value;
            lines.push(Line::from(vec![
                Span::styled(format!(" {}  ", T.sec_score), ui.theme.muted),
                Span::styled(
                    format!("{}/{}", audit.score.total, audit.score.max),
                    ui.theme.title,
                ),
                Span::styled(format!("  grade {}", audit.score.grade), ui.theme.muted),
            ]));
            lines.push(Line::from(""));
            for category in &audit.score.categories {
                lines.push(gauge_line(
                    ui.theme,
                    &category.category,
                    if category.max > 0 {
                        category.score as f64 / category.max as f64 * 100.0
                    } else {
                        0.0
                    },
                    14,
                ));
                for deduction in &category.deductions {
                    lines.push(Line::styled(
                        format!(
                            "    -{} {} ({})",
                            deduction.points, deduction.reason, deduction.finding_id
                        ),
                        ui.theme.muted,
                    ));
                }
            }
            lines.push(Line::from(""));
            lines.push(Line::styled(
                format!(
                    " methodology: {}",
                    truncate(&audit.score.methodology, 120, ui.theme)
                ),
                ui.theme.muted,
            ));
            if !audit.limitations.is_empty() {
                lines.push(Line::from(""));
                lines.push(Line::styled(" limitations", ui.theme.muted));
                for limitation in audit.limitations.iter().take(4) {
                    lines.push(Line::styled(
                        format!("  - {}", truncate(limitation, 110, ui.theme)),
                        ui.theme.warning,
                    ));
                }
            }
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.tab_overview))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn findings(ui: &Ui, frame: &mut Frame, area: Rect) {
    let title = if !ui.state.filter.is_empty() {
        format!(" {} — filter: {} ", T.sec_findings, ui.state.filter)
    } else {
        format!(" {} ", T.sec_findings)
    };
    let block = panel(ui, &title);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(audit) = &ui.state.caches.audit else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = audit
        .value
        .findings
        .iter()
        .filter(|finding| {
            filter.is_empty()
                || finding.title.to_ascii_lowercase().contains(&filter)
                || finding.id.to_ascii_lowercase().contains(&filter)
                || finding.category.to_ascii_lowercase().contains(&filter)
        })
        .map(|finding| {
            vec![
                finding.severity.as_str().to_string(),
                finding.category.clone(),
                truncate(&finding.title, 52, ui.theme),
                format!("-{}", finding.score_impact),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if audit.value.findings.is_empty() {
                    T.sec_good
                } else {
                    T.empty_filtered
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &["Severity", "Category", "Finding", "Impact"],
            rows,
            Some(ui.state.security_selected()),
            &[
                Constraint::Length(9),
                Constraint::Length(14),
                Constraint::Min(20),
                Constraint::Length(7),
            ],
        ),
        inner,
    );
}

fn accounts(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, T.tab_accounts);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(audit) = &ui.state.caches.audit else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = audit
        .value
        .accounts
        .iter()
        .filter(|account| filter.is_empty() || account.name.to_ascii_lowercase().contains(&filter))
        .map(|account| {
            vec![
                account.name.clone(),
                account
                    .uid
                    .map(|u| u.to_string())
                    .unwrap_or_else(|| "-".into()),
                if account.privileged { "yes" } else { "" }.to_string(),
                if account.is_system { "system" } else { "user" }.to_string(),
                if account.login_shell { "yes" } else { "no" }.to_string(),
                format!("{:?}", account.password).to_lowercase(),
                truncate(&account.groups.join(","), 24, ui.theme),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if audit.value.accounts.is_empty() {
                    T.empty_no_accounts
                } else {
                    T.empty_filtered
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &[
                "Account", "UID", "Priv", "Type", "Login", "Password", "Groups",
            ],
            rows,
            Some(ui.state.security_selected()),
            &[
                Constraint::Length(14),
                Constraint::Length(6),
                Constraint::Length(5),
                Constraint::Length(7),
                Constraint::Length(6),
                Constraint::Length(9),
                Constraint::Min(12),
            ],
        ),
        inner,
    );
}

fn listening(ui: &Ui, frame: &mut Frame, area: Rect) {
    let block = panel(ui, T.tab_listening);
    let inner = block.inner(area);
    frame.render_widget(block, area);
    let Some(fresh) = &ui.state.caches.listening else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let filter = ui.state.filter.to_ascii_lowercase();
    let rows: Vec<Vec<String>> = fresh
        .value
        .iter()
        .filter(|port| {
            filter.is_empty()
                || port.address.to_ascii_lowercase().contains(&filter)
                || port
                    .process
                    .clone()
                    .unwrap_or_default()
                    .to_ascii_lowercase()
                    .contains(&filter)
                || port.port.to_string().contains(&filter)
        })
        .map(|port| {
            vec![
                format!("{}:{}", port.address, port.port),
                port.protocol.clone(),
                format!("{:?}", port.scope).to_lowercase(),
                port.state.clone(),
                port.process.clone().unwrap_or_else(|| "-".into()),
                port.pid
                    .map(|p| p.to_string())
                    .unwrap_or_else(|| "-".into()),
                if port.scope == crate::model::ExposureScope::All {
                    "exposed"
                } else if port.scope == crate::model::ExposureScope::Local {
                    "local-only"
                } else {
                    ""
                }
                .to_string(),
            ]
        })
        .collect();
    if rows.is_empty() {
        frame.render_widget(
            Paragraph::new(Line::styled(
                if fresh.value.is_empty() {
                    T.empty_no_listening
                } else {
                    T.empty_filtered
                }
                .to_string(),
                ui.theme.muted,
            )),
            inner,
        );
        return;
    }
    frame.render_widget(
        list_table(
            ui,
            &[
                "Address", "Proto", "Scope", "State", "Process", "PID", "Reach",
            ],
            rows,
            Some(ui.state.security_selected()),
            &[
                Constraint::Length(24),
                Constraint::Length(6),
                Constraint::Length(10),
                Constraint::Length(12),
                Constraint::Min(10),
                Constraint::Length(7),
                Constraint::Length(10),
            ],
        ),
        inner,
    );
}

fn firewall(ui: &Ui, frame: &mut Frame, area: Rect) {
    let rows = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(7), Constraint::Min(4)])
        .split(area);
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.firewall {
        Some(fresh) => {
            let status = &fresh.value;
            lines.push(Line::from(vec![
                Span::styled(" State  ", ui.theme.muted),
                status_badge(
                    ui,
                    match status.enabled {
                        Some(true) => UiStatus::Pass,
                        Some(false) => UiStatus::Warning,
                        None => UiStatus::Unknown,
                    },
                ),
            ]));
            for backend in status.backends.iter().take(3) {
                lines.push(Line::styled(
                    format!(
                        "  {}: {} ({})",
                        backend.name,
                        match backend.active {
                            Some(true) => "active",
                            Some(false) => "inactive",
                            None => "unknown",
                        },
                        backend.via
                    ),
                    ui.theme.muted,
                ));
            }
            for note in status.notes.iter().take(2) {
                lines.push(Line::styled(
                    format!("  note: {}", truncate(note, 100, ui.theme)),
                    ui.theme.muted,
                ));
            }
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    lines.push(Line::styled(
        format!(
            "  b block IP   u unblock (netro-created only)   {}",
            T.fw_scope_warning
        ),
        ui.theme.muted,
    ));
    frame.render_widget(
        Paragraph::new(lines).block(panel(ui, T.tab_firewall)),
        rows[0],
    );

    let block = panel(ui, "RULES");
    let inner = block.inner(rows[1]);
    frame.render_widget(block, rows[1]);
    let Some(rules) = &ui.state.caches.rules else {
        frame.render_widget(
            Paragraph::new(Line::styled(T.loading.to_string(), ui.theme.muted)),
            inner,
        );
        return;
    };
    let rows_data: Vec<Vec<String>> = rules
        .value
        .iter()
        .take(inner.height as usize)
        .map(|rule| {
            vec![
                rule.backend.clone(),
                rule.action.clone(),
                truncate(&rule.raw, 80, ui.theme),
            ]
        })
        .collect();
    frame.render_widget(
        list_table(
            ui,
            &["Backend", "Action", "Rule"],
            rows_data,
            Some(ui.state.security_selected()),
            &[
                Constraint::Length(14),
                Constraint::Length(10),
                Constraint::Min(30),
            ],
        ),
        inner,
    );
}

fn integrity(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    match &ui.state.caches.baseline {
        Some(baseline) => {
            lines.push(Line::styled(
                format!(
                    " {}: {} entries, created {}",
                    T.integ_baseline,
                    baseline.entries.len(),
                    crate::core::reporting::format_epoch(baseline.created_epoch)
                ),
                ui.theme.text,
            ));
            lines.push(Line::styled(
                format!(
                    " {}: {}",
                    T.integ_paths,
                    truncate(&baseline.paths.join(", "), 100, ui.theme)
                ),
                ui.theme.muted,
            ));
        }
        None => lines.push(Line::styled(
            T.integ_no_baseline.to_string(),
            ui.theme.warning,
        )),
    }
    lines.push(Line::styled(
        format!("  c {}   s {}", T.integ_create, T.integ_scan),
        ui.theme.muted,
    ));
    lines.push(Line::from(""));
    if let Some(report) = &ui.state.caches.integrity_report {
        let changed: Vec<&crate::model::IntegrityChange> = report
            .value
            .changes
            .iter()
            .filter(|c| c.status != crate::model::IntegrityStatus::Unchanged)
            .collect();
        if changed.is_empty() {
            lines.push(Line::styled(
                " no changes since baseline".to_string(),
                ui.theme.success,
            ));
        }
        for change in changed.iter().take(20) {
            lines.push(Line::from(vec![
                Span::styled(
                    format!(" {:<9}", format!("{:?}", change.status).to_uppercase()),
                    match change.status {
                        crate::model::IntegrityStatus::Modified => ui.theme.warning,
                        crate::model::IntegrityStatus::Removed => ui.theme.error,
                        _ => ui.theme.accent,
                    },
                ),
                Span::styled(change.path.clone(), ui.theme.text),
            ]));
            for detail in change.details.iter().take(2) {
                lines.push(Line::styled(format!("    - {detail}"), ui.theme.muted));
            }
        }
        lines.push(Line::styled(
            format!(" {} unchanged file(s)", report.value.unchanged),
            ui.theme.muted,
        ));
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.tab_integrity))
            .wrap(Wrap { trim: false }),
        area,
    );
}

fn external(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut lines: Vec<Line> = Vec::new();
    lines.push(Line::styled(
        "External scanners are optional and clearly labelled as external tool output.".to_string(),
        ui.theme.muted,
    ));
    lines.push(Line::styled(
        "  x run external scanners (slow, requires installation)".to_string(),
        ui.theme.muted,
    ));
    lines.push(Line::from(""));
    match &ui.state.caches.external_tools {
        Some(tools) => {
            for tool in &tools.value {
                let status = if tool.ran {
                    UiStatus::Pass
                } else if tool.installed {
                    UiStatus::Info
                } else {
                    UiStatus::Unavailable
                };
                lines.push(Line::from(vec![
                    Span::styled(format!(" {:<12}", tool.tool), ui.theme.text),
                    status_badge(ui, status),
                    Span::raw("  "),
                    Span::styled(
                        tool.summary
                            .clone()
                            .or_else(|| tool.error.clone())
                            .or_else(|| tool.note.clone())
                            .unwrap_or_default(),
                        ui.theme.muted,
                    ),
                ]));
            }
        }
        None => lines.push(Line::styled(T.loading.to_string(), ui.theme.muted)),
    }
    frame.render_widget(
        Paragraph::new(lines)
            .block(panel(ui, T.tab_external))
            .wrap(Wrap { trim: false }),
        area,
    );
}
