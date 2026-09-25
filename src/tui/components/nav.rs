//! Navigation pane (large/medium layouts) and compact screen selector.

use crate::tui::app::Ui;
use crate::tui::state::Screen;
use crate::tui::text::T;
use crate::tui::theme::UiStatus;
use ratatui::layout::Rect;
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Paragraph};
use ratatui::Frame;

/// Health summary shown next to each screen in the navigation list, derived
/// from cached results (never invented).
fn screen_status(ui: &Ui, screen: Screen) -> Option<UiStatus> {
    match screen {
        Screen::Security => {
            let audit = ui.state.caches.audit.as_ref()?;
            let worst = audit.value.findings.iter().map(|f| f.severity).max();
            Some(match worst {
                Some(severity) => UiStatus::from_severity(severity),
                None => UiStatus::Pass,
            })
        }
        Screen::Doctor => {
            if ui.state.doctor.is_running() || ui.is_running(crate::tui::tasks::TaskKind::Doctor) {
                Some(UiStatus::Running)
            } else {
                ui.state.doctor.report.as_ref().map(|report| {
                    if report.summary.failed > 0 {
                        UiStatus::Error
                    } else if report.summary.warnings > 0 {
                        UiStatus::Warning
                    } else {
                        UiStatus::Pass
                    }
                })
            }
        }
        Screen::Network => {
            let connectivity = ui.state.caches.connectivity.as_ref()?;
            if connectivity.value.internet_reachable {
                Some(UiStatus::Pass)
            } else if connectivity.value.gateway_reachable == Some(true) {
                Some(UiStatus::Warning)
            } else {
                Some(UiStatus::Error)
            }
        }
        Screen::System => {
            let system = ui.state.caches.system.as_ref()?;
            if system.value.memory.utilization_percent >= 95.0 {
                Some(UiStatus::Error)
            } else if system.value.memory.utilization_percent >= 85.0 {
                Some(UiStatus::Warning)
            } else {
                Some(UiStatus::Pass)
            }
        }
        Screen::Monitor => ui
            .state
            .monitor
            .sample
            .as_ref()
            .map(|_| {
                if ui
                    .state
                    .monitor
                    .paused
                    .load(std::sync::atomic::Ordering::Relaxed)
                {
                    UiStatus::Cancelled
                } else {
                    UiStatus::Running
                }
            })
            .or(Some(UiStatus::Running)),
        Screen::Discovery => ui.state.discovery.report.as_ref().map(|_| UiStatus::Pass),
        Screen::Scanner => ui.state.scanner.report.as_ref().map(|report| {
            if report
                .ports
                .iter()
                .any(|p| p.state == crate::model::PortState::Open)
            {
                UiStatus::Info
            } else {
                UiStatus::Pass
            }
        }),
        Screen::Snapshots => {
            if ui.state.snapshots.list.is_empty() {
                None
            } else {
                Some(UiStatus::Info)
            }
        }
        _ => None,
    }
}

pub fn render(ui: &Ui, frame: &mut Frame, area: Rect) {
    if area.width == 0 || area.height == 0 {
        return;
    }
    // Small terminals use a one-line selector instead of a vertical pane.
    if area.height <= 2 {
        render_compact(ui, frame, area);
        return;
    }

    let block = Block::default()
        .borders(Borders::LEFT)
        .border_style(ui.theme.border)
        .title(Span::styled(format!(" {} ", T.nav_title), ui.theme.muted));
    let inner = block.inner(area);
    frame.render_widget(block, area);

    let mut lines: Vec<Line> = Vec::new();
    for screen in Screen::ALL {
        let selected = screen == ui.state.screen;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        let mut spans = vec![
            Span::styled(format!(" {marker} "), ui.theme.accent),
            Span::styled(
                screen.title().to_string(),
                if selected {
                    ui.theme.title
                } else {
                    ui.theme.text
                },
            ),
        ];
        if let Some(status) = screen_status(ui, screen) {
            let symbol = ui.theme.symbols.for_status(status);
            spans.push(Span::raw(" "));
            spans.push(Span::styled(
                symbol.to_string(),
                ui.theme.status_style(status),
            ));
        }
        // Keep any task spinner visible in the navigation.
        if ui.is_running(match screen {
            Screen::Doctor => crate::tui::tasks::TaskKind::Doctor,
            Screen::Monitor => crate::tui::tasks::TaskKind::Monitor,
            Screen::Discovery => crate::tui::tasks::TaskKind::Discovery,
            Screen::Scanner => crate::tui::tasks::TaskKind::Scan,
            _ => crate::tui::tasks::TaskKind::System,
        }) && !matches!(
            screen,
            Screen::Doctor | Screen::Monitor | Screen::Discovery | Screen::Scanner
        ) {
            // Avoid showing unrelated spinners on screens with no task.
        }
        lines.push(Line::from(spans));
    }
    lines.push(Line::from(""));
    if let Some(score) = ui
        .state
        .caches
        .audit
        .as_ref()
        .map(|fresh| fresh.value.score.clone())
        .or_else(|| {
            ui.state
                .doctor
                .report
                .as_ref()
                .and_then(|r| r.summary.score.clone())
        })
    {
        lines.push(Line::styled(
            format!(" {}/{} ({})", score.total, score.max, score.grade),
            ui.theme.title,
        ));
        lines.push(Line::styled(format!(" {}", T.sec_score), ui.theme.muted));
    }
    frame.render_widget(Paragraph::new(lines), inner);
}

fn render_compact(ui: &Ui, frame: &mut Frame, area: Rect) {
    let mut spans: Vec<Span> = Vec::new();
    for screen in Screen::ALL {
        let selected = screen == ui.state.screen;
        let marker = if selected {
            ui.theme.symbols.selected
        } else {
            " "
        };
        spans.push(Span::styled(
            format!("{marker}{} ", short_title(screen)),
            if selected {
                ui.theme.selected
            } else {
                ui.theme.muted
            },
        ));
    }
    frame.render_widget(Paragraph::new(Line::from(spans)), area);
}

fn short_title(screen: Screen) -> &'static str {
    match screen {
        Screen::Dashboard => "Dash",
        Screen::System => "System",
        Screen::Network => "Net",
        Screen::Discovery => "Disc",
        Screen::Scanner => "Scan",
        Screen::Security => "Sec",
        Screen::Monitor => "Mon",
        Screen::Doctor => "Doc",
        Screen::Reports => "Rep",
        Screen::Snapshots => "Snap",
        Screen::Settings => "Set",
    }
}
