# netRo TUI

The terminal UI is a presentation layer over the same diagnostic engine the CLI
uses. It contains no probes of its own: every value comes from `core/` through
the platform providers, and every action is a typed `Action`, never a shell
string.

```
TUI (ratatui + crossterm)
   ↓ typed actions / task manager
core (dns, scan, discovery, security, doctor, monitor, reporting, snapshots)
   ↓
platform providers (Linux / Windows / macOS)
```

## Starting

```bash
netro            # launches the TUI when attached to a terminal
netro tui        # explicit; --no-mouse, --theme auto|dark|light|contrast|none
```

Without a terminal (pipes, CI, cron), `netro` prints help instead of hanging.

## Screens

| Screen | Contents |
|--------|----------|
| Dashboard | host/OS/uptime, streamed health checks, network summary, resource gauges, findings |
| System | CPU, memory, storage, GPU and the live process table |
| Network | tabs: Overview, Interfaces, Routes, DNS, Connectivity, Latency, Trace, Connections |
| Discovery | target/method form, real progress, hosts with MAC/vendor/hostname/ports |
| Scanner | port scan (profiles, detection toggles, authorization), host-scan pointer, nmap status |
| Security | tabs: Overview, Findings, Accounts, Listening, Firewall, Integrity, External tools |
| Monitor | rolling CPU/memory/network sparklines, temperatures, top processes |
| Doctor | checks stream in live, summary, findings with smart navigation |
| Reports | format/scope/path selection, generation from cached results |
| Snapshots | create, view, compare (structured diff), delete, export |
| Settings | appearance, monitoring, scan defaults, privacy, integrations (validated) |

## Keyboard

| Key | Action |
|-----|--------|
| `↑ ↓` / `k j` | move selection |
| `← →` / `h l` | switch tabs / change the selected setting (Scanner: cycle form fields) |
| `Enter` | open / edit / run the focused field |
| `Esc` | back, close overlay, clear filter, cancel a running task |
| `Tab` / `Shift+Tab` | next / previous screen (aliases `N` / `P`) |
| `/` | filter the current list (Enter keeps it, Esc clears) |
| `Ctrl+P` | command palette (fuzzy match, typed actions) |
| `r` / `R` | refresh current screen / everything |
| `?` (alias `H`) | contextual help |
| `q` | quit |
| `Ctrl+C` | quit immediately (cancels running tasks) |

Uppercase `N`/`P`/`H` aliases exist because some terminals and keyboard
layouts deliver Tab/`?` through layout-dependent translation; the aliases are
plain letters and work everywhere.

Screen keys: `d` doctor, `g` run the screen's action, `p` pause monitor,
`+`/`-` monitor interval, `c`/`s` integrity baseline/scan, `b`/`u` firewall
block/unblock, `x`/`m`/`e`/`d` snapshot compare/mark/export/delete, `i` inspect
a doctor finding, `1`–`3` scanner tabs (the form fields move with `←`/`→` and
toggle with `Space`). Mouse wheel scrolls lists; the whole UI
is keyboard-operable without a mouse.

## Command palette

`Ctrl+P`, type to filter, `Enter` to run. Commands are typed values
(`Action::RunDoctor`, `Action::OpenScreen(Screen::Scanner, _)`, …) — netRo never
builds a command line from text.

## Tasks, caching and cancellation

* Every slow operation runs in a worker thread (`src/tui/tasks.rs`) and reports
  a typed result; the render loop never blocks on IO.
* Progress is real: scan progress is completed/total probes, discovery reports
  phase/probed/total/found, doctor streams each finished check, monitor streams
  samples. There are no fabricated percentages.
* `Esc` cancels the current long-running task. Cancellation is cooperative and
  verified by tests (`scan_cancellation_produces_partial_result`); partial
  results are returned and labelled `cancelled`.
* Results are cached with per-section freshness (`TTL_*` in `src/tui/state.rs`).
  Screens reuse fresh results instead of re-probing; the doctor reuses a fresh
  connectivity report and security audit, so the same probes never run twice in
  one session. `r`/`R` force a refresh.
* Freshness is always visible (status panel "Data" section and screen footers).

## Terminal support

* Capabilities detected at startup: size, color depth (`none`/16/256/truecolor),
  Unicode, `NO_COLOR`, `TERM=dumb`.
* Responsive breakpoints: three panes ≥120 columns, two panes ≥60, compact
  selector ≥40, and a "terminal too small" screen below 40×12.
* Themes: Auto, Dark, Light, High contrast, No color. Status is always
  conveyed by a symbol **and** text, never by color alone.
* ASCII fallback when Unicode is unavailable (`NETRO_ASCII=1` forces it).
* Terminal lifecycle is guarded: raw mode, alternate screen, cursor and mouse
  capture are restored on normal exit, on error, and on panic (panic hook). A
  crashed TUI cannot leave the terminal in raw mode.

## Safety

* All strings that originate outside the process (service banners, TLS
  certificate fields, DNS answers, discovered hostnames/vendors, scan output)
  pass through `util::sanitize_terminal` at the display boundary; ANSI/OSC
  sequences are stripped. Regression tests inject hostile strings into tables
  and detail drawers and assert nothing reaches the buffer.
* Firewall changes require the confirmation dialog that states the scope ("This
  machine" — it does not disconnect devices from a router). Destructive actions
  are classified in `Action::is_destructive` and always routed through
  confirmation.
* Settings use selectors for enumerated values and the same validated parsers
  as the CLI; invalid values are rejected with a `CONFIG_ERROR` panel.

## Testing

```bash
cargo test --test tui_render       # deterministic snapshots (TestBackend)
cargo test --test tui_interaction  # key sequences against the app loop
cargo test --test tui_pty          # real binary in a PTY (portable-pty)
```

* Rendering snapshots cover 40×12, 60×20, 80×24, 100×30, 120×32 and 160×45,
  every screen, every tab, overlays, empty states and the too-small screen.
* Snapshots are intentional: review the diff, then run `INSTA_UPDATE=always`.
  `scripts/verify.sh` fails if unreviewed `*.snap.new` files are present.
* PTY tests verify launch, navigation, help, resize, Ctrl+C, clean exit,
  alternate-screen restoration (Unix) and that a non-terminal launch prints
  help. They run on Linux, Windows (ConPTY) and macOS in CI.

## Performance

Measured on Linux x86_64 (release build; see `scripts/bench.sh`):

| Metric | Result |
|--------|--------|
| Time to first frame | immediate (tasks run in background) |
| Steady-state idle CPU | ~0% (redraws throttled to 1 Hz when idle) |
| Peak RSS | ~22 MB |
| Startup diagnostics | same cost as `netro doctor` (~5 s), streamed so the UI stays responsive |

## Limitations

* Mouse support is scroll-only; click-to-select is not implemented.
* The TUI cannot elevate privileges; privileged actions report
  `PERMISSION_REQUIRED` with instructions, exactly like the CLI.
* Discovery and scanning are local-scope by default, matching the CLI rules.
* Windows/macOS TUI runtime behavior is validated by CI (compile + PTY tests)
  but has not been exercised on physical hardware in this development
  environment; see `docs/TUI_FINAL_AUDIT.md`.
