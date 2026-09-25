# netRo TUI — final audit

Environment for all local results:

```
host        Linux (Ubuntu 24.04), x86_64, kernel 6.8, normal user
rustc       1.90.0 / cargo 1.90
terminal    real PTY via util-linux `script` and portable-pty
```

Nothing below is claimed beyond the evidence shown. Windows/macOS runtime was
**not** exercised in this session; only compile checks and CI configuration were
produced here.

## Result table

| Area | Result | Evidence |
|------|--------|----------|
| Architecture | PASS | TUI depends only on `core`; no shell/command strings (`rg` checks), typed `Action`s, `src/tui/` layering |
| UI rendering | PASS | 45 deterministic `TestBackend` snapshots at 40×12 … 160×45 for all screens, tabs, overlays, empty and too-small states |
| Keyboard | PASS | 19 interaction tests (including the full acceptance flow) (arrows, j/k, Enter, Esc, Tab/Shift+Tab, `/`, `?`, `Ctrl+P`, `q`, `Ctrl+C`, screen keys) |
| Mouse | PARTIAL | Wheel scroll moves list selection; click-to-select intentionally not implemented (keyboard remains complete) |
| Responsive layout | PASS | breakpoints ≥120 / ≥60 / ≥40 / <40; snapshots at six sizes; resize PTY test |
| Small terminals | PASS | 30×8 PTY test shows "Terminal too small" guidance and quits cleanly |
| Unicode fallback | PASS | ASCII symbol set selected when Unicode unavailable or `NETRO_ASCII=1`; snapshots run with ASCII |
| Color fallback | PASS | NoColor theme test (no colors set), 16/256/truecolor mapping unit tests, `NO_COLOR` honored |
| Async tasks | PASS | every probe runs in a worker; render loop drains typed events only; `tasks.rs` unit tests for result/failure/cancel |
| Cancellation | PASS | `scan_cancellation_produces_partial_result` (Esc → report marked `cancelled`), monitor stop test; discovery cancel implemented |
| Terminal restoration | PASS | PTY tests assert clean exit 0 and alternate-screen leave sequence on quit and Ctrl+C; panic hook restores terminal |
| Security | PASS | ANSI/OSC injection tests at render boundary (tables + detail drawer), typed actions only, destructive actions behind confirmation |
| Performance | PASS | time-to-first-frame immediate; steady-state idle ≈0% CPU (6s vs 18s runs); ~22 MB RSS; `scripts/bench.sh` records baselines |
| Linux runtime | PASS | full PTY flows: launch, help, Tab navigation, resize, doctor with live streamed checks, Ctrl+C, quit |
| Windows runtime | UNVERIFIED | compile check passes (`x86_64-pc-windows-gnu`); CI job `tui-pty` runs ConPTY tests but was not executed here |
| macOS Intel runtime | UNVERIFIED | compile check passes (`x86_64-apple-darwin`); CI job configured, not executed here |
| macOS ARM64 runtime | UNVERIFIED | compile check passes (`aarch64-apple-darwin`); CI job configured, not executed here |
| Snapshot tests | PASS | `cargo test --test tui_render` → 11 tests, 45 snapshots; guard fails on unreviewed `.snap.new` |
| PTY tests | PASS | `cargo test --test tui_pty` → 6 tests on Linux; non-terminal launch prints help (no hang) |
| CI | PASS (config) | `.github/workflows/ci.yml` jobs: quality, test (incl. TUI render/interaction), tui-pty (4 platforms), cross-check; YAML validated |
| Regression suite | PASS | `cargo test` → 239 tests green; `cargo fmt --check`, `clippy -D warnings` clean |

## What was fixed during the TUI self-review (10 passes)

1. **UX**: running the doctor now navigates to the Doctor screen (previously it
   ran invisibly); Esc on the Monitor screen stops monitoring and leaves the
   screen so it is not auto-restarted.
2. **Visual**: nav score no longer truncated; dashboard health rendered as a
   two-column grid; monitor's bogus network gauge replaced with real per-
   direction rates and sparklines; label columns widened in scanner/discovery.
3. **Responsive**: dashboard layout constraints adjusted after reviewing
   snapshots at all six required sizes.
4. **Interaction**: Windows delivers both key-press and key-release records;
   releases were being handled, double-triggering every action (two screens per
   Tab). Releases are now ignored. Plain-letter aliases `N`/`P` (screen
   navigation) and `H` (help) were also added;
   scanner form fields cycle with Left/Right and toggle with
   Space (Tab stays global for screens; 1/2/3 switch scanner tabs); Enter edits
   text fields; doctor findings navigate with Enter
   (`i` opens details); footer hints match the real bindings.
5. **Async**: doctor reuses a fresh connectivity report and security audit
   (no duplicate probes); monitor refresh is skipped when process data was not
   requested; tick redraws throttled to 1 Hz when idle.
6. **Security**: remote strings (banners, TLS fields, DNS answers, discovery
   hostnames/vendors, scan services) are sanitized at the render boundary; a
   regression test injects ANSI/OSC payloads and asserts they never reach the
   terminal buffer.
7. **Cross-platform**: `cargo check` passes for Windows GNU and both macOS
   targets with the ratatui/crossterm stack.
8. **Performance**: measured startup, idle and monitor cost; idle steady state
   is ~0% CPU; TUI memory ≈ CLI doctor peak.
9. **Accessibility**: NoColor theme test, ASCII snapshots, small-terminal
   guidance, status always symbol+text.
10. **Regression**: full suite (core + CLI + TUI) re-run after every fix; all
    green.

## Known limitations

* Mouse clicks are not handled (scroll only).
* Windows/macOS runtime behavior relies on CI; physical-hardware validation is
  still recommended before calling those platforms production-ready.
* The TUI cannot elevate privileges; it reports `PERMISSION_REQUIRED` like the
  CLI.
* Speed test is intentionally CLI-only (it needs a configured server); the
  palette points users to the command.
* The right-hand live status panel is hidden below 120 columns by design.
