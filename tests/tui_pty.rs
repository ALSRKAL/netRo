//! PTY end-to-end tests: the real binary in a pseudo-terminal.
//!
//! These cover what `TestBackend` cannot: terminal setup/teardown, raw mode,
//! alternate screen, real key input and process exit. On Windows portable-pty
//! uses ConPTY, so the same flows run there (CI validates the platform).

use portable_pty::{native_pty_system, Child, CommandBuilder, MasterPty, PtySize};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

/// ConPTY is expensive and flaky when several sessions run concurrently on
/// Windows CI; PTY tests are serialized so each one gets a clean terminal.
static PTY_SERIAL: Mutex<()> = Mutex::new(());

fn serial_guard() -> std::sync::MutexGuard<'static, ()> {
    PTY_SERIAL
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

struct Session {
    master: Box<dyn MasterPty + Send>,
    writer: Arc<Mutex<Box<dyn Write + Send>>>,
    child: Box<dyn Child + Send + Sync>,
    output: Arc<Mutex<String>>,
    exited: bool,
}

impl Session {
    fn spawn(cols: u16, rows: u16) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "netro-pty-{}-{}",
            std::process::id(),
            Instant::now().elapsed().as_nanos()
        ));
        let _ = std::fs::create_dir_all(&dir);

        let pty_system = native_pty_system();
        let pair = pty_system
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .expect("openpty");

        let mut command = CommandBuilder::new(env!("CARGO_BIN_EXE_netro"));
        command.env("XDG_CONFIG_HOME", dir.join("config"));
        command.env("XDG_DATA_HOME", dir.join("data"));
        command.env("XDG_CACHE_HOME", dir.join("cache"));
        command.env("APPDATA", dir.join("appdata"));
        command.env("LOCALAPPDATA", dir.join("localappdata"));
        command.env("HOME", &dir);
        command.env("TERM", "xterm-256color");
        command.env("COLORTERM", "truecolor");
        command.env("LANG", "C.UTF-8");
        command.env("LC_ALL", "C.UTF-8");

        let child = pair.slave.spawn_command(command).expect("spawn netro");
        drop(pair.slave);

        let mut reader = pair.master.try_clone_reader().expect("pty reader");
        let writer: Arc<Mutex<Box<dyn Write + Send>>> =
            Arc::new(Mutex::new(pair.master.take_writer().expect("pty writer")));
        let output = Arc::new(Mutex::new(String::new()));
        let sink = output.clone();
        let responder = writer.clone();
        // ConPTY (and some terminal emulators) query the cursor position with
        // DSR (`ESC[6n`) at startup and wait for a reply. A real terminal
        // answers; this harness must too, otherwise the TUI never renders on
        // Windows. Window-size queries (`ESC[18t`) get a matching reply.
        std::thread::spawn(move || {
            let mut buf = [0u8; 8192];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        let chunk = String::from_utf8_lossy(&buf[..n]).to_string();
                        if let Ok(mut guard) = sink.lock() {
                            guard.push_str(&chunk);
                        }
                        if let Ok(mut out) = responder.lock() {
                            if chunk.contains("\u{1b}[6n") {
                                let _ = out.write_all(b"\x1b[1;1R");
                            }
                            if chunk.contains("\u{1b}[18t") {
                                let _ = out.write_all(format!("\x1b[8;{rows};{cols}t").as_bytes());
                            }
                            let _ = out.flush();
                        }
                    }
                }
            }
        });

        Session {
            master: pair.master,
            writer,
            child,
            output,
            exited: false,
        }
    }

    fn send(&mut self, bytes: &[u8]) {
        if let Ok(mut out) = self.writer.lock() {
            let _ = out.write_all(bytes);
            let _ = out.flush();
        }
    }

    /// Send ESC and wait so the terminal parser does not coalesce it with the
    /// next byte into an Alt+key sequence.
    fn send_escape(&mut self) {
        self.send(b"\x1b");
        std::thread::sleep(Duration::from_millis(250));
    }

    fn text(&self) -> String {
        self.output.lock().map(|g| g.clone()).unwrap_or_default()
    }

    /// Tail of the captured output with escapes made visible, for assertion
    /// messages (so a failure on another platform is diagnosable from CI logs).
    fn tail(&self, chars: usize) -> String {
        let text = self.text().replace('\u{1b}', "<ESC>");
        let mut recent: Vec<char> = text.chars().rev().take(chars).collect();
        recent.reverse();
        recent.into_iter().collect()
    }

    fn wait_for_text(&self, needle: &str, seconds: u64) -> bool {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if self.text().contains(needle) {
                return true;
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        false
    }

    fn resize(&mut self, cols: u16, rows: u16) {
        let _ = self.master.resize(PtySize {
            rows,
            cols,
            pixel_width: 0,
            pixel_height: 0,
        });
    }

    /// Wait for exit and return the exit code.
    fn wait_exit(&mut self, seconds: u64) -> Option<u32> {
        let deadline = Instant::now() + Duration::from_secs(seconds);
        while Instant::now() < deadline {
            if let Ok(Some(status)) = self.child.try_wait() {
                self.exited = true;
                return Some(status.exit_code());
            }
            std::thread::sleep(Duration::from_millis(50));
        }
        None
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        if !self.exited {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
        let _ = std::fs::remove_dir_all(std::env::temp_dir().join("netro-pty-cleanup"));
    }
}

#[test]
fn tui_launches_navigates_and_quits_cleanly() {
    let _serial = serial_guard();
    let mut session = Session::spawn(100, 30);
    assert!(
        session.wait_for_text("NAVIGATION", 45),
        "TUI did not render; tail: {}",
        session.tail(800)
    );
    assert!(session.wait_for_text("Dashboard", 15));
    std::thread::sleep(Duration::from_millis(300));

    // Help overlay via a real keypress.
    session.send(b"?");
    assert!(
        session.wait_for_text("KEYBOARD SHORTCUTS", 20),
        "help overlay missing; tail: {}",
        session.tail(800)
    );
    session.send_escape(); // Esc closes

    // Tab navigates to the System screen.
    session.send(b"\t");
    assert!(
        session.wait_for_text("MEMORY", 20),
        "system screen not reached; tail: {}",
        session.tail(800)
    );

    session.send(b"q");
    let code = session.wait_exit(30);
    assert_eq!(code, Some(0), "unclean exit");
    let output = session.text();
    assert!(!output.contains("panicked"), "panic output: {output}");
    #[cfg(unix)]
    assert!(
        output.contains("\u{1b}[?1049l"),
        "alternate screen was not left on exit"
    );
}

#[test]
fn tui_handles_resize_without_corruption() {
    let _serial = serial_guard();
    let mut session = Session::spawn(80, 24);
    assert!(session.wait_for_text("NAVIGATION", 45));
    session.resize(130, 40);
    std::thread::sleep(Duration::from_millis(500));
    session.send(b"\t"); // System
    assert!(
        session.wait_for_text("MEMORY", 20),
        "system screen not reached after resize; tail: {}",
        session.tail(800)
    );
    session.send(b"q");
    assert_eq!(session.wait_exit(30), Some(0));
    assert!(!session.text().contains("panicked"));
}

#[test]
fn tui_ctrl_c_exits_and_restores_terminal() {
    let _serial = serial_guard();
    let mut session = Session::spawn(90, 25);
    assert!(session.wait_for_text("NAVIGATION", 45));
    session.send(&[0x03]); // Ctrl+C
    assert_eq!(
        session.wait_exit(30),
        Some(0),
        "Ctrl+C did not exit cleanly"
    );
    #[cfg(unix)]
    assert!(
        session.text().contains("\u{1b}[?1049l"),
        "terminal was not restored after Ctrl+C"
    );
}

#[test]
fn tui_runs_doctor_and_renders_summary() {
    let _serial = serial_guard();
    let mut session = Session::spawn(120, 34);
    assert!(session.wait_for_text("NAVIGATION", 45));
    session.send(b"d");
    // Doctor streams checks and finishes with a summary; allow for real probes.
    assert!(
        session.wait_for_text("HEALTH SUMMARY", 240),
        "doctor summary never appeared"
    );
    session.send(b"q");
    assert_eq!(session.wait_exit(30), Some(0));
    assert!(!session.text().contains("panicked"));
}

#[test]
fn tui_small_terminal_shows_guidance_not_corruption() {
    let _serial = serial_guard();
    let mut session = Session::spawn(30, 8);
    assert!(
        session.wait_for_text("Terminal too small", 45),
        "too-small guidance missing: {}",
        session.text()
    );
    session.send(b"q");
    assert_eq!(session.wait_exit(30), Some(0));
}

#[test]
fn bare_netro_without_a_terminal_prints_help_instead_of_hanging() {
    // Not a PTY: stdout/stderr are pipes. The CLI must print help and exit.
    let output = std::process::Command::new(env!("CARGO_BIN_EXE_netro"))
        .env("XDG_CONFIG_HOME", PathBuf::from("/tmp/netro-no-tty/config"))
        .output()
        .expect("run netro");
    assert!(output.status.success());
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(
        text.contains("Usage: netro") || text.contains("Commands:"),
        "expected help output, got: {text}"
    );
}
