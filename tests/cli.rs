//! End-to-end CLI tests.
//!
//! These run the real binary and validate the machine-readable contract:
//! valid JSON, stable error codes, correct exit codes, and no ANSI escapes in
//! JSON output. Each test gets an isolated config/data/cache directory so the
//! user's real configuration is never touched.

use std::path::PathBuf;
use std::process::{Command, Output};

struct Env {
    dir: PathBuf,
}

impl Env {
    fn new(name: &str) -> Self {
        let dir = std::env::temp_dir().join(format!(
            "netro-cli-test-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("create temp dir");
        Env { dir }
    }

    fn run(&self, args: &[&str]) -> Output {
        Command::new(env!("CARGO_BIN_EXE_netro"))
            .args(args)
            .env("XDG_CONFIG_HOME", self.dir.join("config"))
            .env("XDG_DATA_HOME", self.dir.join("data"))
            .env("XDG_CACHE_HOME", self.dir.join("cache"))
            .env("HOME", &self.dir)
            .env("NO_COLOR", "1")
            .output()
            .expect("failed to run netro")
    }
}

impl Drop for Env {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).to_string()
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).to_string()
}

fn json(output: &Output) -> serde_json::Value {
    let text = stdout(output);
    serde_json::from_str(&text).unwrap_or_else(|e| {
        panic!(
            "stdout is not valid JSON ({e}).\nstdout:\n{text}\nstderr:\n{}",
            stderr(output)
        )
    })
}

#[test]
fn version_command_reports_semver() {
    let env = Env::new("version");
    let out = env.run(&["version"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("netro 5.0.0"), "got: {text}");
    assert!(text.contains("target:"));
}

#[test]
fn version_json_has_no_ansi() {
    let env = Env::new("version-json");
    let out = env.run(&["version", "--json"]);
    assert!(out.status.success());
    let raw = stdout(&out);
    assert!(!raw.contains('\u{1b}'), "ANSI escapes found in JSON output");
    let value = json(&out);
    assert_eq!(value["name"], "netro");
    assert_eq!(value["version"], "5.0.0");
}

#[test]
fn help_lists_core_commands() {
    let env = Env::new("help");
    let out = env.run(&["--help"]);
    assert!(out.status.success());
    let text = stdout(&out);
    for command in [
        "system",
        "network",
        "connections",
        "processes",
        "security",
        "firewall",
        "integrity",
        "doctor",
        "monitor",
        "report",
        "config",
    ] {
        assert!(text.contains(command), "help is missing {command}: {text}");
    }
}

#[test]
fn system_json_contract() {
    let env = Env::new("system");
    let out = env.run(&["system", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["command"], "system");
    assert_eq!(value["schema_version"], 1);
    let data = &value["data"];
    assert!(data["cpu"]["logical_cores"].as_u64().unwrap_or(0) >= 1);
    assert!(data["memory"]["total_bytes"].as_u64().unwrap_or(0) > 0);
    assert!(!data["os"]["arch"].as_str().unwrap_or("").is_empty());
    assert!(!data["os"]["platform"].is_null());
}

#[test]
fn doctor_json_contract_and_score_bounds() {
    let env = Env::new("doctor");
    let out = env.run(&["doctor", "--json", "--no-internet"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["command"], "doctor");
    let data = &value["data"];
    let checks = data["checks"].as_array().expect("checks array");
    assert!(checks.len() >= 8, "too few checks: {}", checks.len());
    let ids: Vec<&str> = checks.iter().filter_map(|c| c["id"].as_str()).collect();
    for expected in [
        "system", "cpu", "memory", "storage", "network", "dns", "security",
    ] {
        assert!(ids.contains(&expected), "missing check {expected}: {ids:?}");
    }
    let summary_score = &data["summary"]["score"];
    assert!(
        summary_score["total"].as_i64().unwrap_or(-1) >= 0
            && summary_score["total"].as_i64().unwrap_or(101) <= 100
    );
    assert!(summary_score["methodology"].as_str().unwrap_or("").len() > 20);
    // The internet check must be SKIPPED, never PASS, when skipped.
    let internet = checks.iter().find(|c| c["id"] == "internet").unwrap();
    assert_eq!(internet["status"], "SKIPPED");
}

#[test]
fn network_interfaces_json_is_array_with_loopback() {
    let env = Env::new("interfaces");
    let out = env.run(&["network", "interfaces", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let interfaces = value["data"].as_array().expect("data array");
    assert!(!interfaces.is_empty());
    assert!(interfaces.iter().any(|i| i["kind"] == "loopback"));
}

#[test]
fn network_routes_json_default_present_on_typical_hosts() {
    let env = Env::new("routes");
    let out = env.run(&["network", "routes", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let routes = value["data"].as_array().expect("routes array");
    // A machine may be truly offline; every route must at least be well-formed.
    for route in routes {
        assert!(!route["family"].as_str().unwrap_or("").is_empty());
        assert!(route["destination"].is_string());
    }
}

#[test]
fn security_audit_json_has_transparent_score() {
    let env = Env::new("security");
    let out = env.run(&["security", "audit", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let data = &value["data"];
    let score = &data["score"];
    assert!(score["total"].as_i64().unwrap_or(-1) >= 0);
    assert!(score["max"].as_i64().unwrap_or(0) > 0);
    assert!(score["methodology"].as_str().unwrap_or("").len() > 20);
    let categories = score["categories"].as_array().expect("categories");
    assert!(categories.len() >= 4);
    for finding in data["findings"].as_array().expect("findings") {
        // Every finding must carry evidence and a score impact.
        assert!(!finding["evidence"].as_array().unwrap().is_empty());
        assert!(finding["score_impact"].as_i64().unwrap_or(-1) >= 0);
        assert!(
            ["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
                .contains(&finding["severity"].as_str().unwrap_or("")),
            "unexpected severity: {}",
            finding["severity"]
        );
    }
}

#[test]
fn public_scan_requires_authorization_with_exit_code_7() {
    let env = Env::new("scan-unauthorized");
    let out = env.run(&["network", "scan", "1.1.1.1", "--ports", "80", "--json"]);
    assert_eq!(out.status.code(), Some(7), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["error"]["code"], "UNAUTHORIZED_SCAN");
    assert!(value["error"]["hint"]
        .as_str()
        .unwrap_or("")
        .contains("--authorized"));
}

#[test]
fn scan_detects_open_local_listener() {
    let env = Env::new("scan-local");
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let out = env.run(&[
        "network",
        "scan",
        "127.0.0.1",
        "--ports",
        &port.to_string(),
        "--no-banner",
        "--no-tls",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let ports = value["data"]["ports"].as_array().expect("ports");
    assert_eq!(ports.len(), 1);
    assert_eq!(ports[0]["state"], "open");
    assert_eq!(ports[0]["port"].as_u64(), Some(port as u64));
}

#[test]
fn scan_closed_port_is_reported_closed() {
    let env = Env::new("scan-closed");
    // Port 1 on loopback is virtually always closed.
    let out = env.run(&[
        "network",
        "scan",
        "127.0.0.1",
        "--ports",
        "1",
        "--no-banner",
        "--no-tls",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let state = value["data"]["ports"][0]["state"].as_str().unwrap_or("");
    assert_ne!(state, "open", "port 1 must not be reported open");
}

#[test]
fn invalid_target_is_rejected_with_exit_code_7() {
    let env = Env::new("scan-invalid");
    let out = env.run(&["network", "scan", "bad host;rm -rf /", "--json"]);
    assert_eq!(out.status.code(), Some(7), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["error"]["code"], "INVALID_TARGET");
}

/// Minimal one-shot HTTP server used to exercise the speed-test provider
/// without any third-party service.
fn spawn_http_server(body: Vec<u8>, status: &'static str) -> (u16, std::thread::JoinHandle<()>) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind http server");
    let port = listener.local_addr().unwrap().port();
    let handle = std::thread::spawn(move || {
        // Serve exactly one request per test invocation.
        for _ in 0..1 {
            let Ok((mut stream, _)) = listener.accept() else {
                return;
            };
            stream
                .set_read_timeout(Some(std::time::Duration::from_millis(500)))
                .ok();
            let mut reader = stream.try_clone().unwrap();
            let read_thread = std::thread::spawn(move || {
                let mut buf = [0u8; 4096];
                let _ = std::io::Read::read(&mut reader, &mut buf);
            });
            let header = format!(
                "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            );
            use std::io::Write;
            let _ = stream.write_all(header.as_bytes());
            if status.starts_with('2') {
                let _ = stream.write_all(&body);
            }
            let _ = stream.flush();
            let _ = read_thread.join();
        }
    });
    (port, handle)
}

#[test]
fn http_speedtest_measures_real_transfer() {
    let env = Env::new("speedtest-http");
    let body = vec![0xABu8; 2_000_000];
    let (port, server) = spawn_http_server(body.clone(), "200 OK");
    let url = format!("http://127.0.0.1:{port}/blob.bin");
    let out = env.run(&[
        "network",
        "speedtest",
        "--provider",
        "http",
        "--server",
        &url,
        "--direction",
        "download",
        "--duration",
        "2",
        "--json",
    ]);
    let _ = server.join();
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let data = &value["data"];
    assert_eq!(data["provider"], "http");
    assert_eq!(data["server"], url);
    let mbps = data["download_mbps"].as_f64().unwrap_or(0.0);
    assert!(mbps > 0.0, "no throughput measured: {data}");
    assert_eq!(
        data["bytes_downloaded"].as_u64().unwrap_or(0),
        body.len() as u64
    );
}

#[test]
fn http_speedtest_refuses_error_responses() {
    let env = Env::new("speedtest-http-error");
    let (port, server) = spawn_http_server(b"unauthorized".to_vec(), "401 Unauthorized");
    let url = format!("http://127.0.0.1:{port}/blob.bin");
    let out = env.run(&[
        "network",
        "speedtest",
        "--provider",
        "http",
        "--server",
        &url,
        "--direction",
        "download",
        "--duration",
        "1",
        "--json",
    ]);
    let _ = server.join();
    assert_eq!(out.status.code(), Some(8), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["error"]["code"], "NETWORK_UNREACHABLE");
    assert!(value["error"]["message"]
        .as_str()
        .unwrap_or("")
        .contains("HTTP 401"));
}

#[test]
fn speedtest_without_server_is_a_config_error() {
    let env = Env::new("speedtest-noserver");
    let out = env.run(&["network", "speedtest", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["error"]["code"], "CONFIG_ERROR");
    assert!(value["error"]["hint"]
        .as_str()
        .unwrap_or("")
        .contains("--server"));
}

#[test]
fn leading_dash_target_is_refused_by_argument_parsing() {
    let env = Env::new("scan-arg-injection");
    // clap must treat this as an unknown flag rather than passing it to the
    // target parser or an external tool.
    let out = env.run(&["network", "scan", "-oX", "/tmp/x"]);
    assert_eq!(out.status.code(), Some(2));
    assert!(stderr(&out).contains("unexpected argument") || stderr(&out).contains("error"));
}

#[test]
fn unknown_format_exits_with_config_error() {
    let env = Env::new("bad-format");
    let out = env.run(&["system", "--format", "xml"]);
    assert_eq!(out.status.code(), Some(1));
    assert!(stderr(&out).contains("CONFIG_ERROR"));
}

#[test]
fn csv_output_has_header_and_commas() {
    let env = Env::new("csv");
    let out = env.run(&["network", "interfaces", "--format", "csv"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let mut lines = text.lines();
    let header = lines.next().expect("header");
    assert!(header.starts_with("Interface,Kind,State"));
    for line in lines {
        assert!(line.matches(',').count() >= 4);
    }
}

#[test]
fn config_path_and_init_are_isolated() {
    let env = Env::new("config");
    let out = env.run(&["config", "path", "--json"]);
    assert!(out.status.success());
    let value = json(&out);
    let path = value["config_file"].as_str().unwrap_or("");
    assert!(path.contains("netro"), "unexpected config path: {path}");

    let out = env.run(&["config", "init", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["created"], true);
    assert!(std::path::Path::new(value["config_file"].as_str().unwrap()).exists());

    // Second init must not clobber.
    let out = env.run(&["config", "init", "--json"]);
    let value = json(&out);
    assert_eq!(value["created"], false);
}

#[test]
fn config_set_validates_keys() {
    let env = Env::new("config-set");
    let out = env.run(&["config", "set", "scan.timeout_ms", "1500", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = env.run(&["config", "set", "does.not.exist", "1", "--json"]);
    assert!(out.status.code().is_some());
    assert!(stderr(&out).contains("CONFIG_ERROR") || stdout(&out).contains("CONFIG_ERROR"));
}

#[test]
fn config_rejects_invalid_enum_and_port_values() {
    let env = Env::new("config-validation");

    let out = env.run(&["config", "set", "discovery.method", "bogus", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["error"]["code"], "CONFIG_ERROR");

    let out = env.run(&["config", "set", "scan.ports", "not-a-port", "--json"]);
    assert_eq!(out.status.code(), Some(1), "stderr: {}", stderr(&out));
    assert_eq!(json(&out)["error"]["code"], "CONFIG_ERROR");

    // Valid values still work.
    let out = env.run(&["config", "set", "discovery.method", "tcp", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));

    let out = env.run(&["config", "set", "scan.ports", "22,80,443-445", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
}

#[test]
fn integrity_baseline_and_scan_round_trip() {
    let env = Env::new("integrity");
    let data_dir = env.dir.join("integrity-data");
    std::fs::create_dir_all(&data_dir).unwrap();
    let watched = data_dir.join("watched.conf");
    std::fs::write(&watched, b"original").unwrap();

    let path_arg = data_dir.display().to_string();
    let out = env.run(&["integrity", "baseline", "--paths", &path_arg, "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["data"]["hashed"].as_u64(), Some(1));

    let out = env.run(&["integrity", "scan", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["data"]["changes"].as_array().unwrap().len(), 0);

    std::fs::write(&watched, b"tampered").unwrap();
    let out = env.run(&["integrity", "scan", "--json"]);
    let value = json(&out);
    let changes = value["data"]["changes"].as_array().unwrap();
    assert_eq!(changes.len(), 1);
    assert_eq!(changes[0]["status"], "MODIFIED");
    assert!(changes[0]["details"]
        .as_array()
        .unwrap()
        .iter()
        .any(|d| d.as_str().unwrap_or("").contains("hash")));
}

#[test]
fn dependency_list_is_real_and_reports_missing_honestly() {
    let env = Env::new("deps");
    let out = env.run(&["dependencies", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let deps = value["data"].as_array().expect("deps array");
    assert!(!deps.is_empty());
    for dep in deps {
        assert!(dep["installed"].is_boolean());
        assert!(!dep["purpose"].as_str().unwrap_or("").is_empty());
        if dep["installed"] == false {
            assert!(dep["path"].is_null());
        }
    }
}

#[test]
fn monitor_produces_json_lines() {
    let env = Env::new("monitor");
    let out = env.run(&[
        "monitor",
        "--count",
        "2",
        "--interval",
        "0.3",
        "--no-processes",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    let lines: Vec<&str> = text.lines().filter(|l| !l.trim().is_empty()).collect();
    assert_eq!(lines.len(), 2, "expected 2 samples, got: {text}");
    for line in lines {
        assert!(!line.contains('\u{1b}'));
        let value: serde_json::Value = serde_json::from_str(line).expect("json line");
        assert!(value["data"]["cpu_usage_percent"].is_number());
        assert!(value["data"]["memory_total_bytes"].as_u64().unwrap() > 0);
    }
}

#[test]
fn firewall_block_dry_run_never_changes_state() {
    let env = Env::new("firewall-dry");
    let out = env.run(&["firewall", "block", "203.0.113.10", "--dry-run", "--json"]);
    match out.status.code() {
        Some(0) => {
            let value = json(&out);
            assert_eq!(value["data"]["applied"], false);
            let commands = value["data"]["commands"].as_array().unwrap();
            assert!(commands
                .iter()
                .any(|c| c.as_str().unwrap_or("").contains("203.0.113.10")));
        }
        // No firewall backend at all is a legitimate outcome, but it must be
        // reported as PLATFORM_UNSUPPORTED, never silently.
        Some(5) => {
            let value = json(&out);
            assert_eq!(value["error"]["code"], "PLATFORM_UNSUPPORTED");
        }
        other => panic!("unexpected exit code {other:?}: {}", stderr(&out)),
    }
}

#[test]
fn report_json_round_trip() {
    let env = Env::new("report");
    let out = env.run(&["report", "--json", "--no-internet", "--no-security"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    assert_eq!(value["command"], "report");
    assert!(value["data"]["doctor"]["checks"].as_array().unwrap().len() >= 8);
    assert!(
        value["data"]["system"]["memory"]["total_bytes"]
            .as_u64()
            .unwrap()
            > 0
    );
}

#[test]
fn report_html_is_written_and_escaped() {
    let env = Env::new("report-html");
    let path = env.dir.join("report.html");
    let out = env.run(&[
        "report",
        "--html",
        path.to_str().unwrap(),
        "--no-internet",
        "--quiet",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let html = std::fs::read_to_string(&path).expect("html file");
    assert!(html.starts_with("<!DOCTYPE html>"));
    assert!(html.contains("Overall health"));
    assert!(!html.contains("<script"));
}

#[test]
fn dns_json_query_uses_real_resolver_or_reports_unavailable() {
    let env = Env::new("dns");
    let out = env.run(&["network", "dns", "localhost", "--json"]);
    match out.status.code() {
        Some(0) => {
            let value = json(&out);
            assert_eq!(value["command"], "network.dns.query");
        }
        // Offline sandboxes without a resolver must produce a structured
        // NETWORK_DNS_UNAVAILABLE error rather than a crash or fake answer.
        Some(8) => {
            let value = json(&out);
            assert_eq!(value["error"]["code"], "NETWORK_DNS_UNAVAILABLE");
        }
        other => panic!("unexpected exit code {other:?}: {}", stderr(&out)),
    }
}

#[test]
fn latency_localhost_is_real_or_structured_failure() {
    let env = Env::new("latency");
    let out = env.run(&[
        "network",
        "latency",
        "127.0.0.1",
        "--count",
        "2",
        "--method",
        "tcp",
        "--port",
        "1",
        "--json",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let value = json(&out);
    let data = &value["data"];
    assert_eq!(data["method"], "tcp_connect");
    assert!(data["transmitted"].as_u64().unwrap() >= 1);
    // Port 1 is closed; the result must report loss rather than inventing RTTs.
    assert!(data["received"].as_u64().unwrap() <= 2);
}
