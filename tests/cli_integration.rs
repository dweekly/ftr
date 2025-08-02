//! Integration tests for ftr CLI functionality

#![allow(clippy::unwrap_used)]

use assert_cmd::Command;
use predicates::prelude::*;
use serde_json::Value;

#[test]
fn test_help_output() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.arg("--help");

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("Fast parallel ICMP traceroute"))
        .stdout(predicate::str::contains("--json"))
        .stdout(predicate::str::contains("--port"))
        .stdout(predicate::str::contains("--verbose"));
}

#[test]
fn test_version_output() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.arg("--version");

    let output = cmd.output().expect("Failed to execute command");
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should contain "ftr" followed by a version number
    assert!(stdout.starts_with("ftr "));
    // In debug builds, should contain -UNRELEASED
    if cfg!(debug_assertions) {
        assert!(stdout.contains("-UNRELEASED"));
    }
}

#[test]
fn test_json_output_format() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--json",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "127.0.0.1",
    ]);

    let output = cmd.output().expect("Failed to execute command");

    // Should produce valid JSON
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let parsed: Result<Value, _> = serde_json::from_str(&stdout);
        assert!(parsed.is_ok(), "Output should be valid JSON");

        // Check JSON structure
        if let Ok(json) = parsed {
            assert!(json["target"].is_string());
            assert!(json["target_ip"].is_string());
            assert!(json["hops"].is_array());
            assert!(json["protocol"].is_string());
            assert!(json["socket_mode"].is_string());
        }
    }
}

#[test]
fn test_port_warning_with_icmp() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--protocol",
        "icmp",
        "--port",
        "8080",
        "--start-ttl",
        "1",
        "127.0.0.1",
    ]);

    let output = cmd.output().expect("Failed to execute command");
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Either we get the port warning (if socket creation succeeds)
    // or we get a permission error (if socket creation fails)
    assert!(
        stderr.contains("Warning: Port 8080 specified but will be ignored")
            || stderr.contains("Permission denied")
            || stderr.contains("Failed to create"),
        "Expected either port warning or permission error, got: {}",
        stderr
    );
}

#[test]
fn test_verbose_mode() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--verbose",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "127.0.0.1",
    ]);

    cmd.assert().stderr(predicate::str::contains("Using"));
}

#[test]
fn test_queries_parameter() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--queries",
        "3",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "127.0.0.1",
    ]);

    // Should complete without error
    cmd.assert().code(predicate::eq(0).or(predicate::eq(1)));
}

#[test]
fn test_invalid_ttl() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args(["--start-ttl", "0", "127.0.0.1"]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: start-ttl must be at least 1",
    ));
}

#[test]
fn test_invalid_timeout() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args(["--probe-timeout-ms", "0", "127.0.0.1"]);

    cmd.assert().failure().stderr(predicate::str::contains(
        "Error: probe-timeout-ms must be greater than 0",
    ));
}

#[test]
fn test_localhost_traceroute() {
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "127.0.0.1",
    ]);

    let output = cmd.output().expect("Failed to execute command");

    // Should either succeed or fail with permission error
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Permission denied")
                || stderr.contains("requires root")
                || stderr.contains("Failed to create"),
            "Expected permission error, got: {}",
            stderr
        );
    }
}

#[test]
fn test_socket_mode_selection() {
    // Test that we can request specific socket modes
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args(["--socket-mode", "dgram", "--start-ttl", "1", "127.0.0.1"]);

    // Should either work or fail with appropriate error
    cmd.assert().code(predicate::eq(0).or(predicate::eq(1)));
}

#[test]
fn test_protocol_selection() {
    // Test UDP protocol selection
    let mut cmd = Command::cargo_bin("ftr").expect("Failed to find ftr binary");
    cmd.args([
        "--protocol",
        "udp",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "127.0.0.1",
    ]);

    // Should either work or fail with appropriate error
    cmd.assert().code(predicate::eq(0).or(predicate::eq(1)));
}
