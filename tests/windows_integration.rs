//! Windows-specific integration tests

#![cfg(target_os = "windows")]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_windows_localhost_trace() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--max-hops", "1", "127.0.0.1"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("127.0.0.1"))
        .stdout(predicate::str::contains("localhost"));
}

#[test]
fn test_windows_icmp_mode() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["-v", "--max-hops", "1", "127.0.0.1"]);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Using Raw ICMP IPv4 mode"));
}

#[test]
fn test_windows_gateway_detection() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--max-hops", "1", "8.8.8.8"]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should show first hop (gateway)
    assert!(stdout.contains(" 1 "));
    // Should have RTT measurement
    assert!(stdout.contains(" ms"));
}

#[test]
fn test_windows_json_output() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--json", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Failed to parse JSON output");

    assert_eq!(json["target"], "127.0.0.1");
    assert_eq!(json["target_ip"], "127.0.0.1");
    assert!(json["hops"].is_array());
}

#[test]
fn test_windows_dns_resolution() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--max-hops", "1", "localhost"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("127.0.0.1"))
        .stdout(predicate::str::contains("localhost"));
}

#[test]
fn test_windows_invalid_host() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.arg("invalid.host.that.does.not.exist.example");

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Failed to resolve"));
}

#[test]
fn test_windows_timeout_handling() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&[
        "--probe-timeout-ms",
        "1", // Very short timeout
        "--max-hops",
        "3",
        "8.8.8.8",
    ]);

    // Should complete even with very short timeout
    let output = cmd.output().unwrap();
    assert!(output.status.success());
}

#[test]
fn test_windows_asn_lookup() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--max-hops", "18", "8.8.8.8"]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    // Should have ISP detection working
    assert!(stdout.contains("Detected ISP:"));
    assert!(stdout.contains("AS"));

    // If we reached the destination, check for Google's AS
    if stdout.contains("dns.google (8.8.8.8)") {
        assert!(stdout.contains("AS15169") || stdout.contains("GOOGLE"));
    }
}
