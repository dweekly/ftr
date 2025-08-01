//! Integration tests for traceroute functionality

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_traceroute_to_localhost() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "localhost",
    ]);

    let output = cmd.output().unwrap();

    // Localhost should resolve to 127.0.0.1
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("127.0.0.1"));
    }
}

#[test]
fn test_traceroute_with_multiple_queries() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--queries",
        "2",
        "--start-ttl",
        "2",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "127.0.0.1",
    ]);

    // Should complete (either successfully or with permission error)
    cmd.assert().code(predicate::eq(0).or(predicate::eq(1)));
}

#[test]
fn test_udp_mode_with_custom_port() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--protocol",
        "udp",
        "--port",
        "53",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "127.0.0.1",
    ]);

    let output = cmd.output().unwrap();

    // Check if port is being used (in verbose mode we would see it)
    // For now, just verify command accepts the parameters
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Should not complain about port parameter with UDP
        assert!(!stderr.contains("will be ignored"));
    }
}

#[test]
fn test_no_rdns_flag() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--no-rdns",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "8.8.8.8",
    ]);

    let output = cmd.output().unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should not contain DNS names when --no-rdns is used
        assert!(!stdout.contains("dns.google"));
    }
}

#[test]
fn test_no_enrich_flag() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--no-enrich",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "8.8.8.8",
    ]);

    let output = cmd.output().unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should not contain ASN information when --no-enrich is used
        assert!(!stdout.contains("AS"), "stdout contains 'AS': {}", stdout);
        assert!(!stdout.contains("Google"));
    }
}

#[test]
fn test_json_output_structure() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--json",
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "127.0.0.1",
    ]);

    let output = cmd.output().unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        let json: serde_json::Value = serde_json::from_str(&stdout).expect("Invalid JSON");

        // Verify JSON structure
        assert!(json["version"].is_string());
        let version = json["version"].as_str().unwrap();
        // Version should be in format X.Y.Z or X.Y.Z-UNRELEASED
        assert!(version.chars().filter(|c| *c == '.').count() >= 2);
        if cfg!(debug_assertions) {
            assert!(version.ends_with("-UNRELEASED"));
        }
        assert_eq!(json["target"].as_str().unwrap(), "127.0.0.1");
        assert_eq!(json["target_ip"].as_str().unwrap(), "127.0.0.1");
        assert!(json["hops"].is_array());
        assert!(json["protocol"].is_string());
        assert!(json["socket_mode"].is_string());

        // Check hop structure if any hops exist
        if let Some(hops) = json["hops"].as_array() {
            if !hops.is_empty() {
                let hop = &hops[0];
                assert!(hop["ttl"].is_number());
                // Check optional fields
                assert!(hop["address"].is_string() || hop["address"].is_null());
                assert!(hop["hostname"].is_string() || hop["hostname"].is_null());
            }
        }
    }
}

#[test]
fn test_invalid_hostname() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["this-is-not-a-valid-hostname-12345.invalid"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("Error resolving host"));
}

#[test]
fn test_socket_mode_requires_permissions() {
    // Test that raw socket mode fails appropriately without root
    // This is a CLI test, so we just verify it exits with error status
    // The actual structured error testing is done in error_handling_test.rs
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--socket-mode", "raw", "127.0.0.1"]);

    let output = cmd.output().unwrap();

    // If we're not root, this should fail
    // If we are root, it might succeed or fail for other reasons
    // The important thing is that the CLI handles errors gracefully
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Just verify we got some error output
        assert!(!stderr.is_empty(), "Expected error output but got none");

        // Verify it contains "Error:" prefix (our CLI convention)
        assert!(
            stderr.contains("Error:"),
            "Expected error message to start with 'Error:', got: {}",
            stderr
        );
    }
}
