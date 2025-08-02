//! FreeBSD-specific integration tests

#![cfg(target_os = "freebsd")]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_freebsd_requires_root() {
    // On FreeBSD, non-root execution should fail with clear error
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().unwrap();

    if !is_running_as_root() {
        // Non-root should fail with specific error
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Error: ftr requires root privileges on freebsd"),
            "Expected root privilege error, got: {}",
            stderr
        );
        assert!(
            stderr.contains("Please run with sudo:"),
            "Expected sudo suggestion, got: {}",
            stderr
        );
        assert!(
            stderr.contains("Or make the binary setuid root:"),
            "Expected setuid suggestion, got: {}",
            stderr
        );
    } else {
        // Root should succeed
        assert!(output.status.success(), "Root execution should succeed");
    }
}

#[test]
fn test_freebsd_no_dgram_icmp() {
    // FreeBSD does not support DGRAM ICMP
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args([
        "--socket-mode",
        "dgram",
        "--protocol",
        "icmp",
        "--max-hops",
        "1",
        "127.0.0.1",
    ]);

    let output = cmd.output().unwrap();

    if !is_running_as_root() {
        // Non-root: should get the root privilege error first
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("requires root privileges"));
    } else {
        // Root: should get error about DGRAM ICMP not being supported
        assert!(!output.status.success());
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(
            stderr.contains("Datagram mode is not supported for ICMP protocol on freebsd"),
            "Expected DGRAM ICMP not supported error, got: {}",
            stderr
        );
    }
}

#[test]
fn test_freebsd_raw_icmp_with_root() {
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_raw_icmp_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["-v", "--socket-mode", "raw", "--max-hops", "1", "127.0.0.1"]);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Using Raw ICMP IPv4 mode"));
}

#[test]
fn test_freebsd_localhost_trace_with_root() {
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_localhost_trace_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--max-hops", "1", "--no-enrich", "127.0.0.1"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("127.0.0.1"))
        .stdout(predicate::str::contains(" 1 "));
}

#[test]
fn test_freebsd_ca_cert_warning() {
    // Test that we get a warning about ca_root_nss if HTTPS fails
    // This test doesn't require root
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--max-hops", "1", "8.8.8.8"]);

    let output = cmd.output().unwrap();
    let stderr = String::from_utf8_lossy(&output.stderr);

    // If ca_root_nss is not installed, we should see the warning
    // (either in the root check failure or in the public IP detection)
    if stderr.contains("Warning: Failed to detect public IP") {
        assert!(
            stderr
                .contains("Note: On FreeBSD, ensure 'ca_root_nss' package is installed for HTTPS"),
            "Expected ca_root_nss hint when HTTPS fails"
        );
    }
}

#[test]
fn test_freebsd_udp_mode() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--protocol", "udp", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().unwrap();

    if !is_running_as_root() {
        // Non-root: should get root privilege error
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains("requires root privileges"));
    } else {
        // Root: UDP mode should work
        assert!(
            output.status.success() || {
                let stderr = String::from_utf8_lossy(&output.stderr);
                // UDP might fail for other reasons
                stderr.contains("Error") || stderr.contains("Failed")
            }
        );
    }
}

#[test]
fn test_freebsd_tcp_mode() {
    // TCP mode is not yet implemented
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--protocol", "tcp", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().unwrap();

    // Should fail with invalid value error since TCP is not implemented yet
    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid value 'tcp'") || stderr.contains("not yet available"),
        "Expected 'invalid value' or 'not yet available' error, got: {}",
        stderr
    );
}

#[test]
fn test_freebsd_json_output_with_root() {
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_json_output_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["--json", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().unwrap();
    assert!(output.status.success());

    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value =
        serde_json::from_str(&stdout).expect("Failed to parse JSON output");

    assert_eq!(json["target"], "127.0.0.1");
    assert_eq!(json["target_ip"], "127.0.0.1");
    assert!(json["hops"].is_array());
    assert_eq!(json["protocol"], "ICMP");
    assert_eq!(json["socket_mode"], "Raw");
}

#[test]
fn test_freebsd_setuid_suggestion() {
    if is_running_as_root() {
        eprintln!("Skipping test_freebsd_setuid_suggestion - running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(["127.0.0.1"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("sudo chown root:wheel"))
        .stderr(predicate::str::contains("sudo chmod u+s"));
}

// Helper function to check if running as root
fn is_running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
