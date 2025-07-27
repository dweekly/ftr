//! FreeBSD-specific smoke tests for basic functionality

#![cfg(all(test, target_os = "freebsd"))]

use std::process::Command;

#[test]
fn test_freebsd_binary_runs() {
    // Basic smoke test - binary should at least show help
    let output = Command::new("cargo")
        .args(&["run", "--", "--help"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Fast parallel ICMP traceroute"));
}

#[test]
fn test_freebsd_version() {
    let output = Command::new("cargo")
        .args(&["run", "--", "--version"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("ftr"));
}

#[test]
fn test_freebsd_non_root_error() {
    if unsafe { libc::geteuid() } == 0 {
        eprintln!("Skipping non-root test - running as root");
        return;
    }

    let output = Command::new("cargo")
        .args(&["run", "--", "127.0.0.1"])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should get FreeBSD-specific error message
    assert!(stderr.contains("Error: ftr requires root privileges on freebsd"));
    assert!(stderr.contains("This platform does not support unprivileged traceroute"));
    assert!(stderr.contains("sudo chown root:wheel"));
}

#[test]
fn test_freebsd_with_sudo() {
    // This test requires manual verification or CI setup with sudo
    // It's here as a template for manual testing
    if unsafe { libc::geteuid() } != 0 {
        eprintln!("Skipping root test - not running as root");
        eprintln!("To test with root, run: sudo cargo test test_freebsd_with_sudo");
        return;
    }

    let output = Command::new("cargo")
        .args(&["run", "--", "--max-hops", "1", "127.0.0.1"])
        .output()
        .expect("Failed to execute command");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("127.0.0.1"));
}

#[test]
fn test_freebsd_ca_certs_check() {
    // Check if ca_root_nss is installed by trying to resolve DNS
    let output = Command::new("cargo")
        .args(&["run", "--", "--max-hops", "1", "google.com"])
        .output()
        .expect("Failed to execute command");

    let stderr = String::from_utf8_lossy(&output.stderr);

    // If we see the HTTPS warning, it means ca_root_nss might not be installed
    if stderr.contains("Warning: Failed to detect public IP") {
        assert!(
            stderr.contains("Note: On FreeBSD, ensure 'ca_root_nss' package is installed"),
            "Should show ca_root_nss hint when HTTPS fails"
        );
    }
}

#[test]
fn test_freebsd_socket_compatibility() {
    // Test that asking for DGRAM ICMP explicitly fails with correct error
    let output = Command::new("cargo")
        .args(&[
            "run",
            "--",
            "--socket-mode",
            "dgram",
            "--protocol",
            "icmp",
            "127.0.0.1",
        ])
        .output()
        .expect("Failed to execute command");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);

    // Should either get root error or "not supported" error
    assert!(
        stderr.contains("requires root privileges") || stderr.contains("not supported"),
        "Expected root or not supported error, got: {}",
        stderr
    );
}
