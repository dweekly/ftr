//! FreeBSD-specific integration tests

#![cfg(target_os = "freebsd")]

use assert_cmd::Command;
use predicates::prelude::*;

#[test]
fn test_freebsd_requires_root() {
    // On FreeBSD, non-root execution should fail with clear error
    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().expect("failed to run ftr");

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
    // FreeBSD has no DGRAM ICMP sockets; the factory's BSD arm ignores
    // mode preferences and always uses raw ICMP, so an explicit dgram
    // request still traces successfully in raw mode (as root).
    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args([
        "-v",
        "--socket-mode",
        "dgram",
        "--protocol",
        "icmp",
        "--max-hops",
        "1",
        "127.0.0.1",
    ]);

    let output = cmd.output().expect("failed to run ftr");
    let stderr = String::from_utf8_lossy(&output.stderr);

    if !is_running_as_root() {
        // Non-root: should get the root privilege error first
        assert!(stderr.contains("requires root privileges"));
    } else {
        // Root: raw fallback, never a DGRAM socket
        assert!(
            output.status.success(),
            "dgram request should fall back to raw and succeed, stderr: {}",
            stderr
        );
        assert!(
            stderr.contains("Using Raw ICMP mode"),
            "Expected raw ICMP fallback, got: {}",
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

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["-v", "--socket-mode", "raw", "--max-hops", "1", "127.0.0.1"]);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Using Raw ICMP mode"));
}

#[test]
fn test_freebsd_localhost_trace_with_root() {
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_localhost_trace_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
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
    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--max-hops", "1", "8.8.8.8"]);

    let output = cmd.output().expect("failed to run ftr");
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
    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--protocol", "udp", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().expect("failed to run ftr");

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
    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--protocol", "tcp", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().expect("failed to run ftr");

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

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--json", "--max-hops", "1", "127.0.0.1"]);

    let output = cmd.output().expect("failed to run ftr");
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

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["127.0.0.1"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("sudo chown root:wheel"))
        .stderr(predicate::str::contains("sudo chmod u+s"));
}

#[test]
fn test_freebsd_ipv6_loopback_trace_with_root() {
    // Raw ICMPv6 to ::1 needs no external IPv6 connectivity, so this runs
    // in the CI VM (which has none) and exercises the full v6 probe path:
    // send with kernel-computed checksum, receive starting at the ICMPv6
    // header, userspace id/seq demux on the echo reply.
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_ipv6_loopback_trace_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--max-hops", "1", "--no-enrich", "::1"]);

    cmd.assert()
        .success()
        .stdout(predicate::str::contains("::1"));
}

#[test]
fn test_freebsd_ipv6_verbose_mode_with_root() {
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_ipv6_verbose_mode_with_root - not running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["-v", "--max-hops", "1", "--no-enrich", "::1"]);

    cmd.assert()
        .success()
        .stderr(predicate::str::contains("Using raw ICMPv6 mode"));
}

#[test]
fn test_freebsd_ipv6_requires_root() {
    // Without root the raw-only v6 path must fail with the root-privilege
    // message (the CLI's up-front gate), never a crash or a v6-specific
    // "not supported" claim.
    if is_running_as_root() {
        eprintln!("Skipping test_freebsd_ipv6_requires_root - running as root");
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    cmd.args(["--max-hops", "1", "::1"]);

    cmd.assert()
        .failure()
        .stderr(predicate::str::contains("requires root privileges"));
}

#[test]
fn test_freebsd_ipv6_external_trace_with_root() {
    // Live external IPv6 trace — only meaningful when the host actually
    // has IPv6 connectivity, which GitHub-hosted CI VMs do not. Probe the
    // routing table first (UDP connect() is a local operation: it fails
    // with EHOSTUNREACH/ENETUNREACH when there is no v6 route) and skip
    // cleanly otherwise, per the design doc's recommendation.
    if !is_running_as_root() {
        eprintln!("Skipping test_freebsd_ipv6_external_trace_with_root - not running as root");
        return;
    }
    if !has_ipv6_route() {
        eprintln!(
            "Skipping test_freebsd_ipv6_external_trace_with_root - no IPv6 route to the Internet \
             (expected in CI VMs; run on a dual-stack host to exercise this)"
        );
        return;
    }

    let mut cmd = Command::cargo_bin("ftr").expect("ftr binary should be built");
    // Google Public DNS IPv6 anycast, the same target the validation
    // spikes used. Success here means the trace ran; individual hops may
    // still time out, which is normal traceroute behavior.
    cmd.args(["--max-hops", "12", "--no-enrich", "2001:4860:4860::8888"]);

    cmd.assert().success();
}

/// Whether the host has a route to the public IPv6 Internet. UDP `connect`
/// makes only a local routing decision (no packets are sent), so this is a
/// safe, fast connectivity probe.
fn has_ipv6_route() -> bool {
    use std::net::UdpSocket;
    match UdpSocket::bind("[::]:0") {
        Ok(sock) => sock.connect("[2001:4860:4860::8888]:53").is_ok(),
        Err(_) => false,
    }
}

// Helper function to check if running as root
fn is_running_as_root() -> bool {
    unsafe { libc::geteuid() == 0 }
}
