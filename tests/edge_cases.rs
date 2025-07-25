//! Integration tests for edge cases and performance

use assert_cmd::Command;
use predicates::prelude::*;
use std::time::{Duration, Instant};

#[test]
fn test_very_low_timeout() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&["--probe-timeout-ms", "1", "--start-ttl", "1", "8.8.8.8"]);

    let start = Instant::now();
    let output = cmd.output().unwrap();
    let duration = start.elapsed();

    // Should complete quickly even with low timeout
    assert!(
        duration < Duration::from_secs(5),
        "Command took too long: {:?}",
        duration
    );

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // May have timeouts with 1ms timeout
        assert!(stdout.contains("*") || stdout.contains("8.8.8.8"));
    }
}

#[test]
fn test_high_ttl_value() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&[
        "--start-ttl",
        "64",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "127.0.0.1",
    ]);

    let output = cmd.output().unwrap();

    // Should handle high TTL values appropriately
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Should reach destination before TTL 64
        assert!(stdout.contains("127.0.0.1"));
    }
}

#[test]
fn test_multiple_concurrent_instances() {
    // Test that multiple instances can run simultaneously
    let mut handles = vec![];

    for i in 0..3 {
        let handle = std::thread::spawn(move || {
            let mut cmd = Command::cargo_bin("ftr").unwrap();
            cmd.args(&[
                "--start-ttl",
                "1",
                "--probe-timeout-ms",
                "100",
                "--no-enrich",
                "127.0.0.1",
            ]);
            cmd.env("FTR_INSTANCE", i.to_string());
            cmd.output()
        });
        handles.push(handle);
    }

    // All instances should complete
    for handle in handles {
        let result = handle.join().expect("Thread panicked");
        assert!(result.is_ok());
    }
}

#[test]
fn test_ipv4_address_input() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    cmd.args(&[
        "--start-ttl",
        "1",
        "--probe-timeout-ms",
        "100",
        "--no-enrich",
        "192.168.1.1",
    ]);

    let output = cmd.output().unwrap();

    // Should accept IPv4 addresses directly
    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(stdout.contains("192.168.1.1"));
    }
}

#[test]
fn test_queries_edge_cases() {
    // Test queries parameter boundaries
    let test_cases = vec![
        ("1", true),  // Minimum valid
        ("3", true),  // Normal value
        ("10", true), // Higher value (not 255 to avoid timeout)
    ];

    for (queries, should_succeed) in test_cases {
        let mut cmd = Command::cargo_bin("ftr").unwrap();
        cmd.args(&[
            "--queries",
            queries,
            "--start-ttl",
            "1",
            "--probe-timeout-ms",
            "100",
            "127.0.0.1",
        ]);

        let output = cmd.output().unwrap();

        if should_succeed {
            // Should either succeed or fail with permission error, not parameter error
            if !output.status.success() {
                let stderr = String::from_utf8_lossy(&output.stderr);
                assert!(
                    !stderr.contains("queries"),
                    "Should not fail due to queries parameter"
                );
            }
        }
    }
}

#[test]
fn test_port_boundaries() {
    // Test port parameter boundaries
    let test_cases = vec![
        (1, true),     // Minimum valid port
        (443, true),   // Default HTTPS port
        (8080, true),  // Common alternative port
        (65535, true), // Maximum valid port
    ];

    for (port, _should_succeed) in test_cases {
        let mut cmd = Command::cargo_bin("ftr").unwrap();
        cmd.args(&[
            "--protocol",
            "udp",
            "--port",
            &port.to_string(),
            "--start-ttl",
            "1",
            "--probe-timeout-ms",
            "100",
            "127.0.0.1",
        ]);

        // Should accept all valid port numbers
        cmd.assert().code(predicate::eq(0).or(predicate::eq(1)));
    }
}

#[test]
fn test_silent_hops_minimalist_output() {
    let mut cmd = Command::cargo_bin("ftr").unwrap();
    // Use a high starting TTL to likely get some silent hops
    cmd.args(&[
        "--start-ttl",
        "10",
        "--probe-timeout-ms",
        "50",
        "--no-enrich",
        "8.8.8.8",
    ]);

    let output = cmd.output().unwrap();

    if output.status.success() {
        let stdout = String::from_utf8_lossy(&output.stdout);
        // Check for minimalist silent hop representation (just spaces, not "* * *")
        // This is a bit tricky to test without knowing the exact output
        // but we can check that the output is reasonably formatted
        let lines: Vec<&str> = stdout.lines().collect();
        for line in lines {
            // Silent hops should be minimal (no verbose "* * *" or "[UNKNOWN]")
            if line.trim_start().starts_with(char::is_numeric) {
                assert!(!line.contains("[UNKNOWN]"), "Should not contain [UNKNOWN]");
            }
        }
    }
}
