//! Test to verify CI doesn't filter out tests incorrectly
//!
//! In some Windows environments (particularly Parallels VMs), cargo test
//! may pass an unexpected filter argument like "2" to test binaries,
//! causing tests to be filtered out. This test file helps detect that issue
//! by having tests with and without "2" in their names.

#[test]
fn test_with_2_in_name() {
    // This test would be filtered out if "2" is passed as a filter
    assert_eq!(1 + 1, 2);
}

#[test]
fn test_without_number() {
    // This test has no "2" in the name
    assert!(true);
}

#[test]
fn test_2_another_2_test() {
    // Multiple "2"s in the name
    assert_eq!(2 * 2, 4);
}

// If the filter issue exists in CI, only tests with "2" in the name would run
// We want ALL tests to run
