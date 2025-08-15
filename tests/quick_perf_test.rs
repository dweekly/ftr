//! Quick performance and timing configuration tests

#[test]
fn test_timing_config_values() {
    use ftr::config::timing::*;

    // Verify our timing configuration values
    println!(
        "Receiver poll interval: {}ms",
        DEFAULT_RECEIVER_POLL_INTERVAL_MS
    );
    println!(
        "Main loop poll interval: {}ms",
        DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS
    );
    println!("Socket read timeout: {}ms", DEFAULT_SOCKET_READ_TIMEOUT_MS);

    // The current implementation uses much faster polling intervals
    // for better responsiveness

    assert_eq!(DEFAULT_MAIN_LOOP_POLL_INTERVAL_MS, 5);
    assert_eq!(DEFAULT_RECEIVER_POLL_INTERVAL_MS, 1);
}
