//! Tests for event overhead and performance characteristics

use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_event_channel_overhead() {
    // Measure the overhead of our event-driven approach
    let (tx, mut rx) = mpsc::channel::<u32>(1000); // Increased buffer size to match message count

    // Spawn a task to consume messages concurrently
    let consumer = tokio::spawn(async move {
        let mut count = 0;
        while rx.recv().await.is_some() {
            count += 1;
        }
        count
    });

    // Measure channel send latency
    let start = Instant::now();
    for i in 0..1000 {
        tx.send(i).await.expect("channel send should succeed");
    }
    drop(tx); // Close the channel to signal completion

    // Wait for consumer to finish
    let count = consumer.await.expect("consumer task should not panic");
    let elapsed = start.elapsed();

    println!("Channel operations (1000 messages): {:?}", elapsed);
    println!("Average per message: {:?}", elapsed / 1000);
    assert_eq!(count, 1000);
}

#[tokio::test]
async fn test_polling_vs_event_driven() {
    // Simulate polling approach
    let start_polling = Instant::now();
    let mut iterations = 0;
    let target_time = Instant::now() + Duration::from_millis(100);

    while Instant::now() < target_time {
        // Simulate checking for events
        tokio::time::sleep(Duration::from_millis(10)).await;
        iterations += 1;
    }
    let polling_elapsed = start_polling.elapsed();

    println!(
        "Polling approach: {} iterations in {:?}",
        iterations, polling_elapsed
    );

    // Simulate event-driven approach
    let start_event = Instant::now();
    let (tx, mut rx) = mpsc::channel::<()>(1);

    tokio::spawn(async move {
        tokio::time::sleep(Duration::from_millis(100)).await;
        let _ = tx.send(()).await;
    });

    rx.recv().await;
    let event_elapsed = start_event.elapsed();

    println!("Event-driven approach: {:?}", event_elapsed);

    // The event fires after a 100ms sleep, so event_elapsed must be at least
    // ~100ms (proves we actually waited on the channel, not a spurious wake).
    // We deliberately do NOT assert a tight upper bound: this runs on shared
    // CI runners where task scheduling can add tens to hundreds of ms of
    // jitter under load, which made a 150ms ceiling flaky. The generous 2s
    // ceiling still catches a real regression (a deadlocked channel or a hang)
    // without failing on scheduling noise.
    assert!(
        event_elapsed >= Duration::from_millis(90),
        "Event fired implausibly early ({event_elapsed:?}); expected to block ~100ms"
    );
    assert!(
        event_elapsed < Duration::from_secs(2),
        "Event-driven wakeup took far too long ({event_elapsed:?}); likely a hang"
    );
}
