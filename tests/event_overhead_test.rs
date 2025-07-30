use std::time::{Duration, Instant};
use tokio::sync::mpsc;

#[tokio::test]
async fn test_event_channel_overhead() {
    // Measure the overhead of our event-driven approach
    let (tx, mut rx) = mpsc::channel::<u32>(256);

    // Measure channel send/receive latency
    let start = Instant::now();
    for i in 0..1000 {
        tx.send(i).await.unwrap();
    }
    drop(tx);

    let mut count = 0;
    while let Some(_) = rx.recv().await {
        count += 1;
    }
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

    // Event-driven should be close to 100ms, polling will have overhead
    assert!(
        event_elapsed < Duration::from_millis(110),
        "Event-driven took too long"
    );
}
