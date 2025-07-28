//! Test utilities for DNS module

use std::sync::atomic::{AtomicUsize, Ordering};

/// Global counter for DNS requests made during tests
pub static DNS_REQUEST_COUNT: AtomicUsize = AtomicUsize::new(0);

/// Reset the DNS request counter
pub fn reset_dns_counter() {
    DNS_REQUEST_COUNT.store(0, Ordering::SeqCst);
}

/// Get the current DNS request count
pub fn get_dns_count() -> usize {
    DNS_REQUEST_COUNT.load(Ordering::SeqCst)
}

/// Increment the DNS request counter
pub fn increment_dns_count() {
    DNS_REQUEST_COUNT.fetch_add(1, Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_dns_counter() {
        reset_dns_counter();
        assert_eq!(get_dns_count(), 0);

        increment_dns_count();
        assert_eq!(get_dns_count(), 1);

        increment_dns_count();
        increment_dns_count();
        assert_eq!(get_dns_count(), 3);

        reset_dns_counter();
        assert_eq!(get_dns_count(), 0);
    }
}
