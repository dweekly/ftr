//! DNS functionality for reverse lookups

pub mod cache;
pub mod reverse;

#[cfg(test)]
pub mod test_utils;

pub use cache::{RdnsCache, RDNS_CACHE};
pub use reverse::{create_default_resolver, reverse_dns_lookup, ReverseDnsError};
