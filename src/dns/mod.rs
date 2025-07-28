//! DNS functionality for reverse lookups

pub mod cache;
pub mod reverse;

pub use cache::{RdnsCache, RDNS_CACHE};
pub use reverse::{create_default_resolver, reverse_dns_lookup, ReverseDnsError};
