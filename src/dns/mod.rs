//! DNS functionality for reverse lookups

pub mod cache;
pub mod reverse;
pub mod service;

#[cfg(test)]
pub mod test_utils;

pub use cache::RdnsCache;
pub use reverse::{create_default_resolver, ReverseDnsError};
pub use service::RdnsLookup;
