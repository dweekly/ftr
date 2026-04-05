//! DNS functionality for reverse lookups

pub mod cache;
pub mod resolver;
pub mod reverse;
pub mod service;

#[cfg(test)]
pub mod test_utils;

pub use cache::RdnsCache;
pub use resolver::{resolve_a, resolve_ptr, resolve_txt};
pub use reverse::ReverseDnsError;
pub use service::RdnsLookup;
