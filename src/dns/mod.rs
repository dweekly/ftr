//! DNS functionality for reverse lookups

pub mod reverse;

pub use reverse::{create_default_resolver, reverse_dns_lookup, ReverseDnsError};
