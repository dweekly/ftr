//! ASN (Autonomous System Number) lookup functionality

pub mod cache;
pub mod lookup;

pub use cache::AsnCache;
pub use lookup::{lookup_asn_with_cache, AsnLookupError};

// Re-export AsnInfo from traceroute module
pub use crate::traceroute::AsnInfo;
