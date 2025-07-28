//! ASN (Autonomous System Number) lookup functionality

pub mod cache;
pub mod lookup;

pub use lookup::{lookup_asn, AsnLookupError};

// Re-export AsnInfo from traceroute module
pub use crate::traceroute::AsnInfo;
