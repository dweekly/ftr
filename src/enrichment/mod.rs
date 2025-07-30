//! Enrichment services for traceroute results
//!
//! This module provides services for enriching raw traceroute data with
//! additional information like DNS names and ASN details.

#[cfg(feature = "async")]
pub mod async_service;

#[cfg(feature = "async")]
pub use async_service::{AsyncEnrichmentService, EnrichmentResult};