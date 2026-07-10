//! DNS functionality for reverse lookups

pub mod cache;
pub mod resolver;
pub mod reverse;
pub mod service;
pub mod system;

#[cfg(test)]
pub mod test_utils;

pub use cache::RdnsCache;
pub use resolver::{
    refresh_system_dns, resolve_a, resolve_a_with_servers, resolve_ptr, resolve_ptr_with_servers,
    resolve_txt, resolve_txt_with_servers,
};
pub use reverse::ReverseDnsError;
pub use service::RdnsLookup;
