//! Utility functions for socket operations

/// Check if running as root
pub fn is_root() -> bool {
    #[cfg(unix)]
    {
        unsafe {
            // Use the libc crate to check effective user ID
            extern "C" {
                fn geteuid() -> u32;
            }
            geteuid() == 0
        }
    }
    #[cfg(target_os = "windows")]
    {
        // Windows doesn't have a direct equivalent to root
        // Admin check would require more complex API calls
        false
    }
}

/// Check if the platform has non-root traceroute capabilities
pub fn has_non_root_capability() -> bool {
    #[cfg(target_os = "linux")]
    {
        // Linux has UDP with IP_RECVERR and DGRAM ICMP with ping group
        true
    }
    #[cfg(target_os = "macos")]
    {
        // macOS has DGRAM ICMP support
        true
    }
    #[cfg(target_os = "windows")]
    {
        // Windows IcmpSendEcho works without admin
        true
    }
    #[cfg(any(target_os = "freebsd", target_os = "openbsd", target_os = "netbsd"))]
    {
        // BSD requires root for ICMP
        false
    }
    #[cfg(not(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd",
        target_os = "openbsd",
        target_os = "netbsd"
    )))]
    {
        // Unknown platform - assume no non-root capability
        false
    }
}
