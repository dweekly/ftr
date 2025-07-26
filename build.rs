//! Build script for Windows-specific configuration

/// Main build function that sets up Windows-specific linker paths
fn main() {
    // Currently no Windows-specific build configuration needed
    // The Windows ICMP API (IcmpCreateFile/IcmpSendEcho) is available
    // through windows-sys crate without additional libraries
}
