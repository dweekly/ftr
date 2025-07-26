//! Build script for Windows-specific configuration

/// Main build function that sets up Windows-specific linker paths
fn main() {
    // Only run this on Windows
    if cfg!(target_os = "windows") {
        // Tell cargo to look for libraries in the Npcap SDK directory
        if cfg!(target_arch = "aarch64") {
            // ARM64 libraries
            println!("cargo:rustc-link-search=native=C:\\npcap\\npcap-sdk-1.15\\Lib\\ARM64");
        } else if cfg!(target_arch = "x86_64") {
            // x64 libraries
            println!("cargo:rustc-link-search=native=C:\\npcap\\npcap-sdk-1.15\\Lib\\x64");
        } else {
            // x86 libraries
            println!("cargo:rustc-link-search=native=C:\\npcap\\npcap-sdk-1.15\\Lib");
        }

        // Link against Packet.lib and wpcap.lib
        println!("cargo:rustc-link-lib=Packet");
        println!("cargo:rustc-link-lib=wpcap");
    }
}
