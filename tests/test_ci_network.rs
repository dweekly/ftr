//! Test basic network connectivity in CI environment

#[cfg(test)]
mod tests {
    use std::process::Command;

    #[test]
    fn test_ci_network_basics() {
        eprintln!("\n=== CI Network Environment Test ===");

        // Check environment
        eprintln!("Environment variables:");
        eprintln!("  CI: {:?}", std::env::var("CI"));
        eprintln!("  GITHUB_ACTIONS: {:?}", std::env::var("GITHUB_ACTIONS"));
        eprintln!("  USER: {:?}", std::env::var("USER"));
        eprintln!("  HOME: {:?}", std::env::var("HOME"));

        // Check basic connectivity with ping
        eprintln!("\nTesting ping to 8.8.8.8:");
        let output = Command::new("ping")
            .args(&["-c", "1", "-W", "1", "8.8.8.8"])
            .output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    eprintln!("  ✓ Ping successful");
                    eprintln!("  stdout: {}", String::from_utf8_lossy(&output.stdout));
                } else {
                    eprintln!("  ✗ Ping failed with status: {}", output.status);
                    eprintln!("  stderr: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => eprintln!("  ✗ Failed to run ping: {}", e),
        }

        // Check traceroute
        eprintln!("\nTesting traceroute to 8.8.8.8:");
        let output = Command::new("traceroute")
            .args(&["-n", "-m", "3", "-w", "1", "8.8.8.8"])
            .output();

        match output {
            Ok(output) => {
                eprintln!("  Exit status: {}", output.status);
                eprintln!("  stdout: {}", String::from_utf8_lossy(&output.stdout));
                if !output.stderr.is_empty() {
                    eprintln!("  stderr: {}", String::from_utf8_lossy(&output.stderr));
                }
            }
            Err(e) => eprintln!("  ✗ Failed to run traceroute: {}", e),
        }

        // Check network interfaces
        eprintln!("\nNetwork interfaces:");
        let output = Command::new("ip").args(&["addr", "show"]).output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    let stdout = String::from_utf8_lossy(&output.stdout);
                    for line in stdout.lines() {
                        if line.contains("inet ") || line.contains("state ") || line.contains(": ")
                        {
                            eprintln!("  {}", line.trim());
                        }
                    }
                }
            }
            Err(_) => {
                // Try ifconfig as fallback
                if let Ok(output) = Command::new("ifconfig").output() {
                    if output.status.success() {
                        eprintln!("  (via ifconfig)");
                        let stdout = String::from_utf8_lossy(&output.stdout);
                        for line in stdout.lines().take(20) {
                            eprintln!("  {}", line);
                        }
                    }
                }
            }
        }

        // Check routing table
        eprintln!("\nRouting table:");
        let output = Command::new("ip").args(&["route", "show"]).output();

        match output {
            Ok(output) => {
                if output.status.success() {
                    eprintln!("{}", String::from_utf8_lossy(&output.stdout));
                }
            }
            Err(_) => {
                // Try netstat as fallback
                if let Ok(output) = Command::new("netstat").args(&["-rn"]).output() {
                    if output.status.success() {
                        eprintln!("  (via netstat -rn)");
                        eprintln!("{}", String::from_utf8_lossy(&output.stdout));
                    }
                }
            }
        }
    }
}
