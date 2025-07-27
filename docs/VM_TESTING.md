# VM Testing for ftr

This document describes the VM testing setup for ftr, enabling testing across multiple operating systems.

## Overview

We use Parallels Desktop VMs for testing ftr on different operating systems. Each VM has the ftr source directory mounted at `/media/psf/ftr` for easy access.

## Quick Start Guide

### Testing on a VM

```bash
# SSH into the VM (see ENVIRONMENT.md for specific VM details)
ssh -i ~/.ssh/ftr_vm_key ftr@<vm-ip>

# Inside the VM
cd /media/psf/ftr
source ~/.cargo/env  # If Rust is in cargo env
cargo build --release
./target/release/ftr 8.8.8.8
```

## Current VMs

See ENVIRONMENT.md for details about configured VMs including:
- IP addresses
- SSH credentials
- Shared directory paths

| OS | Version | Status |
|---|---|---|
| Ubuntu | 24.04 LTS ARM64 | ✓ Active |
| Ubuntu | (Old) | ✓ Configured |
| OpenBSD | 7.7 | Needs configuration |
| FreeBSD | TBD | Manually configured |
| Windows | 11 ARM64 | ✓ Configured |

## VM Setup Guidelines

### Shared Directory
- All VMs should have `/media/psf/ftr` mounted from the host
- This allows direct access to source code without copying files
- Changes are immediately visible in both host and VM

### Standard Configuration
- User: `ftr`
- Password: `tr33tr33` (development only)
- SSH key: `~/.ssh/ftr_vm_key`
- Network: Bridged mode for proper traceroute testing

### Testing Workflow
1. SSH into the VM
2. Navigate to `/media/psf/ftr`
3. Build and test as needed
4. Results are immediately available on host

## Platform-Specific Notes

### FreeBSD
- DGRAM ICMP should work similarly to macOS
- Check `net.inet.icmp.icmplim` sysctl for rate limiting
- May need to install Rust toolchain

### OpenBSD
- Similar to FreeBSD for DGRAM ICMP
- Stricter security defaults may require adjustments

### Windows
- Uses Windows ICMP API (IcmpCreateFile/IcmpSendEcho)
- No raw socket support needed
- Build with native-tls feature for ARM64

## Security Considerations

1. **Development Only**: Default passwords for convenience
2. **Local Use**: Not for production or public networks
3. **Isolation**: Each VM is isolated
4. **Shared Directory**: Be aware that `/media/psf/ftr` is shared with host