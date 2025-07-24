# VM Testing Infrastructure for ftr

This document describes the automated VM testing infrastructure for ftr, which enables reproducible testing across multiple operating systems using official sources.

## Overview

The testing infrastructure uses a two-stage approach:
1. **Packer** builds VM images from official ISO files
2. **Vagrant** manages the VM lifecycle using these images

This ensures all VMs are built from official, verifiable sources while maintaining ease of use.

## Directory Structure

```
ftr/
├── packer/              # Stage 1: Build VM images
│   ├── build-vm.sh     # Build automation script
│   ├── *.pkr.hcl       # Packer configurations
│   └── http/           # Automated install configs
├── vagrant/             # Stage 2: Manage VMs
│   ├── manage-vms.sh   # VM management script
│   ├── lib/            # Shared Ruby modules
│   ├── boxes/          # Built VM images
│   └── <os-name>/      # Per-OS Vagrant configs
```

## Quick Start Guide

### 1. Build a VM Image (One-time)

```bash
cd packer/
./build-vm.sh ubuntu-22.04
```

This downloads the official Ubuntu ISO and builds a VM image with:
- `ftr` user configured
- Development tools installed
- Rust toolchain ready
- SSH access enabled

### 2. Create and Use the VM

```bash
cd ../vagrant/
./manage-vms.sh create ubuntu-22.04
./manage-vms.sh ssh ubuntu-22.04
```

### 3. Test ftr

```bash
# Inside the VM
cd /media/psf/ftr
source ~/.cargo/env
cargo build --release
./target/release/ftr 8.8.8.8
```

## Supported Operating Systems

| OS | Version | Build Status | Test Status |
|---|---|---|---|
| Ubuntu | 22.04 LTS | ✓ Ready | ✓ Tested |
| FreeBSD | 14.0 | ✓ Ready | Pending |
| Ubuntu | 24.04 LTS | Planned | - |
| OpenBSD | 7.5 | Planned | - |
| Debian | 12 | Planned | - |

## Design Principles

### 1. Official Sources Only
- All VMs built from official ISO images
- No dependency on third-party Vagrant boxes
- Checksums verified for all downloads

### 2. Reproducibility
- Anyone can rebuild identical VMs
- All configuration is version controlled
- Automated installation process

### 3. Consistency
- Same user (`ftr`) across all VMs
- Same directory structure
- Same development tools

### 4. Modularity
- Shared configuration in Ruby modules
- Easy to add new OS versions
- Reusable patterns

## Adding a New Operating System

### Step 1: Create Packer Configuration

Create `packer/<os-name>.pkr.hcl`:
```hcl
source "parallels-iso" "<os-name>" {
  iso_url      = "https://official-site.org/os.iso"
  iso_checksum = "sha256:..."
  # ... see existing examples
}
```

### Step 2: Add Automated Install Config

Create appropriate config in `packer/http/`:
- Ubuntu: cloud-init files
- BSD: installer scripts
- Other: OS-specific automation

### Step 3: Update Build Script

Add to `packer/build-vm.sh`:
- BUILDS array
- ISO_URLS array
- ISO_CHECKSUMS array

### Step 4: Create Vagrant Config

Create `vagrant/<os-name>/Vagrantfile` using the template.

### Step 5: Update Management Script

Add to `vagrant/manage-vms.sh`:
- VMS array
- VM_IPS array

## Windows Support (Future)

Windows requires a different approach:
- Manual ISO download (licensing)
- Answer file automation
- Different provisioning (PowerShell)
- Separate packer configuration

## Best Practices

### Building VMs
1. Always verify ISO checksums
2. Keep ISOs cached locally (`--skip-iso`)
3. Test builds incrementally
4. Document any OS-specific quirks

### Using VMs
1. One VM at a time for same IP
2. Regular snapshots for testing
3. Clean rebuild when needed
4. Check logs for issues

## Troubleshooting

### Packer Build Issues
```bash
# Enable debug logging
PACKER_LOG=1 ./build-vm.sh ubuntu-22.04

# Check boot commands
# Adjust timing in boot_wait
```

### Vagrant Issues
```bash
# Check VM status
./manage-vms.sh status

# Force cleanup
vagrant destroy -f
rm -rf .vagrant/
```

### Network Issues
- Ensure no IP conflicts
- Check Parallels network settings
- Verify shared folder mounts

## Security Considerations

1. **Development Only**: Default passwords for convenience
2. **Local Use**: Not for production or public networks
3. **Isolation**: Each VM is isolated
4. **Updates**: Rebuild periodically for security updates

## Future Enhancements

1. **CI Integration**: Automated builds on schedule
2. **Test Automation**: Run test suite across all VMs
3. **More Platforms**: Windows, more BSD variants
4. **Architecture Support**: ARM64 for Apple Silicon native