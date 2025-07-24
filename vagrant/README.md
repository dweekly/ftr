# Multi-OS Testing Environment for ftr

This directory contains Vagrant configurations for managing development/testing VMs. The VMs are built from official ISO sources using Packer (see ../packer).

## Prerequisites

1. **Build the VM images first** using Packer:
   ```bash
   cd ../packer
   ./build-vm.sh ubuntu-22.04  # Build Ubuntu image
   ./build-vm.sh freebsd-14    # Build FreeBSD image
   ```

2. **Then use Vagrant** to manage the VMs:
   ```bash
   cd ../vagrant
   ./manage-vms.sh create ubuntu-22.04
   ```

## Quick Start

```bash
# First time setup - build a VM image
cd ../packer && ./build-vm.sh ubuntu-22.04
cd ../vagrant

# List all available VMs
./manage-vms.sh list

# Create Ubuntu 22.04 VM from built image
./manage-vms.sh create ubuntu-22.04

# SSH into a VM
./manage-vms.sh ssh ubuntu-22.04

# Run tests in a VM
./manage-vms.sh test ubuntu-22.04
```

## Available Operating Systems

| OS | Version | Network | Status |
|---|---|---|---|
| Ubuntu | 22.04 LTS | Bridged/DHCP | ✓ Packer config ready |
| Ubuntu | 24.04 LTS | Bridged/DHCP | ✓ Packer config ready |
| FreeBSD | 14.0 | Bridged/DHCP | ✓ Packer config ready |
| OpenBSD | 7.5 | Bridged/DHCP | Planned |

## Two-Stage Process

1. **Stage 1: Build with Packer** (in ../packer/)
   - Downloads official ISO images
   - Runs automated installation
   - Configures base system (user, packages, etc.)
   - Exports as Vagrant box

2. **Stage 2: Manage with Vagrant** (in this directory)
   - Uses Packer-built boxes
   - Handles VM lifecycle (create, start, stop, destroy)
   - Configures networking and shared folders
   - Provides consistent interface across all OS types

## Architecture

### Directory Structure
```
vagrant/
├── lib/                    # Shared Ruby modules
│   ├── base_config.rb     # Common VM configuration
│   └── rust_installer.rb  # Cross-OS Rust installation
├── ubuntu-22.04/          # Ubuntu 22.04 specific config
│   └── Vagrantfile
├── ubuntu-24.04/          # Ubuntu 24.04 specific config
│   └── Vagrantfile
├── freebsd-14/            # FreeBSD 14 specific config
│   └── Vagrantfile
├── openbsd-7.5/           # OpenBSD 7.5 specific config
│   └── Vagrantfile
└── manage-vms.sh          # Unified management script
```

### Design Principles

1. **Modularity**: Common configuration is shared via Ruby modules
2. **Consistency**: All VMs have the same user (ftr), tools, and structure
3. **Official Sources**: Only uses official Vagrant boxes and installers
4. **Predictable IPs**: Each OS family has a predictable IP address
5. **Extensibility**: Easy to add new OS versions or distributions

## VM Management

### Using manage-vms.sh

```bash
# Show all commands
./manage-vms.sh

# VM lifecycle
./manage-vms.sh create <vm-name>    # Create and provision
./manage-vms.sh start <vm-name>     # Start existing VM
./manage-vms.sh stop <vm-name>      # Stop VM
./manage-vms.sh destroy <vm-name>   # Remove VM completely

# Access and testing
./manage-vms.sh ssh <vm-name>       # SSH into VM
./manage-vms.sh exec <vm-name> <cmd> # Execute command via prlctl (no SSH needed)
./manage-vms.sh test <vm-name>      # Run ftr tests
./manage-vms.sh status              # Show all VM statuses

# Bulk operations
./manage-vms.sh create-all          # Create all VMs
./manage-vms.sh destroy-all         # Destroy all VMs
```

### Manual Vagrant Commands

You can also use Vagrant directly:

```bash
cd ubuntu-22.04/
vagrant up          # Create/start VM
vagrant ssh         # SSH as vagrant user
vagrant halt        # Stop VM
vagrant destroy     # Remove VM
```

## VM Details

### Common Configuration

All VMs share:
- **Memory**: 2GB RAM
- **CPUs**: 2 cores
- **User**: `ftr` (password: `ftr`)
- **Sudo**: Passwordless sudo/doas access
- **SSH Key**: `~/.ssh/ftr_vm_key`
- **Rust**: Installed from official rustup
- **Tools**: cargo-audit, cargo-machete, cargo-outdated
- **Network**: Bridged networking with DHCP-assigned IP
- **Serial Console**: Available as alternative access method

### OS-Specific Notes

#### Ubuntu (22.04, 24.04)
- Uses `apt` package manager
- Shared folder at `/media/psf/ftr`

#### FreeBSD 14
- Uses `pkg` package manager
- Shared folder at `/media/psf/ftr`

#### OpenBSD 7.5
- Uses `pkg_add` package manager
- Project at `/home/ftr/ftr` (shared folders can be tricky)
- Uses `doas` instead of `sudo`

### Network Configuration

VMs use bridged networking and get IPs from your LAN's DHCP server:
- **Automatic IP discovery**: Uses `prlctl exec` to query VM directly
- **Direct execution**: `prlctl exec` runs commands without SSH
- **Fallback access**: Always available via `vagrant ssh`
- **Serial console**: Alternative access if network fails

### Direct VM Access with prlctl

The management script leverages Parallels' `prlctl exec` command for direct VM access:

```bash
# Execute any command directly
./manage-vms.sh exec ubuntu-22.04 "ip addr"
./manage-vms.sh exec ubuntu-22.04 "cd /media/psf/ftr && cargo build"

# This is faster than SSH and doesn't require network configuration
```

## Adding New Operating Systems

To add a new OS:

1. Create a directory: `mkdir <os-name>/`
2. Create a Vagrantfile using the template:
```ruby
require_relative '../lib/base_config'
require_relative '../lib/rust_installer'

Vagrant.configure("2") do |config|
  config.vm.box = "official/box-name"
  # ... see existing examples
end
```
3. Add to `manage-vms.sh` VMS and VM_IPS arrays
4. Test: `./manage-vms.sh create <os-name>`

## Windows Support (Future)

Windows VMs will require a different approach:
- Different provisioning (PowerShell instead of shell)
- Different shared folder mechanism
- Different user management
- Possibly manual ISO-based installation

A separate `windows/` directory structure is planned.

## Troubleshooting

### SSH Connection Issues
```bash
# Regenerate SSH key
rm ~/.ssh/ftr_vm_key*
./manage-vms.sh create <vm-name>

# Use vagrant SSH as fallback
cd <vm-name>/
vagrant ssh
```

### Shared Folder Issues
- Ensure Parallels Tools are installed: `vagrant provision`
- Check VM logs: `vagrant ssh -c "dmesg | grep prl"`
- Try manual mount: `vagrant ssh -c "sudo mount -t prl_fs..."`

### Network Issues
- Check Parallels network settings
- Ensure no IP conflicts with existing VMs
- Try destroying and recreating the VM

## Security Notes

- These VMs use default passwords for convenience
- They're intended for local development/testing only
- Do not expose to public networks
- The `ftr` user has passwordless sudo/doas access