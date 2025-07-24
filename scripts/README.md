# Cross-Platform Testing Scripts for ftr

This directory contains scripts to set up and test ftr across different operating systems using UTM virtualization.

## Prerequisites

1. **UTM**: Install from https://mac.getutm.app/
   - UTM supports both Apple Silicon (M1/M2) and Intel Macs
   - The UTM CLI is located at `/Applications/UTM.app/Contents/MacOS/utmctl`

2. **Operating System ISOs**:
   Run `./scripts/download-isos.sh` to automatically download:
   - **Ubuntu 22.04.5 LTS ARM64**: Server edition for ARM64
   - **FreeBSD 14.3 ARM64**: Latest stable release for ARM64
   - **Windows 11**: Must be downloaded manually from Microsoft

## Setup Instructions

### 1. Initial Setup

Run the setup script to generate configurations and see detailed instructions:

```bash
./scripts/setup-utm-vms.sh
```

This will:
- Generate SSH keys for VM access
- Create cloud-init configurations for Ubuntu
- Provide detailed manual setup instructions for each OS

### 2. VM Configuration

**IMPORTANT**: Configure all VMs with **Bridged networking** (not NAT):
1. Stop the VM if running
2. Edit VM settings in UTM
3. Network → Mode: Bridged
4. Network → Bridged Interface: en0 (or your active network interface)
5. Start the VM

Bridged networking is essential for testing traceroute functionality as it allows VMs to:
- Get real IP addresses on your local network
- Send/receive ICMP packets properly
- Test actual network paths

### 3. VM Setup Details

#### Ubuntu Linux
- Use Ubuntu Server 22.04 LTS ARM64 ISO
- Username: `ftr`
- Enable SSH during installation
- Post-install commands:
  ```bash
  curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
  sudo apt update && sudo apt install -y build-essential git libpcap-dev
  git clone https://github.com/dweekly/ftr
  ```

#### FreeBSD
- Use FreeBSD 14.1 RELEASE ARM64 ISO
- Username: `ftr`
- Enable SSH during installation
- Post-install commands:
  ```bash
  pkg install -y rust git
  git clone https://github.com/dweekly/ftr
  ```

#### Windows
- Use Windows 11 ISO (requires x86_64 emulation)
- Install Npcap from https://npcap.com/#download
  - Check "WinPcap API-compatible Mode" during installation
- Install Rust from https://rustup.rs
- Install Git for Windows
- Install Visual Studio Build Tools

## Running Tests

### Automated Testing

After VMs are set up, run the cross-platform test suite:

```bash
./scripts/test-cross-platform.sh
```

Options:
1. Test on Ubuntu Linux
2. Test on FreeBSD
3. Test on Windows
4. Test on all platforms
5. Setup VMs (shows setup instructions)

### Manual SSH Access

Connect to VMs directly:

```bash
./scripts/ssh-to-vm.sh ubuntu   # Connect to Ubuntu VM
./scripts/ssh-to-vm.sh freebsd  # Connect to FreeBSD VM
```

### Individual Test Scripts

Run platform-specific tests directly in VMs:

- `test-ubuntu.sh`: Tests DGRAM ICMP (non-root) and RAW ICMP (root) modes
- `test-freebsd.sh`: Tests FreeBSD's socket implementation (usually requires root)
- `test-windows.ps1`: PowerShell script for Windows testing (requires Administrator)

## Test Coverage

The test scripts check:

1. **Socket Mode Capabilities**:
   - DGRAM ICMP (Linux non-root)
   - RAW ICMP (requires root/admin)
   - Fallback behavior

2. **Functionality**:
   - Basic traceroute to various targets
   - IPv6 support (if available)
   - Error handling
   - Performance comparison with system traceroute

3. **Platform-Specific**:
   - Linux: `/proc/sys/net/ipv4/ping_group_range` for non-root ICMP
   - FreeBSD: BPF device availability, jail support
   - Windows: Npcap/WinPcap service status, firewall configuration

## Troubleshooting

### UTM Issues
- If `utmctl` is not found, enable CLI tools in UTM preferences
- For networking issues, ensure bridged mode is properly configured
- Check that your Mac's firewall isn't blocking VM traffic

### SSH Connection Issues
- Ensure VMs are configured with port forwarding or bridged networking
- Check that SSH is enabled in the VM
- Verify the SSH key was added during VM setup

### Test Failures
- **Permission denied**: Some tests require root/admin privileges
- **Network unreachable**: Check VM network configuration and firewall rules
- **Timeout errors**: Increase timeout values or check network connectivity

## Notes

- Ubuntu typically supports non-root ICMP via DGRAM sockets
- FreeBSD and Windows usually require root/Administrator for raw sockets
- Performance may vary in VMs compared to bare metal
- Some tests may fail in restricted corporate networks