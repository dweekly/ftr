# Quick Start: Automated VM Testing with Vagrant

## Prerequisites

1. Install Vagrant:
   ```bash
   brew install --cask vagrant
   ```

2. Install Vagrant Parallels plugin:
   ```bash
   vagrant plugin install vagrant-parallels
   ```

## Usage

### Start Ubuntu VM (Fully Automated)

```bash
# From the ftr project directory
vagrant up ubuntu
```

This will:
1. Download Ubuntu 22.04 ARM64 box (~1GB, first time only)
2. Create and configure the VM
3. Install all dependencies
4. Install Rust
5. Build ftr
6. Run test traces
7. VM is ready in ~5-10 minutes!

### Access the VM

```bash
# SSH into the VM
vagrant ssh ubuntu

# Inside the VM, ftr is ready:
ftr google.com
sudo ftr google.com
```

### Test Changes

Your local ftr directory is mounted at `/home/vagrant/ftr` in the VM.
Any code changes are immediately available:

```bash
# On your Mac: edit code
# In the VM:
cd ~/ftr
cargo build --release
ftr google.com
```

### Other VMs

```bash
# FreeBSD
vagrant up freebsd
vagrant ssh freebsd

# Windows (requires manual Npcap install)
vagrant up windows
```

### VM Management

```bash
# Stop VM (preserves state)
vagrant halt ubuntu

# Start again
vagrant up ubuntu

# Destroy VM (removes completely)
vagrant destroy ubuntu

# Rebuild VM from scratch
vagrant destroy ubuntu -f && vagrant up ubuntu

# Run provisioning again
vagrant provision ubuntu

# See all VMs
vagrant status
```

### Parallel Testing

```bash
# Start all VMs at once
vagrant up

# Run command on all VMs
vagrant ssh -c "ftr google.com -m 5"
```

## Advantages over Manual Setup

1. **Fully Automated**: No manual OS installation
2. **Reproducible**: Same environment every time
3. **Version Controlled**: Vagrantfile defines exact setup
4. **Quick Reset**: `vagrant destroy && vagrant up` for clean slate
5. **Shared Folders**: Edit on Mac, test in VM instantly
6. **Multiple VMs**: Test on multiple OSes simultaneously

## Troubleshooting

- If bridged networking fails, Vagrant will ask you to select a network interface
- First `vagrant up` downloads the box image (~1GB)
- Use `vagrant reload` if VM networking seems broken
- Check VM is using bridged network: `ip addr show` should show a LAN IP