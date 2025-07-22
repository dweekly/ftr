# -*- mode: ruby -*-
# vi: set ft=ruby :

Vagrant.configure("2") do |config|
  # Use Parallels as default provider
  config.vm.provider "parallels" do |prl|
    prl.memory = 4096
    prl.cpus = 4
    prl.update_guest_tools = true
  end

  # Shared folder for ftr project - mount at consistent location
  config.vm.synced_folder ".", "/home/vagrant/ftr", type: "parallels"

  # Ubuntu 22.04 VM - Primary Linux testing
  config.vm.define "ubuntu", primary: true do |ubuntu|
    ubuntu.vm.box = "bento/ubuntu-22.04-arm64"
    ubuntu.vm.hostname = "ftr-ubuntu"
    ubuntu.vm.box_version = ">= 0"
    
    # Bridged network for real traceroute testing
    ubuntu.vm.network "public_network", bridge: "en0: Wi-Fi", 
      use_dhcp_assigned_default_route: true
    
    # Complete automated provisioning
    ubuntu.vm.provision "shell", privileged: false, inline: <<-'SHELL'
      set -euo pipefail
      
      echo "=== Setting up Ubuntu for ftr testing ==="
      
      # Update system
      sudo apt-get update
      sudo apt-get install -y build-essential git curl libpcap-dev \
        net-tools iputils-ping traceroute dnsutils
      
      # Install Rust if not present
      if ! command -v cargo &> /dev/null; then
        echo "Installing Rust..."
        curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
      fi
      
      # Add cargo to PATH
      source "$HOME/.cargo/env"
      
      # Build ftr
      cd ~/ftr
      echo "Building ftr..."
      cargo build --release
      
      # Create convenience symlink
      sudo ln -sf ~/ftr/target/release/ftr /usr/local/bin/ftr
      
      # Test ftr
      echo
      echo "=== Testing ftr ==="
      echo "Non-root DGRAM ICMP test:"
      ftr google.com -m 5 || echo "Non-root mode may not work"
      
      echo
      echo "Root RAW ICMP test:"
      sudo ftr google.com -m 5
      
      echo
      echo "=== Setup complete! ==="
      echo "ftr is available as 'ftr' command"
      echo "Source code: ~/ftr"
      echo "Binary: ~/ftr/target/release/ftr"
    SHELL
  end

  # FreeBSD 14 VM
  config.vm.define "freebsd", autostart: false do |freebsd|
    freebsd.vm.box = "generic/freebsd14"
    freebsd.vm.hostname = "ftr-freebsd"
    
    # Note: FreeBSD box might not work perfectly with Parallels
    # Alternative: freebsd.vm.box = "freebsd/FreeBSD-14.0-RELEASE"
    
    freebsd.vm.network "public_network", bridge: "en0: Wi-Fi"
    
    # FreeBSD needs different mount options
    freebsd.vm.synced_folder ".", "/home/vagrant/ftr", 
      type: "rsync",
      rsync__exclude: ["target/", ".git/"]
    
    freebsd.vm.provision "shell", privileged: false, inline: <<-'SHELL'
      set -euo pipefail
      
      echo "=== Setting up FreeBSD for ftr testing ==="
      
      # Install packages
      sudo pkg update
      sudo pkg install -y rust git
      
      # Build ftr
      cd ~/ftr
      cargo build --release
      
      # Create convenience symlink
      sudo ln -sf ~/ftr/target/release/ftr /usr/local/bin/ftr
      
      # Test (FreeBSD usually requires root)
      echo
      echo "=== Testing ftr on FreeBSD ==="
      sudo ftr google.com -m 5
      
      echo
      echo "=== Setup complete! ==="
    SHELL
  end

  # Windows 11 VM - Manual steps required
  config.vm.define "windows", autostart: false do |windows|
    # Note: Windows ARM64 boxes are not readily available
    # This uses x64 emulation which will be slower
    windows.vm.box = "StefanScherer/windows_11"
    windows.vm.hostname = "ftr-windows"
    windows.vm.guest = :windows
    windows.vm.communicator = "winrm"
    
    windows.vm.network "public_network", bridge: "en0: Wi-Fi"
    
    windows.vm.provider "parallels" do |prl|
      prl.memory = 8192
      # Windows needs more resources for emulation
    end
    
    # Basic setup - manual steps still required
    windows.vm.provision "shell", inline: <<-'SHELL'
      Write-Host "=== Windows Setup for ftr ==="
      Write-Host ""
      Write-Host "Manual installation required:"
      Write-Host "1. Install Chocolatey:"
      Write-Host "   Set-ExecutionPolicy Bypass -Scope Process -Force; [System.Net.ServicePointManager]::SecurityProtocol = [System.Net.ServicePointManager]::SecurityProtocol -bor 3072; iex ((New-Object System.Net.WebClient).DownloadString('https://community.chocolatey.org/install.ps1'))"
      Write-Host ""
      Write-Host "2. Install dependencies:"
      Write-Host "   choco install -y git rustup.install visualstudio2022buildtools"
      Write-Host ""
      Write-Host "3. Install Npcap from https://npcap.com"
      Write-Host ""
      Write-Host "4. Build ftr:"
      Write-Host "   cd C:\vagrant"
      Write-Host "   cargo build --release"
      Write-Host ""
      Write-Host "Shared folder is at: C:\vagrant"
    SHELL
  end
end