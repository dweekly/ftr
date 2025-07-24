# Base configuration module for all VMs
# Provides common settings and helper methods

module BaseConfig
  # Common VM settings
  COMMON_SETTINGS = {
    memory: 2048,
    cpus: 2,
    provider: "parallels"
  }

  # Network configuration
  NETWORK_BASE = "192.168.36"
  
  # Shared folder configuration
  SHARED_FOLDER = {
    host_path: "../",
    guest_path: "/media/psf/ftr",
    type: "parallels",
    mount_options: ["share"]
  }

  # Configure base VM settings
  def self.configure_base(config, settings = {})
    settings = COMMON_SETTINGS.merge(settings)
    
    # Parallels provider configuration
    config.vm.provider "parallels" do |prl|
      prl.memory = settings[:memory]
      prl.cpus = settings[:cpus]
      prl.update_guest_tools = true
      
      # Performance optimizations
      prl.customize ["set", :id, "--adaptive-hypervisor", "on"]
      prl.customize ["set", :id, "--time-sync", "on"]
      prl.customize ["set", :id, "--startup-view", "headless"]
    end
    
    # SSH configuration
    config.ssh.insert_key = false
  end

  # Configure network - use bridged networking with DHCP
  def self.configure_network(config, os_id)
    # Use bridged networking to get IP from LAN DHCP
    config.vm.network "public_network", bridge: "auto"
    
    # Enable serial console for alternative access
    config.vm.provider "parallels" do |prl|
      # Enable serial port
      prl.customize ["set", :id, "--device-add", "serial", "--output", "socket", "--socket", "#{Dir.pwd}/serial.sock"]
    end
  end
  
  # Helper to discover VM IP after boot
  def self.get_vm_ip_script
    <<-SCRIPT
      # Get IP address from the VM
      ip addr show | grep -E "inet .* (eth|enp|vtnet)" | grep -v "127.0.0.1" | awk '{print $2}' | cut -d/ -f1 | head -1
    SCRIPT
  end

  # Configure shared folders based on OS type
  def self.configure_shared_folder(config, os_type)
    # Some BSDs might need different mount paths
    guest_path = case os_type
    when :openbsd then "/home/ftr/ftr"
    when :netbsd then "/home/ftr/ftr"
    else SHARED_FOLDER[:guest_path]
    end
    
    config.vm.synced_folder SHARED_FOLDER[:host_path], guest_path,
      type: SHARED_FOLDER[:type],
      mount_options: SHARED_FOLDER[:mount_options],
      owner: "ftr",
      group: "ftr"
  end

  # Base provisioning for Unix-like systems
  def self.base_unix_provision(shell, os_family)
    case os_family
    when :debian
      debian_base_provision(shell)
    when :redhat  
      redhat_base_provision(shell)
    when :bsd
      bsd_base_provision(shell)
    end
  end

  private

  def self.debian_base_provision(shell)
    shell.inline = <<-SCRIPT
      set -e
      echo "=== Updating system packages ==="
      apt-get update
      apt-get install -y build-essential git curl pkg-config libssl-dev
    SCRIPT
  end

  def self.redhat_base_provision(shell)
    shell.inline = <<-SCRIPT
      set -e
      echo "=== Updating system packages ==="
      yum update -y
      yum groupinstall -y "Development Tools"
      yum install -y git curl openssl-devel
    SCRIPT
  end

  def self.bsd_base_provision(shell)
    shell.inline = <<-SCRIPT
      set -e
      echo "=== Updating system packages ==="
      pkg update || true
      pkg install -y git curl rust
    SCRIPT
  end
end