# Rust installation module
# Handles Rust toolchain installation across different operating systems

module RustInstaller
  RUST_INSTALLER_URL = "https://sh.rustup.rs"
  
  # Install Rust for a specific user on different OS types
  def self.install_rust_script(username, os_type)
    case os_type
    when :linux, :freebsd
      linux_bsd_install(username)
    when :openbsd
      openbsd_install(username)
    when :netbsd
      netbsd_install(username)
    else
      generic_install(username)
    end
  end

  private

  def self.linux_bsd_install(username)
    <<-SCRIPT
      echo "=== Installing Rust toolchain for #{username} ==="
      sudo -u #{username} bash -c 'curl --proto "=https" --tlsv1.2 -sSf #{RUST_INSTALLER_URL} | sh -s -- -y --default-toolchain stable'
      sudo -u #{username} bash -c 'echo "source \\$HOME/.cargo/env" >> ~/.bashrc'
      sudo -u #{username} bash -c 'echo "source \\$HOME/.cargo/env" >> ~/.profile'
      sudo -u #{username} bash -c 'source $HOME/.cargo/env && rustup update'
    SCRIPT
  end

  def self.openbsd_install(username)
    <<-SCRIPT
      echo "=== Installing Rust for OpenBSD ==="
      # OpenBSD might have Rust in ports
      pkg_add rust || {
        echo "Installing Rust via rustup..."
        sudo -u #{username} bash -c 'curl --proto "=https" --tlsv1.2 -sSf #{RUST_INSTALLER_URL} | sh -s -- -y --default-toolchain stable'
        sudo -u #{username} bash -c 'echo "source \\$HOME/.cargo/env" >> ~/.profile'
      }
    SCRIPT
  end

  def self.netbsd_install(username)
    <<-SCRIPT
      echo "=== Installing Rust for NetBSD ==="
      # NetBSD might need different approach
      pkgin -y install rust || {
        echo "Installing Rust via rustup..."
        sudo -u #{username} bash -c 'curl --proto "=https" --tlsv1.2 -sSf #{RUST_INSTALLER_URL} | sh -s -- -y --default-toolchain stable'
        sudo -u #{username} bash -c 'echo "source \\$HOME/.cargo/env" >> ~/.profile'
      }
    SCRIPT
  end

  def self.generic_install(username)
    <<-SCRIPT
      echo "=== Installing Rust toolchain ==="
      sudo -u #{username} bash -c 'curl --proto "=https" --tlsv1.2 -sSf #{RUST_INSTALLER_URL} | sh -s -- -y --default-toolchain stable'
      sudo -u #{username} bash -c 'echo "source \\$HOME/.cargo/env" >> ~/.profile'
    SCRIPT
  end
end