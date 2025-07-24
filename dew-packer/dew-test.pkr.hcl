packer {
  required_plugins {
    parallels = {
      version = ">= 1.1.5"
      source  = "github.com/hashicorp/parallels"
    }
  }
}

variable "vm_name" {
  type    = string
  default = "ubuntu-24.04-lts-arm64"
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory" {
  type    = number
  default = 4096 # 4 GB
}

variable "disk_size" {
  type    = number
  default = 40960 # 40 GB
}

source "parallels-iso" "ubuntu" {
  guest_os_type      = "ubuntu"
  vm_name            = var.vm_name
  cpus               = var.cpus
  memory             = var.memory
  disk_size          = var.disk_size
  iso_url            = "https://cdimage.ubuntu.com/releases/24.04.2/release/ubuntu-24.04.2-live-server-arm64.iso"
  iso_checksum       = "sha256:9fd122eedff09dc57d66e1c29acb8d7a207e2a877e762bdf30d2c913f95f03a4"
  output_directory   = "output-${var.vm_name}"
  parallels_tools_mode   = "attach"
  parallels_tools_flavor = "lin-arm"
  shutdown_command   = "echo 'ubuntu' | sudo -S shutdown -h now"
  ssh_username       = "ubuntu"
  ssh_password       = "tr33tr33!"
  ssh_timeout        = "30m"
  http_directory     = "http"
  startup_view       = "window"

  prlctl = [
    ["set", "{{.Name}}", "--device-bootorder", "cdrom0 hdd0"]
  ]

  # Below is specific to Ubuntu 24 LTS installer, handcrafted with love by DEW
  boot_wait = "5s"
  boot_command = [
    "e<wait>",
    "<down><down><down><down>",
    "<left><left><left><left><left><left>",
    " autoinstall debug verbose ds=nocloud-net\\;s=http://{{ .HTTPIP }}:{{ .HTTPPort }}/ <wait>",
    "<leftCtrlOn>x<leftCtrlOff><wait>"
  ]
}

build {
  sources = ["source.parallels-iso.ubuntu"]

  provisioner "shell" {
    inline = [
      "echo 'Waiting for cloud-init to finish...'",
      "cloud-init status --wait",
      "sudo rm /etc/netplan/50-cloud-init.yaml"
    ]
  }

  provisioner "shell" {
    only = ["parallels-iso.ubuntu"]
    inline = [
      "echo 'Installing Parallels Tools...'",
      "sudo mkdir -p /mnt/parallels",
      "sudo mount -o ro /dev/cdrom /mnt/parallels",
      "sudo /mnt/parallels/install --install-unattended-with-deps",
      "sudo umount /mnt/parallels",
      "sudo rmdir /mnt/parallels"
    ]
  }
}
