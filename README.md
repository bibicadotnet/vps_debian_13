# One-Click VPS Setup with Docker and System Optimization

## ✨ Features

This script automates a secure, lightweight, and performance-optimized setup for Debian/Ubuntu-based VPS environments. Key features include:

- **Privilege & OS Validation**  
  Ensures execution as root and supports only Debian ≥10 or Ubuntu ≥18.04.

- **Essential Tools Installation**  
  Installs `curl`, `wget`, `git`, `htop`, `jq`, `dnsutils`, `net-tools`, and more for system administration and debugging.

- **Reliable DNS Configuration**  
  Disables `systemd-resolved`, sets immutable `/etc/resolv.conf` with Cloudflare (1.1.1.1) and Google (8.8.8.8) nameservers, and fixes localhost hostname resolution.

- **System Performance Tuning**  
  - Disables IPv6  
  - Sets low `vm.swappiness=1` for memory-sensitive workloads  
  - Configures timezone to `Asia/Ho_Chi_Minh`

- **Optimized Swap Setup**  
  Creates a 2–4 GB swapfile based on RAM size and ensures persistence via `/etc/fstab`.

- **Minimal Logging & Reduced Overhead**  
  - Masks and disables `systemd-journald` entirely  
  - Clears journal logs and disables kernel message buffering (`dmesg`)

- **Transparent Huge Pages (THP) Disabled**  
  Prevents latency spikes in memory-intensive applications (e.g., databases, Docker) via a dedicated systemd service.

- **SSH Keep-Alive Configuration**  
  Sets `ClientAliveInterval 7200` and `ClientAliveCountMax 3` to maintain long-lived SSH sessions without disconnection.

- **Unnecessary Services Removed**  
  Purges `qemu-guest-agent`, disables TTY consoles (`getty@tty1`, `serial-getty@ttyS0`), and removes DHCP clients to enforce static networking.

- **Static IP Enforcement**  
  Converts current dynamic IP to static configuration using `ifupdown` and removes `dhcpcd` to prevent IP conflicts.

- **Docker Installation & Optimization**  
  - Installs Docker Engine via the official `get.docker.com` script  
  - Adds current user to `docker` group  
  - Configures `daemon.json` with:
    - `overlay2` storage driver  
    - Limited log rotation (`10MB × 3 files`)  
    - Custom DNS resolvers  
    - Disabled `userland-proxy` for better network performance  
  - Enables Docker to start on boot

- **Idempotent & Safe**  
  Designed to be run once during provisioning; avoids destructive changes if re-run.

> 💡 **Reboot required** to apply all kernel and networking changes.

---

## 🚀 Installation

This script automates a secure, minimal, and Docker-ready setup for Debian/Ubuntu VPS. Two variants are available:

### 1. **With Docker**
```bash
apt install -y wget sudo && wget -qO vps.sh https://raw.githubusercontent.com/bibicadotnet/vps_debian_13/main/1_vps_docker.sh && sudo bash vps.sh
```

### 2. **Without Docker**
```bash
apt install -y wget sudo && wget -qO vps.sh https://raw.githubusercontent.com/bibicadotnet/vps_debian_13/main/1_vps.sh && sudo bash vps.sh
```
