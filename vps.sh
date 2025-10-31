#!/bin/bash
set -euo pipefail

# === DEFAULT OPTIONS ===
INSTALL_PACKAGES=true
SETUP_HOSTNAME_DNS=true
SETUP_SYSTEM_TUNING=true
SETUP_SWAPFILE=true
DISABLE_LOGGING=false
DISABLE_THP=true
SETUP_SSH_KEEPALIVE=true
REMOVE_SERVICES=true
SETUP_STATIC_IP=true
INSTALL_DOCKER=true

# === PARSE ARGUMENTS ===
while [[ $# -gt 0 ]]; do
    case "$1" in
        -no-packages) INSTALL_PACKAGES=false ;;
        -no-dns) SETUP_HOSTNAME_DNS=false ;;
        -no-tuning) SETUP_SYSTEM_TUNING=false ;;
        -no-swap) SETUP_SWAPFILE=false ;;
        -no-log) DISABLE_LOGGING=true ;;
        -no-thp) DISABLE_THP=false ;;
        -no-ssh) SETUP_SSH_KEEPALIVE=false ;;
        -no-cleanup) REMOVE_SERVICES=false ;;
        -no-static-ip) SETUP_STATIC_IP=false ;;
        -no-docker) INSTALL_DOCKER=false ;;
        -h|--help)
            cat <<'HELP'
VPS Setup Script - Automated VPS Configuration

Usage:
  sudo bash vps.sh              # Install everything (with logging)
  sudo bash vps.sh -no-log      # Install everything but disable logging
  sudo bash vps.sh -no-docker   # Install everything except Docker

Options:
  -no-packages     Skip installing essential packages
  -no-dns          Skip/remove hostname and DNS configuration
  -no-tuning       Skip/remove system tuning (sysctl)
  -no-swap         Skip/remove swapfile
  -no-log          Disable journald logging
  -no-thp          Skip/remove THP disable service
  -no-ssh          Skip/remove SSH keepalive configuration
  -no-cleanup      Skip removing unnecessary services
  -no-static-ip    Skip/remove static IP configuration
  -no-docker       Skip/remove Docker installation
  -h, --help       Display this help message

Examples:
  sudo bash vps.sh -no-log -no-docker
  sudo bash vps.sh -no-static-ip -no-swap
HELP
            exit 0
            ;;
        *)
            echo "WARNING: Unknown option: $1" >&2
            ;;
    esac
    shift
done

# === PRIVILEGE & OS CHECK ===
echo "==> Checking privileges and OS..."
(( EUID == 0 )) || { echo "ERROR: Run as root or with sudo!" >&2; exit 1; }
[ -f /etc/os-release ] || { echo "ERROR: Cannot detect OS." >&2; exit 1; }

. /etc/os-release
case ${ID:-} in
  *) [[ "${ID_LIKE,,}" == *"debian"* || "${ID,,}" == "debian" ]] || { echo "ERROR: Only Debian-based systems supported." >&2; exit 1; } ;;
esac

# === ESSENTIAL PACKAGES ===
if $INSTALL_PACKAGES; then
    echo "==> Installing essential packages..."
    apt-get update -y
    apt-get install -y curl wget git htop unzip nano zip zstd jq sudo \
      python3 net-tools lsof iputils-ping bind9-dnsutils
fi

# === HOSTNAME & DNS ===
if $SETUP_HOSTNAME_DNS; then
    echo "==> Configuring hostname and DNS..."
    grep -q "$(hostname)" /etc/hosts || echo "127.0.0.1 $(hostname)" >> /etc/hosts

    systemctl disable --now systemd-resolved &>/dev/null || :

    { [ -f /etc/resolv.conf ] && chattr -i /etc/resolv.conf 2>/dev/null; } || :
    cat > /etc/resolv.conf <<'EOF'
nameserver 8.8.8.8
nameserver 1.1.1.1
EOF
    chattr +i /etc/resolv.conf || :
else
    echo "==> Removing DNS configuration..."
    { [ -f /etc/resolv.conf ] && chattr -i /etc/resolv.conf 2>/dev/null; } || :
    rm -f /etc/resolv.conf || :
    systemctl enable --now systemd-resolved &>/dev/null || :
    ln -sf /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf 2>/dev/null || :
fi

# === SYSTEM TUNING ===
if $SETUP_SYSTEM_TUNING; then
    echo "==> Applying system tuning..."
    mkdir -p /etc/sysctl.d
    cat > /etc/sysctl.d/99-optimizations.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
vm.swappiness = 1
EOF
    sysctl -p /etc/sysctl.d/99-optimizations.conf &>/dev/null || :

    timedatectl set-timezone Asia/Ho_Chi_Minh || :
else
    echo "==> Removing system tuning..."
    rm -f /etc/sysctl.d/99-optimizations.conf || :
    sysctl --system &>/dev/null || :
fi

# === SWAPFILE ===
if $SETUP_SWAPFILE; then
    echo "==> Creating swapfile..."
    RAM_GB=$(($(awk '/MemTotal/ {print $2}' /proc/meminfo) / 1024 / 1024))
    SWAP_SIZE=$((RAM_GB <= 2 ? 2 : 4))G

    swapoff /swapfile &>/dev/null || :
    rm -f /swapfile || :
    sed -i '\|/swapfile|d' /etc/fstab || :

    if { fallocate -l "$SWAP_SIZE" /swapfile || 
         dd if=/dev/zero of=/swapfile bs=1M count=$(( ${SWAP_SIZE%G} * 1024 )) &>/dev/null; } 2>/dev/null
    then
      chmod 600 /swapfile && mkswap /swapfile &>/dev/null && swapon /swapfile
      echo "/swapfile none swap sw 0 0" >> /etc/fstab
    fi
else
    echo "==> Removing swapfile..."
    swapoff /swapfile &>/dev/null || :
    rm -f /swapfile || :
    sed -i '\|/swapfile|d' /etc/fstab || :
fi

# === DISABLE JOURNALD ===
if $DISABLE_LOGGING; then
    echo "==> Disabling journald logging..."
    systemctl mask --now systemd-journald{,-audit,-dev-log}.socket systemd-journald &>/dev/null || :

    mkdir -p /etc/systemd/journald.conf.d
    echo -e "[Journal]\nStorage=none" > /etc/systemd/journald.conf.d/no-logging.conf
    rm -rf /var/log/journal /run/log/journal &>/dev/null || :
    dmesg -C &>/dev/null || :
else
    echo "==> Enabling journald logging..."
    systemctl unmask systemd-journald{,-audit,-dev-log}.socket systemd-journald &>/dev/null || :
    rm -f /etc/systemd/journald.conf.d/no-logging.conf || :
    systemctl restart systemd-journald &>/dev/null || :
fi

# === DISABLE TRANSPARENT HUGE PAGES ===
if $DISABLE_THP; then
    echo "==> Disabling Transparent Huge Pages..."
    { echo never > /sys/kernel/mm/transparent_hugepage/enabled &&
      echo never > /sys/kernel/mm/transparent_hugepage/defrag; } 2>/dev/null || :

    cat > /etc/systemd/system/disable-thp.service <<'EOF'
[Unit]
Description=Disable Transparent Huge Pages
DefaultDependencies=no
After=sysinit.target local-fs.target
Before=basic.target

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'echo never > /sys/kernel/mm/transparent_hugepage/enabled && echo never > /sys/kernel/mm/transparent_hugepage/defrag'
RemainAfterExit=yes

[Install]
WantedBy=basic.target
EOF

    systemctl daemon-reload || :
    systemctl enable --now disable-thp.service &>/dev/null || :
else
    echo "==> Removing THP disable service..."
    systemctl disable --now disable-thp.service &>/dev/null || :
    rm -f /etc/systemd/system/disable-thp.service || :
    systemctl daemon-reload || :
fi

# === SSH KEEPALIVE ===
if $SETUP_SSH_KEEPALIVE; then
    echo "==> Configuring SSH keepalive..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    sed -i '/^\s*#\?\s*ClientAliveInterval/d;/^\s*#\?\s*ClientAliveCountMax/d' "$SSH_CONFIG" || :
    echo -e "ClientAliveInterval 7200\nClientAliveCountMax 3" >> "$SSH_CONFIG"
    systemctl restart sshd &>/dev/null || :
else
    echo "==> Removing SSH keepalive configuration..."
    SSH_CONFIG="/etc/ssh/sshd_config"
    sed -i '/^\s*ClientAliveInterval\s\+7200/d;/^\s*ClientAliveCountMax\s\+3/d' "$SSH_CONFIG" || :
    systemctl restart sshd &>/dev/null || :
fi

# === REMOVE UNNECESSARY SERVICES ===
if $REMOVE_SERVICES; then
    echo "==> Removing unnecessary services..."
    apt purge -y qemu-guest-agent 2>/dev/null || :
    systemctl stop getty@tty1.service serial-getty@ttyS0.service 2>/dev/null || :
    systemctl mask getty@tty1.service serial-getty@ttyS0.service 2>/dev/null || :
fi

# === CONFIGURE STATIC IP ===
if $SETUP_STATIC_IP; then
    echo "==> Configuring static IP..."
    iface=$(ip route show default | awk '{print $5; exit}')
    gw=$(ip route show default | awk '{print $3; exit}')
    addr_cidr=$(ip -4 addr show dev "$iface" | awk '/inet/ && !/127\.0\.0\.1/ {print $2; exit}')

    dpkg -l ifupdown &>/dev/null || apt install -y ifupdown

    cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $iface
iface $iface inet static
    address $addr_cidr
    gateway $gw
EOF

    apt purge -y dhcpcd5 dhcpcd dhcpcd-base 2>/dev/null || :
    apt autoremove -y 2>/dev/null || :

    systemctl restart networking || :
else
    echo "==> Removing static IP configuration..."
    iface=$(ip route show default | awk '{print $5; exit}')
    
    cat > /etc/network/interfaces <<EOF
auto lo
iface lo inet loopback

auto $iface
iface $iface inet dhcp
EOF
    
    systemctl restart networking || :
fi

# === INSTALL DOCKER ===
if $INSTALL_DOCKER; then
    echo "==> Installing and optimizing Docker..."
    if ! command -v docker &>/dev/null; then
        curl -fsSL https://get.docker.com | sh
        usermod -aG docker "${SUDO_USER:-$(id -un)}" || :
        systemctl enable --now docker || :
    fi

    mkdir -p /etc/docker
    cat > /etc/docker/daemon.json <<'EOF'
{
  "storage-driver": "overlay2",
  "log-driver": "json-file",
  "log-opts": {"max-size": "10m", "max-file": "3"},
  "max-concurrent-downloads": 10,
  "max-concurrent-uploads": 10,
  "dns": ["1.1.1.1", "8.8.8.8"],
  "userland-proxy": false
}
EOF

    systemctl restart docker || :
else
    if command -v docker &>/dev/null; then
        echo "==> Removing Docker..."
        docker stop $(docker ps -aq) 2>/dev/null || :
        docker system prune -af --volumes 2>/dev/null || :
        systemctl stop docker docker.socket containerd 2>/dev/null || :
        systemctl disable docker docker.socket containerd 2>/dev/null || :
        apt purge -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin 2>/dev/null || :
        apt autoremove -y 2>/dev/null || :
        rm -rf /var/lib/docker /etc/docker /var/lib/containerd || :
        rm -f /usr/bin/docker /usr/local/bin/docker || :
        groupdel docker 2>/dev/null || :
        hash -r 2>/dev/null || :
        
        sleep 2
    fi
fi

# === DONE ===
cat <<'EOF'
========================================
VPS SETUP COMPLETED
========================================

Current system configuration:
EOF

# Check DNS
if [ -f /etc/resolv.conf ] && grep -q "8.8.8.8" /etc/resolv.conf 2>/dev/null; then
    DNS_SERVERS=$(grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print $2}' | tr '\n' ', ' | sed 's/,$//' || echo "N/A")
    echo "  DNS:                    $DNS_SERVERS"
else
    echo "  DNS:                    System default (systemd-resolved)"
fi

# Check System tuning
if [ -f /etc/sysctl.d/99-optimizations.conf ]; then
    TIMEZONE=$(timedatectl 2>/dev/null | grep "Time zone" | awk '{print $3}' || echo "N/A")
    echo "  System tuning:          IPv6 disabled, swappiness=1"
    echo "  Timezone:               $TIMEZONE"
else
    echo "  System tuning:          Default settings"
fi

# Check Swapfile
SWAP_INFO=$(swapon --show --noheadings 2>/dev/null | grep "/swapfile" | awk '{print $3}' || echo "")
if [ -n "$SWAP_INFO" ]; then
    echo "  Swapfile:               $SWAP_INFO"
else
    echo "  Swapfile:               Not configured"
fi

# Check Logging
if [ -f /etc/systemd/journald.conf.d/no-logging.conf ]; then
    echo "  Journald logging:       Disabled"
else
    echo "  Journald logging:       Enabled"
fi

# Check THP
if [ -f /etc/systemd/system/disable-thp.service ]; then
    echo "  Transparent Huge Pages: Disabled"
else
    echo "  Transparent Huge Pages: Enabled (default)"
fi

# Check SSH keepalive
SSH_INTERVAL=$(grep "^ClientAliveInterval" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "")
SSH_COUNT=$(grep "^ClientAliveCountMax" /etc/ssh/sshd_config 2>/dev/null | awk '{print $2}' || echo "")
if [ -n "$SSH_INTERVAL" ] && [ -n "$SSH_COUNT" ]; then
    TOTAL_SECONDS=$((SSH_INTERVAL * SSH_COUNT))
    TOTAL_HOURS=$((TOTAL_SECONDS / 3600))
    echo "  SSH keepalive:          ${SSH_INTERVAL}s × ${SSH_COUNT} = ${TOTAL_HOURS}h timeout"
else
    echo "  SSH keepalive:          Default"
fi

# Check Static IP
if grep -q "iface.*inet static" /etc/network/interfaces 2>/dev/null; then
    IFACE=$(ip route show default 2>/dev/null | awk '{print $5; exit}' || echo "")
    
    if [ -n "$IFACE" ]; then
        IP_ADDR=$(ip -4 addr show dev "$IFACE" 2>/dev/null | awk '/inet/ && !/127\.0\.0\.1/ {print $2; exit}' || echo "N/A")
        GATEWAY=$(ip route show default 2>/dev/null | awk '{print $3; exit}' || echo "N/A")
        echo "  Network:                Static IP"
        echo "    Interface:            $IFACE"
        echo "    Address:              $IP_ADDR"
        echo "    Gateway:              $GATEWAY"
    else
        echo "  Network:                Static IP (interface info unavailable)"
    fi
else
    echo "  Network:                DHCP"
fi

# Check Docker
if command -v docker &>/dev/null 2>&1; then
    DOCKER_VER=$(docker --version 2>/dev/null | awk '{print $3}' | sed 's/,$//' || echo "unknown")
    echo "  Docker:                 $DOCKER_VER"
    
    if [ -f /etc/docker/daemon.json ]; then
        STORAGE=$(jq -r '."storage-driver" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        LOG_DRIVER=$(jq -r '."log-driver" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        LOG_SIZE=$(jq -r '."log-opts"."max-size" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        LOG_FILES=$(jq -r '."log-opts"."max-file" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        MAX_DOWN=$(jq -r '."max-concurrent-downloads" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        MAX_UP=$(jq -r '."max-concurrent-uploads" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        DNS_SERVERS=$(jq -r '.dns | join(", ") // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        USERLAND=$(jq -r '."userland-proxy" // "N/A"' /etc/docker/daemon.json 2>/dev/null || echo "N/A")
        
        echo "    Storage driver:       $STORAGE"
        echo "    Log driver:           $LOG_DRIVER"
        echo "    Log max size:         $LOG_SIZE"
        echo "    Log max files:        $LOG_FILES"
        echo "    Max downloads:        $MAX_DOWN"
        echo "    Max uploads:          $MAX_UP"
        echo "    DNS:                  $DNS_SERVERS"
        echo "    Userland proxy:       $USERLAND"
    fi
else
    echo "  Docker:                 Not installed"
fi

cat <<'EOF'

Reboot to apply all settings:
  reboot
EOF
