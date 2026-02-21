#!/bin/bash
# VPS Sentinel - Installation Script
# Tested on: Ubuntu 20.04/22.04/24.04, Debian 11/12

set -e

echo "======================================================================="
echo "  VPS Sentinel - Security Toolkit Installer"
echo "======================================================================="
echo ""

# Must run as root
if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./install.sh)"
    exit 1
fi

# Detect MY_IP and SERVER_IP
DETECTED_IP=$(who am i 2>/dev/null | awk '{print $5}' | tr -d '()')
DETECTED_SERVER_IP=$(curl -4 -s --max-time 5 ifconfig.me 2>/dev/null || hostname -I | awk '{print $1}')

echo "  Detected your IP: ${DETECTED_IP:-not detected}"
echo "  Detected server IP: ${DETECTED_SERVER_IP:-not detected}"
echo ""

# Ask for IPs if not auto-detected
if [ -z "$DETECTED_IP" ]; then
    read -p "  Enter YOUR IP address (to whitelist): " DETECTED_IP
fi
if [ -z "$DETECTED_SERVER_IP" ]; then
    read -p "  Enter this server's public IP: " DETECTED_SERVER_IP
fi

echo ""
echo "  Installing with:"
echo "    Your IP: $DETECTED_IP"
echo "    Server IP: $DETECTED_SERVER_IP"
echo ""
read -p "  Continue? [Y/n] " -n 1 -r
echo ""
[[ $REPLY =~ ^[Nn]$ ]] && exit 0

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# 1. Install dependencies
echo ""
echo "  [1/7] Installing dependencies..."
apt-get update -qq
apt-get install -y -qq fail2ban geoip-bin geoip-database iptables-persistent curl > /dev/null 2>&1
echo "  Done."

# 2. Create config directory and install config
echo "  [2/7] Installing configuration..."
mkdir -p /etc/sentinel
mkdir -p /var/log/sentinel

if [ -f /etc/sentinel/sentinel.conf ]; then
    cp /etc/sentinel/sentinel.conf /etc/sentinel/sentinel.conf.bak
    echo "  Backed up existing config to sentinel.conf.bak"
fi

cp "$SCRIPT_DIR/sentinel.conf" /etc/sentinel/sentinel.conf

# Set detected IPs in config
sed -i "s/^MY_IP=\"\"/MY_IP=\"$DETECTED_IP\"/" /etc/sentinel/sentinel.conf
sed -i "s/^SERVER_IP=\"\"/SERVER_IP=\"$DETECTED_SERVER_IP\"/" /etc/sentinel/sentinel.conf

# Create empty permanent blacklist if not exists
touch /etc/sentinel/permanent_blacklist.txt
echo "  Done."

# 3. Install scripts
echo "  [3/7] Installing scripts to /usr/local/bin/..."
for script in "$SCRIPT_DIR"/scripts/*; do
    name=$(basename "$script")
    cp "$script" "/usr/local/bin/$name"
    chmod +x "/usr/local/bin/$name"
done
echo "  Done. Installed $(ls "$SCRIPT_DIR"/scripts/ | wc -l) scripts."

# 4. Install fail2ban filters
echo "  [4/7] Installing fail2ban filters..."
for filter in "$SCRIPT_DIR"/filters/*.conf; do
    cp "$filter" /etc/fail2ban/filter.d/
done

# Install jail.local (merge with existing if present)
if [ -f /etc/fail2ban/jail.local ]; then
    cp /etc/fail2ban/jail.local /etc/fail2ban/jail.local.bak.pre-sentinel
    echo "  Backed up existing jail.local"
fi

# Generate jail.local with correct IPs
cat > /etc/fail2ban/jail.local << JAIL
[DEFAULT]
backend = auto
bantime = 86400
findtime = 600
maxretry = 2
ignoreip = 127.0.0.1/8 ::1 $DETECTED_IP $DETECTED_SERVER_IP

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2

[sshd-aggressive]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 2
findtime = 3600
bantime = 604800

[nginx-badbots]
enabled = true
port = http,https
filter = nginx-badbots
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-noscript]
enabled = true
port = http,https
filter = nginx-noscript
logpath = /var/log/nginx/access.log
maxretry = 2

[nginx-rdp]
enabled = true
port = http,https
filter = nginx-rdp
logpath = /var/log/nginx/access.log
maxretry = 1
findtime = 86400
bantime = 2592000

[nginx-scanner]
enabled = true
port = http,https
filter = nginx-scanner
backend = auto
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 600
bantime = 86400

[nginx-exploits]
enabled = true
port = http,https
filter = nginx-exploits
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 3600
bantime = 86400

[nginx-protocol-confusion]
enabled = true
port = http,https
filter = nginx-protocol-confusion
logpath = /var/log/nginx/access.log
maxretry = 2
findtime = 3600
bantime = 604800

[nginx-404]
enabled = true
port = http,https
filter = nginx-404
logpath = /var/log/nginx/access.log
maxretry = 30
findtime = 60
bantime = 86400
JAIL
echo "  Done."

# 5. Install nginx security snippet
echo "  [5/7] Installing nginx security snippet..."
mkdir -p /etc/nginx/snippets
cp "$SCRIPT_DIR/nginx/block-exploits.conf" /etc/nginx/snippets/
echo ""
echo "  NOTE: Add this line inside your nginx server block(s):"
echo "    include /etc/nginx/snippets/block-exploits.conf;"
echo ""
echo "  Done."

# 6. Install systemd timer
echo "  [6/7] Installing systemd timer..."
cp "$SCRIPT_DIR/systemd/sentinel.service" /etc/systemd/system/
cp "$SCRIPT_DIR/systemd/sentinel.timer" /etc/systemd/system/
systemctl daemon-reload
systemctl enable sentinel.timer
systemctl start sentinel.timer
echo "  Done."

# 7. Restart fail2ban
echo "  [7/7] Restarting fail2ban..."
systemctl restart fail2ban
echo "  Done."

echo ""
echo "======================================================================="
echo "  VPS Sentinel installed successfully!"
echo "======================================================================="
echo ""
echo "  Config:     /etc/sentinel/sentinel.conf"
echo "  Scripts:    /usr/local/bin/ ($(ls "$SCRIPT_DIR"/scripts/ | wc -l) commands)"
echo "  Logs:       /var/log/sentinel/"
echo "  Timer:      Every 15 minutes (sentinel.timer)"
echo ""
echo "  Quick start:"
echo "    sec                  - Quick security status"
echo "    security-dashboard   - Full dashboard"
echo "    srun                 - Manual security scan"
echo "    threats              - View active threats"
echo "    check-ip <IP>        - Investigate an IP"
echo ""
echo "  Optional: Add 'sec' to /root/.profile for login dashboard"
echo "======================================================================="
