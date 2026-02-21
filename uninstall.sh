#!/bin/bash
# VPS Sentinel - Uninstaller

set -e

if [ "$EUID" -ne 0 ]; then
    echo "Error: Please run as root (sudo ./uninstall.sh)"
    exit 1
fi

echo "======================================================================="
echo "  VPS Sentinel - Uninstaller"
echo "======================================================================="
echo ""
read -p "  This will remove all VPS Sentinel scripts and config. Continue? [y/N] " -n 1 -r
echo ""
[[ ! $REPLY =~ ^[Yy]$ ]] && exit 0

echo ""
echo "  Stopping services..."
systemctl stop sentinel.timer 2>/dev/null || true
systemctl disable sentinel.timer 2>/dev/null || true

echo "  Removing systemd units..."
rm -f /etc/systemd/system/sentinel.service
rm -f /etc/systemd/system/sentinel.timer
systemctl daemon-reload

echo "  Removing scripts..."
SCRIPTS="sentinel-monitor.sh security-dashboard sec srun threats check-ip
security-alerts security-status security-report whitelist-manage
exploit-report exploit-stats exploit-watch ip-analysis network-scan
f2b-summary unblock-ip firewall-restore traffic-stats traffic-history
visitors top-pages visitor-watch session-watch user-sessions"

for script in $SCRIPTS; do
    rm -f "/usr/local/bin/$script"
done

echo "  Removing filters..."
rm -f /etc/fail2ban/filter.d/nginx-404.conf
rm -f /etc/fail2ban/filter.d/nginx-badbots.conf
rm -f /etc/fail2ban/filter.d/nginx-exploits.conf
rm -f /etc/fail2ban/filter.d/nginx-noproxy.conf
rm -f /etc/fail2ban/filter.d/nginx-noscript.conf
rm -f /etc/fail2ban/filter.d/nginx-protocol-confusion.conf
rm -f /etc/fail2ban/filter.d/nginx-rdp.conf
rm -f /etc/fail2ban/filter.d/nginx-scanner.conf

echo "  Removing nginx snippet..."
rm -f /etc/nginx/snippets/block-exploits.conf

echo ""
read -p "  Remove config and logs too? [y/N] " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /etc/sentinel
    rm -rf /var/log/sentinel
    echo "  Config and logs removed."
else
    echo "  Config kept at /etc/sentinel/"
    echo "  Logs kept at /var/log/sentinel/"
fi

echo ""
echo "  VPS Sentinel uninstalled."
echo "  Note: fail2ban and iptables rules are still active."
echo "======================================================================="
