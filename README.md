# VPS Sentinel

A lightweight, zero-dependency security toolkit for VPS servers running nginx. Three layers of defense that catch everything from script kiddies to sophisticated scanners — all in pure bash.

Built from real-world production use protecting web applications against thousands of daily attack attempts.

## How It Works

VPS Sentinel uses a three-layer defense strategy:

```
Layer 1: nginx (instant)        Layer 2: fail2ban (pattern)      Layer 3: sentinel (sweep)
========================        ===========================      ========================
Drops malformed requests        Watches log patterns             Runs every 15 minutes
before they hit your app.       and bans repeat offenders.       Catches everything else.

- Binary/RDP attacks            - SSH brute force                - Critical exploit attempts
- Path traversal                - 404 flooding                   - Protocol confusion
- Shell injection in URI        - Bot/scanner patterns           - CONNECT proxy abuse
- CONNECT proxy attempts        - Router exploit probes          - Empty request floods
- CGI/router exploits           - Script injection               - No-UA scanner detection
- Debug tool probes             - Protocol confusion             - Admin panel scanners
                                - RDP-over-HTTP                  - Multi-pattern attackers

Response: 444 (drop)            Response: temp ban               Response: iptables DROP
Zero bytes sent.                Configurable duration.           Permanent until removed.
```

### Smart Blocking

Not all IPs are treated equally. The monitor maintains a list of known hostile IP ranges (bulletproof hosting, Tor exits, scanner networks). IPs from these ranges get blocked for **any** exploit attempt. Regular IPs only get blocked for **critical** attacks (RCE, protocol confusion, proxy abuse) — reducing false positives while catching real threats.

## What's Included

### 25 Scripts

| Command | Description |
|---------|-------------|
| **Core** | |
| `sec` | Quick security status (ideal for login `.profile`) |
| `srun` | Trigger a manual security scan |
| `security-dashboard` | Full dashboard with threats, traffic, geolocation |
| `threats` | Active threats with country lookup and block status |
| `check-ip <IP>` | Deep investigation of any IP address |
| **Monitoring** | |
| `security-alerts` | Threats from the last hour |
| `security-status` | Compact status overview |
| `security-report` | Generate a full report to `/tmp/` |
| `exploit-report` | Exploit attempts with block verification |
| `exploit-stats` | Daily/weekly exploit statistics with geolocation |
| `exploit-watch` | Live color-coded tail of exploit log |
| `ip-analysis` | Full security metrics and fail2ban jail analysis |
| `network-scan` | Port scan and service audit of your own server |
| **Traffic** | |
| `traffic-stats` | Traffic analysis (visitors, pages, response codes) |
| `traffic-history` | 7-day traffic with rotated log support |
| `visitors` | Quick unique visitor count |
| `top-pages` | Most visited pages |
| **Live Monitoring** | |
| `visitor-watch` | Live tail filtered by whitelist |
| `session-watch` | Live session monitor with status icons and geolocation |
| `user-sessions` | Rich session table with country and block status |
| **Management** | |
| `whitelist-manage` | Add/remove trusted IPs via config |
| `unblock-ip <IP>` | Remove IP from iptables and fail2ban |
| `f2b-summary` | Fail2ban jail summary |
| `firewall-restore` | Restore permanent blacklist on boot |

### 8 Fail2ban Filters

| Filter | What It Catches |
|--------|----------------|
| `nginx-exploits` | Router exploits (LuCI, boaform, GponForm, path traversal) |
| `nginx-scanner` | Sensitive file probes (.env, .git, wp-admin, SQL injection, config files) |
| `nginx-badbots` | Malicious bots and automated scanners |
| `nginx-noscript` | Script execution attempts (.php, .cgi, .pl, .py on non-PHP servers) |
| `nginx-404` | 404 flooding (30+ in 60 seconds = ban) |
| `nginx-rdp` | RDP-over-HTTP attacks (mstshash cookies, binary handshakes) |
| `nginx-protocol-confusion` | SSL/TLS and SSH sent to HTTP port |
| `nginx-noproxy` | Open proxy abuse attempts |

### nginx Security Snippet

Drop-in `block-exploits.conf` for your nginx server blocks:
- Blocks non-standard HTTP methods
- Drops binary content in URIs
- Blocks RDP cookie injection
- Prevents path traversal
- Stops shell command injection in URLs
- Blocks HNAP, XDEBUG, actuator, CONNECT, and CGI probes

## Requirements

- Ubuntu 20.04+ or Debian 11+ (tested on Ubuntu 20.04, 22.04, 24.04 and Debian 11, 12)
- nginx (with access log at `/var/log/nginx/access.log`)
- Root access

The installer handles all other dependencies (`fail2ban`, `geoip-bin`, `geoip-database`, `iptables-persistent`, `curl`).

## Installation

```bash
git clone https://github.com/jaymunshi/vps-sentinel.git
cd vps-sentinel
sudo ./install.sh
```

The installer will:
1. Auto-detect your IP and server IP
2. Install dependencies
3. Copy scripts to `/usr/local/bin/`
4. Install fail2ban filters and generate `jail.local`
5. Add the nginx security snippet
6. Enable the systemd timer (runs every 15 minutes)
7. Restart fail2ban

After installation, add the nginx snippet to your server block(s):

```nginx
server {
    ...
    include /etc/nginx/snippets/block-exploits.conf;
    ...
}
```

Then reload nginx:

```bash
sudo nginx -t && sudo systemctl reload nginx
```

Optionally, add `sec` to `/root/.profile` to see security status on every login.

## Configuration

All configuration lives in `/etc/sentinel/sentinel.conf`:

```bash
# Your IP (never blocked, excluded from traffic stats)
MY_IP="203.0.113.50"

# Server's public IP
SERVER_IP="198.51.100.10"

# Additional trusted IPs (space-separated)
TRUSTED_IPS="10.0.0.1 172.16.0.1"

# Log paths (defaults work for standard Ubuntu/Debian + nginx)
NGINX_LOG="/var/log/nginx/access.log"
AUTH_LOG="/var/log/auth.log"
F2B_LOG="/var/log/fail2ban.log"
EXPLOIT_LOG="/var/log/nginx/blocked_exploits.log"
```

Manage trusted IPs without editing the config directly:

```bash
whitelist-manage show          # List all whitelisted IPs
whitelist-manage add 10.0.0.5  # Add a trusted IP
whitelist-manage remove 10.0.0.5
```

## Usage Examples

```bash
# Quick status check
sec

# Full security dashboard
security-dashboard

# Something suspicious? Investigate an IP
check-ip 45.142.154.47

# View active threats with geolocation
threats

# Run a scan right now
srun

# Watch attacks in real-time
exploit-watch

# Who's on my server right now?
user-sessions

# Traffic analysis
traffic-stats

# Unblock a false positive
unblock-ip 203.0.113.99
```

## How the Timer Works

The systemd timer runs `sentinel-monitor.sh` every 15 minutes. Each scan:

1. Checks nginx logs for critical exploits (RCE, eval-stdin, shell injection)
2. Checks for common exploit patterns (wp-admin, .env, phpmyadmin)
3. Detects binary/RDP attacks, protocol confusion, CONNECT proxy abuse
4. Blocks empty request floods and no-UA scanners above threshold
5. Runs pattern analysis for reporting (multi-vector attackers, suspicious user agents)
6. Logs all actions to `/var/log/sentinel/`

```bash
# Check timer status
systemctl list-timers sentinel.timer

# View scan logs
tail -20 /var/log/sentinel/sentinel.log

# View block log
tail -20 /var/log/sentinel/blocked_ips.log
```

## Uninstallation

```bash
sudo ./uninstall.sh
```

Removes all scripts, filters, systemd units, and nginx snippet. Optionally removes config and logs. Existing fail2ban and iptables rules remain active (remove manually if needed).

## Project Structure

```
vps-sentinel/
├── install.sh                  # Installer (auto-detects IPs, sets up everything)
├── uninstall.sh                # Clean removal
├── sentinel.conf               # Central config (installed to /etc/sentinel/)
├── scripts/
│   ├── sentinel-monitor.sh     # Core scanner (runs via systemd timer)
│   ├── sec                     # Quick status
│   ├── srun                    # Manual scan trigger
│   ├── security-dashboard      # Full dashboard
│   ├── threats                 # Active threats viewer
│   ├── check-ip                # IP investigation
│   ├── security-alerts         # Recent alerts
│   ├── security-status         # Compact status
│   ├── security-report         # Report generator
│   ├── exploit-report          # Exploit analysis
│   ├── exploit-stats           # Exploit statistics
│   ├── exploit-watch           # Live exploit feed
│   ├── ip-analysis             # Security metrics
│   ├── network-scan            # Port/service audit
│   ├── traffic-stats           # Traffic analysis
│   ├── traffic-history         # 7-day traffic
│   ├── visitors                # Visitor count
│   ├── top-pages               # Popular pages
│   ├── visitor-watch           # Live visitor feed
│   ├── session-watch           # Live session monitor
│   ├── user-sessions           # Session table
│   ├── whitelist-manage        # IP whitelist management
│   ├── unblock-ip              # Unblock an IP
│   ├── f2b-summary             # Fail2ban summary
│   └── firewall-restore        # Boot-time firewall setup
├── filters/
│   ├── nginx-exploits.conf     # Router/path exploits
│   ├── nginx-scanner.conf      # Sensitive file scanners
│   ├── nginx-badbots.conf      # Malicious bots
│   ├── nginx-noscript.conf     # Script execution
│   ├── nginx-404.conf          # 404 flooding
│   ├── nginx-rdp.conf          # RDP-over-HTTP
│   ├── nginx-protocol-confusion.conf
│   └── nginx-noproxy.conf      # Open proxy abuse
├── nginx/
│   └── block-exploits.conf     # nginx security snippet
└── systemd/
    ├── sentinel.service        # Oneshot service
    └── sentinel.timer          # 15-minute timer
```

## License

MIT
