# Changelog

All notable changes to VPS Sentinel are documented here.

## [1.1.0] - 2026-02-22

### Fixed
- **threats**: `grep -c || echo 0` anti-pattern caused `"0\n0"` in arithmetic expressions on Ubuntu 25.04 — replaced with `; true` pattern
- **threats**: `iptables -L -n` multi-chain output broke grep count — switched to `iptables-save` for reliable DROP counting
- **threats**: `-oP` (Perl regex) replaced with `-oE` (POSIX extended) for broader compatibility
- **ip-analysis**: `wc -l < blocked_ips.log` failed when log file didn't exist yet — added `-f` guard
- **ip-analysis**: `fail2ban-client status` field parsing broke on tab-indented output — switched to `awk -F:` with whitespace trim
- **ip-analysis**: Same `grep -c || echo 0` double-zero bug in attack method counts

### Changed
- **install.sh**: Now creates `sentinel.log` and `blocked_ips.log` during installation so scripts never hit missing-file errors on fresh installs

### Tested
- Clean install verified on Ubuntu 25.04 (24 cores, 92GB RAM)
- All 25 scripts passing
- Real-world results within minutes: 8,498 SSH attempts detected, 34 IPs auto-banned

## [1.0.0] - 2026-02-21

### Added
- Three-layer defense: nginx instant drop, fail2ban pattern matching, sentinel 15-minute sweep
- 25 security scripts (core, investigation, monitoring, traffic, live monitoring, management)
- 8 custom fail2ban filters (exploits, scanner, badbots, noscript, 404, rdp, protocol-confusion, noproxy)
- nginx `block-exploits.conf` drop-in snippet
- systemd timer for automated 15-minute security scans
- Smart blocking: hostile IP ranges get zero tolerance, regular IPs only blocked for critical attacks
- Central configuration via `/etc/sentinel/sentinel.conf`
- Whitelist management without editing config files
- Pattern analysis and reporting (multi-vector attackers, suspicious UAs, new attack patterns)
- Installer with auto-detection of client and server IPs
- Clean uninstaller with optional config/log removal

### Fixed (from original toolkit)
- **whitelist-manage**: Was sed'ing monitor script directly — rewritten to manage IPs via sentinel.conf
- **exploit-report**: Subshell counter bug (UNBLOCKED_COUNT never incremented) — fixed with tmpfile
- **security-dashboard**: `TERM not set` warning — fixed with `[ -t 1 ] && clear`
- **network-scan**: Showed IPv6 instead of IPv4 — fixed with `curl -4 -s ifconfig.me`
- **traffic-stats**: CONNECT proxy requests polluting top pages — fixed with `grep "^/"` filter
- **All scripts**: Hardcoded IPs replaced with config-driven approach via sentinel.conf
