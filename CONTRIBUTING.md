# Contributing to VPS Sentinel

Thanks for your interest in contributing. VPS Sentinel is a pure-bash security toolkit — no Python, no Node, no Docker. Contributions should keep it that way.

## Getting Started

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/your-feature`
3. Test on a real VPS (not just locally)
4. Submit a pull request

## Guidelines

### Keep it bash

- All scripts must be pure bash (no Python, Ruby, or compiled binaries)
- Target bash 4.0+ for compatibility
- Use standard Unix tools: `grep`, `awk`, `sed`, `curl`, `iptables`, `fail2ban-client`
- No external dependencies beyond what `install.sh` already installs

### Test on real servers

- Test on Ubuntu 20.04+ or Debian 11+ (the supported platforms)
- Run against real nginx logs, not mocked data
- Verify fail2ban filters with `fail2ban-regex` before submitting
- Check that `install.sh` and `uninstall.sh` still work cleanly

### Script conventions

- Source config at the top: `source /etc/sentinel/sentinel.conf`
- Respect the whitelist — never block `$WHITELIST` IPs
- Use `$BLOCKED_LOG` and `$SENTINEL_LOG` for logging (not hardcoded paths)
- Guard file reads: `[ -f "$FILE" ] && ...` or `2>/dev/null`
- Avoid `grep -c ... || echo 0` — use `grep -c ...; true` instead (grep exits 1 on zero matches, causing double output)
- Use `iptables-save | grep -c '\-j DROP'` instead of `iptables -L -n | grep DROP` (multi-chain output breaks counts)

### Fail2ban filters

- Place new filters in `filters/` with the `nginx-` prefix
- Include a `[Definition]` section with `failregex` and `ignoreregex`
- Add a corresponding jail in `install.sh`
- Test with: `fail2ban-regex /var/log/nginx/access.log filters/your-filter.conf`

### Commit messages

- Use imperative mood: "Fix bug" not "Fixed bug"
- First line under 72 characters
- Reference the script name: "threats: fix arithmetic error on zero matches"

## What to Contribute

### High value
- New fail2ban filters for emerging attack patterns
- Improvements to smart blocking logic in `sentinel-monitor.sh`
- Support for additional Linux distributions
- IPv6 support improvements
- Log rotation handling

### Nice to have
- GeoIP accuracy improvements (MaxMind integration)
- Email/webhook alerting
- Rate limiting configurations
- Ansible/cloud-init deployment recipes

## Reporting Bugs

Open an issue with:
- Your OS and version (`cat /etc/os-release`)
- The script that failed and its full output
- Your nginx version (`nginx -v`)
- Your fail2ban version (`fail2ban-client --version`)

## Security

If you find a security vulnerability in VPS Sentinel itself (e.g., a way to bypass the filters, or an injection in the scripts), please report it privately via GitHub Security Advisories rather than opening a public issue.
