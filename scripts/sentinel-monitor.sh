#!/bin/bash
# VPS Sentinel - Core Security Monitor (runs every 15 minutes via systemd timer)

CONF="/etc/sentinel/sentinel.conf"
[ -f "$CONF" ] && source "$CONF" || { echo "Config not found: $CONF"; exit 1; }

REPORT_FILE="${REPORT_DIR}/pattern_analysis_$(date +%Y%m%d).log"

block_ip() {
    local ip=$1
    local reason=$2

    # Skip if whitelisted
    [[ " $WHITELIST " =~ " $ip " ]] && return 0

    # Expanded hostile provider list
    HOSTILE_PROVIDERS="
        ^45\.142\.    # M247 (known for abuse)
        ^45\.145\.    # GlobalLayer (bulletproof hosting)
        ^89\.248\.    # Quasi Networks (attack source)
        ^185\.220\.   # Tor exit nodes
        ^192\.241\.   # DigitalOcean (often abused)
        ^162\.142\.   # Censys scanners
        ^167\.94\.    # Shodan scanners
        ^167\.248\.   # Cyberscan.io
        ^205\.210\.   # Cymru scanners
        ^87\.236\.    # Hostile Russian hosting
        ^94\.102\.    # Known attack hosting
        ^195\.133\.   # RU bulletproof hosting
        ^146\.88\.    # Hostile hosting
        ^152\.89\.    # Known scanner range
        ^3\.130\.     # AWS scanner range
        ^47\.91\.     # Alibaba scanners
        ^104\.234\.   # Known scanner
        ^93\.174\.    # Scanner network
        ^178\.22\.    # Hostile range
        ^149\.130\.   # Proxy scanner
        ^150\.158\.   # Tencent Cloud Shanghai
        ^119\.        # China Telecom
        ^125\.        # China ranges
        ^59\.         # Asia Pacific
        ^61\.         # Asia Pacific
        ^220\.        # Asia Pacific
        ^222\.        # Asia Pacific
        ^180\.        # Asia Pacific
    "

    # Check if it's from a known hostile provider
    local is_hostile=0
    for range in $HOSTILE_PROVIDERS; do
        range=$(echo "$range" | cut -d'#' -f1 | tr -d ' ')
        [[ -z "$range" ]] && continue
        if [[ "$ip" =~ $range ]]; then
            is_hostile=1
            break
        fi
    done

    # For non-hostile IPs, only block CRITICAL attacks
    if [ $is_hostile -eq 0 ]; then
        if [[ "$reason" != *"eval-stdin"* ]] &&
           [[ "$reason" != *"shell?cd"* ]] &&
           [[ "$reason" != *"Binary/RDP"* ]] &&
           [[ "$reason" != *"Protocol confusion"* ]] &&
           [[ "$reason" != *"CONNECT proxy"* ]]; then
            return 0
        fi
    fi

    # Block the IP
    if ! sudo iptables-save | grep -q "$ip.*DROP"; then
        sudo iptables -I INPUT -s "$ip" -j DROP
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Blocked: $ip | Reason: $reason" >> "$BLOCKED_LOG"
    fi
}

# CRITICAL exploits that should always be blocked
CRITICAL_EXPLOITS="phpunit/phpunit/src/Util/PHP/eval-stdin\.php|shell\?cd\+/tmp|wget.*\.sh.*sh|curl.*\|.*bash|XDEBUG_SESSION_START|actuator/gateway|cgi-bin/luci|stok=/locale|boaform|GponForm|setup\.cgi|login\.cgi"

# Check for critical exploits
grep -E "$CRITICAL_EXPLOITS" "$NGINX_LOG" 2>/dev/null | awk '{print $1}' | sort -u | while read ip; do
    exploit=$(grep "$ip" "$NGINX_LOG" | grep -oE "$CRITICAL_EXPLOITS" | head -1)
    block_ip "$ip" "Critical exploit: $exploit"
done

# Common hacking tools/exploits (block from hostile providers only)
COMMON_EXPLOITS="wp-admin|wp-login|\.env|\.git/config|etc/passwd|proc/self|boaform/admin|webshell|c99\.php|r57\.php|phpmyadmin|phppma|pma|mysql/|adminer|db/webdb|sql/websql|myadmin"

grep -E "$COMMON_EXPLOITS" "$NGINX_LOG" 2>/dev/null | awk '{print $1}' | sort -u | while read ip; do
    exploit=$(grep "$ip" "$NGINX_LOG" | grep -oE "$COMMON_EXPLOITS" | head -1)
    block_ip "$ip" "Exploit attempt: $exploit"
done

# Block binary/RDP attacks (these are NEVER legitimate HTTP)
grep -E "\\\\x03\\\\x00\\\\x00|mstshash=|Cookie: mstshash=" "$NGINX_LOG" 2>/dev/null | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    block_ip "$ip" "Binary/RDP attack"
done

# Protocol confusion attacks (SSL/TLS on HTTP, SSH on HTTP)
PROTOCOL_CONFUSION='\\x[0-9a-fA-F]{2}|SSH-[0-9]|^PRI \* HTTP'
grep -E "$PROTOCOL_CONFUSION" "$NGINX_LOG" 2>/dev/null | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    block_ip "$ip" "Protocol confusion attack"
done

# CONNECT proxy attempts
grep "CONNECT " "$NGINX_LOG" 2>/dev/null | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    block_ip "$ip" "CONNECT proxy attempt"
done

# Empty request attacks (often scanners)
grep '" 400 ' "$NGINX_LOG" 2>/dev/null | grep '"-" "-"$' | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    count=$(grep -c "^$ip .* \"\" 400" "$NGINX_LOG")
    if [ "$count" -gt 2 ]; then
        block_ip "$ip" "Multiple empty requests ($count attempts)"
    fi
done

# Multiple 400 errors from same IP (likely scanner)
awk '$9 == 400 {print $1}' "$NGINX_LOG" | sort | uniq -c | while read count ip; do
    if [ "$count" -gt 10 ]; then
        block_ip "$ip" "Excessive 400 errors ($count)"
    fi
done

# Database and PHP admin scanners (we have zero admin panels)
grep -E "phpmyadmin|phppma|pma/|mysql/|adminer|/db/|websql|myadmin|phpldapadmin|phpredisadmin|phppgadmin|phpsysinfo|phpinfo" "$NGINX_LOG" 2>/dev/null | \
    grep " 404 " | grep -oE '^([0-9]{1,3}\.){3}[0-9]{1,3}' | sort -u | while read ip; do
    [[ " $WHITELIST " =~ " $ip " ]] && continue
    if ! sudo iptables-save | grep -q "$ip.*DROP"; then
        sudo iptables -I INPUT -s "$ip" -j DROP
        echo "[$(date '+%Y-%m-%d %H:%M:%S')] Blocked: $ip | Reason: Admin panel scan (no admin tools exist)" >> "$BLOCKED_LOG"
    fi
done

# Block scanners with no user agent making multiple requests
awk '$10 == "\"-\"" && $11 == "\"-\"" {print $1}' "$NGINX_LOG" | \
    sort | uniq -c | while read count ip; do
    if [ "$count" -gt 5 ]; then
        [[ " $WHITELIST " =~ " $ip " ]] && continue
        [[ "$ip" == "::1" ]] && continue
        if ! sudo iptables-save | grep -q "$ip.*DROP"; then
            sudo iptables -I INPUT -s "$ip" -j DROP
            echo "[$(date '+%Y-%m-%d %H:%M:%S')] Blocked: $ip | Reason: No user agent scanner ($count requests)" >> "$BLOCKED_LOG"
        fi
    fi
done

# Pattern analysis for reporting (NOT blocking)
analyze_patterns() {
    echo "==================================================================" >> "$REPORT_FILE"
    echo "Pattern Analysis Report - $(date '+%Y-%m-%d %H:%M:%S')" >> "$REPORT_FILE"
    echo "==================================================================" >> "$REPORT_FILE"

    # Detect multi-pattern attackers
    echo -e "\nMulti-Pattern Attackers (3+ different exploit types):" >> "$REPORT_FILE"
    grep -E "cgi-bin|luci|wp-admin|\.env|admin|CONNECT|\\\\x[0-9a-fA-F]|SSH-" "$NGINX_LOG" 2>/dev/null | \
        awk '{print $1}' | sort | uniq -c | sort -rn | while read count ip; do
        if [ "$count" -gt 3 ]; then
            echo "  $ip - $count different exploit attempts" >> "$REPORT_FILE"
            patterns=$(grep "$ip" "$NGINX_LOG" | grep -oE "(cgi-bin|luci|wp-admin|\.env|CONNECT|SSH-|\\\\x[0-9a-fA-F]{2})" | sort -u | tr '\n' ', ')
            echo "    Patterns: ${patterns%, }" >> "$REPORT_FILE"
        fi
    done

    # Suspicious user agents
    echo -e "\nSuspicious User Agents:" >> "$REPORT_FILE"
    grep -E '"-" "-"$|"python|"curl|"wget|"scanner|"bot' "$NGINX_LOG" 2>/dev/null | \
        grep -v "Googlebot\|bingbot" | \
        awk -F'"' '{print $6}' | sort | uniq -c | sort -rn | head -10 >> "$REPORT_FILE"

    # New exploit patterns not in our filters
    echo -e "\nPotential New Attack Patterns (404/403 responses):" >> "$REPORT_FILE"
    grep " 40[34] " "$NGINX_LOG" | \
        grep -vE "(cgi-bin|luci|wp-admin|\.env|\.git)" | \
        grep -E "(admin|mysql|phpmyadmin|pma|webdb|manager|shell)" | \
        awk '{print $7}' | sort | uniq -c | sort -rn | head -10 >> "$REPORT_FILE"

    # Blocked IPs with geolocation
    echo -e "\nBlocked IPs with Locations:" >> "$REPORT_FILE"
    grep "$(date '+%Y-%m-%d')" "$BLOCKED_LOG" 2>/dev/null | grep "Blocked:" | \
        awk '{print $4}' | head -10 | while read ip; do
        location=$(geoiplookup "$ip" 2>/dev/null | cut -d: -f2 | sed 's/^ //')
        echo "  $ip - $location" >> "$REPORT_FILE"
    done
}

# Run pattern analysis
analyze_patterns

# Log completion
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Security scan completed - $(sudo iptables -L INPUT -n | grep -c DROP) IPs blocked" >> "$SENTINEL_LOG"
echo "[$(date '+%Y-%m-%d %H:%M:%S')] Pattern analysis saved to $REPORT_FILE" >> "$SENTINEL_LOG"
