#!/bin/sh
#
# netscaler_compromise_triage.sh
#
# Fast, read-mostly live-response triage for Citrix NetScaler ADC / Gateway.
# Designed to run from the NetScaler shell using appliance-native utilities.
#
# Usage:
#   shell
#   /bin/sh ./netscaler_compromise_triage.sh
#
# Exit codes:
#   0 = no high/suspicious indicators found by these checks
#   1 = suspicious/hunt findings found
#   2 = high-confidence compromise indicators found
#
# IMPORTANT:
# - This is an IOC/post-compromise triage tool, not a vulnerability scanner.
# - A clean result does NOT prove the appliance is uncompromised.
# - It does not modify configuration, kill processes, delete files, or shut down.
#

VERSION="0.3.0"
HIGH=0
WARN=0
INFO=0

section()
{
    echo
    echo "======================================================================"
    echo "$1"
    echo "======================================================================"
}

high()
{
    HIGH=$((HIGH + 1))
    echo "[HIGH] $1"
}

warn()
{
    WARN=$((WARN + 1))
    echo "[WARN] $1"
}

info()
{
    INFO=$((INFO + 1))
    echo "[INFO] $1"
}

show_file()
{
    if [ -e "$1" ]; then
        ls -ald "$1" 2>/dev/null
        file "$1" 2>/dev/null
    fi
}

check_known_file()
{
    p="$1"
    why="$2"
    if [ -e "$p" ]; then
        high "$why: $p"
        show_file "$p"
    fi
}

check_known_dir()
{
    p="$1"
    why="$2"
    if [ -d "$p" ]; then
        high "$why: $p"
        ls -ald "$p" 2>/dev/null
    fi
}

echo "NetScaler compromise triage v$VERSION"
echo "Host: $(hostname 2>/dev/null)"
echo "Date: $(date 2>/dev/null)"
echo "Kernel: $(uname -a 2>/dev/null)"
echo
echo "This tool performs local IOC and post-exploitation checks only."

section "1. HIGH-CONFIDENCE KNOWN NETSCALER COMPROMISE PATHS"

# Mandiant-observed CVE-2023-3519 webshell/tunneler artifacts.
check_known_file "/var/vpn/themes/info.php"   "Mandiant-observed NetScaler webshell filename"
check_known_file "/var/vpn/themes/prod.php"   "Mandiant-observed NetScaler webshell filename"
check_known_file "/var/vpn/themes/log.php"    "Mandiant-observed NetScaler webshell filename"
check_known_file "/var/vpn/themes/logout.php" "Mandiant-observed NetScaler webshell filename"
check_known_file "/var/vpn/themes/vpn.php"    "Mandiant-observed NetScaler webshell filename"
check_known_file "/var/vpn/themes/config.php" "Mandiant-observed NetScaler webshell filename"

check_known_file "/var/tmp/the" "Mandiant-observed persistent tunneler"
check_known_file "/var/tmp/npc" "Mandiant-observed NPS tunneler"
check_known_file "/var/nstmp/.nscache/httpd" "Known NetScaler backdoor location"

# CISA/FBI/DC3-observed NetScaler webshell paths.
check_known_dir  "/var/vpn/themes/imgs" "CISA-observed directory used to stage NetScaler webshells"
check_known_file "/var/vpn/themes/imgs/netscaler.1" "CISA-observed credential/webshell artifact"
check_known_file "/var/vpn/themes/imgs/netscaler.php" "CISA-observed NetScaler webshell"
check_known_file "/var/vpn/themes/imgs/ctxHeaderLogon.php" "CISA-observed NetScaler webshell"
check_known_file "/netscaler/logon/LogonPoint/uiareas/ui_style.php" "CISA-observed NetScaler webshell"
check_known_file "/netscaler/logon/sanpdebug.php" "CISA-observed NetScaler webshell"

section "2. SUID SHELL / PRIVILEGE BACKDOOR CHECKS"

for p in /var/tmp/sh /var/tmp/bash; do
    if [ -e "$p" ]; then
        if [ -u "$p" ]; then
            high "Setuid shell/backdoor present: $p"
        else
            warn "Shell-like binary present in temporary directory: $p"
        fi
        show_file "$p"
    fi
done

SUID_OUT="$(find /var \( -perm -4001 -or \( -perm -4010 -group nobody \) \) -user root -exec ls -al {} \; 2>/dev/null)"
if [ -n "$SUID_OUT" ]; then
    warn "Root-owned SUID files found under /var; review for unexpected additions:"
    echo "$SUID_OUT"
else
    info "No root-owned SUID files found under /var by the NCSC-style check."
fi

section "3. WEBROOT / WEBSHELL HUNT"

# NCSC-NL uses PHP/XHTML files outside the normal admin_ui tree as live-host
# compromise hunting signals.
PHP_OUT="$(find /var/netscaler/ -type f -name '*.php' -not -path '/var/netscaler/gui/admin_ui/*' -exec ls -al {} \; 2>/dev/null)"
if [ -n "$PHP_OUT" ]; then
    warn "PHP files exist under /var/netscaler outside gui/admin_ui:"
    echo "$PHP_OUT"
else
    info "No unexpected PHP files found under /var/netscaler by this check."
fi

XHTML_OUT="$(find /var/netscaler/ -type f -name '*.xhtml' -not -path '/var/netscaler/gui/admin_ui/*' -exec ls -al {} \; 2>/dev/null)"
if [ -n "$XHTML_OUT" ]; then
    warn "XHTML files exist under /var/netscaler outside gui/admin_ui:"
    echo "$XHTML_OUT"
else
    info "No unexpected XHTML files found under /var/netscaler by this check."
fi

# Hunt for script-like files recently changed in common public/staging paths.
for d in /var/vpn/themes /netscaler/logon /netscaler/portal/scripts /netscaler/portal/templates; do
    if [ -d "$d" ]; then
        RECENT="$(find "$d" -type f -mtime -14 \( -name '*.php' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' -o -name '*.xhtml' \) -exec ls -al {} \; 2>/dev/null)"
        if [ -n "$RECENT" ]; then
            warn "Script-like files modified within 14 days under $d:"
            echo "$RECENT"
        fi
    fi
done

section "4. KNOWN / HIGH-SIGNAL WEBSHELL CONTENT"

# Search only likely web-exposed locations and skip the normal NetScaler admin UI.
# Patterns are intentionally high-signal and derived from observed NetScaler
# post-exploitation tradecraft.
for d in /var/vpn/themes /netscaler/logon /netscaler/portal/scripts /netscaler/portal/templates /var/netscaler; do
    if [ -d "$d" ]; then
        find "$d" -type f \
            -not -path '/var/netscaler/gui/admin_ui/*' \
            \( -name '*.php' -o -name '*.pl' -o -name '*.xhtml' -o -name '*.js' -o -name '*.txt' \) \
            -print 2>/dev/null |
        while IFS= read f; do
            if grep -E -q 'blv_encode|openssl_public_decrypt|[$]_REQUEST[[:space:]]*\[[[:space:]]*["'\'']123["'\'']|@eval[[:space:]]*\(' "$f" 2>/dev/null; then
                echo "[HIGH-FILE] Suspicious webshell content: $f"
                ls -al "$f" 2>/dev/null
            fi
        done
    fi
done

# Because the loop above executes in a pipeline/subshell on some /bin/sh
# implementations, count the same high-signal content in a second lightweight
# pass so the final exit status is reliable.
CONTENT_HITS=0
for d in /var/vpn/themes /netscaler/logon /netscaler/portal/scripts /netscaler/portal/templates /var/netscaler; do
    if [ -d "$d" ]; then
        for f in $(find "$d" -type f \
            -not -path '/var/netscaler/gui/admin_ui/*' \
            \( -name '*.php' -o -name '*.pl' -o -name '*.xhtml' -o -name '*.js' -o -name '*.txt' \) \
            -print 2>/dev/null); do
            if grep -E -q 'blv_encode|openssl_public_decrypt|[$]_REQUEST[[:space:]]*\[[[:space:]]*["'\'']123["'\'']|@eval[[:space:]]*\(' "$f" 2>/dev/null; then
                CONTENT_HITS=$((CONTENT_HITS + 1))
            fi
        done
    fi
done
if [ "$CONTENT_HITS" -gt 0 ]; then
    HIGH=$((HIGH + CONTENT_HITS))
fi

section "5. PERSISTENCE CHECKS"

if [ -f /flash/nsconfig/rc.netscaler ]; then
    RC_HITS="$(grep -E -n 'python|perl|curl|wget|nohup|/var/tmp/|/tmp/|/var/nstmp/|nc[[:space:]]|netcat' /flash/nsconfig/rc.netscaler 2>/dev/null)"
    if [ -n "$RC_HITS" ]; then
        warn "Review commands in /flash/nsconfig/rc.netscaler:"
        echo "$RC_HITS"
    else
        info "No obvious scripting/downloader/temp-path persistence strings in rc.netscaler."
    fi
fi

if [ -d /var/cron/tabs ]; then
    echo "-- /var/cron/tabs --"
    ls -al /var/cron/tabs 2>/dev/null

    if [ -f /var/cron/tabs/nobody ]; then
        NOBODY_CRON="$(grep -v '^[[:space:]]*#' /var/cron/tabs/nobody 2>/dev/null | grep -v '^[[:space:]]*$')"
        if [ -n "$NOBODY_CRON" ]; then
            high "Non-empty nobody crontab present. Mandiant observed this persistence mechanism:"
            echo "$NOBODY_CRON"
        fi
    fi

    CRON_HITS="$(grep -E -n '/var/tmp/|/tmp/|/var/nstmp/|curl|wget|python|perl|php|nohup|[[:space:]]nc[[:space:]]|netcat' /var/cron/tabs/* 2>/dev/null)"
    if [ -n "$CRON_HITS" ]; then
        warn "Crontab entries reference temporary paths, interpreters, or download/network tools:"
        echo "$CRON_HITS"
    fi
fi

section "6. RUNNING PROCESS HUNT"

PS_OUT="$(ps auxww 2>/dev/null)"
if [ -n "$PS_OUT" ]; then
    PROC_HIGH="$(echo "$PS_OUT" | grep -E '/var/nstmp/\.nscache/httpd|/var/tmp/(the|npc|bash|sh)([[:space:]]|$)' | grep -v grep)"
    if [ -n "$PROC_HIGH" ]; then
        high "Known/high-signal suspicious process path is running:"
        echo "$PROC_HIGH"
    fi

    PROC_WARN="$(echo "$PS_OUT" | grep -E '(^|[[:space:]])/var/tmp/|(^|[[:space:]])/tmp/' | grep -v grep)"
    if [ -n "$PROC_WARN" ]; then
        warn "Processes executing from temporary directories:"
        echo "$PROC_WARN"
    else
        info "No processes executing from /tmp or /var/tmp were found."
    fi
else
    warn "Unable to collect process list with ps auxww."
fi

section "7. HTTPD CONFIGURATION TAMPERING CHECKS"

if [ -f /etc/httpd.conf ]; then
    EXT="$(grep 'httpd-php' /etc/httpd.conf 2>/dev/null | grep -oE '\.[A-Za-z0-9]+' 2>/dev/null | grep -Ev '\.phps?$' 2>/dev/null)"
    if [ -n "$EXT" ]; then
        warn "httpd.conf appears to associate PHP handling with nonstandard extension(s): $EXT"
        for e in $EXT; do
            find /var/netscaler -type f -name "*$e" -exec ls -al {} \; 2>/dev/null
        done
    fi

    HTTPD_DENY="$(grep -E -n -C 1 '#[[:space:]]+Require all denied' /etc/httpd.conf 2>/dev/null)"
    if [ -n "$HTTPD_DENY" ]; then
        warn "Commented 'Require all denied' directive found in httpd.conf:"
        echo "$HTTPD_DENY"
    fi

    HTTPD_PHP="$(grep -E -n -C 1 '#[[:space:]]+php_flag engine off' /etc/httpd.conf 2>/dev/null)"
    if [ -n "$HTTPD_PHP" ]; then
        warn "Commented 'php_flag engine off' directive found in httpd.conf:"
        echo "$HTTPD_PHP"
    fi
fi

section "8. SHELL-HISTORY / POST-EXPLOITATION COMMAND HUNT"

for h in /root/.history /root/.bash_history /var/log/bash.log; do
    if [ -f "$h" ]; then
        HITS="$(grep -E -n '/var/vpn/themes|/netscaler/logon|/var/tmp/(bash|sh|the|npc)|chmod[[:space:]]+4[0-9][0-9][0-9]|openssl[[:space:]]+base64|base64[[:space:]]+-d|curl[[:space:]]|wget[[:space:]]|nohup[[:space:]]' "$h" 2>/dev/null)"
        if [ -n "$HITS" ]; then
            warn "Potential post-exploitation commands in $h:"
            echo "$HITS"
        fi
    fi
done

section "9. NSPPE CORE DUMPS"

if [ -d /var/core ]; then
    CORES="$(find /var/core/ -iname 'NSPPE*' -exec ls -al {} \; 2>/dev/null)"
    if [ -n "$CORES" ]; then
        echo "[LOW] NSPPE core dumps exist. These are not proof of compromise, but preserve them:"
        echo "$CORES"
    else
        info "No NSPPE core dumps found."
    fi
fi

section "10. KNOWN-WEBSHELL HTTP ACCESS HUNT"

for log in /var/log/httpaccess.log /var/log/httpaccess.log.*; do
    if [ -f "$log" ]; then
        ACCESS_HITS="$(grep -E -i '(/var/vpn/themes/)?(info|prod|log|logout|vpn|config)\.php|/themes/imgs/(netscaler\.php|ctxHeaderLogon\.php|netscaler\.1)|/LogonPoint/uiareas/ui_style\.php|/sanpdebug\.php' "$log" 2>/dev/null)"
        if [ -n "$ACCESS_HITS" ]; then
            high "HTTP access log contains requests matching documented NetScaler webshell paths in $log:"
            echo "$ACCESS_HITS"
        fi
    fi
done

section "SUMMARY"

echo "High-confidence findings : $HIGH"
echo "Suspicious/hunt findings : $WARN"
echo "Informational findings   : $INFO"
echo

if [ "$HIGH" -gt 0 ]; then
    echo "RESULT: HIGH-CONFIDENCE COMPROMISE INDICATOR(S) FOUND"
    echo
    echo "Recommended response:"
    echo "  1. Preserve evidence if feasible (VPX snapshot / support bundle / relevant logs)."
    echo "  2. Isolate the appliance from the network."
    echo "  3. Rebuild/reimage from known-good media/configuration."
    echo "  4. Rotate credentials, secrets, certificates, and private keys exposed to the appliance."
    echo "  5. Investigate systems the appliance could reach."
    exit 2
fi

if [ "$WARN" -gt 0 ]; then
    echo "RESULT: SUSPICIOUS ARTIFACT(S) FOUND -- INVESTIGATE IMMEDIATELY"
    echo "These checks found hunt signals but not one of the high-confidence indicators above."
    exit 1
fi

echo "RESULT: NO INDICATORS FOUND BY THIS SCRIPT"
echo "This does NOT prove the appliance is clean; memory-only compromise, deleted artifacts,"
echo "log tampering, or unknown tradecraft can evade live-host checks."
exit 0
