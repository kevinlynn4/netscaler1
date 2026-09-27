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

VERSION="0.5.0"
HIGH=0
WARN=0
INFO=0
SUSPICIOUS_FILES=""

# Identify this script so our own execution is not reported as suspicious.
SELF_PID="$$"
SELF_ARG="$0"
SELF_NAME="$(basename "$0" 2>/dev/null)"
[ -n "$SELF_NAME" ] || SELF_NAME="netscaler_compromise_triage.sh"

add_suspicious_file()
{
    p="$1"
    [ -n "$p" ] || return

    # Never report this triage script itself as a suspicious artifact.
    case "$p" in
        "$SELF_ARG"|*/"$SELF_NAME")
            return
            ;;
    esac

    case "
$SUSPICIOUS_FILES
" in
        *"
$p
"*) ;;
        *)
            if [ -n "$SUSPICIOUS_FILES" ]; then
                SUSPICIOUS_FILES="$SUSPICIOUS_FILES
$p"
            else
                SUSPICIOUS_FILES="$p"
            fi
            ;;
    esac
}

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
        add_suspicious_file "$p"
        show_file "$p"
    fi
}

check_known_dir()
{
    p="$1"
    why="$2"
    if [ -d "$p" ]; then
        high "$why: $p"
        add_suspicious_file "$p"
        ls -ald "$p" 2>/dev/null
    fi
}

echo "NetScaler compromise triage v$VERSION"
echo "Host: $(hostname 2>/dev/null)"
echo "Date: $(date 2>/dev/null)"
echo "Kernel: $(uname -a 2>/dev/null)"
echo
echo "This tool performs local IOC and post-exploitation checks only."
echo "Self exclusion: $SELF_NAME (PID $SELF_PID)"

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
        add_suspicious_file "$p"
        show_file "$p"
    fi
done

SUID_PATHS="$(find /var \( -perm -4001 -or \( -perm -4010 -group nobody \) \) -user root -print 2>/dev/null)"
if [ -n "$SUID_PATHS" ]; then
    warn "Root-owned SUID files found under /var; review for unexpected additions:"
    echo "$SUID_PATHS" | while IFS= read p; do
        [ -n "$p" ] && ls -al "$p" 2>/dev/null
    done
    OLDIFS="$IFS"
    IFS='
'
    for p in $SUID_PATHS; do
        [ -n "$p" ] && add_suspicious_file "$p"
    done
    IFS="$OLDIFS"
else
    info "No root-owned SUID files found under /var by the NCSC-style check."
fi

section "3. WEBROOT / WEBSHELL HUNT"

# NCSC-NL uses PHP/XHTML files outside the normal admin_ui tree as live-host
# compromise hunting signals.
PHP_PATHS="$(find /var/netscaler/ -type f -name '*.php' -not -path '/var/netscaler/gui/admin_ui/*' -print 2>/dev/null)"
if [ -n "$PHP_PATHS" ]; then
    warn "PHP files exist under /var/netscaler outside gui/admin_ui:"
    OLDIFS="$IFS"
    IFS='
'
    for p in $PHP_PATHS; do
        [ -n "$p" ] || continue
        add_suspicious_file "$p"
        ls -al "$p" 2>/dev/null
    done
    IFS="$OLDIFS"
else
    info "No unexpected PHP files found under /var/netscaler by this check."
fi

XHTML_PATHS="$(find /var/netscaler/ -type f -name '*.xhtml' -not -path '/var/netscaler/gui/admin_ui/*' -print 2>/dev/null)"
if [ -n "$XHTML_PATHS" ]; then
    warn "XHTML files exist under /var/netscaler outside gui/admin_ui:"
    OLDIFS="$IFS"
    IFS='
'
    for p in $XHTML_PATHS; do
        [ -n "$p" ] || continue
        add_suspicious_file "$p"
        ls -al "$p" 2>/dev/null
    done
    IFS="$OLDIFS"
else
    info "No unexpected XHTML files found under /var/netscaler by this check."
fi

# Hunt for script-like files recently changed in common public/staging paths.
for d in /var/vpn/themes /netscaler/logon /netscaler/portal/scripts /netscaler/portal/templates; do
    if [ -d "$d" ]; then
        RECENT="$(find "$d" -type f -mtime -14 \( -name '*.php' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' -o -name '*.xhtml' \) -print 2>/dev/null)"
        if [ -n "$RECENT" ]; then
            warn "Script-like files modified within 14 days under $d:"
            OLDIFS="$IFS"
            IFS='
'
            for p in $RECENT; do
                [ -n "$p" ] || continue
                add_suspicious_file "$p"
                ls -al "$p" 2>/dev/null
            done
            IFS="$OLDIFS"
        fi
    fi
done

section "4. KNOWN / HIGH-SIGNAL WEBSHELL CONTENT"

# Search only likely web-exposed locations and skip the normal NetScaler admin UI.
# Patterns are intentionally high-signal and derived from observed NetScaler
# post-exploitation tradecraft.
for d in /var/vpn/themes /netscaler/logon /netscaler/portal/scripts /netscaler/portal/templates /var/netscaler; do
    if [ -d "$d" ]; then
        CANDIDATES="$(find "$d" -type f \
            -not -path '/var/netscaler/gui/admin_ui/*' \
            \( -name '*.php' -o -name '*.pl' -o -name '*.xhtml' -o -name '*.js' -o -name '*.txt' \) \
            -print 2>/dev/null)"
        OLDIFS="$IFS"
        IFS='
'
        for f in $CANDIDATES; do
            [ -n "$f" ] || continue
            if grep -E -q 'blv_encode|openssl_public_decrypt|[$]_REQUEST[[:space:]]*\[[[:space:]]*["'\'']123["'\'']|@eval[[:space:]]*\(' "$f" 2>/dev/null; then
                high "Suspicious webshell content: $f"
                add_suspicious_file "$f"
                ls -al "$f" 2>/dev/null
            fi
        done
        IFS="$OLDIFS"
    fi
done

section "5. PERSISTENCE CHECKS"

if [ -f /flash/nsconfig/rc.netscaler ]; then
    RC_HITS="$(grep -E -n 'python|perl|curl|wget|nohup|/var/tmp/|/tmp/|/var/nstmp/|nc[[:space:]]|netcat' /flash/nsconfig/rc.netscaler 2>/dev/null)"
    if [ -n "$RC_HITS" ]; then
        warn "Review commands in /flash/nsconfig/rc.netscaler:"
        add_suspicious_file "/flash/nsconfig/rc.netscaler"
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
            add_suspicious_file "/var/cron/tabs/nobody"
            echo "$NOBODY_CRON"
        fi
    fi

    CRON_HITS="$(grep -E -n '/var/tmp/|/tmp/|/var/nstmp/|curl|wget|python|perl|php|nohup|[[:space:]]nc[[:space:]]|netcat' /var/cron/tabs/* 2>/dev/null)"
    if [ -n "$CRON_HITS" ]; then
        warn "Crontab entries reference temporary paths, interpreters, or download/network tools:"
        for cf in /var/cron/tabs/*; do
            [ -f "$cf" ] || continue
            if grep -E -q '/var/tmp/|/tmp/|/var/nstmp/|curl|wget|python|perl|php|nohup|[[:space:]]nc[[:space:]]|netcat' "$cf" 2>/dev/null; then
                add_suspicious_file "$cf"
            fi
        done
        echo "$CRON_HITS"
    fi
fi

section "6. RUNNING PROCESS HUNT"

PS_OUT="$(ps auxww 2>/dev/null)"
if [ -n "$PS_OUT" ]; then
    # Exclude this triage script itself. It is commonly executed from /var/tmp,
    # which would otherwise make the generic temp-directory process hunt flag
    # its own /bin/sh command line.
    FILTERED_PS="$(echo "$PS_OUT" | grep -v "$SELF_NAME" 2>/dev/null)"

    PROC_HIGH="$(echo "$FILTERED_PS" | grep -E '/var/nstmp/\.nscache/httpd|/var/tmp/(the|npc|bash|sh)([[:space:]]|$)' | grep -v grep)"
    if [ -n "$PROC_HIGH" ]; then
        high "Known/high-signal suspicious process path is running:"
        echo "$PROC_HIGH"
    fi

    PROC_WARN="$(echo "$FILTERED_PS" | grep -E '(^|[[:space:]])/var/tmp/|(^|[[:space:]])/tmp/' | grep -v grep)"
    if [ -n "$PROC_WARN" ]; then
        warn "Processes executing from temporary directories:"
        echo "$PROC_WARN"
    else
        info "No unrelated processes executing from /tmp or /var/tmp were found."
    fi
else
    warn "Unable to collect process list with ps auxww."
fi

section "7. HTTPD CONFIGURATION TAMPERING CHECKS"

if [ -f /etc/httpd.conf ]; then
    EXT="$(grep 'httpd-php' /etc/httpd.conf 2>/dev/null | grep -oE '\.[A-Za-z0-9]+' 2>/dev/null | grep -Ev '\.phps?$' 2>/dev/null)"
    if [ -n "$EXT" ]; then
        warn "httpd.conf appears to associate PHP handling with nonstandard extension(s): $EXT"
        add_suspicious_file "/etc/httpd.conf"
        for e in $EXT; do
            find /var/netscaler -type f -name "*$e" -exec ls -al {} \; 2>/dev/null
        done
    fi

    HTTPD_DENY="$(grep -E -n -C 1 '#[[:space:]]+Require all denied' /etc/httpd.conf 2>/dev/null)"
    if [ -n "$HTTPD_DENY" ]; then
        warn "Commented 'Require all denied' directive found in httpd.conf:"
        add_suspicious_file "/etc/httpd.conf"
        echo "$HTTPD_DENY"
    fi

    HTTPD_PHP="$(grep -E -n -C 1 '#[[:space:]]+php_flag engine off' /etc/httpd.conf 2>/dev/null)"
    if [ -n "$HTTPD_PHP" ]; then
        warn "Commented 'php_flag engine off' directive found in httpd.conf:"
        add_suspicious_file "/etc/httpd.conf"
        echo "$HTTPD_PHP"
    fi
fi

section "8. SHELL-HISTORY / POST-EXPLOITATION COMMAND HUNT"

# History is treated as a weak hunting source. Ordinary administrative commands
# such as "curl ... -o /var/tmp/..." are NOT suspicious by themselves, because
# that is also a normal way to retrieve and run this triage script.
#
# Flag only stronger combinations tied to webroot modification, privilege
# backdoors, documented malicious paths, or persistence.
for h in /root/.history /root/.bash_history /var/log/bash.log; do
    if [ -f "$h" ]; then
        HITS="$(grep -E -n \
'/var/vpn/themes/(info|prod|log|logout|vpn|config)\.php|/var/vpn/themes/imgs/(netscaler\.php|ctxHeaderLogon\.php|netscaler\.1)|/netscaler/logon/LogonPoint/uiareas/ui_style\.php|/netscaler/logon/sanpdebug\.php|/var/nstmp/\.nscache/httpd|/var/tmp/(the|npc)([[:space:]]|$)|chmod[[:space:]]+4[0-9][0-9][0-9][[:space:]]+(/var/tmp/|/tmp/)|/var/cron/tabs/nobody|rc\.netscaler.*(/var/tmp/|/tmp/|/var/nstmp/)' \
"$h" 2>/dev/null | grep -v "$SELF_NAME" 2>/dev/null)"

        if [ -n "$HITS" ]; then
            warn "Potential post-exploitation commands in $h:"
            add_suspicious_file "$h"
            echo "$HITS"
        fi
    fi
done

section "9. NSPPE CORE DUMPS"

if [ -d /var/core ]; then
    CORES="$(find /var/core/ -iname 'NSPPE*' -print 2>/dev/null)"
    if [ -n "$CORES" ]; then
        echo "[LOW] NSPPE core dumps exist. These are not proof of compromise, but preserve them:"
        OLDIFS="$IFS"
        IFS='
'
        for p in $CORES; do
            [ -n "$p" ] || continue
            add_suspicious_file "$p"
            ls -al "$p" 2>/dev/null
        done
        IFS="$OLDIFS"
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
            add_suspicious_file "$log"
            echo "$ACCESS_HITS"
        fi
    fi
done

section "SUMMARY"

echo "High-confidence findings : $HIGH"
echo "Suspicious/hunt findings : $WARN"
echo "Informational findings   : $INFO"
echo

echo "SUSPICIOUS FILES / ARTIFACT PATHS"
echo "----------------------------------------------------------------------"
if [ -n "$SUSPICIOUS_FILES" ]; then
    OLDIFS="$IFS"
    IFS='
'
    for p in $SUSPICIOUS_FILES; do
        [ -n "$p" ] || continue
        case "$p" in
            "$SELF_ARG"|*/"$SELF_NAME")
                continue
                ;;
        esac
        echo "$p"
    done
    IFS="$OLDIFS"
else
    echo "(none identified by file-based checks)"
fi
echo "----------------------------------------------------------------------"
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
