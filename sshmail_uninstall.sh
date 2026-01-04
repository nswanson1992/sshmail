#!/bin/sh
set -e
PATH=/usr/sbin:/usr/bin:/bin

###############################################################################
# SSHMail Uninstall Script
# Removes all SSHMail components from the system
###############################################################################

usage() {
    cat <<USAGE
Usage: $(basename "$0") [OPTIONS]

Completely remove SSHMail from the system.

Options:
  -k            Keep mail data (/var/sshmail) and logs
  -u            Keep the smail user account
  -n            Dry-run mode (show what would be done)
  -v            Verbose output
  -h            Show this help

By default, this removes:
  - systemd service (sshd-sshmail)
  - sshd config (/etc/ssh/sshd_config_sshmail)
  - scripts (sshmail-keys, sshmail-receive, sshmail-send, sshmail-clean)
  - symlinks (smail, smail-clean)
  - smail user account
  - mail data (/var/sshmail)
  - log file (/var/log/sshmail.log)
  - cron jobs for sshmail-clean

Examples:
  $(basename "$0")              # Full uninstall
  $(basename "$0") -k           # Keep mail data
  $(basename "$0") -k -u        # Keep data and user
  $(basename "$0") -n -v        # Dry-run, verbose
USAGE
    exit 1
}

# Defaults
KEEP_DATA=0
KEEP_USER=0
DRY_RUN=0
VERBOSE=0

# Parse options
while getopts "kunvh" opt; do
    case $opt in
        k) KEEP_DATA=1 ;;
        u) KEEP_USER=1 ;;
        n) DRY_RUN=1 ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done

log() {
    [ "$VERBOSE" = "1" ] && echo "$@"
}

run() {
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY-RUN] $*"
    else
        "$@"
    fi
}

# Check for root
if [ "$(id -u)" != "0" ] && [ "$DRY_RUN" != "1" ]; then
    echo "ERROR: This script must be run as root" >&2
    exit 1
fi

echo "SSHMail Uninstall"
echo "================="
[ "$DRY_RUN" = "1" ] && echo "(Dry-run mode - no changes will be made)"
echo

###############################################################################
# Stop and disable systemd service
###############################################################################

if systemctl is-active --quiet sshd-sshmail 2>/dev/null; then
    echo "Stopping sshd-sshmail service..."
    run systemctl stop sshd-sshmail
fi

if systemctl is-enabled --quiet sshd-sshmail 2>/dev/null; then
    echo "Disabling sshd-sshmail service..."
    run systemctl disable sshd-sshmail
fi

if [ -f /etc/systemd/system/sshd-sshmail.service ]; then
    echo "Removing systemd unit file..."
    run rm -f /etc/systemd/system/sshd-sshmail.service
    run systemctl daemon-reload
    log "Removed: /etc/systemd/system/sshd-sshmail.service"
fi

###############################################################################
# Remove sshd configuration
###############################################################################

if [ -f /etc/ssh/sshd_config_sshmail ]; then
    echo "Removing sshd config..."
    run rm -f /etc/ssh/sshd_config_sshmail
    log "Removed: /etc/ssh/sshd_config_sshmail"
fi

###############################################################################
# Remove sudoers rule
###############################################################################

if [ -f /etc/sudoers.d/sshmail ]; then
    echo "Removing sudoers rule..."
    run rm -f /etc/sudoers.d/sshmail
    log "Removed: /etc/sudoers.d/sshmail"
fi

###############################################################################
# Remove scripts and symlinks
###############################################################################

echo "Removing scripts..."

for script in sshmail-keys sshmail-receive sshmail-send sshmail-send-worker sshmail-clean; do
    if [ -f "/usr/local/bin/$script" ]; then
        run rm -f "/usr/local/bin/$script"
        log "Removed: /usr/local/bin/$script"
    fi
done

for link in smail smail-clean; do
    if [ -L "/usr/local/bin/$link" ]; then
        run rm -f "/usr/local/bin/$link"
        log "Removed symlink: /usr/local/bin/$link"
    fi
done

###############################################################################
# Remove cron jobs
###############################################################################

if crontab -l 2>/dev/null | grep -q 'sshmail-clean'; then
    echo "Removing cron jobs..."
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY-RUN] Would remove sshmail-clean from crontab"
    else
        crontab -l 2>/dev/null | grep -v 'sshmail-clean' | crontab - || true
        log "Removed sshmail-clean from crontab"
    fi
fi

###############################################################################
# Remove user account
###############################################################################

if [ "$KEEP_USER" = "0" ]; then
    if id smail >/dev/null 2>&1; then
        echo "Removing smail user..."
        run userdel smail 2>/dev/null || true
        log "Removed user: smail"
    fi
else
    log "Keeping smail user (as requested)"
fi

###############################################################################
# Remove data and logs
###############################################################################

if [ "$KEEP_DATA" = "0" ]; then
    # Remove domain keypair
    if [ -d /var/sshmail/.ssh ]; then
        echo "Removing domain keypair..."
        run rm -rf /var/sshmail/.ssh
        log "Removed: /var/sshmail/.ssh"
    fi

    if [ -d /var/sshmail ]; then
        echo "Removing mail data..."
        run rm -rf /var/sshmail
        log "Removed: /var/sshmail"
    fi
    
    if [ -f /var/log/sshmail.log ]; then
        echo "Removing log file..."
        run rm -f /var/log/sshmail.log
        log "Removed: /var/log/sshmail.log"
    fi
    
    # Remove rotated logs
    for logfile in /var/log/sshmail.log.*; do
        if [ -f "$logfile" ]; then
            run rm -f "$logfile"
            log "Removed: $logfile"
        fi
    done
else
    log "Keeping mail data and logs (as requested)"
fi

###############################################################################
# Summary
###############################################################################

echo
if [ "$DRY_RUN" = "1" ]; then
    echo "Dry-run complete. No changes were made."
else
    echo "SSHMail has been uninstalled."
    [ "$KEEP_DATA" = "1" ] && echo "  - Mail data preserved in /var/sshmail"
    [ "$KEEP_USER" = "1" ] && echo "  - User 'smail' preserved"
fi
