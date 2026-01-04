#!/bin/sh
set -e
PATH=/usr/sbin:/usr/bin:/bin

# --- variables ---
SSHMAIL_PORT=5522
SSHMAIL_USER=smail
MAILROOT=/var/sshmail/mailboxes

###############################################################################
# User setup (unlocked, password-disabled, no shell)
###############################################################################

id smail >/dev/null 2>&1 || /usr/sbin/useradd -r -s /bin/false smail
/usr/sbin/usermod -s /bin/false -p '*' smail

###############################################################################
# Mail storage
###############################################################################

/bin/mkdir -p "$MAILROOT"
/bin/chown root:root /var/sshmail
/bin/chmod 0755 /var/sshmail
/bin/chown root:root "$MAILROOT"
/bin/chmod 0755 "$MAILROOT"

# Create log file
/bin/touch /var/log/sshmail.log
/bin/chown smail:smail /var/log/sshmail.log
/bin/chmod 0640 /var/log/sshmail.log

###############################################################################
# Domain keypair for signing outbound mail
###############################################################################

/bin/mkdir -p /var/sshmail/.ssh
/bin/chmod 700 /var/sshmail/.ssh
/bin/chown smail:smail /var/sshmail/.ssh

if [ ! -f /var/sshmail/.ssh/id_ed25519 ]; then
    /usr/bin/ssh-keygen -t ed25519 -f /var/sshmail/.ssh/id_ed25519 -N "" -C "smail@$(hostname -f)"
fi
/bin/chown smail:smail /var/sshmail/.ssh/id_ed25519 /var/sshmail/.ssh/id_ed25519.pub
/bin/chmod 600 /var/sshmail/.ssh/id_ed25519
/bin/chmod 644 /var/sshmail/.ssh/id_ed25519.pub

###############################################################################
# AuthorizedKeysCommand
###############################################################################

/bin/cat >/usr/local/bin/sshmail-keys <<'EOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/bin

# $1 = username
# $2 = fingerprint
# $3 = key type
# $4 = base64 public key

[ "$1" = "smail" ] || exit 1

# IMPORTANT: must output a plain authorized_keys line
echo "$3 $4"
EOF

/bin/chown root:root /usr/local/bin/sshmail-keys
/bin/chmod 0755 /usr/local/bin/sshmail-keys

###############################################################################
# Receive script
###############################################################################

/bin/cat >/usr/local/bin/sshmail-receive <<'EOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/bin
set -e

MAILROOT=/var/sshmail/mailboxes
LOG=/var/log/sshmail.log

exec >>"$LOG" 2>&1

TMP=$(/usr/bin/mktemp)
TMP_SIG=$(/usr/bin/mktemp)
TMP_BODY=$(/usr/bin/mktemp)
TMP_ALLOWED=$(/usr/bin/mktemp)
trap 'rm -f "$TMP" "$TMP_SIG" "$TMP_BODY" "$TMP_ALLOWED"' EXIT

/bin/cat >"$TMP"

FROM=$(/bin/sed -n 's/^From:[[:space:]]*//p' "$TMP" | /usr/bin/head -n1)
TO=$(/bin/sed -n 's/^To:[[:space:]]*//p' "$TMP" | /usr/bin/head -n1)
SIGNATURE=$(/bin/sed -n 's/^X-SSHMail-Sig:[[:space:]]*//p' "$TMP" | /usr/bin/head -n1)

[ -n "$TO" ] || { echo "ERROR: No To: header"; exit 1; }

TO_USER=$(echo "$TO" | /usr/bin/cut -d@ -f1)
FROM_DOMAIN=$(echo "$FROM" | /usr/bin/cut -d@ -f2)

# Validate recipient user exists on system
if ! /usr/bin/id "$TO_USER" >/dev/null 2>&1; then
    echo "ERROR: Rejecting mail for non-existent user: $TO_USER"
    exit 1
fi

# Verify signature if From domain is present
if [ -n "$FROM_DOMAIN" ] && [ -n "$SIGNATURE" ]; then
    # Fetch public key from DNS
    DNS_RECORD=$(/usr/bin/dig +short TXT _sshmail._ed25519."$FROM_DOMAIN" | /bin/tr -d '"')
    DNS_KEY=$(echo "$DNS_RECORD" | /bin/sed -n 's/.*pub=//p')

    if [ -n "$DNS_KEY" ]; then
        # Build allowed signers file
        echo "$FROM ssh-ed25519 $DNS_KEY" > "$TMP_ALLOWED"

        # Extract signature (base64 decode)
        echo "$SIGNATURE" | /usr/bin/base64 -d > "$TMP_SIG" 2>/dev/null || true

        # Extract body (everything after blank line, excluding signature header)
        /bin/sed '1,/^$/d' "$TMP" | /bin/grep -v '^X-SSHMail-Sig:' > "$TMP_BODY"

        # Verify signature
        if ! /usr/bin/ssh-keygen -Y verify -f "$TMP_ALLOWED" -I "$FROM" -n sshmail -s "$TMP_SIG" < "$TMP_BODY" 2>/dev/null; then
            echo "ERROR: Signature verification failed for $FROM"
            exit 1
        fi
        echo "INFO: Signature verified for $FROM"
    else
        echo "WARN: No DNS key found for $FROM_DOMAIN, accepting unsigned"
    fi
elif [ -n "$FROM_DOMAIN" ] && [ -z "$SIGNATURE" ]; then
    # Check if domain requires signatures
    DNS_RECORD=$(/usr/bin/dig +short TXT _sshmail._ed25519."$FROM_DOMAIN" | /bin/tr -d '"')
    if [ -n "$DNS_RECORD" ]; then
        echo "WARN: Domain $FROM_DOMAIN has key but message unsigned"
    fi
fi

# Create mailbox directory (owned by smail, group smail, users in group can access)
DEST="$MAILROOT/$TO_USER"
if [ ! -d "$DEST" ]; then
    /bin/mkdir -p "$DEST"
    /bin/chown smail:smail "$DEST"
    /bin/chmod 0770 "$DEST"
fi

# Deliver message (owned by smail, group can read)
MAILFILE="$DEST/$(/bin/date +%s)_$$.mail"
/bin/mv "$TMP" "$MAILFILE"
/bin/chown smail:smail "$MAILFILE"
/bin/chmod 0660 "$MAILFILE"

echo "INFO: Delivered to $TO_USER from $FROM"
EOF

/bin/chown root:root /usr/local/bin/sshmail-receive
/bin/chmod 0755 /usr/local/bin/sshmail-receive

###############################################################################
# Send script (runs as smail via sudo to access domain key)
###############################################################################

# Create the actual send worker script (runs as smail)
/bin/cat >/usr/local/bin/sshmail-send-worker <<'EOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/bin
set -e

usage() {
    cat <<USAGE
Usage: $(basename "$0") [OPTIONS] recipient@domain

Send a message via SSHMail protocol.

Options:
  -i KEYFILE    Path to signing key (default: /var/sshmail/.ssh/id_ed25519)
  -f FROM       Sender address (default: \$SUDO_USER@\$(hostname -f))
  -H HOST:PORT  Override server (bypass SRV lookup)
  -u USER       Override SSH user (bypass transport lookup)
  -v            Verbose output
  -h            Show this help

Examples:
  echo "Hello" | smail user@example.com
  smail -v user@example.com < message.txt
  smail -H 192.168.1.10:5522 -u smail user@example.com < message.txt
USAGE
    exit 1
}

# Defaults
KEYFILE="/var/sshmail/.ssh/id_ed25519"
FROM=""
HOST_OVERRIDE=""
USER_OVERRIDE=""
VERBOSE=0

# Parse options
while getopts "i:f:H:u:vh" opt; do
    case $opt in
        i) KEYFILE="$OPTARG" ;;
        f) FROM="$OPTARG" ;;
        H) HOST_OVERRIDE="$OPTARG" ;;
        u) USER_OVERRIDE="$OPTARG" ;;
        v) VERBOSE=1 ;;
        h) usage ;;
        *) usage ;;
    esac
done
shift $((OPTIND - 1))

[ $# -eq 1 ] || usage
RECIPIENT="$1"
DOMAIN=$(echo "$RECIPIENT" | cut -d@ -f2)

[ -n "$DOMAIN" ] || { echo "ERROR: Invalid recipient format"; exit 1; }

log() {
    [ "$VERBOSE" = "1" ] && echo "$@" >&2
}

# Determine From address (use invoking user, not smail)
if [ -z "$FROM" ]; then
    REAL_USER="${SUDO_USER:-$USER}"
    FROM="$REAL_USER@$(hostname -f)"
fi
log "From: $FROM"

# Discover server via SRV or use override
if [ -n "$HOST_OVERRIDE" ]; then
    HOST=$(echo "$HOST_OVERRIDE" | cut -d: -f1)
    PORT=$(echo "$HOST_OVERRIDE" | cut -d: -f2)
    [ "$HOST" = "$PORT" ] && PORT=5522
    log "Using override: $HOST:$PORT"
else
    log "Looking up SRV record for _sshmail._tcp.$DOMAIN"
    SRV_RECORD=$(dig +short SRV _sshmail._tcp."$DOMAIN" 2>/dev/null | head -n1)
    if [ -z "$SRV_RECORD" ]; then
        echo "ERROR: No SRV record found for _sshmail._tcp.$DOMAIN" >&2
        echo "Use -H host:port to specify server manually" >&2
        exit 1
    fi
    # SRV format: priority weight port target
    PORT=$(echo "$SRV_RECORD" | awk '{print $3}')
    HOST=$(echo "$SRV_RECORD" | awk '{print $4}' | sed 's/\.$//')
    log "SRV resolved: $HOST:$PORT"
fi

# Discover transport user or use override
if [ -n "$USER_OVERRIDE" ]; then
    SSH_USER="$USER_OVERRIDE"
    log "Using user override: $SSH_USER"
else
    log "Looking up transport user for _sshmail._transport.$DOMAIN"
    TRANSPORT=$(dig +short TXT _sshmail._transport."$DOMAIN" 2>/dev/null | tr -d '"')
    SSH_USER=$(echo "$TRANSPORT" | sed -n 's/.*user=\([^ ]*\).*/\1/p')
    if [ -z "$SSH_USER" ]; then
        echo "ERROR: No transport user found in _sshmail._transport.$DOMAIN" >&2
        echo "Use -u user to specify SSH user manually" >&2
        exit 1
    fi
    log "Transport user: $SSH_USER"
fi

# Read message from stdin
TMP_MSG=$(mktemp)
TMP_SIG=$(mktemp)
trap 'rm -f "$TMP_MSG" "$TMP_SIG"' EXIT

cat > "$TMP_MSG"

# Check for existing From/To headers
HAS_FROM=$(sed -n '/^From:/p' "$TMP_MSG" | head -n1)
HAS_TO=$(sed -n '/^To:/p' "$TMP_MSG" | head -n1)

# Build message with headers
{
    [ -z "$HAS_FROM" ] && echo "From: $FROM"
    [ -z "$HAS_TO" ] && echo "To: $RECIPIENT"
    
    # Sign the message body
    if [ -f "$KEYFILE" ]; then
        log "Signing with key: $KEYFILE"
        # Extract body for signing (after headers or whole message if no headers)
        if grep -q '^$' "$TMP_MSG"; then
            BODY=$(sed '1,/^$/d' "$TMP_MSG")
        else
            BODY=$(cat "$TMP_MSG")
        fi
        
        SIG=$(echo "$BODY" | ssh-keygen -Y sign -f "$KEYFILE" -n sshmail -q 2>/dev/null | base64 -w0)
        if [ -n "$SIG" ]; then
            echo "X-SSHMail-Sig: $SIG"
            log "Message signed"
        else
            log "WARN: Signing failed, sending unsigned"
        fi
    else
        log "WARN: No signing key at $KEYFILE, sending unsigned"
    fi
    
    # Output original message
    cat "$TMP_MSG"
} | ssh -p "$PORT" -i "$KEYFILE" -o BatchMode=yes -o StrictHostKeyChecking=accept-new \
    "$SSH_USER@$HOST" 2>/dev/null

log "Message sent to $RECIPIENT via $HOST:$PORT"
EOF

/bin/chown smail:smail /usr/local/bin/sshmail-send-worker
/bin/chmod 0755 /usr/local/bin/sshmail-send-worker

# Create wrapper script that runs worker as smail
/bin/cat >/usr/local/bin/sshmail-send <<'EOF'
#!/bin/sh
exec sudo -u smail /usr/local/bin/sshmail-send-worker "$@"
EOF

/bin/chown root:root /usr/local/bin/sshmail-send
/bin/chmod 0755 /usr/local/bin/sshmail-send

# Create smail alias
/bin/ln -sf /usr/local/bin/sshmail-send /usr/local/bin/smail

###############################################################################
# Sudoers rule for passwordless smail execution
###############################################################################

/bin/cat >/etc/sudoers.d/sshmail <<'EOF'
# Allow all users to run sshmail-send-worker as smail without password
ALL ALL=(smail) NOPASSWD: /usr/local/bin/sshmail-send-worker
EOF

/bin/chmod 0440 /etc/sudoers.d/sshmail

###############################################################################
# Clean script
###############################################################################

/bin/cat >/usr/local/bin/sshmail-clean <<'EOF'
#!/bin/sh
PATH=/usr/sbin:/usr/bin:/bin
set -e

MAILROOT=/var/sshmail/mailboxes
LOG=/var/log/sshmail.log
RETENTION_FILE=/var/sshmail/.retention

usage() {
    cat <<USAGE
Usage: $(basename "$0") [OPTIONS]

Clean old mail, logs, and temp files from SSHMail.

Options:
  -d DAYS       Delete mail older than N days (default: 30)
  -u USER       Clean only specific user's mailbox (default: all)
  -a DIR        Archive old mail to DIR instead of deleting
  -l            Also rotate/truncate sshmail.log
  -t            Clean orphan temp files owned by smail
  -c            Install daily cron job (runs at 3am)
  -n            Dry-run mode (show what would be done)
  -f            Force (skip confirmation prompt)
  -v            Verbose output
  -h            Show this help

Retention Config:
  Create $RETENTION_FILE with per-user retention:
    username=DAYS
  Example:
    alice=90
    bob=7

Examples:
  sshmail-clean -n -v                    # Dry-run, show all
  sshmail-clean -d 7 -u alice -f         # Clean alice's mail >7 days
  sshmail-clean -d 30 -a /backup/mail    # Archive mail >30 days
  sshmail-clean -l -t -f                 # Rotate log, clean temp
  sshmail-clean -c                       # Install cron job
USAGE
    exit 1
}

# Defaults
DAYS=30
USER_FILTER=""
ARCHIVE_DIR=""
ROTATE_LOG=0
CLEAN_TEMP=0
INSTALL_CRON=0
DRY_RUN=0
FORCE=0
VERBOSE=0

# Parse options
while getopts "d:u:a:ltcnfvh" opt; do
    case $opt in
        d) DAYS="$OPTARG" ;;
        u) USER_FILTER="$OPTARG" ;;
        a) ARCHIVE_DIR="$OPTARG" ;;
        l) ROTATE_LOG=1 ;;
        t) CLEAN_TEMP=1 ;;
        c) INSTALL_CRON=1 ;;
        n) DRY_RUN=1 ;;
        f) FORCE=1 ;;
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

# Get retention days for a user (check config file, fallback to default)
get_retention() {
    local user="$1"
    if [ -f "$RETENTION_FILE" ]; then
        local custom=$(grep "^${user}=" "$RETENTION_FILE" 2>/dev/null | cut -d= -f2)
        if [ -n "$custom" ]; then
            echo "$custom"
            return
        fi
    fi
    echo "$DAYS"
}

# Install cron job
if [ "$INSTALL_CRON" = "1" ]; then
    CRON_CMD="0 3 * * * /usr/local/bin/sshmail-clean -d 30 -l -t -f >/dev/null 2>&1"
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY-RUN] Would add to root crontab: $CRON_CMD"
    else
        (crontab -l 2>/dev/null | grep -v 'sshmail-clean'; echo "$CRON_CMD") | crontab -
        echo "Cron job installed: $CRON_CMD"
    fi
    exit 0
fi

# Confirmation prompt
if [ "$FORCE" != "1" ] && [ "$DRY_RUN" != "1" ]; then
    echo "This will clean mail older than $DAYS days from $MAILROOT"
    [ -n "$USER_FILTER" ] && echo "  Filtering to user: $USER_FILTER"
    [ -n "$ARCHIVE_DIR" ] && echo "  Archiving to: $ARCHIVE_DIR"
    [ "$ROTATE_LOG" = "1" ] && echo "  Will rotate: $LOG"
    [ "$CLEAN_TEMP" = "1" ] && echo "  Will clean temp files"
    printf "Continue? [y/N] "
    read -r CONFIRM
    case "$CONFIRM" in
        [yY][eE][sS]|[yY]) ;;
        *) echo "Aborted."; exit 1 ;;
    esac
fi

# Create archive directory if needed
if [ -n "$ARCHIVE_DIR" ] && [ "$DRY_RUN" != "1" ]; then
    mkdir -p "$ARCHIVE_DIR"
fi

# Clean mail
TOTAL_CLEANED=0
TOTAL_SIZE=0

if [ -n "$USER_FILTER" ]; then
    MAILBOXES="$MAILROOT/$USER_FILTER"
else
    MAILBOXES="$MAILROOT"/*
fi

for mailbox in $MAILBOXES; do
    [ -d "$mailbox" ] || continue
    user=$(basename "$mailbox")
    user_days=$(get_retention "$user")
    
    log "Processing mailbox: $user (retention: ${user_days} days)"
    
    # Find old mail files
    old_files=$(find "$mailbox" -type f -name "*.mail" -mtime +"$user_days" 2>/dev/null)
    
    for file in $old_files; do
        [ -f "$file" ] || continue
        size=$(stat -c%s "$file" 2>/dev/null || echo 0)
        TOTAL_SIZE=$((TOTAL_SIZE + size))
        TOTAL_CLEANED=$((TOTAL_CLEANED + 1))
        
        if [ -n "$ARCHIVE_DIR" ]; then
            # Archive: preserve user directory structure
            archive_dest="$ARCHIVE_DIR/$user"
            if [ "$DRY_RUN" = "1" ]; then
                echo "[DRY-RUN] Archive: $file -> $archive_dest/"
            else
                mkdir -p "$archive_dest"
                mv "$file" "$archive_dest/"
                log "Archived: $file"
            fi
        else
            # Delete
            if [ "$DRY_RUN" = "1" ]; then
                echo "[DRY-RUN] Delete: $file"
            else
                rm -f "$file"
                log "Deleted: $file"
            fi
        fi
    done
done

# Report
if [ "$TOTAL_CLEANED" -gt 0 ]; then
    SIZE_KB=$((TOTAL_SIZE / 1024))
    action="deleted"
    [ -n "$ARCHIVE_DIR" ] && action="archived"
    echo "Cleaned $TOTAL_CLEANED messages ($SIZE_KB KB) - $action"
else
    echo "No messages older than $DAYS days found"
fi

# Rotate log
if [ "$ROTATE_LOG" = "1" ] && [ -f "$LOG" ]; then
    log_size=$(stat -c%s "$LOG" 2>/dev/null || echo 0)
    if [ "$DRY_RUN" = "1" ]; then
        echo "[DRY-RUN] Rotate log: $LOG ($((log_size / 1024)) KB)"
    else
        # Keep last 1000 lines, archive rest
        if [ "$log_size" -gt 102400 ]; then  # >100KB
            timestamp=$(date +%Y%m%d_%H%M%S)
            cp "$LOG" "${LOG}.${timestamp}"
            tail -n 1000 "$LOG" > "${LOG}.tmp"
            mv "${LOG}.tmp" "$LOG"
            gzip "${LOG}.${timestamp}" 2>/dev/null || true
            log "Rotated: $LOG (kept last 1000 lines)"
            echo "Log rotated: ${LOG}.${timestamp}.gz"
        else
            log "Log too small to rotate: $log_size bytes"
        fi
    fi
fi

# Clean temp files
if [ "$CLEAN_TEMP" = "1" ]; then
    log "Cleaning orphan temp files owned by smail"
    temp_count=0
    for tmp in /tmp/tmp.*; do
        [ -f "$tmp" ] || continue
        owner=$(stat -c%U "$tmp" 2>/dev/null)
        age_days=$(find "$tmp" -mtime +1 2>/dev/null)
        if [ "$owner" = "smail" ] && [ -n "$age_days" ]; then
            temp_count=$((temp_count + 1))
            if [ "$DRY_RUN" = "1" ]; then
                echo "[DRY-RUN] Delete temp: $tmp"
            else
                rm -f "$tmp"
                log "Deleted temp: $tmp"
            fi
        fi
    done
    echo "Cleaned $temp_count orphan temp files"
fi

log "Clean complete"
EOF

/bin/chown root:root /usr/local/bin/sshmail-clean
/bin/chmod 0755 /usr/local/bin/sshmail-clean

# Create smail-clean alias
/bin/ln -sf /usr/local/bin/sshmail-clean /usr/local/bin/smail-clean

###############################################################################
# sshd configuration (sshmail instance)
###############################################################################

/bin/cat >/etc/ssh/sshd_config_sshmail <<EOF
Port $SSHMAIL_PORT
ListenAddress 0.0.0.0
ListenAddress ::

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
UsePAM no
PermitRootLogin no
PermitEmptyPasswords no

AllowUsers smail

AuthorizedKeysCommand /usr/local/bin/sshmail-keys %u %f %t %k
AuthorizedKeysCommandUser nobody

Match User smail
    ForceCommand /usr/local/bin/sshmail-receive
    PermitTTY no
    AllowAgentForwarding no
    AllowTcpForwarding no
    X11Forwarding no
EOF

/usr/sbin/sshd -t -f /etc/ssh/sshd_config_sshmail

###############################################################################
# systemd service
###############################################################################

/bin/cat >/etc/systemd/system/sshd-sshmail.service <<'EOF'
[Unit]
Description=OpenSSH server for sshmail
After=network.target

[Service]
ExecStart=/usr/sbin/sshd -D -f /etc/ssh/sshd_config_sshmail
Restart=always

[Install]
WantedBy=multi-user.target
EOF

/bin/systemctl daemon-reload
/bin/systemctl enable sshd-sshmail
/bin/systemctl restart sshd-sshmail

###############################################################################
# Print DNS record for domain key
###############################################################################

DOMAIN_PUBKEY=$(/bin/cat /var/sshmail/.ssh/id_ed25519.pub | /usr/bin/awk '{print $2}')
HOSTNAME_FULL=$(/bin/hostname -f)
DOMAIN=$(/bin/hostname -d 2>/dev/null || echo "$HOSTNAME_FULL" | /bin/sed 's/^[^.]*\.//')

echo ""
echo "=============================================================================="
echo "SSHMail installed successfully!"
echo "=============================================================================="
echo ""
echo "ADD THIS DNS TXT RECORD TO YOUR DOMAIN:"
echo ""
echo "  Name:  _sshmail._ed25519.${DOMAIN}"
echo "  Type:  TXT"
echo "  Value: \"v=1; k=ed25519; kid=primary; pub=${DOMAIN_PUBKEY}\""
echo ""
echo "Also ensure you have these records:"
echo ""
echo "  _sshmail._tcp.${DOMAIN}        SRV  10 0 ${SSHMAIL_PORT} ${HOSTNAME_FULL}."
echo "  _sshmail._transport.${DOMAIN}  TXT  \"user=smail\""
echo ""
echo "=============================================================================="
