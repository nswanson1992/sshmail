#!/bin/sh
# One-time migration script to fix existing SSHMail installations
# Run as root

set -e

echo "SSHMail Migration Script"
echo "========================"
echo ""
echo "This script will:"
echo "  1. Fix permissions on /var/sshmail/mailboxes"
echo "  2. Add specified users to smail group"
echo "  3. Fix ownership of existing mail"
echo ""

# Fix base directories
echo "Fixing base directory permissions..."
chown root:root /var/sshmail
chmod 0755 /var/sshmail
chown root:root /var/sshmail/mailboxes
chmod 0755 /var/sshmail/mailboxes

# Fix log
if [ -f /var/log/sshmail.log ]; then
    echo "Fixing log file ownership..."
    chown smail:smail /var/log/sshmail.log
    chmod 0640 /var/log/sshmail.log
fi

# Process each existing mailbox
if [ -d /var/sshmail/mailboxes ]; then
    for mailbox in /var/sshmail/mailboxes/*; do
        [ -d "$mailbox" ] || continue
        user=$(basename "$mailbox")
        
        echo "Processing mailbox for user: $user"
        
        # Verify user exists
        if ! id "$user" >/dev/null 2>&1; then
            echo "  WARNING: User $user does not exist, skipping"
            continue
        fi
        
        # Add user to smail group
        if ! groups "$user" | grep -q '\bsmail\b'; then
            echo "  Adding $user to smail group..."
            usermod -a -G smail "$user"
        else
            echo "  User $user already in smail group"
        fi
        
        # Fix mailbox ownership and permissions
        echo "  Fixing mailbox ownership..."
        chown smail:smail "$mailbox"
        chmod 0770 "$mailbox"
        
        # Fix mail file ownership and permissions
        if ls "$mailbox"/*.mail >/dev/null 2>&1; then
            echo "  Fixing mail file permissions..."
            chown smail:smail "$mailbox"/*.mail 2>/dev/null || true
            chmod 0660 "$mailbox"/*.mail 2>/dev/null || true
        fi
    done
fi

echo ""
echo "Migration complete!"
echo ""
echo "IMPORTANT: Users must log out and log back in for group membership to take effect."
echo ""
