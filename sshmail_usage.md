# SSHMail Usage Guide

## Setup User Mailboxes

After installing SSHMail, users must be added to the `smail` group to receive mail:

```sh
# Add user to smail group (run as root)
sudo usermod -a -G smail nathanael

# Create mailbox for the user
sudo mkdir -p /var/sshmail/mailboxes/nathanael && \
sudo chown smail:smail /var/sshmail/mailboxes/nathanael && \
sudo chmod 0770 /var/sshmail/mailboxes/nathanael
```

Replace `nathanael` with the actual username. Users must log out and back in for group membership to take effect.

---

## Sending Messages (smail / sshmail-send)

```sh
# Simple send
echo "Hello world" | smail user@alpha-s1.xyz

# Send from file
smail user@alpha-s1.xyz < message.txt

# Verbose with custom from address
smail -v -f me@mydomain.com user@alpha-s1.xyz < message.txt

# Custom signing key
smail -i ~/.ssh/my_ed25519_key user@alpha-s1.xyz < message.txt

# Manual server override (testing/private networks)
smail -H 192.168.1.10:5522 -u smail user@alpha-s1.xyz < message.txt

# Full options
smail -v -i ~/.ssh/id_ed25519 -f sender@example.com -H mail.example.com:5522 -u smail recipient@example.com < message.txt
```

### Send Options
| Option | Description |
|--------|-------------|
| `-i KEYFILE` | Path to signing key (default: ~/.ssh/id_ed25519) |
| `-f FROM` | Sender address (default: $USER@$(hostname -f)) |
| `-H HOST:PORT` | Override server (bypass SRV lookup) |
| `-u USER` | Override SSH user (bypass transport lookup) |
| `-v` | Verbose output |
| `-h` | Show help |

---

## Maintenance (smail-clean / sshmail-clean)

```sh
# Dry-run to see what would be deleted
sshmail-clean -n -v

# Delete mail older than 7 days for specific user
sshmail-clean -d 7 -u alice

# Archive old mail instead of deleting
sshmail-clean -d 30 -a /backup/mail

# Rotate log and clean temp files
sshmail-clean -l -t

# Install daily cron job (runs at 3am)
sshmail-clean -c

# Force without confirmation
sshmail-clean -d 30 -f
```

### Clean Options
| Option | Description |
|--------|-------------|
| `-d DAYS` | Delete mail older than N days (default: 30) |
| `-u USER` | Clean only specific user's mailbox |
| `-a DIR` | Archive old mail to DIR instead of deleting |
| `-l` | Rotate/truncate sshmail.log |
| `-t` | Clean orphan temp files owned by smail |
| `-c` | Install daily cron job |
| `-n` | Dry-run mode |
| `-f` | Force (skip confirmation) |
| `-v` | Verbose output |

### Per-User Retention
Create `/var/sshmail/.retention`:
```
alice=90
bob=7
```

---

## Uninstall (sshmail_uninstall.sh)

```sh
# Full uninstall (removes everything)
sudo ./sshmail_uninstall.sh

# Keep mail data and logs
sudo ./sshmail_uninstall.sh -k

# Keep smail user account
sudo ./sshmail_uninstall.sh -u

# Keep both data and user
sudo ./sshmail_uninstall.sh -k -u

# Dry-run to preview
sudo ./sshmail_uninstall.sh -n -v
```

### Uninstall Options
| Option | Description |
|--------|-------------|
| `-k` | Keep mail data (/var/sshmail) and logs |
| `-u` | Keep the smail user account |
| `-n` | Dry-run mode |
| `-v` | Verbose output |

---

## DNS Records Required

```
; SRV record for server discovery
_sshmail._tcp.example.com. 300 IN SRV 10 0 5522 mail.example.com.

; Transport user record
_sshmail._transport.example.com. 300 IN TXT "user=smail"

; Public key for signature verification (optional)
_sshmail._ed25519.example.com. 300 IN TXT "pub=AAAA...base64..."
```