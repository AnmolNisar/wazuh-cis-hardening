#!/usr/bin/env bash
# CIS Ubuntu 24.04 hardening - part 2: SSH server.
# Keeps password login ON so you are not locked out. Test a NEW SSH session before closing the old one.
# Run: sudo bash 02-harden-ssh.sh <your-username>
set -uo pipefail
U="${1:-anmol}"
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }

cat > /etc/ssh/sshd_config.d/01-cis-hardening.conf <<X
Banner /etc/issue.net
PermitRootLogin no
MaxAuthTries 4
MaxStartups 10:30:60
LoginGraceTime 60
ClientAliveInterval 15
ClientAliveCountMax 3
DisableForwarding yes
AllowUsers $U
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256
X
chown root:root /etc/ssh/sshd_config /etc/ssh/sshd_config.d/01-cis-hardening.conf
chmod 600 /etc/ssh/sshd_config /etc/ssh/sshd_config.d/01-cis-hardening.conf

if sshd -t; then
  systemctl reload ssh 2>/dev/null || systemctl restart ssh
  echo "===== SSH HARDENED - open a NEW PowerShell tab and test login now ====="
else
  rm -f /etc/ssh/sshd_config.d/01-cis-hardening.conf
  echo "Config test failed - change reverted, nothing applied."
fi
