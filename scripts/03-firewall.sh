#!/usr/bin/env bash
# CIS Ubuntu 24.04 hardening - part 3: host firewall (ufw), default deny incoming.
# Opens only what this Wazuh lab needs. Rules are added BEFORE the firewall is enabled.
set -uo pipefail
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }

DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ufw >/dev/null
ufw allow in on lo
ufw deny in from 127.0.0.0/8
ufw deny in from ::1
ufw allow 22/tcp     comment 'SSH'
ufw allow 443/tcp    comment 'Wazuh dashboard'
ufw allow 1514/tcp   comment 'Wazuh agent events'
ufw allow 1515/tcp   comment 'Wazuh agent enrollment'
ufw allow 55000/tcp  comment 'Wazuh API'
ufw default deny incoming
ufw default allow outgoing
ufw --force enable
ufw status verbose
echo "===== FIREWALL ON ====="
