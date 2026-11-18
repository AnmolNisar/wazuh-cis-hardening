#!/usr/bin/env bash
# CIS Ubuntu 24.04 hardening - part 1: system settings that cannot lock you out.
# Run: sudo bash 01-harden-system.sh <your-username>
set -uo pipefail
U="${1:-anmol}"
[[ $EUID -eq 0 ]] || { echo "Run with sudo"; exit 1; }

echo "[0/12] Backing up /etc to /root/etc-backup-before-cis.tgz"
tar -czf /root/etc-backup-before-cis.tgz /etc 2>/dev/null

echo "[1/12] Packages: add AppArmor utils, pwquality, auditd; remove telnet/ftp clients"
apt-get update -qq
DEBIAN_FRONTEND=noninteractive apt-get install -y -qq apparmor-utils libpam-pwquality auditd audispd-plugins >/dev/null
apt-get purge -y -qq telnet inetutils-telnet ftp tnftp >/dev/null 2>&1 || true
systemctl enable --now auditd >/dev/null 2>&1

echo "[2/12] Disable unused services: rsync, apport (error reporting)"
systemctl disable --now rsync >/dev/null 2>&1 || true; systemctl mask rsync >/dev/null 2>&1 || true
systemctl disable --now apport >/dev/null 2>&1 || true
[[ -f /etc/default/apport ]] && sed -i 's/^enabled=.*/enabled=0/' /etc/default/apport

echo "[3/12] Block unused kernel modules"
for m in dccp tipc rds sctp cramfs freevxfs hfs hfsplus jffs2 udf; do
  printf 'install %s /bin/false\nblacklist %s\n' "$m" "$m" > "/etc/modprobe.d/cis-$m.conf"
  modprobe -r "$m" 2>/dev/null || true
done

echo "[4/12] Network kernel parameters"
cat > /etc/sysctl.d/60-cis.conf <<'X'
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.default.secure_redirects = 0
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv6.conf.all.accept_ra = 0
net.ipv6.conf.default.accept_ra = 0
fs.suid_dumpable = 0
X
sysctl --system >/dev/null

echo "[5/12] Restrict core dumps"
grep -q '^\* hard core 0' /etc/security/limits.conf || echo '* hard core 0' >> /etc/security/limits.conf

echo "[6/12] Login warning banners"
MSG="Authorized users only. All activity may be monitored and reported."
echo "$MSG" > /etc/issue; echo "$MSG" > /etc/issue.net
chown root:root /etc/issue /etc/issue.net; chmod 644 /etc/issue /etc/issue.net

echo "[7/12] Cron and at permissions"
chown root:root /etc/crontab /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
chmod 600 /etc/crontab
chmod 700 /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly /etc/cron.d
rm -f /etc/cron.deny /etc/at.deny
touch /etc/cron.allow /etc/at.allow
chown root:root /etc/cron.allow /etc/at.allow; chmod 640 /etc/cron.allow /etc/at.allow

echo "[8/12] sudo log file and restricted su"
echo 'Defaults logfile="/var/log/sudo.log"' > /etc/sudoers.d/60-cis-log
chmod 440 /etc/sudoers.d/60-cis-log
visudo -cf /etc/sudoers.d/60-cis-log >/dev/null || { rm -f /etc/sudoers.d/60-cis-log; echo "  sudo log skipped"; }
getent group sugroup >/dev/null || groupadd sugroup
grep -q 'pam_wheel.so use_uid group=sugroup' /etc/pam.d/su || echo 'auth required pam_wheel.so use_uid group=sugroup' >> /etc/pam.d/su

echo "[9/12] Root umask and idle shell timeout (15 min)"
for f in /root/.bashrc /root/.bash_profile; do grep -q '^umask 0027' "$f" 2>/dev/null || echo 'umask 0027' >> "$f"; done
printf 'TMOUT=900\nreadonly TMOUT\nexport TMOUT\n' > /etc/profile.d/60-cis-tmout.sh

echo "[10/12] Log settings: journald rotation, rsyslog file mode, time server"
mkdir -p /etc/systemd/journald.conf.d /etc/systemd/timesyncd.conf.d
printf '[Journal]\nSystemMaxUse=1G\nSystemKeepFree=500M\nRuntimeMaxUse=200M\nRuntimeKeepFree=50M\nMaxFileSec=1month\n' > /etc/systemd/journald.conf.d/60-cis.conf
systemctl restart systemd-journald
if [[ -d /etc/rsyslog.d ]]; then echo '$FileCreateMode 0640' > /etc/rsyslog.d/60-cis.conf; systemctl restart rsyslog 2>/dev/null || true; fi
printf '[Time]\nNTP=time.google.com\nFallbackNTP=ntp.ubuntu.com\n' > /etc/systemd/timesyncd.conf.d/60-cis.conf
systemctl restart systemd-timesyncd 2>/dev/null || true

echo "[11/12] Password ageing (365 days max, 1 day min, lock 45 days after expiry)"
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS\t365/; s/^PASS_MIN_DAYS.*/PASS_MIN_DAYS\t1/' /etc/login.defs
useradd -D -f 45
chage --maxdays 365 --mindays 1 --inactive 45 "$U"
chage --maxdays 365 --mindays 1 root

echo "[12/12] /dev/shm noexec + AppArmor and audit on the kernel command line"
grep -q '[[:space:]]/dev/shm[[:space:]]' /etc/fstab || echo 'tmpfs /dev/shm tmpfs defaults,rw,nosuid,nodev,noexec,relatime 0 0' >> /etc/fstab
mount -o remount /dev/shm 2>/dev/null || true
if ! grep -q 'audit=1' /etc/default/grub; then
  sed -i 's/^GRUB_CMDLINE_LINUX="\(.*\)"/GRUB_CMDLINE_LINUX="\1 apparmor=1 security=apparmor audit=1 audit_backlog_limit=8192"/' /etc/default/grub
  update-grub >/dev/null 2>&1
fi

echo "===== PART 1 DONE ====="
