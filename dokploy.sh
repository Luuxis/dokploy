#!/usr/bin/env bash
set -Eeuo pipefail

# ==============================
# Hardening Debian 12 existant
# Cas: utilisateur déjà en place
# User: luuxis
# Usage prévu: Dokploy
# ==============================

# -------- CONFIG --------
EXISTING_USER="${EXISTING_USER:-luuxis}"
SSH_PORT="${SSH_PORT:-45678}"
DOKPLOY_SETUP_PORT="${DOKPLOY_SETUP_PORT:-3000}"
# ------------------------

if [[ "$EUID" -ne 0 ]]; then
  echo "Ce script doit être lancé en root."
  exit 1
fi

if [[ ! -f /etc/debian_version ]]; then
  echo "Ce script est prévu pour Debian."
  exit 1
fi

BACKUP_DIR="/root/hardening-backups-$(date +%F-%H%M%S)"
mkdir -p "$BACKUP_DIR"

log()  { echo -e "\033[1;32m[+]\033[0m $*"; }
warn() { echo -e "\033[1;33m[!]\033[0m $*"; }
err()  { echo -e "\033[1;31m[-]\033[0m $*" >&2; }

backup_file() {
  local f="$1"
  if [[ -f "$f" ]]; then
    cp -a "$f" "$BACKUP_DIR/"
  fi
}

trap 'err "Erreur ligne $LINENO. Backups disponibles dans $BACKUP_DIR"' ERR

log "Vérification utilisateur"
if ! id "$EXISTING_USER" >/dev/null 2>&1; then
  err "L'utilisateur $EXISTING_USER n'existe pas."
  exit 1
fi

if [[ ! -f "/home/$EXISTING_USER/.ssh/authorized_keys" ]]; then
  err "Aucune clé trouvée dans /home/$EXISTING_USER/.ssh/authorized_keys"
  exit 1
fi

log "Mise à jour système"
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get -y full-upgrade

log "Installation des paquets de sécurité"
apt-get install -y \
  sudo curl wget ca-certificates gnupg lsb-release \
  openssh-server nftables fail2ban unattended-upgrades apt-listchanges \
  apparmor apparmor-utils auditd audispd-plugins rsyslog logrotate \
  lynis aide needrestart debsums

log "Activation AppArmor"
systemctl enable apparmor
systemctl restart apparmor || true

log "Activation journaux persistants"
mkdir -p /var/log/journal
systemd-tmpfiles --create --prefix /var/log/journal
if grep -q '^#\?Storage=' /etc/systemd/journald.conf; then
  sed -i 's/^#\?Storage=.*/Storage=persistent/' /etc/systemd/journald.conf
else
  echo 'Storage=persistent' >> /etc/systemd/journald.conf
fi
systemctl restart systemd-journald

log "Permissions SSH utilisateur"
chmod 700 "/home/$EXISTING_USER/.ssh"
chmod 600 "/home/$EXISTING_USER/.ssh/authorized_keys"
chown -R "$EXISTING_USER:$EXISTING_USER" "/home/$EXISTING_USER/.ssh"

log "Verrouillage compte root"
sudo usermod -L root
sudo passwd -l root

log "Durcissement SSH"
backup_file /etc/ssh/sshd_config

cat > /etc/ssh/sshd_config <<EOF
Port ${SSH_PORT}
Protocol 2
AddressFamily any
ListenAddress 0.0.0.0

HostKey /etc/ssh/ssh_host_ed25519_key
HostKey /etc/ssh/ssh_host_rsa_key

PermitRootLogin no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
ChallengeResponseAuthentication no
PermitEmptyPasswords no
UsePAM yes
AuthenticationMethods publickey

MaxAuthTries 3
MaxSessions 3
LoginGraceTime 20
StrictModes yes

AllowUsers ${EXISTING_USER}

X11Forwarding no
AllowTcpForwarding no
AllowAgentForwarding no
PermitTunnel no
GatewayPorts no
AllowStreamLocalForwarding no

ClientAliveInterval 300
ClientAliveCountMax 2
TCPKeepAlive no

Ciphers chacha20-poly1305@openssh.com,aes256-gcm@openssh.com
KexAlgorithms curve25519-sha256,curve25519-sha256@libssh.org,sntrup761x25519-sha512,sntrup761x25519-sha512@openssh.com
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com

PermitUserEnvironment no
Banner none
PrintMotd no
Subsystem sftp internal-sftp
PidFile /run/sshd.pid
LogLevel VERBOSE
EOF

sudo sshd -t
systemctl enable ssh
systemctl restart ssh

log "Configuration mises à jour automatiques"
backup_file /etc/apt/apt.conf.d/20auto-upgrades
backup_file /etc/apt/apt.conf.d/50unattended-upgrades

cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename},label=Debian-Security";
        "origin=Debian,codename=${distro_codename},label=Debian";
};
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

systemctl enable unattended-upgrades
systemctl restart unattended-upgrades || true

log "Durcissement sysctl"
cat > /etc/sysctl.d/99-hardening.conf <<'EOF'
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.yama.ptrace_scope = 2
fs.protected_fifos = 2
fs.protected_regular = 2
fs.suid_dumpable = 0

net.ipv4.ip_forward = 1
net.ipv6.conf.all.forwarding = 1
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.log_martians = 1
net.ipv4.conf.default.log_martians = 1
net.ipv4.conf.all.rp_filter = 1
net.ipv4.conf.default.rp_filter = 1
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.tcp_syncookies = 1

net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv6.conf.all.accept_source_route = 0
net.ipv6.conf.default.accept_source_route = 0
EOF

sudo sysctl --system

log "Configuration nftables"
backup_file /etc/nftables.conf

cat > /etc/nftables.conf <<EOF
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
  chain input {
    type filter hook input priority 0;
    policy drop;

    iif lo accept
    ct state established,related accept
    ct state invalid drop

    ip protocol icmp accept

    tcp dport ${SSH_PORT} ct state new accept comment "SSH"
    tcp dport { 80, 443, ${DOKPLOY_SETUP_PORT} } ct state new accept comment "Web/Dokploy"

    counter reject with icmpx type admin-prohibited
  }

  chain forward {
    type filter hook forward priority 0;
    policy drop;

    ct state established,related accept

    # Réseaux Docker classiques
    iifname { "docker0", "docker_gwbridge" } accept
    oifname { "docker0", "docker_gwbridge" } accept

    # Réseaux bridge Docker user-defined (souvent en 172.16.0.0/12)
    ip saddr 172.16.0.0/12 accept
    ip daddr 172.16.0.0/12 accept
  }

  chain output {
    type filter hook output priority 0;
    policy accept;
  }
}
EOF

/usr/sbin/nft -c -f /etc/nftables.conf
/usr/sbin/nft -f /etc/nftables.conf
systemctl enable nftables
systemctl restart nftables

log "Création du service de rechargement nftables après Docker"
cat > /etc/systemd/system/nftables-reapply.service <<'EOF'
[Unit]
Description=Reapply nftables rules after Docker
After=network-online.target docker.service
Wants=network-online.target
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/sbin/nft -f /etc/nftables.conf
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload

log "Configuration Fail2Ban"
mkdir -p /etc/fail2ban

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime = 1h
findtime = 10m
maxretry = 3
backend = systemd
banaction = nftables-multiport

[sshd]
enabled = true
port = ${SSH_PORT}
logpath = %(sshd_log)s
mode = aggressive
EOF

systemctl enable fail2ban
systemctl restart fail2ban

log "Configuration docker DNS"
mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<'EOF'
{
  "dns": ["8.8.8.8", "1.1.1.1"]
}
EOF
systemctl restart docker || true

log "UMASK renforcé"
if ! grep -q '^umask 027' /etc/profile; then
  echo 'umask 027' >> /etc/profile
fi

log "Initialisation AIDE"
aideinit || true
if [[ -f /var/lib/aide/aide.db.new ]]; then
  mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db
elif [[ -f /var/lib/aide/aide.db.new.gz ]]; then
  mv /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
fi

log "Activation auditd"
systemctl enable auditd
systemctl restart auditd

log "Configuration needrestart"
mkdir -p /etc/needrestart/conf.d
cat > /etc/needrestart/conf.d/99-local.conf <<'EOF'
$nrconf{restart} = 'i';
EOF

log "Suppression outils inutiles si présents"
apt-get purge -y telnet rsh-client rsh-redone-client talk ftp || true
apt-get autoremove -y

log "Installation de Dokploy"
curl -sSL https://dokploy.com/install.sh | sh

log "Activation du service nftables-reapply après installation Docker/Dokploy"
systemctl enable nftables-reapply.service
systemctl start nftables-reapply.service

log "Ajout de $EXISTING_USER au groupe docker"
if ! groups "$EXISTING_USER" | grep -qw "docker"; then
  sudo usermod -aG docker "$EXISTING_USER"
fi

log "Ajout de $EXISTING_USER au groupe sudo"
if ! groups "$EXISTING_USER" | grep -qw "sudo"; then
  sudo usermod -aG sudo "$EXISTING_USER"
fi

log "Configuration sudo sans mot de passe pour $EXISTING_USER"
if ! sudo -lU "$EXISTING_USER" 2>/dev/null | grep -q 'ALL=(ALL) NOPASSWD: ALL'; then
  echo "$EXISTING_USER ALL=(ALL) NOPASSWD: ALL" > "/etc/sudoers.d/90-$EXISTING_USER"
  chmod 440 "/etc/sudoers.d/90-$EXISTING_USER"
fi

log "Audit Lynis"
sudo lynis audit system --quick || true

log "Vérifications finales"
sudo sshd -t
/usr/sbin/nft list ruleset >/dev/null
fail2ban-client ping >/dev/null
systemctl is-enabled nftables >/dev/null
systemctl is-enabled nftables-reapply.service >/dev/null

cat <<EOF

========================================
HARDENING TERMINÉ
========================================

Utilisateur autorisé SSH : ${EXISTING_USER}
Port SSH                : ${SSH_PORT}
Backups                 : ${BACKUP_DIR}
fierwall
 - file nftables : /etc/nftables.conf
 - reload : nft -f /etc/nftables.conf

Ports ouverts :
- ${SSH_PORT}/tcp
- 80/tcp
- 443/tcp
- ${DOKPLOY_SETUP_PORT}/tcp

IMPORTANT :

1. modifier le mot de passe de $EXISTING_USER
    echo "$EXISTING_USER:$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 32)" | sudo chpasswd

2. fermer le port 3000 après la configuration de Dokploy
    nano /etc/nftables.conf
    # supprimer le port $DOKPLOY_SETUP_PORT de la ligne suivante :
    # tcp dport {80, 443 ,$DOKPLOY_SETUP_PORT} ct state new accept comment "Web/Dokploy"
    nft -f /etc/nftables.conf
EOF
