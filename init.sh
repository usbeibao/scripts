#!/bin/bash
# Init script. Initialize for debian bullseye with proper apt source and prepare the tools
# Author: ratneo<https://ihost.wiki>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

coloredEcho() {
  echo -e "${1}${@:2}${PLAIN}"
}

checkRoot() {
  result=$(id | awk '{print $1}')
  if [[ $result != "uid=0(root)" ]]; then
    coloredEcho $RED " 请以root身份执行该脚本"
    exit 1
  fi
}

apt_source() {
  cat > /etc/apt/sources.list<<-EOF
deb http://deb.debian.org/debian bullseye main
deb-src http://deb.debian.org/debian bullseye main

deb http://deb.debian.org/debian-security/ bullseye-security main
deb-src http://deb.debian.org/debian-security/ bullseye-security main

deb http://deb.debian.org/debian bullseye-updates main
deb-src http://deb.debian.org/debian bullseye-updates main

deb http://deb.debian.org/debian bullseye-backports main
deb-src http://deb.debian.org/debian bullseye-backports main
EOF
  apt update -y && apt upgrade -y
  apt install curl wget git less screen xz-utils net-tools dnsutils mtr unzip iperf3 jq nethogs iftop lsof sudo certbot python3-certbot-nginx -y
  coloredEcho $GREEN " 初始化完成"
}

fail2ban_install() {
  apt install fail2ban -y
  systemctl enable --now fail2ban
  
  mkdir -p /etc/nftables/
  
  # Configure nftables for fail2ban, nftables is the default for Debian 11+
  cat > /etc/nftables/fail2ban.conf <<-EOF
#!/usr/sbin/nft -f
table ip fail2ban {
        chain input {
                type filter hook input priority 100;
        }
}
EOF

  echo "include \"/etc/nftables/fail2ban.conf\"" >> /etc/nftables.conf
  nft -f /etc/nftables/fail2ban.conf

  cat > /etc/fail2ban/action.d/nftables-common.local <<-EOF
[Init]
# Definition of the table used
nftables_family = ip
nftables_table  = fail2ban

# Drop packets 
blocktype       = drop

# Remove nftables prefix. Set names are limited to 15 char so we want them all
nftables_set_prefix =
EOF

  cat > /etc/fail2ban/jail.local <<-EOF
[sshd]
enabled   = true
mode      = aggressive

bantime   = 48h
findtime  = 48h
maxretry  = 3

port    = 38658
logpath = /var/log/auth.log

banaction = nftables-multiport
chain     = input
EOF



  fail2ban-client restart
  coloredEcho $GREEN " Fail2Ban 安装完成"
}

ssh_key_install() {
  useradd -d /home/$2 -s /bin/bash -m $2
  usermod -aG sudo $2
  sed -i '/sudo/s/ALL$/NOPASSWD: ALL/' /etc/sudoers
  mkdir /home/$2/.ssh
  touch /home/$2/.ssh/authorized_keys
  curl https://github.com/$1.keys > /home/$2/.ssh/authorized_keys
  chmod 400 /home/$2/.ssh/authorized_keys
  chmod 700 /home/$2/.ssh/
  chown $2:$2 /home/$2/.ssh -R

  cd /etc/ssh/
  sed -i "/PermitRootLogin yes/c PermitRootLogin no" sshd_config
  sed -i "/PasswordAuthentication no/c PasswordAuthentication no" sshd_config
  sed -i "/RSAAuthentication no/c RSAAuthentication yes" sshd_config
  sed -i "/PubkeyAuthentication no/c PubkeyAuthentication yes" sshd_config
  sed -i "/PasswordAuthentication yes/c PasswordAuthentication no" sshd_config
  sed -i "/RSAAuthentication yes/c RSAAuthentication yes" sshd_config
  sed -i "/PubkeyAuthentication yes/c PubkeyAuthentication yes" sshd_config
  sed -i "/#Port 22/c Port 38658" /etc/ssh/sshd_config
  sed -i "/Port 22/c Port 38658" /etc/ssh/sshd_config
  systemctl restart sshd
  systemctl restart ssh
  
  coloredEcho $GREEN " SSH Key 安装完成"
}

cloudflare_doh_install() {
  bash <(curl -sL https://github.com/wikihost-opensource/centos-init/raw/main/network/dns-over-https/cloudflare.sh)
  rm wikihost_cloudflare_doh_install.log
  chattr +i /etc/resolv.conf
  coloredEcho $GREEN " Cloudflare-DOH 安装完成"
}

worsttrace_install() {
  [[ ! -f /usr/local/bin/worsttrace ]] && wget https://pkg.wtrace.app/linux/worsttrace -O /usr/local/bin/worsttrace
  [[ ! -f /usr/local/bin/worsttrace ]] && echo -e "${Error} download failed, please check!" && exit 1
  chmod +x /usr/local/bin/worsttrace
  coloredEcho $GREEN " WorstTrace 安装完成"
}

besttrace_install() {
  [[ ! -f /usr/local/bin/besttrace ]] && wget https://github.com/zhucaidan/BestTrace-Linux/raw/master/besttrace -O /usr/local/bin/besttrace
  [[ ! -f /usr/local/bin/besttrace ]] && echo -e "${Error} download failed, please check!" && exit 1
  chmod +x /usr/local/bin/besttrace
  coloredEcho $GREEN " BestTrace 安装完成"
}

checkRoot
apt_source
fail2ban_install
ssh_key_install $1 $2
cloudflare_doh_install
besttrace_install
worsttrace_install

read -p "系统初始化完成，建议重启后安装BBR，是否现在重启 ? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
  echo -e "${Info} VPS 重启中..."
  reboot
fi
