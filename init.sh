#!/bin/bash
#
# init.sh — Debian 13 (trixie) 系统初始化
# 用法:
#   bash init.sh [github_username] [new_user]
#   SSH_PORT=2222 bash init.sh myghuser frank   # 自定义SSH端口
#
# 安全设计:
#   - GitHub 用户名 + 新用户必传, 且 SSH key 成功拉取(非空)才会关闭密码登录
#     (否则保留密码登录, 防止锁死自己)
#   - SSH 端口变量化(默认38658), fail2ban 自动联动同一端口
#   - 不强行覆盖 apt 源(DD 已配好), 仅校验+提示

set -uo pipefail

RED="\033[31m"
GREEN="\033[32m"
YELLOW="\033[33m"
BLUE="\033[36m"
PLAIN='\033[0m'

coloredEcho() { echo -e "${1}${@:2}${PLAIN}"; }

# ---------- 参数 ----------
GH_USER="${1:-}"
NEW_USER="${2:-}"
SSH_PORT="${SSH_PORT:-38658}"   # 可用环境变量覆盖

checkRoot() {
  if [[ "$(id -u)" != "0" ]]; then
    coloredEcho $RED " 请以 root 身份执行该脚本"
    exit 1
  fi
}

# ---------- apt 源: 不强行覆盖, 仅校验 ----------
# DD(leitbogioro)已写好正确的 trixie 源。这里只检查, 不对才提示。
checkAptSource() {
  coloredEcho $BLUE "\n========== 检查 apt 源 ==========\n"
  if grep -rq "trixie" /etc/apt/sources.list /etc/apt/sources.list.d/ 2>/dev/null; then
    coloredEcho $GREEN " apt 源已是 trixie ✓ (不覆盖)"
  else
    coloredEcho $YELLOW " 当前源不是 trixie, 写入标准 trixie 源..."
    cp /etc/apt/sources.list "/etc/apt/sources.list.bak.$(date +%s)" 2>/dev/null || true
    cat > /etc/apt/sources.list <<-EOF
deb http://deb.debian.org/debian trixie main contrib non-free non-free-firmware
deb http://deb.debian.org/debian trixie-updates main contrib non-free non-free-firmware
deb http://security.debian.org/debian-security trixie-security main contrib non-free non-free-firmware
EOF
    coloredEcho $GREEN " 已写入 trixie 源(含 contrib non-free)"
  fi
  apt update -y >/dev/null 2>&1 && coloredEcho $GREEN " apt update 完成" \
    || coloredEcho $RED " apt update 有警告, 请检查源"
}

# ---------- 基础工具 ----------
installBaseTools() {
  coloredEcho $BLUE "\n========== 安装基础工具 ==========\n"
  # Debian 13 兼容包名: dnsutils→bind9-dnsutils, mlocate→plocate
  apt -y install curl wget git less screen xz-utils bind9-dnsutils plocate \
    net-tools mtr-tiny unzip iperf3 jq nethogs iftop lsof sudo ca-certificates \
    chrony nftables >/dev/null 2>&1
  # 关键工具校验
  local miss=""
  for t in curl wget git jq; do command -v "$t" >/dev/null 2>&1 || miss+=" $t"; done
  [[ -n "$miss" ]] && coloredEcho $RED " 关键工具缺失:$miss (检查 apt 源)" \
    || coloredEcho $GREEN " 基础工具安装完成"
}

# ---------- fail2ban (端口与 SSH 联动) ----------
fail2ban_install() {
  coloredEcho $BLUE "\n========== 安装 Fail2Ban ==========\n"
  apt -y install fail2ban >/dev/null 2>&1
  [ ! -f /var/log/auth.log ] && touch /var/log/auth.log
  mkdir -p /etc/nftables/

  cat > /etc/nftables/fail2ban.conf <<-EOF
#!/usr/sbin/nft -f
table ip fail2ban {
        chain input {
                type filter hook input priority 100;
        }
}
EOF
  grep -q 'fail2ban.conf' /etc/nftables.conf 2>/dev/null \
    || echo "include \"/etc/nftables/fail2ban.conf\"" >> /etc/nftables.conf
  nft -f /etc/nftables/fail2ban.conf 2>/dev/null || true

  cat > /etc/fail2ban/action.d/nftables-common.local <<-EOF
[Init]
nftables_family = ip
nftables_table  = fail2ban
blocktype       = drop
nftables_set_prefix =
EOF

  # 端口跟随 SSH_PORT 变量
  cat > /etc/fail2ban/jail.local <<-EOF
[sshd]
enabled   = true
mode      = aggressive
bantime   = 48h
findtime  = 48h
maxretry  = 3
port      = ${SSH_PORT}
logpath   = /var/log/auth.log
banaction = nftables-multiport
chain     = input
EOF

  systemctl enable --now nftables >/dev/null 2>&1
  systemctl enable --now fail2ban >/dev/null 2>&1
  fail2ban-client reload >/dev/null 2>&1 || fail2ban-client restart >/dev/null 2>&1
  coloredEcho $GREEN " Fail2Ban 安装完成 (防护端口 ${SSH_PORT})"
}

# ---------- SSH key + 改端口 (防锁死) ----------
ssh_key_install() {
  coloredEcho $BLUE "\n========== 配置 SSH ==========\n"

  # 防锁死前置校验: 没传用户名/新用户, 跳过(不关密码登录)
  if [[ -z "$GH_USER" || -z "$NEW_USER" ]]; then
    coloredEcho $YELLOW " 未传 github用户名/新用户, 跳过 SSH key 配置"
    coloredEcho $YELLOW " (保留密码登录, 仅按需改端口)"
    changeSshPort
    return 0
  fi

  # 建用户
  if ! id "$NEW_USER" >/dev/null 2>&1; then
    useradd -d "/home/${NEW_USER}" -s /bin/bash -m "$NEW_USER"
  fi
  usermod -aG sudo "$NEW_USER"
  sed -i '/^%sudo/s/ALL$/NOPASSWD: ALL/' /etc/sudoers 2>/dev/null || true

  # 拉 GitHub 公钥
  mkdir -p "/home/${NEW_USER}/.ssh"
  local keys; keys=$(curl -fsSL "https://github.com/${GH_USER}.keys" 2>/dev/null)

  # 关键: 拉到的 key 非空(含 ssh- 开头)才写入并关密码登录, 否则保留密码登录防锁死
  if [[ -n "$keys" ]] && echo "$keys" | grep -q "^ssh-"; then
    echo "$keys" > "/home/${NEW_USER}/.ssh/authorized_keys"
    chmod 600 "/home/${NEW_USER}/.ssh/authorized_keys"
    chmod 700 "/home/${NEW_USER}/.ssh"
    chown -R "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}/.ssh"
    coloredEcho $GREEN " 已写入 ${GH_USER} 的 SSH key 到用户 ${NEW_USER}"

    # key 就位, 安全地关闭密码登录 + root 登录
    sed -ri 's/^#?PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config
    sed -ri 's/^#?PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config
    sed -ri 's/^#?PubkeyAuthentication.*/PubkeyAuthentication yes/' /etc/ssh/sshd_config
    coloredEcho $GREEN " 已关闭密码登录(仅 key 登录)"
  else
    coloredEcho $RED " ⚠ 拉取 ${GH_USER} 的 SSH key 失败或为空!"
    coloredEcho $YELLOW " 为防锁死, 保留密码登录。请检查 GitHub 用户名是否正确。"
  fi

  changeSshPort
}

# ---------- 改 SSH 端口(独立函数, 变量化) ----------
changeSshPort() {
  if [[ "$SSH_PORT" != "22" ]]; then
    sed -ri "s/^#?Port .*/Port ${SSH_PORT}/" /etc/ssh/sshd_config
    coloredEcho $GREEN " SSH 端口改为 ${SSH_PORT}"
    coloredEcho $YELLOW " ⚠ 记得在云安全组放行端口 ${SSH_PORT}, 否则重连不上!"
  fi
  systemctl restart ssh 2>/dev/null || systemctl restart sshd 2>/dev/null || true
}

# ---------- nexttrace ----------
nexttrace_install() {
  coloredEcho $BLUE "\n========== 安装 NextTrace ==========\n"
  if [[ ! -f /usr/local/bin/nexttrace ]]; then
    wget -qO /usr/local/bin/nexttrace \
      "https://github.com/nxtrace/NTrace-core/releases/latest/download/nexttrace_linux_amd64" 2>/dev/null
  fi
  if [[ -f /usr/local/bin/nexttrace ]]; then
    chmod +x /usr/local/bin/nexttrace
    coloredEcho $GREEN " NextTrace 安装完成"
  else
    coloredEcho $YELLOW " NextTrace 下载失败(网络?), 跳过"
  fi
}

# ---------- smartdns (不依赖行号) ----------
smartdns_install() {
  coloredEcho $BLUE "\n========== 安装 SmartDNS ==========\n"
  wget -qO /tmp/smartdns.deb \
    "https://github.com/pymumu/smartdns/releases/download/Release46.1/smartdns.1.2025.03.02-1533.x86-debian-all.deb" 2>/dev/null
  if [[ ! -f /tmp/smartdns.deb ]]; then
    coloredEcho $YELLOW " SmartDNS 下载失败, 跳过"; return 0
  fi
  dpkg -i /tmp/smartdns.deb >/dev/null 2>&1; rm -f /tmp/smartdns.deb

  local conf=/etc/smartdns/smartdns.conf
  # DoH 上游(去重追加)
  grep -q "1.1.1.1/dns-query" "$conf" 2>/dev/null || cat >> "$conf" <<-EOF

# Cloudflare DoH
server-https https://1.1.1.1/dns-query
# Google DoH
server-https https://dns.google/dns-query
EOF
  # 绑定本地(不依赖行号: 替换已有 bind 行 / 没有则追加)
  if grep -qE '^bind ' "$conf"; then
    sed -ri 's|^bind .*|bind 127.0.0.1:53|' "$conf"
  else
    echo "bind 127.0.0.1:53" >> "$conf"
  fi
  sed -i '/^bind \[::\]:53/d' "$conf" 2>/dev/null || true

  echo "nameserver 127.0.0.1" > /etc/resolv.conf
  chattr +i /etc/resolv.conf 2>/dev/null || true
  systemctl enable --now smartdns >/dev/null 2>&1
  systemctl restart smartdns >/dev/null 2>&1
  coloredEcho $GREEN " SmartDNS 安装完成"
}

# ---------- 主流程 ----------
checkRoot
checkAptSource
installBaseTools
fail2ban_install
ssh_key_install
nexttrace_install
smartdns_install

coloredEcho $GREEN "\n========== 系统初始化完成 ==========\n"
coloredEcho $YELLOW " 建议重启后再装代理(让内核/服务干净加载)"
[[ "$SSH_PORT" != "22" ]] && coloredEcho $YELLOW " 重连请用端口 ${SSH_PORT}, 确认云安全组已放行!"

read -p " 是否现在重启? [Y/n] :" yn
[ -z "${yn}" ] && yn="y"
if [[ $yn == [Yy] ]]; then
  coloredEcho $BLUE " VPS 重启中..."
  reboot
fi
