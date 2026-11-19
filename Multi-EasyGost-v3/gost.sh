#!/usr/bin/env bash
set -euo pipefail
umask 077

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
repo=https://github.com/go-gost/gost
config_dir=/etc/gost
raw_conf_path=$config_dir/rawconf
v3_config=$config_dir/config-v3.json
cert_dir=/root/gost_cert
bin_dir=/usr/local/lib/multi-easygost
binary=$bin_dir/gost
unit=/etc/systemd/system/gost.service
legacy=$config_dir/backup-v2
cron_file=/etc/cron.d/multi-easygost
stage=
is_cert=n

die() { printf '错误：%s\n' "$*" >&2; exit 1; }

safe_directory() {
  local path=$1
  [[ ! -L "$path" ]] || die "目录是符号链接：$path"
  install -d -m 700 -- "$path"
  [[ -O "$path" ]] || die "目录须由 root 拥有：$path"
  chmod 700 -- "$path"
}

render() {
  python3 "$script_dir/render_config.py" "$1" "$config_dir" "$cert_dir"
}

download_release() {
  local tag=${1:-latest} url arch filename hash version
  case $(uname -m) in
    x86_64) arch=amd64 ;;
    aarch64|arm64) arch=arm64 ;;
    i[3-6]86) arch=386 ;;
    armv[567]l) arch=$(uname -m); arch=${arch%l} ;;
    *) die "此架构未配置官方发行包：$(uname -m)" ;;
  esac
  local curl_options=(--fail --silent --show-error --connect-timeout 10 --max-time 120 --retry 2 --proto '=https' --proto-redir '=https')
  if [[ "$tag" == latest ]]; then
    url=$(curl "${curl_options[@]}" --head --output /dev/null --write-out '%{redirect_url}' "$repo/releases/latest")
    [[ "$url" == "$repo/releases/tag/"* ]] || die "无法从官方 GitHub 获取稳定版"
    tag=${url##*/}
  fi
  [[ "$tag" =~ ^v3\.[0-9]+\.[0-9]+$ ]] || die "仅接受 v3 正式版标签，例如 v3.3.3"
  version=${tag#v}
  filename="gost_${version}_linux_${arch}.tar.gz"
  url="$repo/releases/download/$tag"
  printf '下载官方 GOST %s (%s)\n' "$tag" "$arch" >&2
  curl "${curl_options[@]}" --location "$url/checksums.txt" --output "$stage/checksums.txt"
  curl "${curl_options[@]}" --location "$url/$filename" --output "$stage/$filename"
  hash=$(awk -v file="$filename" '$2 == file { print $1 }' "$stage/checksums.txt")
  [[ "$hash" =~ ^[[:xdigit:]]{64}$ ]] || die "官方校验文件中没有唯一的发行包 SHA-256"
  (cd "$stage" && printf '%s  %s\n' "$hash" "$filename" | sha256sum --check --status) ||
    die "发行包 SHA-256 校验失败"
  tar -xOf "$stage/$filename" gost > "$stage/gost"
  chmod 700 "$stage/gost"
  [[ $("$stage/gost" -V) == "gost $version ("* ]] || die "二进制版本与标签不符"
}

# Rename within the destination filesystem so systemd never observes a partial file.
publish() {
  local source=$1 destination=$2 mode=$3 temporary
  temporary=$(mktemp -- "${destination}.XXXXXX") || return
  if ! install -m "$mode" -- "$source" "$temporary" || ! mv -fT -- "$temporary" "$destination"; then
    rm -f -- "$temporary"
    return 1
  fi
}

start_checked() {
  systemctl restart gost.service &&
    sleep 2 &&
    systemctl is-active --quiet gost.service
}

had_active_service() { systemctl is-active --quiet gost.service; }

require_v3() {
  [[ -x "$binary" && -f "$v3_config" &&
     $(systemctl show -p ExecStart --value gost.service) == *"$binary -C $v3_config"* ]] ||
    die "请先安装或迁移到 GOST v3"
}

apply_rules() {
  local rules=$1 was_active=no
  require_v3
  render "$rules" > "$stage/config.json" || return
  "$binary" -C "$stage/config.json" -O json >/dev/null || return
  cp -p -- "$v3_config" "$stage/previous.json" || return
  if had_active_service; then was_active=yes; fi
  if publish "$stage/config.json" "$v3_config" 600 && start_checked &&
     { [[ "$rules" == "$raw_conf_path" ]] || publish "$rules" "$raw_conf_path" 600; }; then
    return
  fi
  publish "$stage/previous.json" "$v3_config" 600 || die "恢复配置失败，检查 $v3_config"
  if [[ "$was_active" == yes ]]; then
    start_checked || die "已恢复配置，旧服务启动失败，请查看 journalctl -u gost.service"
  else
    systemctl stop gost.service || die "恢复旧服务状态失败"
  fi
  printf '新配置未生效，已恢复原配置。请查看 journalctl -u gost.service\n' >&2
  return 1
}

upgrade() {
  require_v3
  local was_active=no
  download_release "${1:-latest}"
  "$stage/gost" -C "$v3_config" -O json >/dev/null
  if [[ $("$stage/gost" -V) == "$("$binary" -V)" ]]; then
    "$binary" -V
    return
  fi
  cp -p -- "$binary" "$stage/previous-gost"
  if had_active_service; then was_active=yes; fi
  if publish "$stage/gost" "$binary" 755 && { [[ "$was_active" == no ]] || start_checked; }; then
    "$binary" -V
    return
  fi
  publish "$stage/previous-gost" "$binary" 755 || die "恢复旧二进制失败"
  [[ "$was_active" == no ]] || start_checked || die "已恢复旧二进制，旧服务启动失败"
  die "升级失败，已恢复旧二进制。请查看 journalctl -u gost.service"
}

restore_v2() {
  [[ -f "$legacy/active" && -f "$legacy/enabled" ]] || die "找不到迁移前的服务状态"
  systemctl stop gost.service || return
  systemctl disable gost.service || return
  if [[ -f "$legacy/gost.service" ]]; then
    publish "$legacy/gost.service" "$unit" 644 || return
  else
    rm -f -- "$unit" || return
  fi
  if [[ -f "$raw_conf_path" ]]; then
    publish "$raw_conf_path" "$legacy/rawconf-v3" 600 || return
  fi
  if [[ -f "$cron_file" ]]; then
    mv -- "$cron_file" "$legacy/cron-v3" || return
  fi
  if [[ -f "$legacy/rawconf" ]]; then
    publish "$legacy/rawconf" "$raw_conf_path" 600 || return
  else
    rm -f -- "$raw_conf_path" || return
  fi
  systemctl daemon-reload || return
  if [[ $(<"$legacy/enabled") == enabled ]]; then
    systemctl enable gost.service || return
  fi
  if [[ $(<"$legacy/active") == active ]]; then
    start_checked || return
  fi
  # Archive the migration snapshot and retain the inactive v3 binary/config.
  mv -T -- "$legacy" "$config_dir/backup-v2-restored-$(date +%Y%m%d-%H%M%S)-$$"
}

install_v3() {
  local action=$1 tag=${2:-latest} fragment enabled active=inactive rules
  if ! fragment=$(systemctl show -p FragmentPath --value gost.service); then
    [[ $(systemctl show -p LoadState --value gost.service 2>/dev/null || true) == not-found ]] ||
      die "无法读取 gost.service 的状态"
  fi
  if [[ "$action" == migrate ]]; then
    [[ -f "$config_dir/config.json" && -x /usr/bin/gost && -n "$fragment" ]] ||
      die "找不到原版 Multi-EasyGost 的配置、二进制或 systemd 服务"
    [[ $(systemctl show -p ExecStart --value gost.service) == *'/usr/bin/gost -C /etc/gost/config.json'* ]] ||
      die "旧服务的启动路径与 Multi-EasyGost 默认值不同，请先核对现有服务"
    [[ ! -e "$legacy" ]] || die "已有 v2 备份，请先核对当前安装状态"
    enabled=$(systemctl is-enabled gost.service 2>/dev/null || true)
    [[ "$enabled" == enabled || "$enabled" == disabled ]] || die "旧服务状态为 $enabled，暂不能自动迁移"
    if had_active_service; then active=active; fi
    rules=$raw_conf_path
    [[ -s "$rules" ]] || die "找不到可迁移的 rawconf 规则。请先核对旧 config.json"
    [[ ! -L "$unit" ]] || die "旧 unit 是符号链接，请先核对服务定义"
    [[ -z $(systemctl show -p DropInPaths --value gost.service) ]] ||
      die "旧服务包含 systemd drop-in，请先核对覆盖项"
  else
    [[ -z "$fragment" && ! -e "$unit" && ! -L "$unit" && ! -e "$config_dir/config.json" ]] ||
      die "检测到现有 GOST。v2 请选迁移，v3 请选升级"
    rules=$stage/empty
    : > "$rules"
    if [[ -f "$raw_conf_path" ]]; then rules=$raw_conf_path; fi
    enabled=enabled
    active=active
  fi

  render "$rules" > "$stage/config.json"
  download_release "$tag"
  "$stage/gost" -C "$stage/config.json" -O json >/dev/null
  if [[ "$action" == migrate ]]; then
    install -d -m 700 -- "$stage/backup-v2"
    printf '%s\n' "$active" > "$stage/backup-v2/active"
    printf '%s\n' "$enabled" > "$stage/backup-v2/enabled"
    [[ ! -f "$unit" ]] || install -m 600 -- "$unit" "$stage/backup-v2/gost.service"
    install -m 600 -- "$raw_conf_path" "$stage/backup-v2/rawconf"
    mv -T -- "$stage/backup-v2" "$legacy"
    chmod 600 -- "$raw_conf_path" "$config_dir/config.json"
  fi

  safe_directory "$bin_dir"
  # Recreate any enable link so it points to the v3 unit instead of the vendor unit.
  if publish "$stage/gost" "$binary" 755 &&
     publish "$stage/config.json" "$v3_config" 600 &&
     publish "$script_dir/gost.service" "$unit" 644 &&
     systemctl daemon-reload &&
     { [[ "$active" == inactive ]] || start_checked; } &&
     { [[ "$enabled" == disabled ]] || systemctl reenable gost.service; }; then
    "$binary" -V
    return
  fi

  if [[ "$action" == migrate ]]; then
    restore_v2 || die "迁移失败且自动恢复未完成，请核对 $legacy 与 journalctl -u gost.service"
    die "迁移失败，已恢复 v2 服务。请查看 journalctl -u gost.service"
  fi
  systemctl disable --now gost.service || true
  rm -f -- "$unit" "$v3_config" "$binary"
  systemctl daemon-reload
  die "安装失败。请查看 journalctl -u gost.service"
}

uninstall() {
  require_v3
  [[ $(systemctl show -p FragmentPath --value gost.service) == "$unit" ]] &&
    cmp -s -- "$unit" "$script_dir/gost.service" || die "当前服务由其他安装方式管理"
  [[ ! -d "$legacy" ]] || die "检测到 v2 迁移备份，请选回退 v2"
  systemctl disable --now gost.service
  rm -f -- "$unit" "$binary" "$cron_file"
  systemctl daemon-reload
  printf '已移除 v3 服务与二进制，规则保存在 %s\n' "$config_dir"
}

show_rules() {
  if [[ ! -s "$raw_conf_path" ]]; then
    printf '暂无规则\n'
    return
  fi
  awk '{
    if ($0 ~ /^(ss|http|socks)\//) {
      split($0, a, "/"); sub(/^.*#/, "", $0)
      printf "%d  %s  :%s  [凭据隐藏]\n", NR, a[1], $0
    } else {
      printf "%d  %s\n", NR, $0
    }
  }' "$raw_conf_path"
}

restart_with_rules() {
  : > "$stage/empty"
  if [[ -f "$raw_conf_path" ]]; then
    apply_rules "$raw_conf_path"
  else
    apply_rules "$stage/empty"
  fi
}

add_rule() {
  require_v3
  read_protocol
  read_s_port
  read_d_ip
  read_d_port
  [[ "$flag_c" != *'#'* && "$flag_d" != *'#'* ]] || die "用户名、地址和端口不能含有 #"
  : > "$stage/rules"
  if [[ -s "$raw_conf_path" ]]; then
    awk '1' "$raw_conf_path" >> "$stage/rules"
  fi
  printf '%s/%s#%s#%s\n' "$flag_a" "$flag_b" "$flag_c" "$flag_d" >> "$stage/rules"
  if [[ "$flag_a" == peer* ]]; then
    publish "$stage/peers" "$config_dir/peers/$flag_c.txt" 600
  fi
  if ! apply_rules "$stage/rules"; then
    if [[ "$flag_a" == peer* ]]; then rm -f -- "$config_dir/peers/$flag_c.txt"; fi
    die "添加规则失败"
  fi
  show_rules
}

delete_rule() {
  local number
  show_rules
  [[ -s "$raw_conf_path" ]] || return 0
  read -r -p '要删除的规则编号：' number
  [[ "$number" =~ ^[1-9][0-9]*$ ]] || die "请输入有效规则编号"
  awk -v number="$number" 'NR != number; END { if (number > NR) exit 1 }' \
    "$raw_conf_path" > "$stage/rules" || die "规则不存在"
  apply_rules "$stage/rules"
  show_rules
}

cron_restart() {
  local choice hour schedule systemctl_path
  require_v3
  read -r -p '[1] 每 N 小时 [2] 每日固定小时 [3] 删除定时任务：' choice
  case "$choice" in
    1|2)
      read -r -p '小时数：' hour
      [[ "$hour" =~ ^[0-9]{1,2}$ ]] || die "请输入 0–23 的整数"
      hour=$((10#$hour))
      if [[ "$choice" == 1 ]]; then
        (( hour >= 1 && hour <= 23 )) || die "请输入 1–23 小时"
        schedule="*/$hour"
      else
        (( hour <= 23 )) || die "请输入 0–23 点"
        schedule=$hour
      fi
      systemctl_path=$(command -v systemctl)
      printf '0 %s * * * root %s restart gost.service\n' "$schedule" "$systemctl_path" > "$stage/cron"
      publish "$stage/cron" "$cron_file" 644
      ;;
    3) rm -f -- "$cron_file" ;;
    *) die "请选择 1–3" ;;
  esac
}

cert() {
  local choice domain CF_Token acme=/root/.acme.sh/acme.sh
  safe_directory "$cert_dir"
  read -r -p '[1] ACME HTTP-01 [2] ACME Cloudflare DNS-01 [3] 手动放置证书：' choice
  if [[ "$choice" == 3 ]]; then
    printf '请放置 %s/{cert.pem,key.pem}，然后从菜单重读配置。\n' "$cert_dir"
    return
  fi
  [[ "$choice" == 1 || "$choice" == 2 ]] || die "请选择 1–3"
  [[ -x "$acme" ]] || die "请先安装 acme.sh 并完成账户配置：$acme"
  read -r -p '证书域名：' domain
  [[ "$domain" =~ ^[[:alnum:]][[:alnum:].-]*$ ]] || die "域名格式错误"
  if [[ "$choice" == 1 ]]; then
    "$acme" --issue -d "$domain" --standalone -k ec-256
  else
    read -rs -p 'Cloudflare DNS API Token：' CF_Token
    printf '\n'
    [[ -n "$CF_Token" ]] || die "请输入 API Token"
    CF_Token="$CF_Token" "$acme" --issue -d "$domain" --dns dns_cf -k ec-256
  fi
  "$acme" --install-cert -d "$domain" --ecc --fullchain-file "$cert_dir/cert.pem" \
    --key-file "$cert_dir/key.pem" --reloadcmd 'systemctl try-restart gost.service'
  printf '证书已保存。首次使用自定义证书时，请从菜单重读配置。\n'
}

read_protocol() {
  echo -e "请问您要设置哪种功能: "
  echo -e "-----------------------------------"
  echo -e "[1] tcp+udp流量转发, 不加密"
  echo -e "说明: 一般设置在国内中转机上"
  echo -e "-----------------------------------"
  echo -e "[2] 加密隧道流量转发"
  echo -e "说明: 用于转发原本加密等级较低的流量, 一般设置在国内中转机上"
  echo -e "     选择此协议意味着你还有一台机器用于接收此加密流量, 之后须在那台机器上配置协议[3]进行对接"
  echo -e "-----------------------------------"
  echo -e "[3] 解密由gost传输而来的流量并转发"
  echo -e "说明: 对于经由gost加密中转的流量, 通过此选项进行解密并转发给本机的代理服务端口或转发给其他远程机器"
  echo -e "      一般设置在用于接收中转流量的国外机器上"
  echo -e "-----------------------------------"
  echo -e "[4] 一键安装ss/socks5/http代理"
  echo -e "说明: 使用gost内置的代理协议，轻量且易于管理"
  echo -e "-----------------------------------"
  echo -e "[5] 进阶：多落地均衡负载"
  echo -e "说明: 支持各种加密方式的简单均衡负载"
  echo -e "-----------------------------------"
  echo -e "[6] 进阶：转发CDN自选节点"
  echo -e "说明: 只需在中转机设置"
  echo -e "-----------------------------------"
  read -r -p "请选择: " numprotocol

  if [ "$numprotocol" == "1" ]; then
    flag_a="nonencrypt"
  elif [ "$numprotocol" == "2" ]; then
    encrypt
  elif [ "$numprotocol" == "3" ]; then
    decrypt
  elif [ "$numprotocol" == "4" ]; then
    proxy
  elif [ "$numprotocol" == "5" ]; then
    enpeer
  elif [ "$numprotocol" == "6" ]; then
    cdn
  else
    die "无效选项"
  fi
}
read_s_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "-----------------------------------"
    read -r -s -p "请输入 SS 密码： " flag_b
    printf '\n'
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -r -s -p "请输入 SOCKS5 密码： " flag_b
    printf '\n'
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -r -s -p "请输入 HTTP 密码： " flag_b
    printf '\n'
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机哪个端口接收到的流量进行转发?"
    read -r -p "请输入: " flag_b
  fi
}
read_d_ip() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问您要设置的ss加密(仅提供常用的几种): "
    echo -e "-----------------------------------"
    echo "[1] aes-256-gcm  [2] chacha20-ietf-poly1305"
    read -r -p "请选择加密方式： " ssencrypt
    case "$ssencrypt" in
      1) flag_c=aes-256-gcm ;;
      2) flag_c=chacha20-ietf-poly1305 ;;
      *) die "无效选项" ;;
    esac
  elif [ "$flag_a" == "socks" ]; then
    echo -e "-----------------------------------"
    read -r -p "请输入socks用户名: " flag_c
  elif [ "$flag_a" == "http" ]; then
    echo -e "-----------------------------------"
    read -r -p "请输入http用户名: " flag_c
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请输入落地列表文件名"
    read -r -p "自定义但不同配置应不重复，不用输入后缀，例如ips1、iplist2: " flag_c
    [[ "$flag_c" =~ ^[a-zA-Z0-9_-]+$ ]] || die "列表名格式错误"
    safe_directory "$config_dir/peers"
    [[ ! -e "$config_dir/peers/$flag_c.txt" && ! -e "/root/$flag_c.txt" ]] ||
      die "落地列表已存在，请使用不同名称"
    : > "$stage/peers"
    while true; do
      read -r -p "落地 IP 或域名： " peer_ip
      read -r -p "落地端口： " peer_port
      printf '%s:%s\n' "$peer_ip" "$peer_port" >> "$stage/peers"
      read -r -p "继续添加落地？[y/N] " addyn
      [[ "$addyn" == [Yy] ]] || break
    done
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "将本机从${flag_b}接收到的流量转发向的自选ip:"
    read -r -p "请输入: " flag_c
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
    echo -e "[1] 80"
    echo -e "[2] 443"
    echo -e "[3] 自定义端口（如8080等）"
    read -r -p "请选择端口: " cdnport
    if [ "$cdnport" == "1" ]; then
      flag_c="$flag_c:80"
    elif [ "$cdnport" == "2" ]; then
      flag_c="$flag_c:443"
    elif [ "$cdnport" == "3" ]; then
      read -r -p "请输入自定义端口: " customport
      flag_c="$flag_c:$customport"
    else
      die "无效选项"
    fi
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向哪个IP或域名?"
    echo -e "注: IP既可以是[远程机器/当前机器]的公网IP, 也可是以本机本地回环IP(即127.0.0.1)"
    echo -e "具体IP地址的填写, 取决于接收该流量的服务正在监听的IP(详见: https://github.com/KANIKIG/Multi-EasyGost)"
    if [[ ${is_cert} == [Yy] ]]; then
      echo -e "注意: 落地机开启自定义tls证书，务必填写域名"
    fi
    read -r -p "请输入: " flag_c
  fi
}
read_d_port() {
  if [ "$flag_a" == "ss" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置ss代理服务的端口?"
    read -r -p "请输入: " flag_d
  elif [ "$flag_a" == "socks" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置socks代理服务的端口?"
    read -r -p "请输入: " flag_d
  elif [ "$flag_a" == "http" ]; then
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要设置http代理服务的端口?"
    read -r -p "请输入: " flag_d
  elif [[ "$flag_a" == "peer"* ]]; then
    echo -e "------------------------------------------------------------------"
    echo -e "您要设置的均衡负载策略: "
    echo -e "-----------------------------------"
    echo -e "[1] round - 轮询"
    echo -e "[2] random - 随机"
    echo -e "[3] fifo - 自上而下"
    echo -e "-----------------------------------"
    read -r -p "请选择均衡负载类型: " numstra

    if [ "$numstra" == "1" ]; then
      flag_d="round"
    elif [ "$numstra" == "2" ]; then
      flag_d="random"
    elif [ "$numstra" == "3" ]; then
      flag_d="fifo"
    else
      die "无效选项"
    fi
  elif [[ "$flag_a" == "cdn"* ]]; then
    echo -e "------------------------------------------------------------------"
    read -r -p "请输入host:" flag_d
  else
    echo -e "------------------------------------------------------------------"
    echo -e "请问你要将本机从${flag_b}接收到的流量转发向${flag_c}的哪个端口?"
    read -r -p "请输入: " flag_d
    if [[ ${is_cert} == [Yy] ]]; then
      flag_d="$flag_d?secure=true"
    fi
  fi
}
encrypt() {
  echo -e "请问您要设置的转发传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls隧道"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  echo -e "-----------------------------------"
  read -r -p "请选择转发传输类型: " numencrypt

  if [ "$numencrypt" == "1" ]; then
    flag_a="encrypttls"
    echo -e "注意: 选择 是 将针对落地的自定义证书开启证书校验保证安全性，稍后落地机务必填写域名"
    read -r -p "落地机是否开启了自定义tls证书？[y/n]:" is_cert
  elif [ "$numencrypt" == "2" ]; then
    flag_a="encryptws"
  elif [ "$numencrypt" == "3" ]; then
    flag_a="encryptwss"
    echo -e "注意: 选择 是 将针对落地的自定义证书开启证书校验保证安全性，稍后落地机务必填写域名"
    read -r -p "落地机是否开启了自定义tls证书？[y/n]:" is_cert
  else
    die "无效选项"
  fi
}
enpeer() {
  echo -e "请问您要设置的均衡负载传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] tls隧道"
  echo -e "[3] ws隧道"
  echo -e "[4] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认同一配置的传输类型相同"
  echo -e "此脚本仅支持简单型均衡负载，具体可参考官方文档"
  echo -e "gost均衡负载官方文档：https://gost.run/concepts/selector/"
  echo -e "-----------------------------------"
  read -r -p "请选择转发传输类型: " numpeer

  if [ "$numpeer" == "1" ]; then
    flag_a="peerno"
  elif [ "$numpeer" == "2" ]; then
    flag_a="peertls"
  elif [ "$numpeer" == "3" ]; then
    flag_a="peerws"
  elif [ "$numpeer" == "4" ]; then
    flag_a="peerwss"

  else
    die "无效选项"
  fi
}
cdn() {
  echo -e "请问您要设置的CDN传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] 不加密转发"
  echo -e "[2] ws隧道"
  echo -e "[3] wss隧道"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！"
  echo -e "此功能只需在中转机设置"
  echo -e "-----------------------------------"
  read -r -p "请选择CDN转发传输类型: " numcdn

  if [ "$numcdn" == "1" ]; then
    flag_a="cdnno"
  elif [ "$numcdn" == "2" ]; then
    flag_a="cdnws"
  elif [ "$numcdn" == "3" ]; then
    flag_a="cdnwss"
  else
    die "无效选项"
  fi
}
decrypt() {
  echo -e "请问您要设置的解密传输类型: "
  echo -e "-----------------------------------"
  echo -e "[1] tls"
  echo -e "[2] ws"
  echo -e "[3] wss"
  echo -e "注意: 同一则转发，中转与落地传输类型必须对应！本脚本默认开启tcp+udp"
  echo -e "-----------------------------------"
  read -r -p "请选择解密传输类型: " numdecrypt

  if [ "$numdecrypt" == "1" ]; then
    flag_a="decrypttls"
  elif [ "$numdecrypt" == "2" ]; then
    flag_a="decryptws"
  elif [ "$numdecrypt" == "3" ]; then
    flag_a="decryptwss"
  else
    die "无效选项"
  fi
}
proxy() {
  echo -e "------------------------------------------------------------------"
  echo -e "请问您要设置的代理类型: "
  echo -e "-----------------------------------"
  echo -e "[1] shadowsocks"
  echo -e "[2] socks5(强烈建议加隧道用于Telegram代理)"
  echo -e "[3] http"
  echo -e "-----------------------------------"
  read -r -p "请选择代理类型: " numproxy
  if [ "$numproxy" == "1" ]; then
    flag_a="ss"
  elif [ "$numproxy" == "2" ]; then
    flag_a="socks"
  elif [ "$numproxy" == "3" ]; then
    flag_a="http"
  else
    die "无效选项"
  fi
}

usage() {
  cat <<'EOF'
用法：bash gost.sh [命令]
  install [latest|v3.x.y]   全新安装
  migrate [latest|v3.x.y]   从原版 v2 迁移
  upgrade [latest|v3.x.y]   升级已安装的 v3
  rollback-v2               恢复迁移前的 v2 服务与规则
  render RAWCONF            输出 v3 JSON（包含代理凭据）
  list                      查看规则
省略命令时显示交互菜单。
EOF
}

main() {
  local action=${1:-menu} tag=${2:-latest} answer
  case "$action" in
    -h|--help) usage; return ;;
    render)
      [[ $# == 2 ]] || die "请指定 rawconf 路径"
      render "$2"
      return
      ;;
  esac

  (( EUID == 0 )) || die "请用 sudo 或 root 运行"
  local command_name path
  for command_name in python3 curl tar sha256sum flock systemctl; do
    command -v "$command_name" >/dev/null || die "缺少依赖 $command_name"
  done
  systemctl show -p Version --value >/dev/null || die "需要正在运行的 systemd"
  safe_directory "$config_dir"
  for path in "$raw_conf_path" "$v3_config" "$config_dir/config.json"; do
    [[ ! -L "$path" ]] || die "配置文件是符号链接：$path"
    [[ ! -e "$path" || ( -f "$path" && -O "$path" ) ]] || die "配置文件须由 root 拥有：$path"
  done
  [[ ! -L "$config_dir/.multi-easygost.lock" ]] || die "锁文件是符号链接"
  exec 9>"$config_dir/.multi-easygost.lock"
  flock -n 9 || die "另一个 Multi-EasyGost 管理操作正在进行"
  stage=$(mktemp -d "$config_dir/.stage.XXXXXX")
  trap 'rm -rf -- "$stage"' EXIT

  if [[ "$action" == menu ]]; then
    cat <<'EOF'
Multi-EasyGost · GOST v3
 1. 安装最新稳定版       2. 升级 v3              3. 卸载 v3 服务
 4. 启动                5. 停止                 6. 重读规则并重启
 7. 新增规则            8. 查看规则             9. 删除规则
10. 定时重启           11. TLS 证书            12. 从 v2 迁移
13. 回退到 v2
EOF
    read -r -p '请选择 [1–13]：' action
  fi
  case "$action" in
    1|install) install_v3 install "$tag" ;;
    2|upgrade) upgrade "$tag" ;;
    3)
      read -r -p '确认卸载 v3 服务？[y/N] ' answer
      [[ "$answer" != [Yy] ]] || uninstall
      ;;
    4) require_v3; systemctl start gost.service ;;
    5) require_v3; systemctl stop gost.service ;;
    6) restart_with_rules ;;
    7) add_rule ;;
    8|list) show_rules ;;
    9) delete_rule ;;
    10) cron_restart ;;
    11) require_v3; cert ;;
    12|migrate) install_v3 migrate "$tag" ;;
    13|rollback-v2) restore_v2 ;;
    *) usage >&2; exit 1 ;;
  esac
}

main "$@"
