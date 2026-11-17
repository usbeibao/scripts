#!/usr/bin/env bash
# 交互菜单：sudo bash xray_dual_version.sh
set -euo pipefail
umask 077

old_ver=25.10.15
new_ver=26.10.31
bindir=/usr/local/bin
old_bin=$bindir/xray
new_bin=$bindir/xray-new
old_conf=/usr/local/etc/xray
new_conf=/usr/local/etc/xray-new
old_geo=${XRAY_LOCATION_ASSET:-/usr/local/share/xray}
new_geo=/usr/local/share/xray-new
unit=/etc/systemd/system/xray-new.service

die() { echo "$*" >&2; exit 1; }
action=${1:-}
instance=xray
case "$action" in
    -h|--help)
        echo "用法：sudo bash $0 [--upgrade-xray|--install-new|--install-new-only]"
        echo "      sudo bash $0 --upgrade-latest {xray|xray-new}"
        echo "不带参数打开菜单。--install-new 依次切换主实例到 $old_ver 并安装第二实例。"
        exit 0 ;;
    --upgrade-latest)
        [[ $# == 2 && ( $2 == xray || $2 == xray-new ) ]] || die "请在 --upgrade-latest 后指定 xray 或 xray-new。"
        instance=$2 ;;
    ''|--upgrade-xray|--install-new|--install-new-only)
        (( $# <= 1 )) || die "参数过多，请查看 --help。" ;;
    *) die "未知参数：$1" ;;
esac
(( EUID == 0 )) || die "请使用 sudo bash $0 运行。"
interactive=false
if [[ -z "$action" ]]; then
    interactive=true
    echo "Xray 双版本管理"
    echo "1) 将 xray 切换到固定版本 $old_ver"
    echo "2) 安装 xray-new $new_ver"
    echo "3) 将 xray 切换到 $old_ver 并安装 xray-new"
    echo "4) 升级到官方最新正式版（选择 xray 或 xray-new）"
    echo "0) 退出"
    while true; do
        read -r -p "请选择 [0-4]：" choice || exit 0
        case "$choice" in
            1) action=--upgrade-xray; break ;;
            2) action=--install-new-only; break ;;
            3) action=--install-new; break ;;
            4) action=--upgrade-latest; break ;;
            0) exit 0 ;;
            *) echo "请输入 0 到 4 之间的数字。" ;;
        esac
    done
    if [[ $action == --upgrade-latest ]]; then
        printf '%s\n' '请选择要升级的实例' '1) xray' '2) xray-new' '0) 退出'
        while true; do
            read -r -p "请选择 [0-2]：" choice || exit 0
            case "$choice" in
                1|xray) instance=xray; break ;;
                2|xray-new) instance=xray-new; break ;;
                0) exit 0 ;;
                *) echo "请输入 1、2 或 0。" ;;
            esac
        done
    fi
fi
if [[ $instance == xray-new ]]; then
    [[ -x "$new_bin" && -f "$new_conf/config.json" ]] || die "找不到 xray-new 的程序或配置，请先安装第二实例。"
else
    [[ -x "$old_bin" && -d "$old_conf" ]] || die "找不到已有的 xray 程序或配置目录。"
fi
[[ $(systemctl show -p LoadState --value "$instance.service") == loaded ]] || die "未找到可用的 $instance.service。"
case "$(uname -m)" in
    x86_64|amd64) arch=64 ;;
    aarch64|arm64) arch=arm64-v8a ;;
    *) die "仅支持 Linux x86_64 / ARM64。" ;;
esac

exec 9>>/run/xray-dual-version.lock
flock -n 9 || die "已有另一个升级进程在运行。"
stage=$(mktemp -d "$bindir/.xray-stage.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT

version_of() { "$1" version | awk 'NR == 1 && $1 == "Xray" {print $2}'; }

latest_release() {
    curl -fLsS --retry 2 --connect-timeout 10 --max-time 30 \
        -H 'Accept: application/vnd.github+json' \
        https://api.github.com/repos/XTLS/Xray-core/releases/latest \
        -o "$stage/release.json" || die "无法查询 XTLS/Xray-core 最新正式版。"
    python3 - "$stage/release.json" "Xray-linux-$arch.zip" <<'PY'
import json
import re
import sys

metadata, filename = sys.argv[1:]
try:
    with open(metadata, encoding="utf-8") as f:
        release = json.load(f)
except (OSError, ValueError) as exc:
    sys.exit(f"无法读取官方发布信息：{exc}")

if not isinstance(release, dict) or release.get("draft") is not False or release.get("prerelease") is not False:
    sys.exit("官方响应中没有可用的正式版。")
tag = re.fullmatch(r"v([0-9]+\.[0-9]+\.[0-9]+)", release.get("tag_name") or "")
if not tag:
    sys.exit("无法识别官方版本标签。")
for asset in release.get("assets", []):
    if asset.get("name") == filename and asset.get("state") == "uploaded":
        digest = re.fullmatch(r"sha256:([0-9a-fA-F]{64})", asset.get("digest") or "")
        if not digest:
            sys.exit(f"官方发布信息中缺少 {filename} 的有效 SHA-256。")
        print(tag.group(1), digest.group(1).lower())
        break
else:
    sys.exit(f"官方发布中未找到 {filename}。")
PY
}

download_core() {
    local ver=$1 dst=$2 sha=${3:-}
    if [[ -z $sha ]]; then
        # 固定版本的官方发行包摘要。
        case "$ver/$arch" in
            25.10.15/64) sha=df22ad60c1251c9fb63d7f85b3677872edf61c6715eba64b06adbfec658f4938 ;;
            25.10.15/arm64-v8a) sha=67ea391812f90fa17e29a60c8faa834bcf30ead0f84eb6b2bbd2d398d56b759e ;;
            26.10.31/64) sha=e4bd9119f50ae7c41658b1abd0679ae06f98bd864a2907ff33f2f2cf7081b214 ;;
            26.10.31/arm64-v8a) sha=1811c8f1da0c3b6dc707ebaf1c8390e987ba39859a8f0a7aadd8526157f2ec8d ;;
            *) die "未登记的发行包：$ver/$arch" ;;
        esac
    fi
    curl -fLsS --retry 2 --connect-timeout 10 --max-time 180 \
        "https://github.com/XTLS/Xray-core/releases/download/v$ver/Xray-linux-$arch.zip" -o "$stage/core.zip"
    printf '%s  %s\n' "$sha" "$stage/core.zip" | sha256sum -c -
    unzip -p "$stage/core.zip" xray > "$dst"
    chmod 0755 "$dst"
    [[ $(version_of "$dst") == "$ver" ]] || die "解包程序的版本与 $ver 不符。"
}

wait_listening() {
    local svc=$1 bin=$2 attempt pid
    for attempt in {1..8}; do
        sleep 1
        pid=$(systemctl show -p MainPID --value "$svc") || continue
        if [[ $pid =~ ^[1-9][0-9]*$ && /proc/$pid/exe -ef "$bin" ]] &&
           systemctl is-active --quiet "$svc" &&
           ss -H -lntup | grep -F "pid=$pid," >/dev/null; then
            return 0
        fi
    done
    return 1
}

geo_for_service() {
    local svc=$1 pid=$2 setting live_geo='' unit_env
    if [[ $pid =~ ^[1-9][0-9]*$ && -r /proc/$pid/environ ]]; then
        while IFS= read -r -d '' setting; do
            case "$setting" in
                xray.location.asset=?*) printf '%s\n' "${setting#*=}"; return ;;
                XRAY_LOCATION_ASSET=?*) live_geo=${setting#*=} ;;
            esac
        done <"/proc/$pid/environ"
    fi
    if [[ -n $live_geo || -n ${XRAY_LOCATION_ASSET:-} ]]; then
        printf '%s\n' "${live_geo:-$old_geo}"
        return
    fi
    # 已停止的实例仍可从 systemd 单元中取得自己的 Geo 目录。
    unit_env=$(systemctl show -p Environment --value "$svc") || return 1
    if [[ $unit_env == *XRAY_LOCATION_ASSET=* || $unit_env == *xray.location.asset=* ]]; then
        python3 -c '
import shlex, sys
env = dict(item.split("=", 1) for item in shlex.split(sys.stdin.read()) if "=" in item)
print(env.get("xray.location.asset") or env.get("XRAY_LOCATION_ASSET") or sys.argv[1])
' "$old_geo" <<< "$unit_env"
    else
        printf '%s\n' "$old_geo"
    fi
}

upgrade_instance() {
    local target=$1 sha=${2:-} svc="$instance.service" bin=$old_bin other_bin=$new_bin
    local disk live='' pid='' state candidate backup source current assets
    local -a config_args=(-confdir "$old_conf")
    if [[ $instance == xray-new ]]; then
        bin=$new_bin
        other_bin=$old_bin
        config_args=(-config "$new_conf/config.json")
    fi
    disk=$(version_of "$bin")
    [[ -n "$disk" ]] || die "无法识别 $bin 的版本。"
    state=$(systemctl show -p ActiveState --value "$svc")
    case "$state" in
        active)
            pid=$(systemctl show -p MainPID --value "$svc")
            live=$(version_of "/proc/$pid/exe")
            [[ -n "$live" ]] || die "无法识别运行中的 $instance。"
            ;;
        inactive|failed) ;;
        *) die "$svc 正处于 $state 状态，请等状态稳定后重试。" ;;
    esac
    if [[ $action == --upgrade-latest ]]; then
        echo "$instance 磁盘版本 $disk，运行版本 ${live:-未运行}，官方最新正式版 $target。"
        for current in "$disk" "$live"; do
            if [[ -n $current ]] && dpkg --compare-versions "${current%%[-+]*}" gt "$target"; then
                echo "本机版本 $current 高于 $target，跳过。"
                return
            fi
        done
    fi
    if [[ "$disk" == "$target" && ( -z "$live" || "$live" == "$target" ) ]]; then
        echo "$instance 已是 $target（$state），跳过。"
        return
    fi
    if [[ -e "$other_bin" && $(readlink -f "$bin") == "$(readlink -f "$other_bin")" ]]; then
        die "两套核心指向同一程序，无法独立替换 $instance。"
    fi

    candidate=$bin
    if [[ "$disk" != "$target" ]]; then
        candidate=$stage/$instance
        download_core "$target" "$candidate" "$sha"
    fi
    assets=$(geo_for_service "$svc" "$pid")
    echo "使用 $assets 的 Geo 数据校验 ${config_args[*]}。"
    XRAY_LOCATION_ASSET="$assets" "$candidate" run -test "${config_args[@]}"

    backup="$bin.bak.$(date +%Y%m%d-%H%M%S).$$"
    source=$bin
    if [[ -n "$pid" && ! /proc/$pid/exe -ef "$bin" ]]; then source="/proc/$pid/exe"; fi
    cp -pL -- "$source" "$backup"
    echo "原核心备份：$backup"
    if [[ "$candidate" != "$bin" ]]; then mv -fT -- "$candidate" "$bin"; fi
    if [[ "$state" != active ]]; then
        echo "磁盘版已更新为 $target，服务原状态为 $state。"
        return
    fi
    if systemctl restart "$svc" && wait_listening "$svc" "$bin"; then
        echo "$instance $target 已运行并监听。"
        return
    fi
    journalctl -u "$svc" -n 15 --no-pager >&2 || true
    cp -p -- "$backup" "$stage/restore"
    mv -fT -- "$stage/restore" "$bin"
    systemctl reset-failed "$svc" || true
    if systemctl restart "$svc" && wait_listening "$svc" "$bin"; then
        die "$instance 升级后的启动验证失败，已恢复 $live 并确认监听。"
    fi
    die "已恢复原程序，但服务仍未就绪。请查看 journalctl -u $svc。"
}

# 首次创建第二实例。
install_new() (
    if systemctl cat xray-new.service >/dev/null 2>&1; then
        echo "已有 xray-new.service，跳过首次安装。"
        return
    fi
    for path in "$new_bin" "$new_conf/config.json" "$unit"; do
        [[ ! -e "$path" && ! -L "$path" ]] || die "发现已有文件：$path。保留现场，跳过安装。"
    done
    if "$interactive"; then
        read -r -p "REALITY 端口偏移量 [${XRAY_PORT_OFFSET:-2000}]：" offset || exit 1
        XRAY_PORT_OFFSET=${offset:-${XRAY_PORT_OFFSET:-2000}}
    fi
    pid=$(systemctl show -p MainPID --value xray.service)
    # 如已为新实例准备了单独的第三方数据，使用该目录。否则直接读取原实例的数据。
    assets=$(geo_for_service xray.service "$pid")
    for name in geoip.dat geosite.dat; do
        if [[ -e "$new_geo/$name" || -L "$new_geo/$name" ]]; then assets=$new_geo; fi
    done
    for name in geoip.dat geosite.dat; do
        [[ -r "$assets/$name" && -s "$assets/$name" ]] || die "第三方数据缺失或不可读：$assets/$name"
    done

    python3 - "$old_conf/config.json" "$stage/config.json" "${XRAY_PORT_OFFSET:-2000}" <<'PY'
import json, subprocess, sys

source, output, offset = sys.argv[1:]
if not offset.isascii() or not offset.isdigit() or not 1 <= int(offset) <= 65534:
    sys.exit("XRAY_PORT_OFFSET 必须是 1～65534 的整数")
with open(source) as f:
    config = json.load(f)
items = [i for i in config["inbounds"] if i.get("streamSettings", {}).get("security") == "reality"]
if not items:
    sys.exit("旧配置没有 REALITY 入站")
for item in items:
    old = str(item.get("port"))
    if not old.isascii() or not old.isdigit() or not 1 <= int(old) <= 65535 - int(offset):
        sys.exit(f"无法转换 REALITY 端口：{old}")
    new = int(old) + int(offset)
    if subprocess.check_output(["ss", "-H", "-lntu", f"sport = :{new}"]).strip():
        sys.exit(f"端口 {new} 已在使用")
    print(f"REALITY {old} -> {new}")
    item["port"] = new
config["inbounds"] = items
with open(output, "w") as f:
    json.dump(config, f, indent=2, ensure_ascii=False)
    f.write("\n")
PY
    download_core "$new_ver" "$stage/xray-new"
    XRAY_LOCATION_ASSET="$assets" "$stage/xray-new" run -test -config "$stage/config.json"
    asset_setting=$(python3 -c 'import json, sys; print(json.dumps("XRAY_LOCATION_ASSET=" + sys.argv[1].replace("%", "%%"), ensure_ascii=False))' "$assets")
    cat >"$stage/xray-new.service" <<EOF
[Unit]
Description=Xray New Instance
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=root
Environment=$asset_setting
ExecStart=$new_bin run -config $new_conf/config.json
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
UMask=0077
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
EOF
    created=()
    own_dir=false
    undo_new() {
        local rc=$?
        if (( rc != 0 )); then
            if [[ -f "$unit" ]]; then systemctl disable --now xray-new.service >/dev/null 2>&1 || true; fi
            if (( ${#created[@]} )); then rm -f -- "${created[@]}"; fi
            if "$own_dir"; then rmdir "$new_conf" 2>/dev/null || true; fi
            systemctl daemon-reload || true
        fi
    }
    trap undo_new EXIT
    if [[ ! -d "$new_conf" ]]; then mkdir -m 0700 "$new_conf"; own_dir=true; fi
    created+=("$new_conf/config.json")
    install -m 0600 "$stage/config.json" "$new_conf/config.json"
    created+=("$new_bin")
    install -m 0755 "$stage/xray-new" "$new_bin"
    created+=("$unit")
    install -m 0644 "$stage/xray-new.service" "$unit"
    systemctl daemon-reload
    systemctl enable --now xray-new.service
    if ! wait_listening xray-new.service "$new_bin"; then
        journalctl -u xray-new.service -n 15 --no-pager >&2 || true
        die "xray-new 启动验证失败，撤销本次新建的实例文件。"
    fi
    echo "xray-new $new_ver 已启动并设为开机自启，Geo 目录：$assets"
)

case "$action" in
    --upgrade-xray) upgrade_instance "$old_ver" ;;
    --upgrade-latest)
        release_info=$(latest_release)
        read -r target_version asset_sha <<< "$release_info"
        upgrade_instance "$target_version" "$asset_sha"
        ;;
    --install-new-only) install_new ;;
    --install-new) upgrade_instance "$old_ver"; install_new ;;
esac
