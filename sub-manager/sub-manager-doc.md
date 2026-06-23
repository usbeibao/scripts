# 自托管订阅系统 — 安装与维护手册

> 一套自用的代理订阅分发系统。节点服务器(sing-box / Xray)把节点推送到中心面板(sub-manager),
> 面板按客户端类型(Clash/Loon/圈X/小火箭/v2rayN/Stash)生成订阅,分发给自己和朋友。
>
> 最后更新:2026-06(含 节点健康检查/备注、Token生命周期、Telegram /sub+主动告警、批量编辑、异地备份、面板重建、menu.sh 总控、leitbogioro DD)

---

## 目录

1. [系统架构](#1-系统架构)
2. [组件清单](#2-组件清单)
3. [中心面板 sub-manager 部署](#3-中心面板-sub-manager-部署)
4. [节点服务器开荒](#4-节点服务器开荒)
5. [menu.sh 总控用法](#5-menush-总控用法)
6. [脚本变量速查](#6-脚本变量速查)
7. [Xray 机器接入](#7-xray-机器接入)
8. [面板功能与日常维护](#8-面板功能与日常维护)
9. [排错](#9-排错)
10. [凭据清单](#10-凭据清单)

---

## 1. 系统架构

```
                         ┌─────────────────────────────┐
   节点服务器(多台)        │   中心面板 sub-manager        │       客户端
                         │   (Oracle 大阪, 墙外)          │
  ┌──────────────┐       │                              │    ┌──────────┐
  │ sing-box 机   │──推送→│  Flask + SQLite + Docker     │←订阅─│ Clash    │
  │ menu.sh→      │       │  https://sub-manager.        │    │ Loon     │
  │ reality.sh    │       │       202205.xyz             │    │ 圈X      │
  └──────────────┘       │  - 节点管理/去重/运营商命名    │    │ 小火箭   │
  ┌──────────────┐       │  - 节点健康检查(TCP探测)      │    │ v2rayN   │
  │ Xray 机       │──推送→│  - Token(地区/正则过滤)      │    │ Stash    │
  │ xray_to_sub.sh│       │  - 7+ 客户端订阅格式生成       │    └──────────┘
  └──────────────┘       │  - 模板编辑/规则映射/订阅预览  │
                         │  - CF DNS 自动解析            │
                         └─────────────────────────────┘
```

**数据流**:节点机装好代理 → 脚本 POST 节点参数到面板 `/api/nodes/push` → 面板存 SQLite →
客户端拉 `https://sub-manager.202205.xyz/sub/<token>?target=clash` → 面板按 target 实时生成对应格式订阅。

**关键设计**:面板在墙外(查 IP 归属/运营商通畅、分发不受 GFW 影响);节点凭据全客户端共用(自用规模);朋友每人独立 token(可单独过滤地区/禁用/看访问记录)。

---

## 2. 组件清单

### 中心面板
| 文件 | 说明 |
|------|------|
| `sub-manager.zip` | 面板全部代码(Flask + Vue 单文件前端 + Docker) |

### 节点脚本(传到节点服务器,放同一目录)
| 脚本 | 用途 | 放哪台机器 |
|------|------|-----------|
| `menu.sh` | **总控入口**(菜单调用下列脚本) | sing-box 机 / 任意节点机 |
| `init.sh` | 系统初始化(SSH/fail2ban/smartdns/工具) | 新机器 |
| `reality.sh` | 装 sing-box 四协议 + 推送 | sing-box 机 |
| `push_to_sub.sh` | sing-box 节点推送(被 reality.sh 调用) | sing-box 机 |
| `xray_to_sub.sh` | 从现有 Xray 提取节点推送 | Xray 机 |
| `common_lib.sh` | 公共库(地区探测/时区映射/IP探测) | **所有节点机**(跟脚本同目录) |
| `backup_db.sh` | 面板 DB 定时备份(本地+GDrive异地) | 面板宿主机 |
| `restore.sh` + `RESTORE.md` | 面板灾难重建(拉代码+恢复DB+起容器) | 面板宿主机 |

### DD 重装(系统重装)
| 工具 | 说明 |
|------|------|
| leitbogioro `InstallNET.sh` | 推荐。审计干净、活跃维护、支持 Debian 13 / Ubuntu 新版 |

---

## 3. 中心面板 sub-manager 部署

### 3.1 首次部署
```bash
scp sub-manager.zip oracle-osaka-1:/opt/
ssh oracle-osaka-1
cd /opt && unzip -o sub-manager.zip
cd sub-manager
cp .env.example .env
vim .env     # 改 ADMIN_PASSWORD / PUSH_TOKEN / CF_API_TOKEN(cfut_用户令牌)
docker compose up -d --build
curl -s -o /dev/null -w "%{http_code}\n" http://127.0.0.1:8000/   # 期望 200
```

`.env` 关键项:
```ini
ADMIN_PASSWORD=面板登录密码          # 必改
PUSH_TOKEN=随机长字符串              # 节点推送鉴权, 必改
CF_API_TOKEN=cfut_xxx               # CF DNS 自动解析(用户令牌, 不是 cfat_)
```

### 3.2 Nginx 反代
面板容器监听 `127.0.0.1:8000`,nginx 反代到 `https://sub-manager.202205.xyz`(CF 橙云):
```nginx
location / {
    proxy_pass http://127.0.0.1:8000;
    proxy_set_header Host $host;
    proxy_set_header X-Forwarded-For $remote_addr;   # token 访问记录靠这个拿真实IP
    proxy_set_header X-Forwarded-Proto $scheme;
}
```

### 3.3 更新面板(保留数据 + 本地配置)
```bash
scp sub-manager.zip oracle-osaka-1:/opt/
cd /opt
cp -r sub-manager sub-manager.bak.$(date +%Y%m%d)   # 保险备份
# 排除 docker-compose.yml 和 .env(保留本地配置), data 目录不动(SQLite持久化)
unzip -o sub-manager.zip -x "sub-manager/docker-compose.yml" -x "sub-manager/.env"
cd sub-manager && docker compose up -d --build
```
> 更新后浏览器 **Ctrl+F5 强刷**(index.html 变了,清缓存)。

### 3.4 部署前比对(可选,确认无意外改动)
```bash
cd /opt/sub-manager
find . -type f -not -path '*/__pycache__/*' -not -name '*.pyc' \
  -not -path './data/*' -not -path './backups/*' -not -name '.node-env' \
  | sort | xargs md5sum 2>/dev/null
```
逐文件哈希,和新 zip 对比,确认只有预期文件不同(docker-compose.yml 是本地配置,排除即可)。

---

## 4. 节点服务器开荒

### 4.1 DD 重装系统(leitbogioro)
```bash
sudo -s; cd ~
apt install wget -y 2>/dev/null || yum install wget -y 2>/dev/null
wget --no-check-certificate -qO InstallNET.sh \
  'https://raw.githubusercontent.com/leitbogioro/Tools/master/Linux_reinstall/InstallNET.sh' \
  && chmod a+x InstallNET.sh

# Debian 13(走官方源)
bash InstallNET.sh -debian 13 -v 64 -pwd "你的强密码" -port 22 -a
# Ubuntu 新版(Alpine跳板 + cloud image)
bash InstallNET.sh -ubuntu 24.04 -v 64 -pwd "你的强密码" -port 22 -a
```
- `-pwd` **必填**(默认密码 LeitboGi0ro 是公开的)
- `-a` 自动模式(无人值守)
- 装完用新密码登录,先验证:`cat /etc/apt/sources.list`(应为 trixie 不是 bookworm)、`apt update`(无冲突)
- `yum: command not found` 是无害噪音(跨发行版逻辑跑空一句),不影响

### 4.2 开荒(menu.sh 一键梭哈)
```bash
# 传脚本到新机同一目录(menu/init/reality/push_to_sub/common_lib)
scp menu.sh init.sh reality.sh push_to_sub.sh common_lib.sh root@新机IP:/root/
ssh root@新机IP
cd /root && chmod +x *.sh
bash menu.sh
# 选 1) 一键梭哈, 首次会问 SUB_API/PUSH_TOKEN/NODE_NAME/REGION/DOMAIN, 存入 .node-env
```
一键梭哈流程:init.sh(不重启)→ 装 sing-box(无人值守)→ 地区自动探测 → 清理旧节点 → 推送 → 自检 → 统一问重启。

---

## 5. menu.sh 总控用法

```
╔══════════ 节点机总控 ══════════╗
  当前: NODE_NAME=xxx  REGION=(自动探测)
  域名: (无, Hy2/TUIC自签)  推送: https://...
╠════════════════════════════════╣
  1) 一键梭哈 (init + sing-box + 推送)
  2) 重装/更新 sing-box 配置并推送
  3) 提取并推送 Xray 配置
  4) 系统初始化 (init.sh)
  5) 节点状态查看
  9) 重新配置 (SUB_API/Token/地区)
  0) 退出
╚════════════════════════════════╝
```

- **配置存 `.node-env`**(同目录,权限600):首次交互填,之后免输。含 SUB_API/PUSH_TOKEN/NODE_NAME/NODE_REGION/NODE_DOMAIN/CF_API_TOKEN
- 调用同目录脚本(`SCRIPT_DIR` 定位),缺脚本会提示
- 一键梭哈时 init 用 `NO_REBOOT=1`(不中途重启),装完统一问

---

## 6. 脚本变量速查

### menu.sh / .node-env
| 变量 | 说明 |
|------|------|
| SUB_API | 面板地址 |
| PUSH_TOKEN | 面板部署 token |
| NODE_NAME | 节点标识(命名 `NODE_NAME-Reality` 等) |
| NODE_REGION | 地区码,空=自动探测 |
| NODE_DOMAIN | 域名(填了配真证书) |
| CF_API_TOKEN | CF 用户令牌(cfut_,真证书+解析) |

### init.sh
| 变量/参数 | 默认 | 说明 |
|------|------|------|
| `$1` github用户名 | — | 拉 SSH key;空则跳过(保留密码登录防锁死) |
| `$2` 新用户名 | — | 创建的 sudo 用户 |
| `SSH_PORT` | 38658 | SSH 端口(fail2ban 自动联动) |
| `NO_REBOOT` | — | =1 跳过末尾重启(menu 梭哈用) |

### reality.sh(sing-box)
| 变量 | 默认 | 说明 |
|------|------|------|
| `SUB_API` `PUSH_TOKEN` | — | 推送(填了 PUSH_TOKEN 即无人值守) |
| `NONINTERACTIVE` | — | =1 强制无人值守 |
| `NODE_NAME` | hostname | 节点标识 |
| `NODE_REGION` | 自动探测 | 地区码 |
| `TZ` | 按地区 | 强制时区 |
| `REALITY_PORT` | 443 | reality 端口 |
| `SS_PORT/HY2_PORT/TUIC_PORT` | 随机 | 各协议端口 |
| `NODE_DOMAIN` + `CF_API_TOKEN` | — | 配真证书(cfut_令牌) |

### xray_to_sub.sh
| 变量 | 必填 | 说明 |
|------|------|------|
| `SUB_API` `PUSH_TOKEN` | 是 | 推送 |
| `NODE_NAME` | 建议 | 节点标识 |
| `NODE_REGION` | 可选 | 空=自动探测 |
| `XRAY_CONFIG` | 可选 | 默认 `/usr/local/etc/xray/config.json` |
| `CLEANUP_OLD` | 1 | 推送前清同机器旧节点 |

### backup_db.sh
| 变量 | 默认 |
|------|------|
| `DB_PATH` | `/opt/sub-manager/data/sub.db` |
| `BACKUP_DIR` | `/opt/sub-manager/backups` |
| `KEEP` | 14 |

---

## 7. Xray 机器接入
```bash
scp xray_to_sub.sh common_lib.sh root@xray机:/root/
ssh root@xray机 && cd /root
SUB_API="https://sub-manager.202205.xyz" PUSH_TOKEN="xxx" \
NODE_NAME="tff-hk-1" bash xray_to_sub.sh
```
提取逻辑:直连 reality 直接提取;nginx 前置节点正向追链(stream map 域名→upstream→conf.d→xray inbound 看实际协议)。

---

## 8. 面板功能与日常维护

### 8.1 面板操作(浏览器, 用 ADMIN_PASSWORD 登录)
| 操作 | 位置 |
|------|------|
| 看/管节点(分组/去重) | 节点区 |
| 🔍 检测配置 | 节点区(参数完整性 + Clash结构校验) |
| 📶 检测活性 | 节点区(TCP端口探测, 状态点显示真实可达性+延迟) |
| 批量操作 | 多选 → 批量启用/禁用、改地区、删除 |
| 节点备注 | 编辑节点填「备注」(如"6月底续费"), 列表名称下显示; 脚本重推不覆盖 |
| 模板编辑 / Clash规则映射 / 订阅预览 | 配置文件区(进阶) |
| 新建/管理 token | 令牌区(可设到期时间、IP数限制) |
| Token 到期预警 | 列表自动标黄(7天内)/标红(已过期) |
| Token IP 限制 | 超限标红「IP超限」(只告警不阻断) |
| Token 访问记录 | 令牌「访问」列(次数/IP数/详情含IP明细) |
| 复制订阅 / 二维码 | 令牌「复制订阅」 |
| DB 备份/恢复 | 标题栏「备份」 |
| 改密码 | 标题栏 |

### 8.2 节点健康检查(检测活性)
点「📶 检测活性」→ 面板 TCP 探测所有节点 server:port → 状态点变真实可达性(绿=可达/红=不可达)+ 显示延迟。
**注意**:面板在墙外,探的是**墙外可达性**(发现宕机/端口变/服务挂这类硬故障);**测不出 GFW 墙的因素**(需客户端墙内实测)。只显示不自动禁用。

### 8.3 给朋友分享 + Token 生命周期
令牌区新建 token(备注如「朋友A」)→ 可选:
- **限定地区/正则过滤**:只给某些地区或匹配的节点
- **到期时间**:临时分享设期限(如14天), 到期订阅自动失效(返404); 自己主力 token 留空=永不过期
- **IP 数限制**:防转传。设 ip_limit(如3), 该 token 访问过的不同 IP 超过时列表标红「IP超限」。**只告警不阻断**(朋友换网络/切流量IP会变, 硬断会误伤), 看到超限先点「访问详情」看 IP 明细判断是否真被转传

到期预警:列表里 7 天内到期标黄「即将到期」, 已过期标红。扫一眼就知道哪些要续期。

### 8.4 节点批量编辑
节点区勾选多个 → 批量操作栏:批量启用/禁用、改地区为...、批量删除。
用途:新推一批节点地区识别错了全选改对; 临时禁用某地区一批节点。

### 8.5 Telegram 通知(/sub 查询 + 主动告警)
sub-manager 提供只读状态接口, daily.py(TG Bot)调用, 实现查询 + 主动告警。
- **状态接口**:`GET /api/report` (REPORT_TOKEN 鉴权), 返回 token 状态(过期/即将到期/IP超限)+节点数/地区分布+一句话 summary。轻量(查库即得)
- **健康端点**:`GET /api/health` (不鉴权, 极轻量), 返回 status/db/uptime/节点数。供外部监控探活, DB正常200/异常503
- **配置**:sub-manager 的 `.env` 设 `REPORT_TOKEN`(并在 docker-compose.yml 的 environment 加 `REPORT_TOKEN: "${REPORT_TOKEN:-}"` 透传); daily.py 的 `.env` 设 `SUBMGR_API`(走域名 https://sub-manager.202205.xyz)+`SUBMGR_REPORT_TOKEN`
- **被动查**:Telegram 发 `/sub` → 立即返回状态。命令菜单在 BotFather 手动设(加新命令记得补)
- **主动告警**:daily.py 每小时探测(`run_submanager_watch`), 出事主动推 TG:
  - 面板挂了(health探不通/503) → 推「⚠️面板异常」, 恢复推「✅已恢复」
  - token 新告警(过期/即将到期/IP超限) → 只推新出现的(去重不刷屏)
  - 告警状态持久化到 `/app/logs/.submgr_alert_state.json`(容器重启不丢, 否则漏恢复告警)
  - **不含节点健康**:面板和节点都在墙外, TCP探测测不准真实可用性(GFW因素), 接告警会误报, 故节点活性靠手动「检测活性」按钮看, 不主动告警

### 8.6 给朋友分享(导入提示)
复制订阅链接或扫码给朋友。过段时间看「访问」详情确认是否导入成功(有访问次数=导入了)。

### 8.7 节点重装/更新(幂等)
节点机重跑 menu.sh(选2)或 reality.sh/xray_to_sub.sh——推送前自动清理同 NODE_NAME 旧节点,不残留。改端口、重装系统直接重跑即可。

### 8.8 DB 自动备份(本地 + GDrive 异地)
```bash
crontab -e
0 3 * * * /opt/sub-manager/backup_db.sh >> /var/log/sub-manager-backup.log 2>&1
```
backup_db.sh 流程:sqlite3 .backup → gzip → 本地 `backups/` 留14份 → **cp 到 GDrive 异地** `/opt/siftminsk_gdrive/sub-manager-backups/` 留14份。
- **异地用 GDrive**(rclone mount 挂载点), cp 前检查挂载正常(`mountpoint`), 挂载掉了则跳过+警告(避免假备份到本地空目录)
- 异地失败不影响本地备份
- 可调环境变量:`GDRIVE_DIR`/`GDRIVE_SUBDIR`/`GDRIVE_KEEP`
- 手动验证:`bash backup_db.sh` 看有无「✓ 已异地备份到 GDrive」, 再 `ls /opt/siftminsk_gdrive/sub-manager-backups/`

### 8.9 sing-box 节点维护
```bash
systemctl status sing-box / restart sing-box
journalctl -u sing-box -n 50
/usr/local/bin/sing-box check -c /etc/sing-box/config.json
ss -tunlp | grep sing-box
```

---

### 8.10 面板灾难重建(机器挂了/换机)
完整步骤见 `RESTORE.md`。核心:代码(zip)+配置(.env)+数据(DB备份)+外围(nginx/CF/cron/告警)。
```bash
# 新机器装 docker, 传 sub-manager.zip 到 /opt
curl -fsSL https://get.docker.com | sh
cd /opt && unzip -o sub-manager.zip "sub-manager/restore.sh"
bash sub-manager/restore.sh   # 自动: 解压→.env→找最新DB备份恢复→起容器→健康检查
```
- restore.sh 自动从 GDrive(或本地)找**最新** DB 备份恢复 —— 节点/token 数据全在 `data/sub.db`
- 恢复后手动补:nginx 反代、CF 解析、cron 备份、daily.py 告警配置
- **关键**:`.env` 凭据(ADMIN_PASSWORD/PUSH_TOKEN/REPORT_TOKEN/CF_API_TOKEN)务必**另存到 Vaultwarden** —— 机器全挂时 zip 能重下、DB 能从 GDrive 拉, 但凭据没另存就得全部重设(PUSH_TOKEN 一改, 所有节点机 .node-env 跟着改)

## 9. 排错

**节点推送后面板看不到**:看脚本末尾推送响应;`curl -I https://sub-manager.202205.xyz`;确认 PUSH_TOKEN 与面板 .env 一致。

**sing-box 装完连不上**:看 reality.sh 自检 [✗] 项;**云控制台安全组放行端口**(脚本只配系统防火墙):TCP REALITY(443)、TCP/UDP SS、UDP Hy2/TUIC;`journalctl -u sing-box -n 30`。

**证书申请失败 invalid domain**:CF_API_TOKEN 用错了——要 `cfut_` 用户令牌(权限 Zone:DNS:Edit),不是 `cfat_` 账户令牌。reality.sh 会预检 cfat_ 并提示降级自签。

**DD Debian 13 后 apt 报 perl/12-13冲突**:旧 DD 脚本 bug(系统装13但源写成bookworm)。用 leitbogioro 重装,或手动改 `/etc/apt/sources.list` 为 trixie 后 `apt full-upgrade`。

**Debian 13 装包报 mlocate/dnsutils/tuned 找不到**:Debian 13 改名(mlocate→plocate, dnsutils→bind9-dnsutils);tuned 是 RedHat 系不该装。init.sh/reality.sh 已兼容。

**menu.sh 选项卡住**:流媒体检测已移除(交互式脚本 stdin 冲突)。

**/sub 返回 invalid report token**:容器没读到 .env 的 REPORT_TOKEN(自己生成了另一个)。原因:docker-compose.yml 的 environment 段没透传该变量。解法:environment 加 `REPORT_TOKEN: "${REPORT_TOKEN:-}"` 后 `docker compose up -d` 重建。或直接用容器日志里自动生成的那个 token(`docker compose logs | grep 状态报告 token`)。

**daily.py 容器调 /api/report 连不上**:daily-report 和 sub-manager 是不同 compose、不同 docker 网络, 容器内 `127.0.0.1` 指容器自己。用 nginx 域名 https://sub-manager.202205.xyz(容器能上外网即可)。daily.py 的 .env 用 `env_file` 自动注入, 加 SUBMGR_API/SUBMGR_REPORT_TOKEN 即可。

**异地备份没推上去/GDrive目录空**:backup_db.sh 会先检查 `/opt/siftminsk_gdrive` 是否真挂载(rclone mount 可能掉了), 没挂载就跳过并警告。看备份日志有无「⚠ 未挂载」。重新挂载 rclone mount 即可。

**恢复告警没收到(只收到异常)**:旧版告警状态存内存, 重启 daily 容器会丢。已修为持久化到 `/app/logs/.submgr_alert_state.json`。确认该文件可写(logs 目录已挂载)。

**时区不对**:reality.sh 按地区自动设;手动 `TZ=Asia/Tokyo` 或 `timedatectl set-timezone Asia/Tokyo`。

**BBR 是否生效**:`sysctl net.ipv4.tcp_congestion_control`(应 bbr)。不用重启,sysctl --system 即时生效。

---

## 10. 凭据清单

> ⚠️ 妥善保管,DB 备份文件 + .node-env 含敏感信息,勿外泄/勿提交公开 git。

| 项 | 值 |
|------|-----|
| 面板地址 | https://sub-manager.202205.xyz |
| 面板登录密码 | `.env` 的 ADMIN_PASSWORD |
| 推送 token | `.env` 的 PUSH_TOKEN |
| 状态报告 token | `.env` 的 REPORT_TOKEN (/api/report + daily.py /sub 用) |
| CF API token | `.env` 的 CF_API_TOKEN(cfut_用户令牌) |
| CF Zone ID (202205.xyz) | 71e749cbdbcba45da7ba9a3a8f661c61 |
| 节点机配置 | 各机 `.node-env`(权限600) |
| DB 异地备份 | /opt/siftminsk_gdrive/sub-manager-backups/ (GDrive, 留14份) |

> ⚠️ **强烈建议**: 上述 `.env` 凭据另存一份到 Vaultwarden —— 机器全挂时是唯一无法从别处恢复的东西(zip能重下/DB能从GDrive拉, 凭据丢了得全部重设)。

---

## 附:常用一键命令

```bash
# DD Debian 13
bash InstallNET.sh -debian 13 -v 64 -pwd "密码" -a

# 开荒新节点机(传脚本后)
bash menu.sh   # 选 1 一键梭哈

# Xray 机提取推送
SUB_API="https://sub-manager.202205.xyz" PUSH_TOKEN="xxx" NODE_NAME="tff-hk-1" bash xray_to_sub.sh

# 面板更新(保留数据)
cd /opt && unzip -o sub-manager.zip -x "sub-manager/docker-compose.yml" -x "sub-manager/.env" && cd sub-manager && docker compose up -d --build

# DB 手动备份
DB_PATH=/opt/sub-manager/data/sub.db bash backup_db.sh
```
