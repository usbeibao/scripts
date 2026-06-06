# 自托管订阅系统 — 安装与维护手册

> 一套自用的代理订阅分发系统。节点服务器(sing-box / Xray)把节点推送到中心面板(sub-manager),
> 面板按客户端类型(Clash/Loon/圈X/小火箭/v2rayN/Stash)生成订阅,分发给自己和朋友。

---

## 目录

1. [系统架构](#1-系统架构)
2. [组件清单](#2-组件清单)
3. [中心面板 sub-manager 部署](#3-中心面板-sub-manager-部署)
4. [节点服务器开荒(DD + sing-box)](#4-节点服务器开荒)
5. [脚本变量速查](#5-脚本变量速查)
6. [Xray 机器接入](#6-xray-机器接入)
7. [日常维护](#7-日常维护)
8. [排错](#8-排错)
9. [凭据清单](#9-凭据清单)

---

## 1. 系统架构

```
                         ┌─────────────────────────────┐
   节点服务器(多台)        │   中心面板 sub-manager        │       客户端
                         │   (Oracle 大阪, 墙外)          │
  ┌──────────────┐       │                              │    ┌──────────┐
  │ sing-box 机   │──推送→│  Flask + SQLite + Docker     │←订阅─│ Clash    │
  │ reality.sh    │       │  https://sub-manager.        │    │ Loon     │
  └──────────────┘       │       202205.xyz             │    │ 圈X      │
  ┌──────────────┐       │                              │    │ 小火箭   │
  │ Xray 机       │──推送→│  - 节点管理/去重/运营商命名    │    │ v2rayN   │
  │ xray_to_sub.sh│       │  - Token(地区/正则过滤)      │    │ Stash    │
  └──────────────┘       │  - 7+ 客户端订阅格式生成       │    └──────────┘
                         │  - CF DNS 自动解析            │
                         └─────────────────────────────┘
```

**数据流**:节点服务器装好代理 → 脚本把节点参数 POST 到面板 `/api/nodes/push` → 面板存 SQLite →
客户端拉 `https://sub-manager.202205.xyz/sub/<token>?target=clash` → 面板按 target 实时生成对应格式订阅。

**关键设计**:
- 面板在墙外(Oracle 大阪),查 IP 归属/运营商通畅,订阅分发不受 GFW 影响
- 节点凭据全客户端共用(自用规模,不做 per-user 流量统计)
- 朋友每人一个独立 token(可单独过滤地区/禁用/看访问记录)

---

## 2. 组件清单

### 中心面板
| 文件 | 说明 |
|------|------|
| `sub-manager.zip` | 面板全部代码(Flask + Vue + Docker) |

### 节点脚本(传到节点服务器)
| 脚本 | 用途 | 放哪台机器 |
|------|------|-----------|
| `bootstrap.sh` | 开荒主脚本(串系统初始化 + reality.sh) | 新 sing-box 机 |
| `reality.sh` | 装 sing-box 四协议 + 推送 | sing-box 机 |
| `push_to_sub.sh` | sing-box 节点推送(被 reality.sh 调用) | sing-box 机 |
| `xray_to_sub.sh` | 从现有 Xray 提取节点推送 | Xray 机 |
| `common_lib.sh` | 公共库(地区探测/时区映射/IP探测) | **所有节点机**(跟推送脚本同目录) |
| `backup_db.sh` | 面板 DB 定时备份 | 面板宿主机 |

### DD 重装(可选)
| 脚本 | 用途 |
|------|------|
| `InstallNET.sh` | MoeClub 系网络重装(已加 Debian 13 trixie 支持) |

---

## 3. 中心面板 sub-manager 部署

### 3.1 首次部署

```bash
# 1. 上传并解压
scp sub-manager.zip oracle-osaka-1:/opt/
ssh oracle-osaka-1
cd /opt && unzip -o sub-manager.zip
cd sub-manager

# 2. 配置环境变量(首次必须改密码和 token)
cp .env.example .env
vim .env
```

`.env` 关键项:
```ini
ADMIN_PASSWORD=你的面板登录密码        # 必改
PUSH_TOKEN=一个随机长字符串            # 节点推送鉴权,必改
CF_API_TOKEN=cfut_xxx                 # Cloudflare DNS 自动解析(域名模式节点需要)
```

```bash
# 3. 启动
docker compose up -d --build

# 4. 确认运行
docker compose ps
curl -s http://127.0.0.1:8000/ -o /dev/null -w "%{http_code}\n"   # 期望 200
```

### 3.2 Nginx 反代(面板对外)

面板容器监听 `127.0.0.1:8000`,nginx 反代到 `https://sub-manager.202205.xyz`(CF 橙云):

```nginx
server {
    listen 443 ssl http2;
    server_name sub-manager.202205.xyz;
    # ssl 证书略
    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;   # 关键: token 访问记录靠这个拿真实IP
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### 3.3 更新面板(已部署过,保留数据)

```bash
scp sub-manager.zip oracle-osaka-1:/opt/
ssh oracle-osaka-1
cd /opt
# 排除 docker-compose.yml 和 .env(保留你的配置), data 目录不动(SQLite 持久化)
unzip -o sub-manager.zip -x "sub-manager/docker-compose.yml" -x "sub-manager/.env"
cd sub-manager && docker compose up -d --build
```

> 更新后浏览器 **Ctrl+F5** 强刷(index.html 变了,清缓存)。

---

## 4. 节点服务器开荒

### 4.1 DD 重装系统(可选,新机器或重装)

```bash
# 下载 DD 脚本
wget --no-check-certificate -qO InstallNET.sh \
  'https://raw.githubusercontent.com/你的仓库/InstallNET.sh' && chmod +x InstallNET.sh

# 装 Debian 13(已支持)
bash InstallNET.sh -d 13 -v 64 -p "临时root密码" -port 22
# 等待重装完成(约5-15分钟),用新密码 SSH 登录
```

> **系统支持**:Debian 12/13 均可。Ubuntu 22.04+ 因官方取消 netboot,本脚本装不了(需 DD cloud image,以后再说)。

### 4.2 一键开荒(装 sing-box + 推送)

把 `bootstrap.sh` `reality.sh` `push_to_sub.sh` `common_lib.sh` 传到新机同一目录:

```bash
scp bootstrap.sh reality.sh push_to_sub.sh common_lib.sh root@新机IP:/root/
ssh root@新机IP
cd /root
```

**全自动开荒**(无人值守,推荐):
```bash
SUB_API="https://sub-manager.202205.xyz" \
PUSH_TOKEN="面板的PUSH_TOKEN" \
NODE_NAME="dmit-tokyo-1" \
bash bootstrap.sh
```

- 带了 `PUSH_TOKEN` → reality.sh 自动进入**无人值守模式**(参数全自动生成,不交互)
- `NODE_REGION` 不传 → **自动探测**(查 IP 归属国家)
- 时区 → 按地区自动设(日本→Asia/Tokyo)
- 装完**自动自检**(进程/端口/配置/证书)+ 推送到面板

### 4.3 只装 sing-box(单跑 reality.sh,不用 bootstrap)

```bash
# 全自动
SUB_API="https://sub-manager.202205.xyz" PUSH_TOKEN="xxx" \
NODE_NAME="dmit-tokyo-1" bash reality.sh

# 手动交互(不传 PUSH_TOKEN 和 NONINTERACTIVE 则交互填参数)
bash reality.sh
```

### 4.4 带真证书的 Hy2/TUIC(可选)

Hy2/TUIC 默认用自签证书(客户端需 insecure)。要真证书(免 insecure):

```bash
SUB_API="..." PUSH_TOKEN="..." NODE_NAME="..." \
NODE_DOMAIN="tokyo3.202205.xyz" \
CF_API_TOKEN="cfut_xxx" \
bash bootstrap.sh
```

- `NODE_DOMAIN` + `CF_API_TOKEN` → acme.sh 经 CF DNS-01 申请真证书,Hy2/TUIC 用真证书

---

## 5. 脚本变量速查

### bootstrap.sh
| 变量 | 必填 | 说明 | 例 |
|------|------|------|-----|
| `SUB_API` | 推送时必填 | 面板地址 | `https://sub-manager.202205.xyz` |
| `PUSH_TOKEN` | 推送时必填 | 面板部署 token | `EHDPN2eq...` |
| `NODE_NAME` | 建议填 | 节点来源标识(面板区分机器) | `dmit-tokyo-1` |
| `NODE_REGION` | 可选 | 地区码,不填自动探测 | `jp` `hk` `us` |
| `INIT_GH_USER` | 可选 | init.sh 取 SSH key 的 GitHub 用户 | |
| `INIT_NEW_USER` | 可选 | init.sh 创建的新用户 | |

### reality.sh(sing-box)
| 变量 | 默认 | 说明 |
|------|------|------|
| `SUB_API` | — | 面板地址(不填则只装不推送) |
| `PUSH_TOKEN` | — | 推送 token(**填了即进无人值守模式**) |
| `NONINTERACTIVE` | — | `=1` 强制无人值守(即使没 PUSH_TOKEN) |
| `NODE_NAME` | hostname | 节点标识,命名 `NODE_NAME-Reality` 等 |
| `NODE_REGION` | 自动探测 | 地区码 |
| `TZ` | 按地区 | 强制指定时区(覆盖地区推断) |
| `REALITY_PORT` | 443 | reality 端口 |
| `SS_PORT` | 随机2万+ | Shadowsocks 端口 |
| `HY2_PORT` | 随机3万+ | Hysteria2 端口 |
| `TUIC_PORT` | 随机4万+ | TUIC 端口 |
| `SS_PASSWORD` | 随机 | SS 密码 |
| `HY2_PASSWORD` | 随机 | Hy2 密码 |
| `TUIC_UUID` `TUIC_PASSWORD` | 随机 | TUIC 凭据 |
| `UUID` | 随机 | reality UUID |
| `REALITY_DEST` | 随机选池 | reality 回落域名(SNI 伪装) |
| `NODE_DOMAIN` | — | 配真证书的域名(配合 CF_API_TOKEN) |
| `CF_API_TOKEN` | — | Cloudflare token(真证书 + 域名解析) |

### xray_to_sub.sh(Xray 提取)
| 变量 | 必填 | 说明 |
|------|------|------|
| `SUB_API` | 是 | 面板地址 |
| `PUSH_TOKEN` | 是 | 推送 token |
| `NODE_NAME` | 建议 | 节点标识(默认 hostname) |
| `NODE_REGION` | 可选 | 不填自动探测 |
| `XRAY_CONFIG` | 可选 | Xray 配置路径(默认 `/usr/local/etc/xray/config.json`) |
| `SNI_DOMAIN` | 可选 | 覆盖 reality 的 SNI(一般用 config 原值) |
| `NODE_DOMAIN` | 可选 | 域名模式(配 CF 解析) |
| `CF_API_TOKEN` `CF_ZONE_ID` | 可选 | CF 自动建子域名 |
| `CLEANUP_OLD` | 1 | 推送前清同机器旧节点(`=0` 关闭) |

### push_to_sub.sh(被 reality.sh 调用,一般不单独跑)
| 变量 | 说明 |
|------|------|
| `CLEANUP_OLD` | 1=推送前清理同 NODE_NAME 旧节点 |
| 其余 | 由 reality.sh export 传入 |

### backup_db.sh(面板 DB 备份)
| 变量 | 默认 | 说明 |
|------|------|------|
| `DB_PATH` | `/opt/sub-manager/data/sub.db` | DB 路径(按 volume 实际改) |
| `BACKUP_DIR` | `/opt/sub-manager/backups` | 备份目录 |
| `KEEP` | 14 | 保留最近几份 |

---

## 6. Xray 机器接入

已有 Xray 服务器(reality + nginx 前置 vmess),提取节点推送:

```bash
scp xray_to_sub.sh common_lib.sh root@xray机:/root/
ssh root@xray机
cd /root

SUB_API="https://sub-manager.202205.xyz" \
PUSH_TOKEN="xxx" \
NODE_NAME="tff-hk-1" \
bash xray_to_sub.sh
```

**提取逻辑**:
- 直连 reality(非 127.0.0.1):直接提取
- nginx 前置节点:正向追链(stream map 域名 → upstream → conf.d → xray inbound 看实际协议)
- 协议从 xray inbound 实际读(不信 nginx map 标签名)

---

## 7. 日常维护

### 7.1 面板操作(浏览器)

登录 `https://sub-manager.202205.xyz`,用 `ADMIN_PASSWORD`。

| 操作 | 位置 |
|------|------|
| 看/管节点 | 节点区 |
| 批量删节点 | 节点多选 → 批量删除 |
| 检测配置正确性 | 节点区「🔍 检测配置」 |
| 新建/管理 token | 令牌区 |
| 看 token 访问记录 | 令牌「访问」列 → 详情(次数/时间/IP/UA) |
| 复制订阅链接 | 令牌「复制订阅」 |
| 订阅二维码 | 复制订阅弹窗 → node 区「二维码」(v2ray/小火箭/clash节点可扫) |
| 数据库备份/恢复 | 标题栏「备份」 |
| 改面板密码 | 标题栏「改密码」 |

### 7.2 给朋友分享

1. 令牌区「+ 新建令牌」,备注如「朋友A」
2. (可选)限定地区/正则过滤
3. 复制订阅链接发给朋友,或让他扫二维码
4. 过段时间看「访问」详情确认导入成功(长期 0 次 = 没导入成功)

### 7.3 节点重装/更新(幂等)

节点机重跑 reality.sh / xray_to_sub.sh 即可——**推送前自动清理同 NODE_NAME 旧节点**,不会残留。
所以改了端口、重装系统,直接重跑脚本,面板自动更新。

### 7.4 DB 自动备份(面板宿主机)

```bash
# 改 backup_db.sh 里的 DB_PATH 为实际 volume 路径,然后加 cron
crontab -e
# 每天凌晨3点备份,保留14份
0 3 * * * /opt/sub-manager/backup_db.sh >> /var/log/sub-manager-backup.log 2>&1
```

### 7.5 sing-box 节点维护(节点机)

```bash
systemctl status sing-box        # 状态
systemctl restart sing-box       # 重启
journalctl -u sing-box -n 50     # 日志
/usr/local/bin/sing-box check -c /etc/sing-box/config.json   # 校验配置
ss -tunlp | grep sing-box        # 看端口监听
```

---

## 8. 排错

### 节点推送后面板看不到
1. 节点机看推送响应(脚本末尾打印 created/id)
2. 检查 `SUB_API` 能否访问:`curl -I https://sub-manager.202205.xyz`
3. `PUSH_TOKEN` 是否和面板 `.env` 一致

### sing-box 装完连不上
1. 节点机自检输出看哪项 [✗]
2. **云控制台安全组**放行端口(脚本只配了系统防火墙,云平台安全组要手动放):
   - TCP: REALITY_PORT(443)
   - TCP/UDP: SS_PORT
   - UDP: HY2_PORT, TUIC_PORT
3. `journalctl -u sing-box -n 30`

### 客户端导入订阅为空
- v2rayN:实际能导入,需**手动刷新订阅**才显示
- 检查 token 是否启用、是否过期
- 看 token 访问记录,确认请求到达面板

### Debian 13 装 sing-box 报依赖错
- reality.sh 已兼容 Debian 13 包名(dnsutils→bind9-dnsutils 双名容错)
- 若仍报「关键依赖缺失」,检查 apt 源是否正常:`apt update`

### 时区不对
- reality.sh 按地区自动设。手动指定:`TZ=Asia/Tokyo bash reality.sh`
- 已装好的机器:`timedatectl set-timezone Asia/Tokyo`

### BBR 是否生效
```bash
sysctl net.ipv4.tcp_congestion_control   # 应输出 bbr
# 不用重启,reality.sh 的 sysctl --system 已即时生效
```

---

## 9. 凭据清单

> ⚠️ 妥善保管,DB 备份文件含这些敏感信息。

| 项 | 值 |
|------|-----|
| 面板地址 | https://sub-manager.202205.xyz |
| 面板登录密码 | `.env` 的 ADMIN_PASSWORD |
| 推送 token | `.env` 的 PUSH_TOKEN |
| CF API token | `.env` 的 CF_API_TOKEN |
| CF Zone ID (202205.xyz) | 71e749cbdbcba45da7ba9a3a8f661c61 |
| 当前订阅 token | 面板令牌区查看 |

---

## 附:常用一键命令

```bash
# 开荒新 sing-box 机(全自动)
SUB_API="https://sub-manager.202205.xyz" PUSH_TOKEN="xxx" NODE_NAME="dmit-tokyo-1" bash bootstrap.sh

# Xray 机提取推送
SUB_API="https://sub-manager.202205.xyz" PUSH_TOKEN="xxx" NODE_NAME="tff-hk-1" bash xray_to_sub.sh

# 面板更新(保留数据)
cd /opt && unzip -o sub-manager.zip -x "sub-manager/docker-compose.yml" -x "sub-manager/.env" && cd sub-manager && docker compose up -d --build

# DD Debian 13
bash InstallNET.sh -d 13 -v 64 -p "密码"

# DB 手动备份
DB_PATH=/opt/sub-manager/data/sub.db bash backup_db.sh
```
