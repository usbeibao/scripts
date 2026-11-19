# Multi-EasyGost for GOST v3

基于 [KANIKIG/Multi-EasyGost](https://github.com/KANIKIG/Multi-EasyGost) 的 v2 分支（`1c31ffc`）。保留原作者及贡献者署名，按原项目的 [GPL-3.0](LICENSE) 授权。

这个版本为 Linux + systemd 提供交互式安装、升级及转发规则管理。默认从 [go-gost/gost 官方 Releases](https://github.com/go-gost/gost/releases/latest) 获取最新稳定版，使用同一发行版的 `checksums.txt` 校验安装包的 SHA-256，并校对二进制版本。测试版本为 **GOST v3.3.3**。

## 全新安装

解压后进入项目目录。需要 Bash、Python 3.6+、curl、tar、sha256sum、flock 和正在运行的 systemd。支持官方 Linux 的 amd64、arm64、386、armv5/6/7 发行包。

```bash
sudo bash gost.sh install v3.3.3
sudo bash gost.sh
```

使用菜单 **7** 新增规则。安装、升级和迁移命令省略版本时会自动获取最新稳定版。

| 操作 | 命令 |
| --- | --- |
| 安装最新稳定版 | `sudo bash gost.sh install` |
| 升级当前 v3 到最新稳定版 | `sudo bash gost.sh upgrade` |
| 升级或切换到指定 v3 版本 | `sudo bash gost.sh upgrade v3.3.3` |
| 查看规则 | `sudo bash gost.sh list` |
| 查看服务状态 | `sudo systemctl status gost.service --no-pager` |
| 查看服务日志 | `sudo journalctl -u gost.service -n 80 --no-pager` |

定时重启使用 `/etc/cron.d/multi-easygost`，需要系统已安装并启用 cron。每 N 小时按本地时间的整点计算。

## 从原版 v2.11.2 迁移

1. 先核对 `/etc/gost/rawconf` 是否覆盖当前在用的规则。迁移按这个文件生成配置。手改过旧 `config.json` 的内容，需先核对并补到规则里。旧均衡负载的 `/root/<列表名>.txt` 可继续使用。以下命令可预览生成结果，预览文件含代理凭据。
   ```bash
   sudo sh -c 'umask 077; bash gost.sh render /etc/gost/rawconf > /root/gost-v3-preview.json'
   ```
2. **先迁移落地机，再迁移中转机**。在 v2.11.2 与 v3.3.3 的本地双向测试中，v2 中转连接 v3 落地时，Relay TLS、WS、WSS 的 TCP 和 UDP 均通过。反过来的测试未通过。更新每端后分别验证实际业务。
   ```bash
   sudo bash gost.sh migrate v3.3.3
   sudo systemctl status gost.service --no-pager
   ```
3. 如需回退，先回退中转机，再回退落地机。
   ```bash
   sudo bash gost.sh rollback-v2
   ```

迁移沿用 `gost.service`，并保留旧二进制 `/usr/bin/gost` 和原 `/etc/gost/config.json`。新二进制位于 `/usr/local/lib/multi-easygost/gost`，新配置位于 `/etc/gost/config-v3.json`。迁移记录保存在 `/etc/gost/backup-v2`。回退恢复旧 unit、旧规则及原启用和运行状态，并归档回退前的 v3 规则。迁移会把原规则和旧配置收紧为仅 root 可读写。

## 规则和 TLS

- 支持 TCP／UDP 直转、Relay TLS／WS／WSS、多个落地节点、CDN 自选节点，以及带认证的 Shadowsocks、SOCKS5 和 HTTP。WS 链路为明文。
- v3.3.3 启动实测拒绝旧菜单的 `aes-256-cfb`、`chacha20`、`rc4-md5` 和旧拼写 `AEAD_CHACHA20_POLY1305`。使用这些值时，迁移会报出规则行号。先将客户端和规则一起改为 `aes-256-gcm` 或 `chacha20-ietf-poly1305`。
- 自定义 TLS 证书默认从 `/root/gost_cert/cert.pem` 和 `/root/gost_cert/key.pem` 加载。首次添加后用菜单 **6** 重新生成配置。菜单 **11** 可调用已安装的 acme.sh，Cloudflare DNS-01 使用 API Token。
- 普通 Relay TLS／WSS 中转规则保留原规则中的 `secure=true` 选项，启用后用落地域名校验证书。CDN WSS 以填写的 Host 域名同时作为 SNI，并校验证书。
- 新建或删除规则时，脚本先生成并解析 v3 配置，然后重启检查。启动失败时恢复旧配置。菜单 **6** 也会按 rawconf 重建配置，因此请通过规则管理菜单维护自定义转发。

## 验证范围

用官方 GOST v3.3.3 Linux amd64 二进制跑过本地 TCP／UDP 直转、TLS／WS／WSS 隧道、落地列表、CDN 节点，以及带认证的 HTTP、SOCKS5 和 Shadowsocks 流量。安装、规则变更失败恢复、迁移和回退流程使用模拟 systemctl 验证。
