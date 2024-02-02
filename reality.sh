#!/usr/bin/env bash
# 检测区
# -------------------------------------------------------------

export LANG=en_US.UTF-8

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

XRAY_CONFIG_FILE="/usr/local/etc/xray/config.json"
NGINX_CONF_PATH="/etc/nginx/conf.d/"
NGINX_SERVICE_FILE="/lib/systemd/system/nginx.service"
XRAY_VER="v1.8.7"

coloredEcho() {
  echo -e "${1}${@:2}${PLAIN}"
}

checkRoot() {
  result=$(id | awk '{print $1}')
  if [[ $result != "uid=0(root)" ]]; then
    coloredEcho $YELLOW " 请以root身份执行该脚本"
    exit 1
  fi
}

archAffix(){
    case "$(uname -m)" in
        i686|i386)
            echo '32'
        ;;
        x86_64|amd64)
            echo '64'
        ;;
        armv5tel)
            echo 'arm32-v5'
        ;;
        armv6l)
            echo 'arm32-v6'
        ;;
        armv7|armv7l)
            echo 'arm32-v7a'
        ;;
        armv8|aarch64)
            echo 'arm64-v8a'
        ;;
        mips64le)
            echo 'mips64le'
        ;;
        mips64)
            echo 'mips64'
        ;;
        mipsle)
            echo 'mips32le'
        ;;
        mips)
            echo 'mips32'
        ;;
        ppc64le)
            echo 'ppc64le'
        ;;
        ppc64)
            echo 'ppc64'
        ;;
        ppc64le)
            echo 'ppc64le'
        ;;
        riscv64)
            echo 'riscv64'
        ;;
        s390x)
            echo 's390x'
        ;;
        *)
            coloredEcho $RED " 不支持的CPU架构！"
            exit 1
        ;;
    esac

    return 0
}

checkSystem() {
    if [[ -f "/etc/issue" ]] && grep </etc/issue -q -i "debian" || [[ -f "/proc/version" ]] && grep </etc/issue -q -i "debian" || [[ -f "/etc/os-release" ]] && grep </etc/os-release -q -i "ID=debian"; then
        release="debian"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'

    elif [[ -f "/etc/issue" ]] && grep </etc/issue -q -i "ubuntu" || [[ -f "/proc/version" ]] && grep </etc/issue -q -i "ubuntu"; then
        release="ubuntu"
        installType='apt -y install'
        upgrade="apt update"
        updateReleaseInfoChange='apt-get --allow-releaseinfo-change update'
        removeType='apt -y autoremove'
        if grep </etc/issue -q -i "16."; then
            release=
        fi
    fi

    if [[ -z ${release} ]]; then
        echoContent red "\n本脚本不支持此系统，请将下方日志反馈给开发者\n"
        echoContent yellow "$(cat /etc/issue)"
        echoContent yellow "$(cat /proc/version)"
        exit 0
    fi
}

getInput() {
  echo ""
  read -p " 请输入vmess伪装域名：" VMESS_DOMAIN
  DOMAIN=${VMESS_DOMAIN,,}
  coloredEcho ${BLUE}  " vmess伪装域名(host)：$VMESS_DOMAIN"

  echo ""
  read -p " 请设置SS连接密码，回车随机生成:" PASSWORD
  [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
  coloredEcho $BLUE " SS密码：$PASSWORD"
  
  echo ""
  read -p " 请设置VMESS密码，回车随机生成:" VMESS_PASSWORD
  [[ -z "$VMESS_PASSWORD" ]] && VMESS_PASSWORD=`cat /proc/sys/kernel/random/uuid`
  coloredEcho $BLUE " VMESS密码：$VMESS_PASSWORD"
  
  echo ""
  read -p " 请输入伪装路径，以/开头(不懂请直接回车)：" WSPATH
  if [[ -z "${WSPATH}" ]]; then
      len=`shuf -i5-12 -n1`
      ws=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w $len | head -n 1`
      WSPATH="/$ws"
  fi
  coloredEcho ${BLUE}  " ws路径：$WSPATH"

  echo ""
  read -p " 请设置reality端口，回车随机10000-30000:" reality_Port
  if [[ -z "${reality_Port}" ]]; then
      reality_Port=$((RANDOM % 20001 + 10000))
  fi
  coloredEcho $BLUE " 密码：$reality_Port"

  PROXY_URL="https://bing.gifposter.com"
  REMOTE_HOST=`echo ${PROXY_URL} | cut -d/ -f3`
  ALLOW_SPIDER="n"
  coloredEcho ${BLUE}  " 伪装域名：$REMOTE_HOST"
  coloredEcho ${BLUE}  " 是否允许爬虫：$ALLOW_SPIDER"
}

getCert() {
  certbot certonly --nginx --register-unsafely-without-email -d $VMESS_DOMAIN
}

initRealityKey() {
    coloredEcho ${BLUE} "\n========================== 生成key ==========================\n"
    if [[ -z "${realityPrivateKey}" ]]; then
        realityX25519Key=$(/usr/local/bin/xray x25519)
        realityPrivateKey=$(echo "${realityX25519Key}" | head -1 | awk '{print $3}')
        realityPublicKey=$(echo "${realityX25519Key}" | tail -n 1 | awk '{print $3}')
    fi
    coloredEcho ${GREEN} "\n privateKey:${realityPrivateKey}"
    coloredEcho ${GREEN} "\n publicKey:${realityPublicKey}"
}

initRealityDest() {
    if [[ -n "${domain}" ]]; then
        realityDestDomain=${domain}:${port}
    else
        local realityDestDomainList=
        realityDestDomainList="gateway.icloud.com,itunes.apple.com,download-installer.cdn.mozilla.net,addons.mozilla.org,www.microsoft.com,www.lovelive-anime.jp,www.speedtest.net,www.speedtest.org,swdist.apple.com,swcdn.apple.com,updates.cdn-apple.com,mensura.cdn-apple.com,osxapps.itunes.apple.com,aod.itunes.apple.com,cdn-dynmedia-1.microsoft.com,update.microsoft,software.download.prss.microsoft.com,s0.awsstatic.com,d1.awsstatic.com,images-na.ssl-images-amazon.com,m.media-amazon.com,player.live-video.net,dl.google.com,www.google-analytics.com"

        coloredEcho ${BLUE} "\n===== 生成配置回落的域名 例如:[addons.mozilla.org:443] ======\n"
        coloredEcho ${GREEN} "回落域名列表：https://www.v2ray-agent.com/archives/1680104902581#heading-8\n"
        read -r -p "请输入[回车]使用随机:" realityDestDomain
        if [[ -z "${realityDestDomain}" ]]; then
            local randomNum=
            randomNum=$((RANDOM % 24 + 1))
            realityDestDomain=$(echo "${realityDestDomainList}" | awk -F ',' -v randomNum="$randomNum" '{print $randomNum":443"}')
        fi
        if ! echo "${realityDestDomain}" | grep -q ":"; then
            coloredEcho ${RED} "\n ---> 域名不合规范，请重新输入"
            initRealityDest
        else
            coloredEcho ${YELLOW} "\n ---> 回落域名: ${realityDestDomain}"
        fi
    fi
}

initRealityClientServersName() {
    if [[ -n "${domain}" ]]; then
        realityServerNames=\"${domain}\"
    elif [[ -n "${realityDestDomain}" ]]; then
        realityServerNames=$(echo "${realityDestDomain}" | cut -d ":" -f 1)

        realityServerNames=\"${realityServerNames//,/\",\"}\"
    else
        coloredEcho ${BLUE} "\n================ 配置客户端可用的serverNames ================\n"
        coloredEcho ${YELLOW} "#注意事项"
        coloredEcho ${GREEN} "客户端可用的serverNames 列表：https://www.v2ray-agent.com/archives/1680104902581#heading-8\n"
        coloredEcho ${YELLOW} "录入示例:addons.mozilla.org\n"
        read -r -p "请输入[回车]使用随机:" realityServerNames
        if [[ -z "${realityServerNames}" ]]; then
            realityServerNames=\"addons.mozilla.org\"
        else
            realityServerNames=\"${realityServerNames//,/\",\"}\"
        fi
    fi

    coloredEcho ${YELLOW} "\n ---> 客户端可用域名: ${realityServerNames}\n"
}

installNginx() { 

    if [[ "${release}" == "debian" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/debian $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        # gpg --dry-run --quiet --import --import-options import-show /tmp/nginx_signing.key
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1

    elif [[ "${release}" == "ubuntu" ]]; then
        sudo apt install gnupg2 ca-certificates lsb-release -y >/dev/null 2>&1
        echo "deb http://nginx.org/packages/mainline/ubuntu $(lsb_release -cs) nginx" | sudo tee /etc/apt/sources.list.d/nginx.list >/dev/null 2>&1
        echo -e "Package: *\nPin: origin nginx.org\nPin: release o=nginx\nPin-Priority: 900\n" | sudo tee /etc/apt/preferences.d/99nginx >/dev/null 2>&1
        curl -o /tmp/nginx_signing.key https://nginx.org/keys/nginx_signing.key >/dev/null 2>&1
        sudo mv /tmp/nginx_signing.key /etc/apt/trusted.gpg.d/nginx_signing.asc
        sudo apt update >/dev/null 2>&1
    fi
    ${installType} nginx python3-certbot-nginx >/dev/null 2>&1
}

configNginx() {
  mkdir -p /usr/share/nginx/html;
  if [[ "$ALLOW_SPIDER" = "n" ]]; then
    echo 'User-Agent: *' > /usr/share/nginx/html/robots.txt
    echo 'Disallow: /' >> /usr/share/nginx/html/robots.txt
    ROBOT_CONFIG="    location = /robots.txt {}"
  else
    ROBOT_CONFIG=""
  fi

  if [[ ! -f /etc/nginx/nginx.conf.bak ]]; then
    mv /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak
  fi
  res=`id nginx 2>/dev/null`
  if [[ "$?" != "0" ]]; then
    user="www-data"
  else
    user="nginx"
  fi
  cat > /etc/nginx/nginx.conf<< EOF
user $user;
worker_processes auto;
error_log /var/log/nginx/error.log;
pid /run/nginx.pid;

events {
    worker_connections 65535;
}

http {
    log_format  main  '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                      '\$status \$body_bytes_sent "\$http_referer" '
                      '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log  /var/log/nginx/access.log  main;
    server_tokens off;

    sendfile            on;
    tcp_nopush          on;
    tcp_nodelay         on;
    keepalive_timeout   65;
    types_hash_max_size 2048;
    gzip                on;

    include             /etc/nginx/mime.types;
    default_type        application/octet-stream;

    # Load modular configuration files from the /etc/nginx/conf.d directory.
    # See http://nginx.org/en/docs/ngx_core_module.html#include
    # for more information.
    include /etc/nginx/conf.d/*.conf;
}
stream {
    map \$ssl_preread_server_name \$sni {
        ${VMESS_DOMAIN}  vmess;
    }
    upstream vmess {
        server 127.0.0.1:21093;
    }
    server {
        listen 443      reuseport;
        listen [::]:443 reuseport;
        proxy_pass      \$sni;
        ssl_preread     on;
    }
    server {
        listen 26518      reuseport;
        listen [::]:26518 reuseport;
        proxy_pass      \$sni;
        ssl_preread     on;
    }
}
EOF

  mkdir -p ${NGINX_CONF_PATH}

  if [[ "$PROXY_URL" = "" ]]; then
    action=""
  else
    action="proxy_ssl_server_name on;
    proxy_pass $PROXY_URL;
    proxy_set_header Accept-Encoding '';
    sub_filter \"$REMOTE_HOST\" \"$VMESS_DOMAIN\";
    sub_filter_once off;"
  fi
  cat > ${NGINX_CONF_PATH}${VMESS_DOMAIN}.conf<< EOF
server {
    listen 80;
    listen [::]:80;
    server_name ${VMESS_DOMAIN};
    location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:49520;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location / {
        $action
    }
    $ROBOT_CONFIG
}

server {
    listen 20950;
    listen [::]:20950;
    server_name ${VMESS_DOMAIN};
    location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:49520;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }
    location / {
        $action
    }
    $ROBOT_CONFIG
}

server {
    listen 21093 ssl;
    listen [::]:21093 ssl;
    http2 on;
    server_name ${VMESS_DOMAIN};

    ssl_certificate /etc/letsencrypt/live/${VMESS_DOMAIN}/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/${VMESS_DOMAIN}/privkey.pem;
    include /etc/letsencrypt/options-ssl-nginx.conf;
    ssl_dhparam /etc/letsencrypt/ssl-dhparams.pem;

    location /grpc {
        grpc_pass grpc://127.0.0.1:38096;
    }

    location ${WSPATH} {
      proxy_redirect off;
      proxy_pass http://127.0.0.1:49520;
      proxy_http_version 1.1;
      proxy_set_header Upgrade \$http_upgrade;
      proxy_set_header Connection "upgrade";
      proxy_set_header Host \$host;
      proxy_set_header X-Real-IP \$remote_addr;
      proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;
    }

    location / {
        $action
    }
    $ROBOT_CONFIG

    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
}
EOF
cat > ${NGINX_SERVICE_FILE}<< EOF
# Stop dance for nginx
# =======================
#
# ExecStop sends SIGSTOP (graceful stop) to the nginx process.
# If, after 5s (--retry QUIT/5) nginx is still running, systemd takes control
# and sends SIGTERM (fast shutdown) to the main process.
# After another 5s (TimeoutStopSec=5), and if nginx is alive, systemd sends
# SIGKILL to all the remaining processes in the process group (KillMode=mixed).
#
# nginx signals reference doc:
# http://nginx.org/en/docs/control.html
#
[Unit]
Description=A high performance web server and a reverse proxy server
Documentation=man:nginx(8)
After=network.target nss-lookup.target
StartLimitIntervalSec=0

[Service]
Type=forking
PIDFile=/run/nginx.pid
ExecStartPre=/usr/sbin/nginx -t -q -g 'daemon on; master_process on;'
ExecStart=/usr/sbin/nginx -g 'daemon on; master_process on;'
ExecReload=/usr/sbin/nginx -g 'daemon on; master_process on;' -s reload
ExecStop=-/sbin/start-stop-daemon --quiet --stop --retry QUIT/5 --pidfile /run/nginx.pid
TimeoutStopSec=5
KillMode=mixed
Restart=on-failure
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF
}

installXray() {
    rm -rf /tmp/xray
    mkdir -p /tmp/xray/geo
    DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-$(archAffix).zip"
    GEOIP_LINK="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geoip.dat"
    GEOSITE_LINK="https://github.com/Loyalsoldier/v2ray-rules-dat/releases/latest/download/geosite.dat"
    coloredEcho $BLUE " 下载Xray: ${DOWNLOAD_LINK}"
    curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        coloredEcho $RED " 下载Xray文件失败，请检查服务器网络设置"
        exit 1
    fi
    mkdir -p /usr/local/etc/xray /usr/local/share/xray && \
    unzip /tmp/xray/xray.zip -d /tmp/xray
    cp /tmp/xray/xray /usr/local/bin
    wget -P /usr/local/share/xray ${GEOIP_LINK} ${GEOSITE_LINK}
    if [ $? != 0 ];then
        coloredEcho $RED " 下载增强版geo文件失败，使用Xray默认geo文件"
        cp /tmp/xray/geo* /usr/local/share/xray
    fi    
    chmod +x /usr/local/bin/xray || {
        coloredEcho $RED " Xray安装失败"
        exit 1
    }

    cat >/etc/systemd/system/xray.service<< EOF
[Unit]
Description=Xray Service
After=network.target nss-lookup.target

[Service]
User=root
#User=nobody
#CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
#AmbientCapabilities=CAP_NET_ADMIN CAP_NET_BIND_SERVICE
NoNewPrivileges=true
ExecStart=/usr/local/bin/xray run -confdir /usr/local/etc/xray
Restart=on-failure
RestartPreventExitStatus=23

[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable nginx
}

configXray() {
    mkdir -p /usr/local/xray
   cat > $XRAY_CONFIG_FILE<< EOF
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [
    {
      "port": ${reality_Port},
      "protocol": "vless",
      "tag": "VLESSReality",
      "settings": {
        "clients": [
          {
            "id": "${VMESS_PASSWORD}",
            "flow": "xtls-rprx-vision"
          }
        ],
        "decryption": "none",
        "fallbacks": [
          {
            "dest": "38326",
            "xver": 1
          }
        ]
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "dest": "${realityDestDomain}",
          "xver": 0,
          "serverNames": [
            ${realityServerNames}
          ],
          "privateKey": "${realityPrivateKey}",
          "publicKey": "${realityPublicKey}",
          "maxTimeDiff": 0,
          "shortIds": [
            ""
          ]
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
    {
      "port": 38326,
      "listen": "127.0.0.1",
      "protocol": "vless",
      "tag": "VLESSRealityGRPC",
      "settings": {
        "clients": [
          {
            "id": "${VMESS_PASSWORD}",
            "flow": ""
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "grpc",
        "grpcSettings": {
          "serviceName": "grpc",
          "multiMode": true
        },
        "sockopt": {
          "acceptProxyProtocol": true
        }
      },
      "sniffing": {
        "enabled": true,
        "destOverride": [
          "http",
          "tls"
        ]
      }
    },
    {
    "port": 49520,
    "listen": "127.0.0.1",
    "protocol": "vmess",
    "settings": {
      "clients": [
        {
          "id": "${VMESS_PASSWORD}",
          "level": 1,
          "alterId": 0
        }
      ],
      "disableInsecureEncryption": false
    },
    "streamSettings": {
        "network": "ws",
        "wsSettings": {
            "path": "${WSPATH}",
            "headers": {
                "Host": "${VMESS_DOMAIN}"
            }
        }
      }
    },
    {
      "port": 61481,
      "protocol": "shadowsocks",
      "settings": {
        "clients": [
          {
            "method": "chacha20-poly1305",
            "password": "${PASSWORD}",
            "level": 0
          }
        ],
        "network": "tcp,udp"
      }
    }
  ],
  "outbounds": [
    {
      "tag": "direct",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv4"
      }
    },
    {
      "tag":"IP6_out",
      "protocol": "freedom",
      "settings": {
        "domainStrategy": "UseIPv6"
      }
    },
    {
      "tag": "blackhole",
      "protocol": "blackhole",
      "settings": {}
    },
    {
      "tag": "proxy",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "address": "1.1.1.1",
            "port": 61481,
            "method": "chacha20-poly1305",
            "password": "${PASSWORD}"
          }
        ]
      }
    }
  ],
  "routing": {
    "domainStrategy": "IPIfNonMatch",
    "rules": [
      {
        "type": "field",
        "protocol": [
          "bittorrent"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "ip": [
          "127.0.0.1/32",
          "10.0.0.0/8",
          "fc00::/7",
          "fe80::/10",
          "172.16.0.0/12"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "domain": [
          "steamcommunity.com",
          "steampowered.com",
          "steamserver.net",
          "valve.net",
          "battle.net",
          "blizzard.com",
          "epicgames.com",
          "unrealengine.com",
          "origin.com",
          "ea.com",
          "riotgames.com",
          "leagueoflegends.com",
          "playstation.com",
          "ea.com",
          "playstation.net"
        ],
        "outboundTag": "blackhole"
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "google.com",
          "googlevideo.com",
          "gstatic.com",
          "youtube.com"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "domain": [
          "geosite:netflix",
          "geosite:hulu",
          "geosite:disney",
          "geosite:hbo",
          "amazonaws.com"
        ]
      },
      {
        "type": "field",
        "outboundTag": "direct",
        "network": "udp,tcp"
      }
    ]
  }
}
EOF
  systemctl daemon-reload
  systemctl enable xray
}

install() {
  apt clean all
  apt update -y
  apt install sudo wget vim unzip tar net-tools dnsutils mtr mlocate xz-utils openssl libssl-dev gcc g++ -y

  echo “”
  coloredEcho $BLUE " 安装nginx..."
  installNginx

  coloredEcho $BLUE " 申请证书..."
  getCert

  configNginx
  coloredEcho $BLUE " 证书和Nginx配置完毕..."

  coloredEcho $BLUE " 安装Xray ${XRAY_VER} ，架构$(archAffix)"
  installXray
  initRealityKey
  initRealityDest
  initRealityClientServersName
  configXray

  pkill -9 nginx && systemctl restart nginx
  systemctl restart xray
  sleep 2
  coloredEcho $BLUE " 安装完成"
}

checkRoot
checkSystem
getInput
install
