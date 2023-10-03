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
XRAY_VER="v1.8.4"

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

getInput() {
  echo ""
  read -p " 请设置SS连接密码（不输则随机生成）:" PASSWORD
  [[ -z "$PASSWORD" ]] && PASSWORD=`cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w 16 | head -n 1`
  coloredEcho $BLUE " 密码：$PASSWORD"
}

installXray() {
  if [ -x "$(command -v xray)" ]; then
    coloredEcho $BLUE "Xray is already installed."
    return 0
  else
    coloredEcho $BLUE "Xray is not installed. Installing..."
    rm -rf /tmp/xray
    mkdir -p /tmp/xray
    DOWNLOAD_LINK="https://github.com/XTLS/Xray-core/releases/download/${XRAY_VER}/Xray-linux-$(archAffix).zip"
    coloredEcho $BLUE " 下载Xray: ${DOWNLOAD_LINK}"
    curl -L -H "Cache-Control: no-cache" -o /tmp/xray/xray.zip ${DOWNLOAD_LINK}
    if [ $? != 0 ];then
        coloredEcho $RED " 下载Xray文件失败，请检查服务器网络设置"
        exit 1
    fi
    systemctl stop xray
    mkdir -p /usr/local/etc/xray /usr/local/share/xray && \
    unzip /tmp/xray/xray.zip -d /tmp/xray
    cp /tmp/xray/xray /usr/local/bin
    cp /tmp/xray/geo* /usr/local/share/xray
    chmod +x /usr/local/bin/xray || {
        coloredEcho $RED " Xray安装失败"
        exit 1
    }
    coloredEcho $BLUE "Xray installed successfully." 
  fi

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
    systemctl enable xray.service
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
            "port": 61481,
            "protocol": "shadowsocks",
            "settings": {
                "method": "chacha20-poly1305",
                "password": "$PASSWORD",
                "network": "tcp,udp"
            }
        }
    ],
    "outbounds": [
        {
            "protocol": "freedom"
        }
    ]
}
EOF
}


install() {
  apt clean all
  apt update -y
  apt install wget vim unzip tar gcc openssl net-tools libssl-dev g++ -y

  coloredEcho $BLUE " 安装Xray ${XRAY_VER} ，架构$(archAffix)"
  installXray
  configXray

  systemctl restart nginx
  systemctl restart xray
  sleep 2
  coloredEcho $BLUE " 安装完成"
}

checkRoot
getInput
install
