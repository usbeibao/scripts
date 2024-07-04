#!/bin/bash

if [ "$(id -u)" -ne 0 ]; then
  echo "此脚本必须以root用户运行，请使用'sudo su'切换到root用户或使用'sudo'运行。" >&2
  exit 1
fi

if ! command -v jq &> /dev/null
then
    echo "jq未安装，正在安装jq..."
    apt-get update && apt-get install -y jq
fi

fetch_latest_version() {
  response=$(curl -s https://api.github.com/repos/XTLS/Xray-core/releases/latest)
  latest_version=$(echo "$response" | jq -r '.tag_name')
  if [ -z "$latest_version" ]; then
    echo "获取最新版本失败，请检查您的网络连接或GitHub API限制。" >&2
    exit 1
  fi
  echo $latest_version
}

VERSION=${1:-$(fetch_latest_version)}

cd
mkdir -p xray_update && cd xray_update

wget "https://github.com/XTLS/Xray-core/releases/download/$VERSION/Xray-linux-64.zip"
if [ $? -eq 0 ]; then
    unzip Xray-linux-64.zip
    mv xray /usr/local/bin/
    systemctl restart xray
    echo "Xray已更新至版本 $VERSION，并已重启服务。"
else
    echo "下载Xray失败，请检查提供的版本号和网络连接。"
fi

cd ..
rm -rf xray_update
