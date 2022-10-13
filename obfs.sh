#!/bin/bash
# Install simple-obfs
# Author: ratneo<https://ihost.wiki>

RED="\033[31m"      # Error message
GREEN="\033[32m"    # Success message
YELLOW="\033[33m"   # Warning message
BLUE="\033[36m"     # Info message
PLAIN='\033[0m'

SYSTEMD="/etc/systemd/system/obfs-server.service"

coloredEcho() {
  echo -e "${1}${@:2}${PLAIN}"
}

install_simple_obfs() {
  apt install -y --no-install-recommends build-essential autoconf libtool libssl-dev libpcre3-dev libev-dev asciidoc xmlto automake
  git clone https://github.com/shadowsocks/simple-obfs.git
  cd simple-obfs
  git submodule update --init --recursive
  ./autogen.sh
  ./configure && make
  make install

  cd && rm -rf simple-obfs

 if [ -f ${SYSTEMD} ]; then
   echo "Found existing service..."
   systemctl daemon-reload
   systemctl restart obfs-server
 else
   echo "Generating new service..."
   cat > ${SYSTEMD} <<-EOF
   [Unit]
   Description=Simple-obfs Server Service
   After=network.target
   
   [Service]
   Type=simple
   LimitNOFILE=32768
   ExecStart=/usr/local/bin/obfs-server -s 0.0.0.0 -p 2083 --obfs tls -r 127.0.0.1:61481 --failover 127.0.0.1:443
   
   [Install]
   WantedBy=multi-user.target
   systemctl daemon-reload
   systemctl enable obfs-server
   systemctl start obfs-server
 fi
 EOF
}

install_simple_obfs