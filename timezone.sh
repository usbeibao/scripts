#!/bin/bash

# 选择大洲
echo "请选择时区所在的大陆或洲:" 
select continent in "Africa" "America" "Asia" "Atlantic" "Australia" "Europe" "Indian" "Pacific"
do
  case $continent in
    Africa | America | Asia | Atlantic | Australia | Europe | Indian | Pacific ) break;;
    *) echo "无效选择,请重试";;
  esac
done

# 根据大洲生成该洲时区区域选择菜单
zones=$(ls /usr/share/zoneinfo/$continent | sort)
echo "请选择$continent下的时区区域或城市:"
select zone in ${zones[@]}  
do
  if [[ -z $zone ]]; then  # 如果 zone 为空，即用户选择无效
    echo "无效选择,请重试"
  else
    break
  fi
done 

# 拼接最终时区  
timezone="/usr/share/zoneinfo/$continent/$zone"

# 设置时区
ln -sf $timezone /etc/localtime

# 安装chrony
apt update 
apt install -y chrony

# 配置chrony
sed -i 's/^pool/#&/' /etc/chrony/chrony.conf
sed -i '/^#pool/a\server time1.google.com minpoll 4 maxpoll 10 iburst \
server time2.google.com minpoll 4 maxpoll 10 iburst \
server time3.google.com minpoll 4 maxpoll 10 iburst \
server time4.google.com minpoll 4 maxpoll 10 iburst' /etc/chrony/chrony.conf

# 启动并启用开机自启动  
systemctl restart chrony
systemctl enable chrony

# 查看时区和时间同步状态
timedatectl status
chronyc tracking
