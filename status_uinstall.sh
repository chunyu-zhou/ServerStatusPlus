#!/usr/bin/env bash
PATH=/bin:/sbin:/usr/bin:/usr/sbin:/usr/local/bin:/usr/local/sbin:~/bin
export PATH

Green_font_prefix="\033[32m" && Red_font_prefix="\033[31m" && Green_background_prefix="\033[42;37m" && Red_background_prefix="\033[41;37m" && Font_color_suffix="\033[0m"
Info="${Green_font_prefix}[信息]${Font_color_suffix}"
Error="${Red_font_prefix}[错误]${Font_color_suffix}"
Tip="${Green_font_prefix}[注意]${Font_color_suffix}"

#检查系统
check_sys(){
	if [[ -f /etc/redhat-release ]]; then
		release="centos"
	elif cat /etc/issue | grep -q -E -i "debian"; then
		release="debian"
	elif cat /etc/issue | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /etc/issue | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
	elif cat /proc/version | grep -q -E -i "debian"; then
		release="debian"
	elif cat /proc/version | grep -q -E -i "ubuntu"; then
		release="ubuntu"
	elif cat /proc/version | grep -q -E -i "centos|red hat|redhat"; then
		release="centos"
    fi
	bit=`uname -m`
}
Installation_dependency(){
	python_status=$(python --help)
	if [[ ${release} == "centos" ]]; then
		yum -y install epel-release
		yum -y install python3
		yum -y install gcc
		yum -y install python3-devel
		yum -y install python3-pip
		yum -y install wget
	else
		apt-get update
		apt-get install -y python3
		apt-get install-y python3-pip
		apt-get install-y wget
	fi
	pip3 install requests
	pip3 install psutil
	pip3 install wmi
	pip3 install cachelib
}
Install_ServerStatus_client(){
	if [[ ${release} == "centos" ]]; then
		cat /etc/redhat-release |grep 7\..*|grep -i centos>/dev/null
		if [[ $? != 0 ]]; then
			echo -e "${Info} 检测到你的系统为 CentOS6，该系统自带的 Python2.6 版本过低，会导致无法运行客户端，如果你有能力升级为 Python2.7，那么请继续(否则建议更换系统)：[y/N]"
			read -e -p "(默认: N 继续安装):" sys_centos6
			[[ -z "$sys_centos6" ]] && sys_centos6="n"
			if [[ "${sys_centos6}" == [Nn] ]]; then
				echo -e "\n${Info} 已取消...\n"
				exit 1
			fi
		fi
	fi
	echo -e "${Info} 开始安装/配置 依赖..."
	Installation_dependency
	echo -e "${Info} 开始写入 配置..."
	Read_config_client
	Service_Server_Status_client
	echo -e "${Info} 所有步骤 安装完毕，开始启动..."
	Start_ServerStatus_client
}
Read_config_client(){
	check_pid_client
	[[ ! -z $PID ]] && kill -9 ${PID}
	rm -rf /etc/init.d/status-plus-client
	if [[ ${release} = "centos" ]]; then
		chkconfig --del status-plus-client
	else
		update-rc.d -f status-plus-client remove
	fi
	rm -rf "/usr/local/ServerStatusPlus/*"
	mkdir -p "/usr/local/ServerStatusPlus/config"
	mkdir -p "/usr/local/ServerStatusPlus/log"
	echo "$ServerToken" > "/usr/local/ServerStatusPlus/config/ServerToken.conf"
	echo "$GroupToken" > "/usr/local/ServerStatusPlus/config/GroupToken.conf"
	echo "$host" > "/usr/local/ServerStatusPlus/config/host.conf"
	wget -N --no-check-certificate -O "/usr/local/ServerStatusPlus/config/version" "http://cloud.onetools.cn/api/version"
	wget -N --no-check-certificate -O "/usr/local/ServerStatusPlus/status-plus-client.py" "https://cdn.jsdelivr.net/gh/chunyu-zhou/ServerStatusPlus/client-psutil.py"
	if [[ ! -e "/usr/local/ServerStatusPlus/status-plus-client.py" ]]; then
		echo -e "${Error} ServerStatus 客户端文件不存在 !" && exit 1
	fi
}
Service_Server_Status_client(){
	if [[ ${release} = "centos" ]]; then
		if ! wget -N --no-check-certificate "https://cdn.jsdelivr.net/gh/chunyu-zhou/ServerStatusPlus/service/client_centos" -O /etc/init.d/status; then
			echo -e "${Error} ServerStatusPlus 客户端服务管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/status
		chkconfig --add status
		chkconfig status on
	else
		if ! wget -N --no-check-certificate "https://cdn.jsdelivr.net/gh/chunyu-zhou/ServerStatusPlus/service/client_debian" -O /etc/init.d/status; then
			echo -e "${Error} ServerStatusPlus 客户端服务管理脚本下载失败 !" && exit 1
		fi
		chmod +x /etc/init.d/status
		update-rc.d -f status defaults
	fi
	echo -e "${Info} ServerStatusPlus 客户端服务管理脚本下载完成 !"
}
check_pid_client(){
	PID=`ps -ef| grep "status-plus-client.py"| grep -v grep| grep -v ".sh"| grep -v "init.d"| grep -v "service"| awk '{print $2}'`
}
Start_ServerStatus_client(){
	check_pid_client
	[[ ! -z ${PID} ]] && echo -e "${Error} ServerStatusPlus 正在运行，请检查 !" && exit 1
	/etc/init.d/status start
}
Stop_ServerStatus_client(){
	check_pid_client
	[[ -z ${PID} ]] && echo -e "${Error} ServerStatusPlus 没有运行，请检查 !" && exit 1
	/etc/init.d/status stop
}
Restart_ServerStatus_client(){
	check_pid_client
	[[ ! -z ${PID} ]] && /etc/init.d/status stop
	/etc/init.d/status start
}
Uninstall_ServerStatus_client(){
	echo "确定要卸载 ServerStatusPlus 客户端(如果同时安装了服务端，则只会删除客户端) ? [y/N]"
	echo
	read -e -p "(默认: n):" unyn
	[[ -z ${unyn} ]] && unyn="n"
	if [[ ${unyn} == [Yy] ]]; then
		check_pid_client
		[[ ! -z $PID ]] && kill -9 ${PID}
		rm -rf "/usr/local/ServerStatusPlus"
		rm -rf /etc/init.d/status
		if [[ ${release} = "centos" ]]; then
			chkconfig --del status
		else
			update-rc.d -f status remove
		fi
		echo && echo "ServerStatusPlus 卸载完成 !" && echo
	else
		echo && echo "卸载已取消..." && echo
	fi
}

View_client_Log(){
	[[ ! -e ${client_log_file} ]] && echo -e "${Error} 没有找到日志文件 !" && exit 1
	echo && echo -e "${Tip} 按 ${Red_font_prefix}Ctrl+C${Font_color_suffix} 终止查看日志" && echo -e "如果需要查看完整日志内容，请用 ${Red_font_prefix}cat ${client_log_file}${Font_color_suffix} 命令。" && echo
	tail -f ${client_log_file}
}
# action=$1
# if [ ${#action} != 32 ] ; then
# 	echo -e "${Error} Token错误，请检查 !" && exit 1
# fi
while getopts ":u:s:g:h:" opt
do
    case $opt in
        u)
        echo "参数uk的值$OPTARG"
        UserToken=$OPTARG
        ;;
        s)
        echo "参数sk的值$OPTARG"
        ServerToken=$OPTARG
        ;;
        g)
        echo "参数gk的值$OPTARG"
        GroupToken=$OPTARG
        ;;
        h)
        echo "参数host的值$OPTARG"
        host=$OPTARG
        ;;
        ?)
        echo "未知参数: -$OPTARG index:$OPTIND"
        exit 1;;
    esac
done

if [ ${#ServerToken} != 32 ] ; then
	echo -e "${Error} ServerToken错误，请检查 !" && exit 1
fi
if [ ${#GroupToken} != 32 ] ; then
	echo -e "${Error} GroupToken错误，请检查 !" && exit 1
fi

check_sys
Install_ServerStatus_client