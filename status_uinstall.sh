#!/bin/bash

check_pid_client(){
	PID=`ps -ef| grep "status-plus-client.py"| grep -v grep| grep -v ".sh"| grep -v "init.d"| grep -v "service"| awk '{print $2}'`
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


Install_ServerStatus_client
