#!/usr/bin/env python3
# coding: utf-8
import time
import json
import sys
import requests
from typing import List, Dict, Any
from icmplib import ping, ICMPLibError
import asyncio
from concurrent.futures import ThreadPoolExecutor

APIDOMAIN="http://monitor.onecdn.cn"

VERSION = '1.0.0'
SERVERTOKEN=open("/usr/local/ServerStatusPlus/config/ServerToken.conf", "r").read().strip()
PINGTIME=20
IPV4=''
IPV6=''
SUCCESS = 0
FAILED = 1
RES=[]
nodes_length = 0

try:
    from queue import Queue     # python3
except ImportError:
    from Queue import Queue     # python2

if sys.platform.startswith("win32"):
    timer = time.clock
else:
    timer = time.time

def request_fun(path='',data={},request_type='get'):
    request_type == request_type.lower()
    APIURL = "{}{}?server_token={}&client_version={}&ipv4={}&ipv6={}".format(APIDOMAIN,path,SERVERTOKEN,VERSION,IPV4,IPV6)
    if request_type == 'get':
        res = requests.get(APIURL, data=data,headers={"server_token":SERVERTOKEN}, timeout=30, verify=False)
    elif request_type == 'post':
        res = requests.post(APIURL, data=data,headers={"server_token":SERVERTOKEN}, timeout=30, verify=False)
    return res

def get_ip():
    global IPV4
    global IPV6
    try:
        ip4=requests.get("https://ifconfig.me", timeout=5).text.strip()
    except:
        try:
            ip4=requests.get("https://api.myip.la", timeout=5, verify=False).text.strip()
        except:
            ip4 = ''
    try:
        ip6=requests.get("http://api-ipv6.ip.sb/ip", timeout=5).text.strip()
    except:
        try:
            ip6 = requests.get("https://ipv6.ping0.cc", timeout=5, verify=False).text.strip()
        except:
            ip6 = ''
    IPV4=ip4
    IPV6=ip6
    return ip4, ip6

def ping_test(node):
    ip=node['node_ipv4']
    host = ping(ip, count=60, interval=1)
    
    print(host)
    print('address: ')
    print(host.address)
    
    
    print('rtts: ')
    print(host.rtts)
    
    print('packets_sent: ')
    print(host.packets_sent)
    
    print('packets_received: ')
    print(host.packets_received)
    
    print('packet_loss: ')
    print(host.packet_loss)
    
    print('jitter: ')
    print(host.jitter)
    
    print('is_alive: ')
    print(host.is_alive)
    
    # print(loss1)
    exit()

def check_alive(ip,node_key,from_type):
    global nodes_length,RES
    
    ping_data = {}
    ping_data['max_rtt'] = 0
    ping_data['min_rtt'] = 0
    ping_data['avg_rtt'] = 0
    ping_data['packet_lost'] = 1
    ping_data['jitter'] = 0
    ping_data['packet_size'] = 0
    ping_data['dest'] = ip
    ping_data['dest_ip'] = ''
    ping_data['from_ip_type'] = from_type
    # ping_data['from_ip_v4'] = IPV4
    # ping_data['from_ip_v6'] = IPV6
    ping_data['node_key'] = node_key
    ping_data['is_alive'] = 0
    if from_type == 'ipv6':
        ping_data['from_ip_v6'] = IPV6
        ping_data['from_ip_v4'] = ''
    else:
        ping_data['from_ip_v6'] = ''
        ping_data['from_ip_v4'] = IPV4
    
    # https://github.com/ValentinBELYN/icmplib
    try:
        ping_result = ping(ip, count=10, interval=0.5)
        ping_data['max_rtt'] = ping_result.max_rtt
        ping_data['min_rtt'] = ping_result.min_rtt
        ping_data['avg_rtt'] = ping_result.avg_rtt
        ping_data['packet_lost'] = ping_result.packet_loss
        ping_data['jitter'] = ping_result.jitter
        ping_data['packet_size'] = ping_result.packets_sent
        ping_data['dest_ip'] = ping_result.address
        if ping_result.is_alive == True:
            ping_data['is_alive'] = 1
        else:
            ping_data['is_alive'] = 0
            
    except ICMPLibError as e:
        pass
    RES.append(ping_data)
        
    #     RES.append(ping_data)
    #     # ping_data['ping_data'] = json.loads(ping_result)
    #     # res = request_fun('/api/monitor/ping_data', {'data':json.dumps(ping_data)},'post')
    #     # res = res.json()
    #     # print('ipv6: {} --> submit res:'.format(ip,res.msg))
    #     # print(res.text)
        
    nodes_length -= 1
    if nodes_length==0:
        res = request_fun('/api/monitor/ping_data', {'data':json.dumps(RES)},'post')
        # res = res.json()
        # print(res.text)
        # time.sleep(PINGTIME)
        RES = []
            
    
    
def do_ping(host):
    if host['node_ipv4'] != None and IPV4 != '' and IPV4  != None:
        check_alive(host['node_ipv4'], host['node_key'], 'ipv4')
        
    if host['node_ipv6'] != None and IPV6 != '' and IPV6  != None:
        check_alive(host['node_ipv6'], host['node_key'], 'ipv6')
    
def get_ping():
    global nodes_length
    nodes_length = 0
    ping_hosts = request_fun('/api/monitor/ping_hosts',{},'get')
    try:
        ping_hosts = ping_hosts.json()
        if 'code' in ping_hosts and ping_hosts['code'] == 0 and len(ping_hosts['data']) > 0:
            ping_hosts = ping_hosts['data']
            nodes_length  = len(ping_hosts)
            max_value = 1000  # 线程池最大数量
            thread_pool = ThreadPoolExecutor(max_workers=max_value)  # 初始化线程池
            for host in ping_hosts:
                thread_pool.submit(do_ping, host)
            
    except ValueError:
        print('在获取Ping数据时，服务端返回数据错误')
        
    while True:
        if nodes_length == 0:
            get_ping()
            break;
        # else:
            
    


if __name__ == '__main__':
    get_ip()
    get_ping()
