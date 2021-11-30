#!/usr/bin/env python
# coding: utf-8

APIURL="https://baidu.com"
INTERVAL = 1
PORBEPORT = 80
TOKEN = open("/usr/local/ServerStatusPlus/config/token.conf", "r").read().strip()
CU = "www.chinaunicom.com"
CT = "www.189.cn"
CM = "www.10086.cn"
PING_PACKET_HISTORY_LEN = 100

import socket
import time
import timeit
import re
import os
import sys
import json
import errno
import subprocess
import threading
import requests
try:
    from queue import Queue     # python3
except ImportError:
    from Queue import Queue     # python2

def get_uptime():
    with open('/proc/uptime', 'r') as f:
        uptime = f.readline().split('.', 2)
        return int(uptime[0])

def get_memory():
    re_parser = re.compile(r'^(?P<key>\S*):\s*(?P<value>\d*)\s*kB')
    result = dict()
    for line in open('/proc/meminfo'):
        match = re_parser.match(line)
        if not match:
            continue
        key, value = match.groups(['key', 'value'])
        result[key] = int(value)
    MemTotal = float(result['MemTotal'])
    MemUsed = MemTotal-float(result['MemFree'])-float(result['Buffers'])-float(result['Cached'])-float(result['SReclaimable'])
    SwapTotal = float(result['SwapTotal'])
    SwapFree = float(result['SwapFree'])
    return int(MemTotal), int(MemUsed), int(SwapTotal), int(SwapFree)

def get_hdd():
    p = subprocess.check_output(['df', '-Tlm', '--total', '-t', 'ext4', '-t', 'ext3', '-t', 'ext2', '-t', 'reiserfs', '-t', 'jfs', '-t', 'ntfs', '-t', 'fat32', '-t', 'btrfs', '-t', 'fuseblk', '-t', 'zfs', '-t', 'simfs', '-t', 'xfs']).decode("Utf-8")
    total = p.splitlines()[-1]
    used = total.split()[3]
    size = total.split()[2]
    return int(size), int(used)

def get_time():
    with open("/proc/stat", "r") as f:
        time_list = f.readline().split(' ')[2:6]
        for i in range(len(time_list))  :
            time_list[i] = int(time_list[i])
        return time_list

def delta_time():
    x = get_time()
    time.sleep(INTERVAL)
    y = get_time()
    for i in range(len(x)):
        y[i]-=x[i]
    return y

def get_cpu():
    t = delta_time()
    st = sum(t)
    if st == 0:
        st = 1
    result = 100-(t[len(t)-1]*100.00/st)
    return round(result, 1)

def liuliang():
    NET_IN = 0
    NET_OUT = 0
    with open('/proc/net/dev') as f:
        for line in f.readlines():
            netinfo = re.findall('([^\s]+):[\s]{0,}(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)', line)
            if netinfo:
                if netinfo[0][0] == 'lo' or 'tun' in netinfo[0][0] \
                        or 'docker' in netinfo[0][0] or 'veth' in netinfo[0][0] \
                        or 'br-' in netinfo[0][0] or 'vmbr' in netinfo[0][0] \
                        or 'vnet' in netinfo[0][0] or 'kube' in netinfo[0][0] \
                        or netinfo[0][1]=='0' or netinfo[0][9]=='0':
                    continue
                else:
                    NET_IN += int(netinfo[0][1])
                    NET_OUT += int(netinfo[0][9])
    return NET_IN, NET_OUT

def tupd():
    '''
    tcp, udp, process, thread count: for view ddcc attack , then send warning
    :return:
    '''
    s = subprocess.check_output("ss -t|wc -l", shell=True)
    t = int(s[:-1])-1
    s = subprocess.check_output("ss -u|wc -l", shell=True)
    u = int(s[:-1])-1
    s = subprocess.check_output("ps -ef|wc -l", shell=True)
    p = int(s[:-1])-2
    s = subprocess.check_output("ps -eLf|wc -l", shell=True)
    d = int(s[:-1])-2
    return t,u,p,d

def ip_status():
    ip_check = 0
    for i in [CU, CT, CM]:
        try:
            socket.create_connection((i, PORBEPORT), timeout=1).close()
        except:
            ip_check += 1
    if ip_check >= 2:
        return False
    else:
        return True

def get_network(ip_version):
    if(ip_version == 4):
        HOST = "ipv4.google.com"
    elif(ip_version == 6):
        HOST = "ipv6.google.com"
    try:
        socket.create_connection((HOST, 80), 2).close()
        return True
    except:
        return False

lostRate = {
    '10010': 0.0,
    '189': 0.0,
    '10086': 0.0
}
pingTime = {
    '10010': 0,
    '189': 0,
    '10086': 0
}
netSpeed = {
    'netrx': 0.0,
    'nettx': 0.0,
    'clock': 0.0,
    'diff': 0.0,
    'avgrx': 0,
    'avgtx': 0
}

def _ping_thread(host, mark, port):
    lostPacket = 0
    packet_queue = Queue(maxsize=PING_PACKET_HISTORY_LEN)

    IP = host
    if host.count(':') < 1:     # if not plain ipv6 address, means ipv4 address or hostname
        try:
            if PROBE_PROTOCOL_PREFER == 'ipv4':
                IP = socket.getaddrinfo(host, None, socket.AF_INET)[0][4][0]
            else:
                IP = socket.getaddrinfo(host, None, socket.AF_INET6)[0][4][0]
        except Exception:
                pass

    while True:
        if packet_queue.full():
            if packet_queue.get() == 0:
                lostPacket -= 1
        try:
            b = timeit.default_timer()
            socket.create_connection((IP, port), timeout=1).close()
            pingTime[mark] = int((timeit.default_timer() - b) * 1000)
            packet_queue.put(1)
        except socket.error as error:
            if error.errno == errno.ECONNREFUSED:
                pingTime[mark] = int((timeit.default_timer() - b) * 1000)
                packet_queue.put(1)
            #elif error.errno == errno.ETIMEDOUT:
            else:
                lostPacket += 1
                packet_queue.put(0)

        if packet_queue.qsize() > 30:
            lostRate[mark] = float(lostPacket) / packet_queue.qsize()

        time.sleep(INTERVAL)

def _net_speed():
    while True:
        with open("/proc/net/dev", "r") as f:
            net_dev = f.readlines()
            avgrx = 0
            avgtx = 0
            for dev in net_dev[2:]:
                dev = dev.split(':')
                if "lo" in dev[0] or "tun" in dev[0] \
                        or "docker" in dev[0] or "veth" in dev[0] \
                        or "br-" in dev[0] or "vmbr" in dev[0] \
                        or "vnet" in dev[0] or "kube" in dev[0]:
                    continue
                dev = dev[1].split()
                avgrx += int(dev[0])
                avgtx += int(dev[8])
            now_clock = time.time()
            netSpeed["diff"] = now_clock - netSpeed["clock"]
            netSpeed["clock"] = now_clock
            netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
            netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
            netSpeed["avgrx"] = avgrx
            netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)

def get_realtime_date():
    t1 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CU,
            'mark': '10010',
            'port': PORBEPORT
        }
    )
    t2 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CT,
            'mark': '189',
            'port': PORBEPORT
        }
    )
    t3 = threading.Thread(
        target=_ping_thread,
        kwargs={
            'host': CM,
            'mark': '10086',
            'port': PORBEPORT
        }
    )
    t4 = threading.Thread(
        target=_net_speed,
    )
    t1.setDaemon(True)
    t2.setDaemon(True)
    t3.setDaemon(True)
    t4.setDaemon(True)
    t1.start()
    t2.start()
    t3.start()
    t4.start()

if __name__ == '__main__':
    for argc in sys.argv:
        if 'token' in argc:
            TOKEN = argc.split('token=')[-1]
        elif 'INTERVAL' in argc:
            INTERVAL = int(argc.split('INTERVAL=')[-1])
    get_realtime_date()
    while True:
        try:
            print("Connecting...")
            while True:
                CPU = get_cpu()
                NET_IN, NET_OUT = liuliang()
                Uptime = get_uptime()
                Load_1, Load_5, Load_15 = os.getloadavg()
                MemoryTotal, MemoryUsed, SwapTotal, SwapFree = get_memory()
                HDDTotal, HDDUsed = get_hdd()
                IP_STATUS = ip_status()

                array = {}
                array['uptime'] = Uptime
                array['load_1'] = Load_1
                array['load_5'] = Load_5
                array['load_15'] = Load_15
                array['memory_total'] = MemoryTotal
                array['memory_used'] = MemoryUsed
                array['swap_total'] = SwapTotal
                array['swap_used'] = SwapTotal - SwapFree
                array['hdd_total'] = HDDTotal
                array['hdd_used'] = HDDUsed
                array['cpu'] = CPU
                array['network_rx'] = netSpeed.get("netrx")
                array['network_tx'] = netSpeed.get("nettx")
                array['network_in'] = NET_IN
                array['network_out'] = NET_OUT
                array['ip_status'] = IP_STATUS
                array['ping_10010'] = lostRate.get('10010') * 100
                array['ping_189'] = lostRate.get('189') * 100
                array['ping_10086'] = lostRate.get('10086') * 100
                array['time_10010'] = pingTime.get('10010')
                array['time_189'] = pingTime.get('189')
                array['time_10086'] = pingTime.get('10086')
                array['tcp'], array['udp'], array['process'], array['thread'] = tupd()
                
                
                try:
                    requests.post(APIURL, json.dumps(array),headers={"token":TOKEN}, timeout=5)  
                    break
                except requests.exceptions.ConnectionError:
                    print('连接到API错误 -- 请等待3秒')
                    time.sleep(3)
                except requests.exceptions.ChunkedEncodingError:
                    print('分块编码错误 -- 请等待3秒')
                    time.sleep(3)    
                except:
                    print('未知错误, 请等待3秒')
                    time.sleep(3)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print("捕获异常:", e)
            time.sleep(3)
    
