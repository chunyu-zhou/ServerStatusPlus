#!/usr/bin/env python3
# coding: utf-8
import socket
import time
import os
import json
import psutil
import sys
import threading
import requests
import platform
import hashlib
import re
import subprocess
import fileinput
import distro
from typing import List, Dict, Any
from cachelib import SimpleCache

APIDOMAIN="http://monitor.onecdn.cn"

VERSION = '1.0.0'
INTERVAL = 1
PORBEPORT = 80
SERVERTOKEN=open("/usr/local/ServerStatusPlus/config/ServerToken.conf", "r").read().strip()
CU="www.chinaunicom.com"
CT="www.189.cn"
CM="www.10086.cn"
GETIPTIME=10
PINGTIME=10
UPGRDETIME=600
IPV4=''
IPV6=''
PING_PACKET_HISTORY_LEN = 100
PROBE_PROTOCOL_PREFER = "ipv4"  # ipv4, ipv6
SUCCESS = 0
FAILED = 1
UNIX: bool = os.name == 'posix'
SYS: str = platform.system()

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

# 参考文档 https://blog.csdn.net/qq_26373925/article/details/108047836
class CpuConstants:
    def __init__(self):
        '''
        初始化CPU常量（多平台）
        Returns
        -------
        self.
        '''
        self.WMI = None
        self.initialed: bool = False
        self.cpuList: list = [] # windows only

        self.cpuCount: int = 0 # 物理cpu数量
        self.cpuCore: int = 0 # cpu物理核心数
        self.cpuThreads: int = 0 # cpu逻辑核心数
        self.cpuName: str = '' # cpu型号

        self.Update(True)


    def Update(self, update: bool = False) -> None:
        '''
        更新cpu数据
        Returns
        -------
        None.
        '''
        if UNIX: self.GetCpuConstantsUnix(update)
        else: self.GetCpuConstantsWindows(update)

        self.initialed: bool = True


    @property
    def getDict(self) -> Dict[int, str]:
        '''
        以字典格式获取当前cpu常量
        Returns
        -------
        Dict[int, str]
            DESCRIPTION.
        '''
        if not self.initialed: self.Update()
        return {
            'cpu_count': self.cpuCount,
            'cpu_name': self.cpuName,
            'cpu_core': self.cpuCore,
            'cpu_threads': self.cpuThreads
        }


    def GetCpuConstantsUnix(self, update: bool = False) -> None:
        '''
        获取unix下的cpu信息
        Parameters
        ----------
        update : bool, optional
            DESCRIPTION. The default is False.
        Returns
        -------
        None
            DESCRIPTION.
        '''
        if update or not self.initialed:
            ids: list = re.findall("physical id.+", readFile('/proc/cpuinfo'))

            # 物理cpu个数
            self.cpuCount: int = len(set(ids))

            # cpu型号（名称）
            self.cpuName: str = self.getCpuTypeUnix()


            self.GetCpuConstantsBoth()


    def InitWmi(self) -> None:
        '''
        初始化wmi（for windows）
        Returns
        -------
        None
            DESCRIPTION.
        '''
        import wmi
        self.WMI = wmi.WMI()


    def GetCpuConstantsBoth(self, update: bool = False) -> None:
        '''
        获取多平台共用的cpu信息
        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.
        Returns
        -------
        None
            DESCRIPTION.
        '''
        if update or not self.initialed:

            # cpu逻辑核心数
            self.cpuThreads: int = psutil.cpu_count()

            # cpu物理核心数
            self.cpuCore: int = psutil.cpu_count(logical=False)


    def GetCpuConstantsWindows(self, update: bool = False) -> None:
        '''
        获取windows平台的cpu信息
        Parameters
        ----------
        update : bool, optional
            强制更新数据. The default is False.
        Returns
        -------
        None
            DESCRIPTION.
        '''
        if update or not self.initialed:

            # 初始化wmi
            if self.WMI == None: self.InitWmi()

            # cpu列表
            self.cpuList: list = self.WMI.Win32_Processor()

            # 物理cpu个数
            self.cpuCount: int = len(self.cpuList)

            # cpu型号（名称）
            self.cpuName: str = self.cpuList[0].Name


            self.GetCpuConstantsBoth()


    @staticmethod
    def getCpuTypeUnix() -> str:
        '''
        获取CPU型号（unix）
        Returns
        -------
        str
            CPU型号.
        '''
        cpuinfo: str = readFile('/proc/cpuinfo')
        rep: str = 'model\s+name\s+:\s+(.+)'
        tmp = re.search(rep,cpuinfo,re.I)
        cpuType: str = ''
        if tmp:
            cpuType: str = tmp.groups()[0]
        else:
            cpuinfo = ExecShellUnix('LANG="en_US.UTF-8" && lscpu')[0]
            rep = 'Model\s+name:\s+(.+)'
            tmp = re.search(rep,cpuinfo,re.I)
            if tmp: cpuType = tmp.groups()[0]
        return cpuType


def GetCpuInfo(interval: int = 1) -> Dict[str, Any]:
    '''
    获取CPU信息
    Parameters
    ----------
    interval : int, optional
        DESCRIPTION. The default is 1.
    Returns
    -------
    Dict[float, list, dict]
        DESCRIPTION.
    '''
    time.sleep(0.5)


    # cpu总使用率
    used: float = psutil.cpu_percent(interval)

    # 每个逻辑cpu使用率
    usedList: List[float] = psutil.cpu_percent(percpu=True)


    return {'used': used, 'used_list': usedList, **cpuConstants.getDict}


def readFile(filename: str) -> str:
    '''
    读取文件内容
    Parameters
    ----------
    filename : str
        文件名.
    Returns
    -------
    str
        文件内容.
    '''
    try:
        with open(filename, 'r', encoding='utf-8') as file: return file.read()
    except:
        pass

    return ''


def GetLoadAverage() -> dict:
    '''
    获取服务器负载状态（多平台）
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    try: c: list = os.getloadavg()
    except: c: list = [0,0,0]
    data: dict = {i: c[idx] for idx, i in enumerate(('one', 'five', 'fifteen'))}
    data['max'] = psutil.cpu_count() * 2
    data['limit'] = data['max']
    data['safe'] = data['max'] * 0.75
    return data


def GetMemInfo() -> dict:
    '''
    获取内存信息（多平台）
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    if UNIX: return GetMemInfoUnix()
    return GetMemInfoWindows()


def GetMemInfoUnix() -> Dict[str, int]:
    '''
    获取内存信息（unix）
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    mem = psutil.virtual_memory()
    memInfo: dict = {
        'memTotal': ToSizeInt(mem.total, 'KB'),
        'memFree': ToSizeInt(mem.free, 'KB'),
        'memBuffers': ToSizeInt(mem.buffers, 'KB'),
        'memCached': ToSizeInt(mem.cached, 'KB'),
    }
    memInfo['memRealUsed'] = \
        memInfo['memTotal'] - \
        memInfo['memFree'] - \
        memInfo['memBuffers'] - \
        memInfo['memCached']

    memInfo['memUsedPercent'] = memInfo['memRealUsed'] / memInfo['memTotal'] * 100

    return memInfo


def GetMemInfoWindows() -> dict:
    '''
    获取内存信息（windows）
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    mem = psutil.virtual_memory()
    memInfo: dict = {
        'memTotal': ToSizeInt(mem.total, 'KB'),
        'memFree': ToSizeInt(mem.free, 'KB'),
        'memRealUsed': ToSizeInt(mem.used, 'KB'),
        'menUsedPercent': mem.used / mem.total * 100
    }

    return memInfo


def ToSizeInt(byte: int, target: str) -> int:
    '''
    将字节大小转换为目标单位的大小
    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）
    target : str
        目标单位，str.
    Returns
    -------
    int
        转换为目标单位后的字节大小.
    '''
    return int(byte/1024**(('KB','MB','GB','TB').index(target) + 1))


def ToSizeString(byte: int) -> str:
    '''
    获取字节大小字符串
    Parameters
    ----------
    byte : int
        int格式的字节大小（bytes size）.
    Returns
    -------
    str
        自动转换后的大小字符串，如：6.90 GB.
    '''
    units: tuple = ('b','KB','MB','GB','TB')
    re = lambda: '{:.2f} {}'.format(byte, u)
    for u in units:
        if byte < 1024: return re()
        byte /= 1024
    return re()


def GetDiskInfo() -> list:
    '''
    获取磁盘信息（多平台）
    Returns
    -------
    list
        列表.
    '''
    try:
        if UNIX: return GetDiskInfoUnix()
        return GetDiskInfoWindows()
    except Exception as err:
        print('获取磁盘信息异常（unix: {}）：'.format(UNIX), err)
        return []


def GetDiskInfoWindows() -> list:
    '''
    获取磁盘信息Windows
    Returns
    -------
    diskInfo : list
        列表.
    '''
    diskIo: list = psutil.disk_partitions()
    diskInfo: list = []
    for disk in diskIo:
        tmp: dict = {}
        try:
            tmp['path'] = disk.mountpoint.replace("\\","/")
            usage = psutil.disk_usage(disk.mountpoint)
            tmp['size'] = {
                'total': usage.total,
                'used': usage.used,
                'free': usage.free,
                'percent': usage.percent
            }
            tmp['fstype'] = disk.fstype
            tmp['inodes'] = False
            diskInfo.append(tmp)
        except:
            pass
    return diskInfo


def GetDiskInfoUnix() -> list:
     '''
    获取硬盘分区信息（unix）
    Returns
    -------
    list
        DESCRIPTION.
    '''
     temp: list = (
         ExecShellUnix("df -h -P|grep '/'|grep -v tmpfs")[0]).split('\n')
     tempInodes: list = (
         ExecShellUnix("df -i -P|grep '/'|grep -v tmpfs")[0]).split('\n')
     diskInfo: list = []
     n: int = 0
     cuts: list = [
         '/mnt/cdrom',
         '/boot',
         '/boot/efi',
         '/dev',
         '/dev/shm',
         '/run/lock',
         '/run',
         '/run/shm',
         '/run/user'
     ]
     for tmp in temp:
         n += 1
         try:
             inodes: list = tempInodes[n-1].split()
             disk: list = tmp.split()
             if len(disk) < 5: continue
             if disk[1].find('M') != -1: continue
             if disk[1].find('K') != -1: continue
             if len(disk[5].split('/')) > 10: continue
             if disk[5] in cuts: continue
             if disk[5].find('docker') != -1: continue
             arr = {}
             arr['path'] = disk[5]
             tmp1 = [disk[1],disk[2],disk[3],disk[4]]
             arr['size'] = tmp1
             arr['inodes'] = [inodes[1],inodes[2],inodes[3],inodes[4]]
             diskInfo.append(arr)
         except Exception as ex:
             print('信息获取错误：', str(ex))
             continue
     return diskInfo



def md5(strings: str) -> str:
    '''
    生成md5
    Parameters
    ----------
    strings : TYPE
        要进行hash处理的字符串
    Returns
    -------
    str[32]
        hash后的字符串.
    '''

    m = hashlib.md5()
    m.update(strings.encode('utf-8'))
    return m.hexdigest()


def GetErrorInfo() -> str:
    '''
    获取traceback中的错误
    Returns
    -------
    str
        DESCRIPTION.
    '''
    import traceback
    errorMsg = traceback.format_exc()
    return errorMsg


def ExecShellUnix(cmdstring: str, shell=True):
    '''
    执行Shell命令（Unix）
    Parameters
    ----------
    cmdstring : str
        DESCRIPTION.
    shell : TYPE, optional
        DESCRIPTION. The default is True.
    Returns
    -------
    a : TYPE
        DESCRIPTION.
    e : TYPE
        DESCRIPTION.
    '''
    a: str = ''
    e: str = ''
    import subprocess,tempfile

    try:
        rx: str = md5(cmdstring)
        succ_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_succ',
            prefix = 'btex_' + rx ,
            dir = '/dev/shm'
        )
        err_f = tempfile.SpooledTemporaryFile(
            max_size = 4096,
            mode = 'wb+',
            suffix = '_err',
            prefix = 'btex_' + rx ,
            dir = '/dev/shm'
        )
        sub = subprocess.Popen(
            cmdstring,
            close_fds = True,
            shell = shell,
            bufsize = 128,
            stdout = succ_f,
            stderr = err_f
        )
        sub.wait()
        err_f.seek(0)
        succ_f.seek(0)
        a = succ_f.read()
        e = err_f.read()
        if not err_f.closed: err_f.close()
        if not succ_f.closed: succ_f.close()
    except Exception as err:
        print(err)
    try:
        if type(a) == bytes: a = a.decode('utf-8')
        if type(e) == bytes: e = e.decode('utf-8')
    except Exception as err:
        print(err)

    return a,e


def GetNetWork() -> dict:
    '''
    获取系统网络信息
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    networkIo: list = [0,0,0,0]
    cache_timeout: int = 86400
    try:
        networkIo = psutil.net_io_counters()[:4]
    except:
        pass

    otime = cache.get("otime")
    if not otime:
        otime = time.time()
        cache.set('up',networkIo[0],cache_timeout)
        cache.set('down',networkIo[1],cache_timeout)
        cache.set('otime',otime ,cache_timeout)

    ntime = time.time()
    networkInfo: dict = {'up': 0, 'down': 0}
    networkInfo['upTotal']   = networkIo[0]
    networkInfo['downTotal'] = networkIo[1]
    try:
        networkInfo['up'] = round(
            float(networkIo[0] - cache.get("up")) / 1024 / (ntime - otime),
            2
        )
        networkInfo['down'] = round(
            float(networkIo[1] - cache.get("down")) / 1024 / (ntime -  otime),
            2
        )
    except:
        pass

    networkInfo['downPackets'] = networkIo[3]
    networkInfo['upPackets'] = networkIo[2]

    cache.set('up',networkIo[0],cache_timeout)
    cache.set('down',networkIo[1],cache_timeout)
    cache.set('otime', time.time(),cache_timeout)

    return networkInfo


def GetSystemInfo() -> dict:
    systemInfo: dict = {}
    systemInfo['cpu'] = GetCpuInfo()
    systemInfo['load'] = GetLoadAverage()
    systemInfo['mem'] = GetMemInfo()
    systemInfo['disk'] = GetDiskInfo()

    return systemInfo



def GetIoReadWrite() -> Dict[str, int]:
    '''
    获取系统IO读写
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    ioDisk = psutil.disk_io_counters()
    ioTotal: dict = {}
    ioTotal['write'] = GetIoWrite(ioDisk.write_bytes)
    ioTotal['read'] = GetIoRead(ioDisk.read_bytes)
    return ioTotal


def GetIoWrite(ioWrite: int) -> int:
    '''
    获取IO写
    Parameters
    ----------
    ioWrite : TYPE
        DESCRIPTION.
    Returns
    -------
    int
        DESCRIPTION.
    '''
    diskWrite: int = 0
    oldWrite: int = cache.get('io_write')
    if not oldWrite:
        cache.set('io_write', ioWrite)
        return diskWrite;

    oldTime: float = cache.get('io_time')
    newTime: float = time.time()
    if not oldTime: oldTime = newTime
    ioEnd: int = (ioWrite - oldWrite)
    timeEnd: float = (time.time() - oldTime)
    if ioEnd > 0:
        if timeEnd < 1: timeEnd = 1
        diskWrite = ioEnd / timeEnd
    cache.set('io_write',ioWrite)
    cache.set('io_time',newTime)
    if diskWrite > 0: return int(diskWrite)
    return 0


def GetIoRead(ioRead):
    '''
    读取IO读
    Parameters
    ----------
    ioRead : TYPE
        DESCRIPTION.
    Returns
    -------
    TYPE
        DESCRIPTION.
    '''
    diskRead: int = 0
    oldRead: int = cache.get('io_read')
    if not oldRead:
        cache.set('io_read',ioRead)
        return diskRead;
    oldTime: float = cache.get('io_time')
    newTime: float = time.time()
    if not oldTime: oldTime = newTime
    ioEnd: int = (ioRead - oldRead)
    timeEnd: float = (time.time() - oldTime)
    if ioEnd > 0:
        if timeEnd < 1: timeEnd = 1;
        diskRead = ioEnd / timeEnd;
    cache.set('io_read', ioRead)
    if diskRead > 0: return int(diskRead)
    return 0


def GetRegValue(key: str, subkey: str, value: str) -> Any:
    '''
    获取系统注册表信息
    Parameters
    ----------
    key : str
        类型.
    subkey : str
        路径.
    value : str
        key.
    Returns
    -------
    value : Any
        DESCRIPTION.
    '''
    import winreg
    key = getattr(winreg, key)
    handle = winreg.OpenKey(key, subkey)
    (value, type) = winreg.QueryValueEx(handle, value)
    return value


def GetSystemVersion() -> str:
    '''
    获取操作系统版本（多平台）
    Returns
    -------
    str
        DESCRIPTION.
    '''
    if UNIX: return GetSystemVersionUnix()
    return GetSystemVersionWindows()


def GetSystemVersionWindows() -> str:
    '''
    获取操作系统版本（windows）
    Returns
    -------
    str
        DESCRIPTION.
    '''
    try:
        import platform
        bit: str = 'x86';
        if 'PROGRAMFILES(X86)' in os.environ: bit = 'x64'

        def get(key: str):
            return GetRegValue(
                "HKEY_LOCAL_MACHINE",
                "SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion",
                key
            )

        osName = get('ProductName')
        build = get('CurrentBuildNumber')

        version: str = '{} (build {}) {} (Py{})'.format(
            osName, build, bit, platform.python_version())
        return version
    except Exception as ex:
        print('获取系统版本失败，错误：' + str(ex))
        return '未知系统版本.'


def GetSystemVersionUnix() -> str:
    '''
    获取系统版本（unix）
    Returns
    -------
    str
        系统版本.
    '''
    try:
        version: str = readFile('/etc/redhat-release')
        if not version:
            version = readFile(
                '/etc/issue'
            ).strip().split("\n")[0].replace('\\n','').replace('\l','').strip()
        else:
            version = version.replace(
                'release ',''
            ).replace('Linux','').replace('(Core)','').strip()
        v = sys.version_info
        return version + '(Py {}.{}.{})'.format(v.major, v.minor, v.micro)
    except Exception as err:
        print('获取系统版本失败，错误：', err)
        return '未知系统版本.'

def GetSystemVersionCore() -> str:
    '''
    获取系统内核版本（unix）
    Returns
    -------
    str
        系统版本.
    '''
    return platform.release()

def getHostname():
    return platform.node()
    
def GetBootTime() -> dict:
    '''
    获取当前系统启动时间
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    bootTime: float = psutil.boot_time()
    return {
        'timestamp': bootTime,
        'runtime': time.time() - bootTime,
        'datetime': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime())
    }


def GetCpuConstants() -> dict:
    '''
    获取CPU常量信息
    Parameters
    ----------
    cpuConstants : CpuConstants
        DESCRIPTION.
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    return cpuConstants.getDict


def GetFullSystemData() -> dict:
    '''
    获取完全的系统信息
    Returns
    -------
    dict
        DESCRIPTION.
    '''
    systemData: dict = {
        **GetSystemInfo(),
        'network': { **GetNetWork() },
        'io': { **GetIoReadWrite() },
        'boot': { **GetBootTime() },
        'time': time.time()
    }
    return systemData

cpuConstants = CpuConstants()
cache = SimpleCache()

def get_uptime():
    return int(time.time() - psutil.boot_time())

def get_memory():
    Mem = psutil.virtual_memory()
    return int(Mem.total), int(Mem.used)

def get_swap():
    Mem = psutil.swap_memory()
    return int(Mem.total), int(Mem.used)

def get_hdd():
    valid_fs = [ "ext4", "ext3", "ext2", "reiserfs", "jfs", "btrfs", "fuseblk", "zfs", "simfs", "ntfs", "fat32", "exfat", "xfs" ]
    disks = dict()
    size = 0
    used = 0
    for disk in psutil.disk_partitions():
        if not disk.device in disks and disk.fstype.lower() in valid_fs:
            disks[disk.device] = disk.mountpoint
    for disk in disks.values():
        usage = psutil.disk_usage(disk)
        size += usage.total
        used += usage.used
    return int(size), int(used)

def get_cpu():
    return psutil.cpu_percent(interval=INTERVAL)

def liuliang():
    NET_IN = 0
    NET_OUT = 0
    net = psutil.net_io_counters(pernic=True)
    for k, v in net.items():
        if 'lo' in k or 'tun' in k \
                or 'docker' in k or 'veth' in k \
                or 'br-' in k or 'vmbr' in k \
                or 'vnet' in k or 'kube' in k:
            continue
        else:
            NET_IN += v[1]
            NET_OUT += v[0]
    return NET_IN, NET_OUT

def tupd():
    '''
    tcp, udp, process, thread count: for view ddcc attack , then send warning
    :return:
    '''
    try:
        if sys.platform.startswith("linux") is True:
            t = int(os.popen('ss -t|wc -l').read()[:-1])-1
            u = int(os.popen('ss -u|wc -l').read()[:-1])-1
            p = int(os.popen('ps -ef|wc -l').read()[:-1])-2
            d = int(os.popen('ps -eLf|wc -l').read()[:-1])-2
        elif sys.platform.startswith("win") is True:
            t = int(os.popen('netstat -an|find "TCP" /c').read()[:-1])-1
            u = int(os.popen('netstat -an|find "UDP" /c').read()[:-1])-1
            p = len(psutil.pids())
            d = 0
            # cpu is high, default: 0
            # d = sum([psutil.Process(k).num_threads() for k in [x for x in psutil.pids()]])
        else:
            t,u,p,d = 0,0,0,0
        return t,u,p,d
    except:
        return 0,0,0,0

def ip_status():
    ip_check = 0
    for i in [CU, CT, CM]:
        try:
            socket.create_connection((i, PORBEPORT), timeout=5).close()
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

def _net_speed():
    while True:
        avgrx = 0
        avgtx = 0
        for name, stats in psutil.net_io_counters(pernic=True).items():
            if "lo" in name or "tun" in name \
                    or "docker" in name or "veth" in name \
                    or "br-" in name or "vmbr" in name \
                    or "vnet" in name or "kube" in name:
                continue
            avgrx += stats.bytes_recv
            avgtx += stats.bytes_sent
        now_clock = time.time()
        netSpeed["diff"] = now_clock - netSpeed["clock"]
        netSpeed["clock"] = now_clock
        netSpeed["netrx"] = int((avgrx - netSpeed["avgrx"]) / netSpeed["diff"])
        netSpeed["nettx"] = int((avgtx - netSpeed["avgtx"]) / netSpeed["diff"])
        netSpeed["avgrx"] = avgrx
        netSpeed["avgtx"] = avgtx
        time.sleep(INTERVAL)

def get_realtime_date():
    # t1 = threading.Thread(
    #     target=_ping_thread,
    #     kwargs={
    #         'host': CU,
    #         'mark': '10010',
    #         'port': PORBEPORT
    #     }
    # )
    # t2 = threading.Thread(
    #     target=_ping_thread,
    #     kwargs={
    #         'host': CT,
    #         'mark': '189',
    #         'port': PORBEPORT
    #     }
    # )
    # t3 = threading.Thread(
    #     target=_ping_thread,
    #     kwargs={
    #         'host': CM,
    #         'mark': '10086',
    #         'port': PORBEPORT
    #     }
    # )
    t4 = threading.Thread(
        target=_net_speed,
    )
    # t1.setDaemon(True)
    # t2.setDaemon(True)
    # t3.setDaemon(True)
    t4.setDaemon(True)
    # t1.start()
    # t2.start()
    # t3.start()
    t4.start()

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

def check_upgrade():
    print('检测更新...')
    version = request_fun('/api/config/version', {},'get').text.strip()
    if version != VERSION:
        print('需要更新，最新版本：{} 当前版本：{}'.format(version,VERSION))
        cmd='/etc/init.d/status stop && wget -N --no-check-certificate -O "/usr/local/ServerStatusPlus/status-plus-client.py" "https://gitee.com/zcyso/ServerStatusPlus/raw/master/status-plus-client.py" && /etc/init.d/status start && /etc/init.d/status status'
        os.system(cmd)
    else:
        print('不需要更新，当前版本：{}'.format(VERSION))
    # time.sleep(UPGRDETIME)
    # check_upgrade()

def machine():
    """Return type ofmachine."""
    if os.name == 'nt' and sys.version_info[:2] < (2,7):
        returnos.environ.get("PROCESSOR_ARCHITEW6432",
                os.environ.get('PROCESSOR_ARCHITECTURE',''))
    else:
        return platform.machine()

def os_bits(machine=machine()):
    """Return bitness ofoperating system, or None if unknown."""
    machine2bits = {'AMD64':64, 'x86_64': 64, 'i386': 32, 'x86': 32}
    return machine2bits.get(machine, None)
def get_virtualization_type():
    if UNIX:
        virtualization_type = ExecShellUnix('LANG="en_US.UTF-8" && systemd-detect-virt')[0].strip()
        if virtualization_type=='' or virtualization_type=='none' or virtualization_type==None:
            virtualization_type='物理机'
    else:
        # windows系统
        virtualization_type = ''
    return virtualization_type
    

def get_mac_cpu_speed():
    commond = 'system_profiler SPHardwareDataType | grep "Processor Speed" | cut -d ":" -f2'
    proc = subprocess.Popen([commond], shell=True, stdout=subprocess.PIPE)
    output = proc.communicate()[0]
    output = output.decode()   # bytes 转str
    speed = output.lstrip().rstrip('\n')
    return speed


def get_linux_cpu_speed():
    for line in fileinput.input('/proc/cpuinfo'):
        if 'MHz' in line:
            value = line.split(':')[1].strip()
            value = float(value)
            speed = round(value / 1024, 1)
            return "{speed} GHz".format(speed=speed)


def get_windows_cpu_speed():
    import winreg
    key = winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, r"HARDWARE\DESCRIPTION\System\CentralProcessor\0")
    speed, type = winreg.QueryValueEx(key, "~MHz")
    speed = round(float(speed)/1024, 1)
    return "{speed} GHz".format(speed=speed)


def get_cpu_speed():
    osname = platform.system()  # 获取操作系统的名称
    speed = ''
    if osname == "Darwin":
        speed = get_mac_cpu_speed()
    if osname == "Linux":
        speed = get_linux_cpu_speed()
    if osname in ["Windows", "Win32"]:
        speed = get_windows_cpu_speed()

    return speed

def get_virtualization_firmware_enabled():
    osname = platform.system()  # 获取操作系统的名称
    is_enabled = 0
    if osname in ["Windows", "Win32"]:
        import wmi
        _is_enabled = wmi.WMI().Win32_Processor()[0].VirtualizationFirmwareEnabled
        if _is_enabled == True:
            is_enabled = 1
        else:
            is_enabled = 0
    else:
        _is_enabled = re.findall("flags", ExecShellUnix("grep -E '(vmx|svm)' /proc/cpuinfo")[0])
        if len(_is_enabled) > 0:
            _is_enabled = 1

    return is_enabled

def get_cpu_cache_size():
    osname = platform.system()  # 获取操作系统的名称
    cache_size = 0
    if osname in ["Windows", "Win32"]:
        import wmi
        cache_size = wmi.WMI().Win32_Processor()[0].VirtualizationFirmwareEnabled
    else:
        cache_size = ExecShellUnix("cat /proc/cpuinfo |grep -m 1 'cache size'")[0].strip().split(':')[1].strip().split(' ')[0]

    return cache_size
    
def get_cpu_vendor_id():
    osname = platform.system()  # 获取操作系统的名称
    vendor_id = ''
    if osname in ["Windows", "Win32"]:
        import wmi
        vendor_id = wmi.WMI().Win32_Processor()[0].Manufacturer
    else:
        vendor_id = ExecShellUnix("cat /proc/cpuinfo |grep -m 1 'vendor_id'")[0].strip().split(':')[1].strip().split(' ')[0]

    return vendor_id
    
def getOsInfo():
    SwapTotal, SwapUsed = get_swap()
    HDDTotal, HDDUsed = get_hdd()
    # try:
    #     os_dist = platform.dist()
    # except:
    #     os_dist = distro.linux_distribution(full_distribution_name=False)
    # if UNIX:
    #     os_dist = distro.linux_distribution(full_distribution_name=False)
    # os_dist = distro.linux_distribution(full_distribution_name=False)
    CpuConstants = GetCpuConstants()
    MemInfo = GetMemInfo()
    CpuInfo = GetCpuInfo()
    # IPV4, IPV6 = get_ip()
    
    array = {}
    array['cpu_count'] = CpuInfo['cpu_count'] # CPU逻辑数量
    array['cpu_core'] = CpuInfo['cpu_core'] # CPU核心
    array['cpu_threads'] = CpuInfo['cpu_threads'] # CPU线程
    array['os'] = distro.id()
    array['os_version'] = distro.version()
    array['os_name'] = distro.name()
    array['os_bit_versions'] = os_bits()
    array['os_bit'] = platform.architecture()[0]
    array['release_version'] = GetSystemVersionCore()
    array['platform'] = platform.platform(True)
    array['host_name'] = getHostname()
    array['cpu_speed'] = get_cpu_speed()
    array['cpu_name'] = CpuConstants['cpu_name']
    array['memory_total'] = MemInfo['memTotal']*1024
    array['swap_total'] = SwapTotal
    array['disk_total'] = HDDTotal
    array['ipv4'] = IPV4
    array['ipv6'] = IPV6
    array['virtualization_type'] = get_virtualization_type()
    array['os_type'] = platform.system()
    array['virtualization_firmware_enabled'] = get_virtualization_firmware_enabled() # 是否开启虚拟化
    array['cpu_cache_size'] = get_cpu_cache_size() # 是否开启虚拟化
    array['cpu_vendor_id'] = get_cpu_vendor_id() # 是否开启虚拟化
    
    
    try:
        res = request_fun('/api/monitor/set_system_info', {'data':json.dumps(array)},'post')
        # print(res.text)
    except requests.exceptions.ConnectionError:
        print('连接到API错误 -- 请等待3秒')
        time.sleep(3)
    except requests.exceptions.ChunkedEncodingError:
        print('分块编码错误 -- 请等待3秒')
        time.sleep(3)  
    except KeyboardInterrupt:
        raise  
    except:
        print('未知错误, 请等待3秒')

def get_disk_info():
    
    diskinfo = {}
    disks = psutil.disk_partitions()
    i=0;
    # device: 设备路径（例如“/dev/hda1”）。 在 Windows 上，这是驱动器号（例如“C:\\”）。
    # mountpoint: 挂载点路径（例如“/”）。 在 Windows 上，这是驱动器号（例如“C:\\”）。
    # fstype: 分区文件系统（例如 UNIX 上的“ext3”或 Windows 上的“NTFS”）。
    # opts: 一个逗号分隔的字符串，指示驱动器/分区的不同挂载选项。 平台相关。
    # maxfile: 文件名可以具有的最大长度。
    # maxpath: 路径名（目录名 + 基本文件名）的最大长度。
    for disk in disks:
        diskinfo[i] = {}
        diskinfo[i]['device'] = disk.device
        diskinfo[i]['mountpoint'] = disk.mountpoint
        diskinfo[i]['fstype'] = disk.fstype
        diskinfo[i]['opts'] = disk.opts
        diskinfo[i]['maxfile'] = disk.maxfile
        diskinfo[i]['maxpath'] = disk.maxpath
        
        disk_usage = psutil.disk_usage(disk.mountpoint) 
        diskinfo[i]['total'] = disk_usage.total
        diskinfo[i]['used'] = disk_usage.used
        diskinfo[i]['free'] = disk_usage.free
        diskinfo[i]['percent'] = disk_usage.percent
        
        i+=1
    return diskinfo
    

def get_io_info():
    diskio = {}
    diskio['ALL'] = {}
    diskio['ALL']['read_count'] = 0
    diskio['ALL']['write_count'] = 0
    diskio['ALL']['read_bytes'] = 0
    diskio['ALL']['write_bytes'] = 0
    diskio['ALL']['read_time'] = 0
    diskio['ALL']['write_time'] = 0
    diskio['ALL']['read_merged_count'] = 0
    diskio['ALL']['write_merged_count'] = 0
    diskio['ALL']['busy_time'] = 0
    
    info = psutil.disk_io_counters(perdisk=True)
    for disk_name in info.keys():
        diskio[disk_name] = {}
        diskio[disk_name]['read_count']   = int(info[disk_name].read_count)
        diskio[disk_name]['write_count']  = int(info[disk_name].write_count)
        diskio[disk_name]['read_bytes']   = int(info[disk_name].read_bytes)
        diskio[disk_name]['write_bytes']  = int(info[disk_name].write_bytes)
        diskio[disk_name]['read_time']    = int(info[disk_name].read_time)
        diskio[disk_name]['write_time']   = int(info[disk_name].write_time)
        diskio[disk_name]['read_merged_count'] = int(info[disk_name].read_merged_count)
        diskio[disk_name]['write_merged_count'] = int(info[disk_name].write_merged_count)
        diskio[disk_name]['busy_time'] = int(info[disk_name].busy_time)
            
        diskio['ALL']['read_count'] += diskio[disk_name]['read_count']
        diskio['ALL']['write_count'] += diskio[disk_name]['write_count']
        diskio['ALL']['read_bytes'] += diskio[disk_name]['read_bytes']
        diskio['ALL']['write_bytes'] += diskio[disk_name]['write_bytes']
        if diskio['ALL']['read_time'] < diskio[disk_name]['read_time']:
            diskio['ALL']['read_time'] = diskio[disk_name]['read_time']
        if diskio['ALL']['write_time'] < diskio[disk_name]['write_time']:
            diskio['ALL']['write_time'] = diskio[disk_name]['write_time']
        if diskio['ALL']['busy_time'] < diskio[disk_name]['busy_time']:
            diskio['ALL']['busy_time'] = diskio[disk_name]['busy_time']
        diskio['ALL']['read_merged_count'] += diskio[disk_name]['read_merged_count']
        diskio['ALL']['write_merged_count'] += diskio[disk_name]['write_merged_count']
    return diskio

def monitor_main():
    while True:
        try:
            while True:
                # CPU = get_cpu()
                NET_IN, NET_OUT = liuliang()
                Uptime = get_uptime()
                Load_1, Load_5, Load_15 = os.getloadavg() if 'linux' in sys.platform else (0.0, 0.0, 0.0)
                MemoryTotal, MemoryUsed = get_memory()
                SwapTotal, SwapUsed = get_swap()
                HDDTotal, HDDUsed = get_hdd()
                # IP_STATUS = ip_status()
                SYSTEM_LOAD = GetLoadAverage()  # 当前系统负载信息
                # IO_INFO = GetIoReadWrite()  # 当前系统负载信息
                IO_INFO = get_io_info()  # 当前系统负载信息
                NETWORK_INFO = GetNetWork()  # 当前系统负载信息
            
                array = {}
                array['uptime'] = Uptime
                array['load_1'] = Load_1
                array['load_5'] = Load_5
                array['load_15'] = Load_15
                array['memory_used'] = MemoryUsed
                array['swap_used'] = SwapUsed
                array['hdd_used'] = HDDUsed
                array['cpu_used'] = psutil.cpu_percent(None) # 整体CPU使用率
                array['cpu_all_used'] = psutil.cpu_percent(percpu=True) # 显示所有物理核心的利用率
                array['network_rx'] = netSpeed.get("netrx")
                array['network_tx'] = netSpeed.get("nettx")
                array['network_in'] = NET_IN
                array['network_out'] = NET_OUT
                # array['ip_status'] = IP_STATUS
                array['tcp'], array['udp'], array['process'], array['thread'] = tupd()
                
                array['sys_load_one'] = SYSTEM_LOAD['one']
                array['sys_load_five'] = SYSTEM_LOAD['five']
                array['sys_load_fifteen'] = SYSTEM_LOAD['fifteen']
                array['sys_load_max'] = SYSTEM_LOAD['max']
                array['sys_load_limit'] = SYSTEM_LOAD['limit']
                array['sys_load_safe'] = SYSTEM_LOAD['safe']
                # array['disk_info'] = GetDiskInfo()
                array['disk_info'] = get_disk_info()
                array['io_info_write'] = IO_INFO['ALL']['write_merged_count']
                array['io_info_read'] = IO_INFO['ALL']['read_merged_count']
                array['read_time'] = IO_INFO['ALL']['read_time']
                array['write_time'] = IO_INFO['ALL']['write_time']
                array['read_count'] = IO_INFO['ALL']['read_count']
                array['write_count'] = IO_INFO['ALL']['write_count']
                
                array['up'] = NETWORK_INFO['up']
                array['down'] = NETWORK_INFO['down']
                array['upTotal'] = NETWORK_INFO['upTotal']
                array['downTotal'] = NETWORK_INFO['downTotal']
                array['downPackets'] = NETWORK_INFO['downPackets']
                array['upPackets'] = NETWORK_INFO['upPackets']
                array['diskio'] = IO_INFO
                
                try:
                    res = request_fun('/api/monitor/monitor_log', {'data':json.dumps(array)},'post')
                    # print(res.text)
                    time.sleep(3)
                    break
                except requests.exceptions.RequestException:
                    print('连接到API超时 -- 请等待3秒')
                    time.sleep(3)
                except requests.exceptions.ConnectionError:
                    print('连接到API错误 -- 请等待3秒')
                    time.sleep(3)
                except requests.exceptions.ChunkedEncodingError:
                    print('分块编码错误 -- 请等待3秒')
                    time.sleep(3)  
                except KeyboardInterrupt:
                    raise  
                except:
                    print('未知错误, 请等待3秒')
                    time.sleep(3)
        except KeyboardInterrupt:
            raise
        except Exception as e:
            print("捕获异常:", e)
            time.sleep(3)

def get_ip_info():
    ipip_info = requests.get('https://api.myip.la/cn?json').json()
    ipip_info = ipip_info['location']
    
    try:
        # ip_info = requests.get('https://ipapi.co/json/')
        ip_info = requests.get('http://ip-api.com/json/?lang=zh-CN&fields=status,message,continent,continentCode,country,countryCode,region,regionName,city,district,zip,lat,lon,timezone,offset,currency,isp,org,as,asname,reverse,mobile,proxy,hosting,query')
        try:
            ip_info = ip_info.json()
            ip_info['country'] = ipip_info['country_name']
            ip_info['regionName'] = ipip_info['province']
            ip_info['city'] = ipip_info['city']
            ip_info['lat'] = ipip_info['latitude']
            ip_info['lon'] = ipip_info['longitude']
            ip_info['country_code'] = ipip_info['country_code']
            if 'status' in ip_info and ip_info['status'] == 'success':
                try:
                    res2 = request_fun('/api/monitor/set_ip_info', {'data':json.dumps(ip_info)},'post')
                    # print(res2.text)
                except requests.exceptions.RequestException as e:
                    print('在更新IP信息时，连接服务端超时')
                    get_ip_info()
                except requests.exceptions.ConnectionError:
                    print('在更新IP信息时，连接失败')
                    get_ip_info()
            else:
                print('ip获取失败')
                time.sleep(3600)
                get_ip_info()
        except ValueError:
            print('在获取IP信息时，服务端返回数据错误')
            get_ip_info()
    except requests.exceptions.RequestException as e:
        print('在获取IP信息时，连接服务端超时')
        get_ip_info()
    except requests.exceptions.ConnectionError:
        print('在获取IP信息时，连接失败')
        get_ip_info()
                 

def check_sys():
    is_run= False
    _ipv4, _ipv6 = get_ip()
    
    if _ipv4=='' and _ipv6=='':
        print('IP获取失败，停止执行')
        exit()
    elif _ipv4!='' or _ipv6!='':
        IPV4 = _ipv4
        IPV6 = _ipv6
        try:
            res = request_fun('/api/monitor/get_new_token', {'server_token':SERVERTOKEN,"ipv4":IPV4,"ipv6":IPV6},'post')
            try:
                res = res.json()
                if res['code'] == 0:
                    file= open('/usr/local/ServerStatusPlus/config/ServerToken.conf', mode='w+', encoding='UTF-8')
                    file.write(res['data']['server_token'])
                    file.close() # 关闭文件
                    is_run = True
                else:
                    is_run = True
                    
                get_ip_info()
                get_realtime_date() # 获取当前网速
            except ValueError:
                print('在校验客户端时，服务端返回数据错误')
                check_sys()
        except requests.exceptions.RequestException as e:
            print('在校验客户端时，连接服务端超时')
            check_sys()
    else:
        print('获取客户端IP失败，3秒后重试')
        time.sleep(3)
        check_sys()

if __name__ == '__main__':
    check_sys()
    getOsInfo()
    monitor_main()
