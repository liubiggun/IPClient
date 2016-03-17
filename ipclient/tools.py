# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

from datetime import datetime, timedelta
import threading
import os
import socket
from platform import system


def get_ip():
    """
    获取需要连接校园网的真实ip（在Windows系统下如果有虚拟网卡时使用gethostbyname将可能获取错误的信息）
    注意：1.上级连接了路由的话，该方法仍然无效，最好是用refresh_get_news包从服务器获取真实的校内ip.
    2.测试openwrt使用该方法也错误，最好指定eth来获取ip或用refresh_get_news包
    :return:
    """
    sys_str = system()
    hostname = socket.getfqdn(socket.gethostname())
    if sys_str == 'Windows':
        ip = ''
        # # IPs可能为['192.168.56.1', '192.168.15.1', '172.xx.xx.xx']，前两个是虚拟网卡
        for item in socket.gethostbyname_ex(hostname)[2]:
            ip = item
            first = item.split('.')[0]
            if first == '202' or first == '172':
                break
        return ip
    elif sys_str == 'Linux':
        return socket.gethostbyname(hostname)


def get_mac_from_ip(ip):
    """
    根据ip获取本地网卡对应的mac地址（windows & linux）
    :param ip:
    :return:
    """
    import re
    sys_str = system()
    patt_mac = re.compile(
        r'[a-f0-9]{2}[-:][a-f0-9]{2}[-:][a-f0-9]{2}[-:][a-f0-9]{2}[-:][a-f0-9]{2}[-:][a-f0-9]{2}[\n ]',  # \n or space
        re.I
    )
    res = ''
    if sys_str == 'Windows':
        res = os.popen('ipconfig /all').read()
    elif sys_str == 'Linux':
        res = os.popen('ifconfig').read()

    index = re.search(ip, res).start()                     # 获取对应ip字符串所在的索引
    mac = patt_mac.findall(res, endpos=index)              # 获取离该ip字符串最近的并在其之前的mac字符串
    if mac:
        mac_addr = mac[-1].strip()
    else:
        mac_addr = None
    return mac_addr or '00-00-00-00-00-00'


def get_mac_linux(ethname):
    """
    获取指定网卡的MAC地址，返回str字符串
    :param ethname:
    :return:
    """
    mac = os.popen(
        "ifconfig {0}|grep 'HWaddr'|sed 's/^.*addr //g'|sed -r 's/ //g'".format(ethname)
    ).read().strip()
    print('MAC:{0}'.format(mac))
    return mac


def get_ip_linux(ethname):
    """
    获取指定网卡的IP地址,返回str字符串
    :param ethname:
    :return:
    """
    ip = os.popen(
        "ifconfig {0}|grep 'inet addr'|sed -r 's/^.+addr://g'|cut -d' ' -f1".format(ethname)
    ).read().strip()
    print('IP:{0}'.format(ip))
    return ip


def restart_eth_linux(ethname):
    """
    重启网络接口
    :param ethname:
    :return:
    """
    try:
        os.system('ifup {0}'.format(ethname))
    except Exception:
        print('ifup raised a error!')


def check_online():
    """
    判断是否能够上网
    """
    cnt = 0
    cmd = ''
    sys_str = system()

    if sys_str == 'Windows':
        cmd = 'ping -n 2 {0} > NUL && if errorlevel 0 echo ok'
    elif sys_str == 'Linux':
        cmd = 'ping -c2 {0} > /dev/null && echo ok'

    weblist = [ '114.114.114.119',  # 114 DNS安全版
                '114.114.114.114',  # 114 DNS
                '114.114.114.110',  # 114 DNS家庭版
                '112.124.47.27',    # oneDNS南方首选
                '114.215.126.16'    # oneDNS北方首选
              ]
    for w in weblist:
        if os.popen(cmd.format(w)).read().strip() == 'ok':
            cnt += 1
    return True if cnt > 1 else False


def check_server_connected():
    """
    判断是否能够连接校园网服务器
    """
    cmd = ''
    sys_str = system()
    if sys_str == 'Windows':
        cmd = 'ping -n 2 202.193.160.123 > NUL && if errorlevel 0 echo ok'
    elif sys_str == 'Linux':
        cmd = 'ping -c2 202.193.160.123 > /dev/null && echo ok'

    return True if os.popen(cmd).read().strip() == 'ok' else False


def period_task(days=0, hours=0, mins=0, seconds=0, milliseconds=0, verbose=False,
                condition=lambda *args, **kwargs: True, condition_args=(), condition_kwargs={},
                task=lambda *args, **kwargs: None, task_args=(), task_kwargs={}):
    """
    循环定时执行指定任务
    :param days:
    :param hours:
    :param mins:
    :param seconds:
    :param milliseconds:
    :param verbose: 是否打印时间信息
    :param condition: 循环中判断循环是否要继续的判断函数，当其返回False将结束循环
    :param condition_args:
    :param condition_kwargs:
    :param task: 要定时执行的函数
    :param task_args:
    :param task_kwargs:
    :return:
    """

    def trace(msg):
        if verbose:
            print(msg)

    now = datetime.now()  # 获取当前时间
    trace("now: {0}".format(now))
    # 得到第一次执行定时任务的下一轮时间
    period = timedelta(days=days, hours=hours, minutes=mins, seconds=seconds, milliseconds=milliseconds)  # 任务时间差
    next_time = now + period  # 下一次要执行任务的时间
    trace("next time: {0}\n{1}".format(next_time, "-"*30))
    while True:
        if not condition(*condition_args, **condition_kwargs):
            break

        iter_now = datetime.now()  # 获取当前时间

        if iter_now >= next_time:  # 如果到达指定时间了
            trace("start work: {0}".format(iter_now))
            task(*task_args, **task_kwargs)  # 进行任务
            trace("task done.")
            next_time = iter_now + period  # 并更新下轮进行任务的时间
            trace("next time: {0}\n{1}".format(next_time, "-"*30))


class PeriodTask(threading.Thread):
    def __init__(self, days=0, hours=0, mins=0, seconds=0, milliseconds=0, verbose=False,
                 condition=lambda *args, **kwargs: True, condition_args=(), condition_kwargs={},
                 task=lambda *args, **kwargs: None, task_args=(), task_kwargs={}):
        """
        循环定时执行指定任务的后台线程（daemon = True）
        :param days:
        :param hours:
        :param mins:
        :param seconds:
        :param milliseconds:
        :param verbose: 是否打印时间信息
        :param condition: 循环中判断循环是否要继续的判断函数，当其返回False将结束循环
        :param condition_args:
        :param condition_kwargs:
        :param task: 要定时执行的函数
        :param task_args:
        :param task_kwargs:
        :return:
        """
        super(PeriodTask, self).__init__()
        self.period = timedelta(days=days, hours=hours, minutes=mins,
                                seconds=seconds, milliseconds=milliseconds)  # 任务时间差
        self.condition = lambda: condition(*condition_args, **condition_kwargs)
        self.task = lambda: task(*task_args, **task_kwargs)
        self.daemon = True
        self.verbose = verbose

    def run(self):
        def trace(msg):
            if self.verbose:
                print(msg)

        now = datetime.now()  # 获取当前时间
        trace("now: {0}".format(now))

        next_time = now + self.period  # 下一次要执行任务的时间
        trace("next time: {0}\n{1}".format(next_time, "-" * 30))
        while True:
            if not self.condition():
                break

            iter_now = datetime.now()  # 获取当前时间

            if iter_now >= next_time:  # 如果到达指定时间了
                trace("start work: {0}".format(iter_now))
                self.task()  # 进行任务
                trace("task done.")
                next_time = iter_now + self.period  # 并更新下轮进行任务的时间
                trace("next time: {0}\n{1}".format(next_time, "-" * 30))


