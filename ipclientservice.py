# -*- coding: utf-8 -*-
"""
openwrt 的 ipclient service应用

其中的脚本文件可以如下
/etc/init.d/ipclient:
#!/bin/sh /etc/rc.common
#ipclient服务

START=41
STOP=88

stop(){
    ps | grep 'python /root/IPClient/ipclientservice.py' | awk '{print $1}' | xargs kill > /dev/null 2>&1

}

start(){
    stop
    python /root/IPClient/ipclientservice.py > /dev/null 2>&1 &

}

restart(){
    start
}

配置文件如下
/etc/config/ipclient
config interface 'wan'
        option ifname 'eth0.2'
        option pppname 'gxnu'
        option proto 'dhcp'
        option macaddr '66:66:66:66:66:66'
        option gateway '172.xx.xx.xx'
        option cnproto '1'
        option username '66666666666'
        option password '12345678'
        option cnusername '2xxxxxxxxxx'
        option cnpassword '123456'
        option ipaddr '172.xx.xx.xx'
        option netmask '255.255.255.0'
        option dns '202.193.160.33'

option ifname 'eth0.2'指明要使用的wan口
interface 'wan'指明接口
option proto 'wan'的协议，应用会根据它修改wan
option pppname 'gxnu' 指明若使用外网，新建的pppoe的名称
option macaddr '66:66:66:66:66:66' 这里会将该MAC地址设置到WAN上
option gateway '172.xx.xx.xx' 在设置为静态ip时，应用会将其设置在wan口上，动态ip时仅仅作为保存当前默认网关而已
option cnproto，-1不启用，0表示校园网，1为联通，2为电信，3为移动
option username pppoe用户名
option password pppoe密码
option cnusername 校园网用户名
option cnpassword 校园网密码
option ipaddr 设置wan协议为静态时的静态IP
option netmask 设置wan协议为静态时的子网掩码
option dns 设置wan协议为静态时的DNS

本应用会在使用校园外网的时候添加一个以ipclient config中的pppname命名的pppoe接口，获取拨号权限后拨号上网
使用校园网时则会删除这个pppname接口，登陆校园网账号并发送心跳包维持ip开放状态。并且会根据proto修改wan的协议
不使用该服务时则会删除这个pppname接口

启动该服务将会先配置好网络并重启network
"""

from __future__ import print_function
from ipclient import IPClientCN, get_perm_eth, check_online, check_server_connected, get_ip_linux

import logging
import logging.config
import os
from time import sleep
import signal
import sys

DIR = os.path.dirname(os.path.abspath(__file__))  # 脚本所在目录


class IPClientService:
    def __init__(self, logfile=os.path.join(DIR, 'IPClient.log'),
                 cnfile=os.path.join(DIR, 'CNInfo.log')):
        # 配置logger
        self.LOGGING['handlers']['file']['filename'] = logfile
        logging.config.dictConfig(self.LOGGING)
        self.logger = logging.getLogger('IPClient')
        self.clogger = logging.getLogger('IPClient.cn')
        self.plogger = logging.getLogger('IPClient.pppoe')
        self.mail_logger = logging.getLogger('IPClient.mail')

        self.logger.info('Service start------------------.')

        # 绑定信号事件
        signal.signal(signal.SIGINT, self._exit)
        signal.signal(signal.SIGTERM, self._exit)

        # 要添加的指向校园网关的静态路由
        self.static_routes = [
            '202.193.160.0/20',

        ]

        # 使用流量和余额信息的文件名
        self.cnfile = cnfile

        # 读取uci配置并记录日志
        self.proto_names = ['campus', 'CTCC', 'CUCC', 'CMCC']
        self.interface = None  # 目标网络接口对应的wan名称（network config中的interface名称）
        # uci的option
        self.pppname = self.cn_gw = self.ifname = self.cnproto = self.macaddr = self.username = self.password = None
        self.cnusername = self.cnpassword = self.ipaddr = self.netmask = self.dns = self.proto = None

        self.ppp_gw = None  # 拨号后的外网网关
        self.logger.info(self._uci_parse())

        if self.cnproto == -1:  # 不使用本服务
            self._uci_remove_pppname()
            os.system('/etc/init.d/network restart')
            sleep(8)
            self.logger.info('Service stop.')
            return

        self.b_online = self.b_on_CN = True  # 是否联网/是否在校园网内

        self.ip = get_ip_linux(self.ifname)
        self._check_gw_changed()

        # 初始化helper实例
        self.pppoe_helper = get_perm_eth
        self.cn_helper = IPClientCN()

        # 使用ipclient则启动服务，否则直接退出
        self.start_service()

    def start_service(self):
        # 先配置wan口协议
        self._uci_set_ifname()
        if self.cnproto == 0:  # 校园网
            self.logger.info('Serve for campus network mode.')

            # 删除专门pppoe拨号的接口pppname
            self._uci_remove_pppname()
            os.system('/etc/init.d/network restart')
            sleep(8)

            self._cn_service()
        else:  # 校园外网
            self.logger.info('Serve for pppoe mode.')

            self._uci_add_pppname()
            os.system('/etc/init.d/network restart')
            sleep(8)

            # 添加校园网静态路由
            self._change_static_routes()

            self._pppoe_service()

    def _cn_service(self):
        def heart_beat_condition():
            """
            循环中判断循环是否要继续的判断函数，当其返回False将结束循环
            :return:
            """
            self._check_net()
            if not self.b_on_CN:  # 连接不到校园网服务器，进行记录
                self.clogger.error('Can not connect to server!')
            return self.b_online

        def heart_beat_callback(args):
            """
            发送心跳包后的回调
            :param args:(bool, flow, money)(是否成功获取服务器返回的使用流量和余额数据,使用流量,剩余金额)
            :return:
            """
            res, flow, money = args
            if res:
                with open(self.cnfile, 'w') as f:
                    f.write("flow='{0:.2f}'\nmoney='{1:.2f}'\n".format(flow / 1024.0, money))
            else:
                self.clogger.error('Can not connect to server!')

        while 1:
            self.cn_helper.submit(self.cnusername, self.cnpassword)
            succeeded, msg = self.cn_helper.login()
            # 登录失败，重新尝试直到成功
            if not succeeded:
                self.clogger.error(u'{}. Now retry until succeed.'.format(msg))
                while not succeeded:
                    sleep(3)
                    # 检查是否可以连接服务器，不行则等待可以连接服务器，若dhcp则需要重启wan口，获取默认网关，否则只是等待
                    if not check_server_connected():
                        self.clogger.error('Can not connect to server!wait until the router can connect server')
                        while not check_server_connected():
                            if self.proto == 'dhcp':
                                os.system('ifup {}'.format(self.interface))
                                sleep(5)
                    # 可以连接服务器了，尝试登陆
                    succeeded, msg = self.cn_helper.login()

            # 成功获取后发送服务器公告，，
            # 之后进行发送心跳包并检测，断网后跳到外层循环重新发送udp包以保证自动重连
            try:
                self.clogger.info('Succeed to login!')
                self.clogger.info(u'最新公告: {}.'.format(self.cn_helper.news_from_server))
            except UnicodeEncodeError:  # openwrt上的python2对unicode支持有问题
                pass

            # 联网邮件通知
            try:
                self.mail_logger.info('{}:ip={};gw={}'.format(self.ifname, get_ip_linux(self.ifname), self.cn_gw))
            except Exception:
                pass

            self.cn_helper.heart_beat(condition=heart_beat_condition, callback=heart_beat_callback)  # loop!
            self.clogger.warning('offline!')

    def _pppoe_service(self):

        while 1:
            self._check_gw_changed()  # 处理路由器换到另一个网关下的情况
            succeeded, msg = self.pppoe_helper(self.cnproto, self.ifname)
            # 获取失败，重新尝试直到成功
            if not succeeded:
                self.plogger.error(u'{}. Now retry until succeed.'.format(msg))
                while not succeeded:
                    sleep(3)
                    # 检查是否可以连接服务器，不行则等待可以连接服务器，若dhcp则需要重启wan口，获取默认网关，否则只是等待
                    if not check_server_connected():
                        self.plogger.error('Can not connect to server!wait until the router can connect server')
                        while not check_server_connected():
                            if self.proto == 'dhcp':
                                os.system('ifup {}'.format(self.interface))
                                sleep(5)

                    # 可以连接服务器了，尝试登陆
                    self._check_gw_changed()  # 处理路由器换到另一个网关下的情况
                    succeeded, msg = self.pppoe_helper(self.cnproto, self.ifname)

            self.plogger.info('Receive:{}.Succeed to get permission!'.format(msg))

            # 重启pppoe并获取ppp的网关
            os.system('ifup {}'.format(self.pppname))
            sleep(10)
            self.ppp_gw = os.popen("ip ro|grep default|awk '{print $3}'").read().strip()
            ppp_ifname = 'pppoe-' + self.pppname
            ppp_ip = get_ip_linux(ppp_ifname)
            self.plogger.info('ppp_ip: {}, ppp_gw: {}'.format(ppp_ip, self.ppp_gw))

            # 联网邮件通知
            try:
                self.mail_logger.info('{}:ip={};gw={}\n{}:ip={};gw={}'.format(
                    self.ifname, get_ip_linux(self.ifname), self.cn_gw,
                    ppp_ifname, ppp_ip, self.ppp_gw
                ))
            except Exception:
                pass

            # 成功获取权限后，由于openwrt的pppoe断线会自动重连，此时应该可以上网了，
            # 之后进行循环检测，断网后跳到外层循环重新发送udp包以保证自动重连
            while self._check_net():  # loop
                pass
            self.plogger.warning('Offline!')

    def _check_gw_changed(self):
        """
        处理路由器换到另一个网关下的情况
        """
        # 先关闭pppoe接口，防止之前pppoe成功后路由重启，得到的网关是ppp的网关
        os.system('ifdown {}'.format(self.pppname))

        # 先检查默认路由是否存在（pppoe断网后默认路由不存在），若存在可能有新的网关
        if os.popen('ip ro|grep default').read().strip() != '':
            # 再确认不是ppp的网关（pppoe成功后直接拔掉网线后ppp默认路由仍在）
            if os.popen("ip ro|grep default|grep {}".format(self.pppname)).read().strip() == '':
                cn_gw = os.popen("ip ro|grep default|awk '{print $3}'").read().strip()  # 重新获取到的网关
                if self.cn_gw != cn_gw:  # 网关改变则更新ip和校园网网关，删除之前的静态路由，添加新的静态路由
                    self.cn_gw = cn_gw
                    os.system('uci set ipclient.{}.gateway={} && uci commit ipclient'.format(self.interface, self.cn_gw))

                    self._change_static_routes()

                    self.ip = get_ip_linux(self.ifname)
                    self.plogger.info('cn_ip: {} . cn_gw: {}'.format(self.ip, self.cn_gw))

    def _change_static_routes(self):
        """
        修改需要添加的静态路由，如果不存在则添加，存在则修改
        :return:
        """
        for route in self.static_routes:
            if os.popen('ip route show {}'.format(route)).read().strip() == '':
                os.system('ip route add {} via {}'.format(route, self.cn_gw))
            else:
                os.system('ip route change {} via {}'.format(route, self.cn_gw))

            self.plogger.info('{} via {}'.format(route, self.cn_gw))

    def _exit(self, num, stack):
        if self.cnproto == 0:  # 协议为校园网时
            succeeded, msg = self.cn_helper.logout()
            if succeeded:
                self.clogger.info('Succeed to logout!')
            else:
                self.clogger.warning('\nFail to logout,server will close your ip after several minutes automatically.')
        if self.cn_helper:
            self.cn_helper.clean()
        self.logger.info('Service stop.')
        sys.exit()

    def _check_net(self):
        """
        检查网络连接，并更新字段
        :return: 是否联网成功
        """
        self.b_online = check_online()
        self.b_on_CN = check_server_connected()
        return self.b_online

    def _uci_set_ifname(self):
        """
        设置ifname的proto
        :return:
        """
        # 设置wan的proto
        os.system("uci set network.{}.proto={}".format(self.interface, self.proto))
        if self.proto == 'static':
            os.system("uci set network.{}.ipaddr={}".format(self.interface, self.ipaddr))
            os.system("uci set network.{}.netmask={}".format(self.interface, self.netmask))
            os.system("uci set network.{}.gateway={}".format(self.interface, self.cn_gw))
            os.system("uci set network.{}.dns='{}'".format(self.interface, self.dns))
        else:  # dhcp
            os.system("uci set network.{}.mac='{}'".format(self.interface, self.macaddr))
            os.system("uci delete network.{}.ipaddr".format(self.interface))
            os.system("uci delete network.{}.netmask".format(self.interface))
            os.system("uci delete network.{}.gateway".format(self.interface))
            os.system("uci delete network.{}.dns".format(self.interface))

        os.system("uci commit network")

    def _uci_add_pppname(self):
        """
        使用校园网外网时，添加专门pppoe拨号的接口pppname
        proto="pppoe",
        ifname="eth0.2",
        username=network_wan_username,
        password=network_wan_password,
        macaddr="28:28:28:28:28:28",
        auto=0
        :return:
        """
        # network中没有pppname则添加
        if os.popen('uci show network|grep {}.proto=pppoe'.format(self.pppname)).read().strip() == '':
            os.system('uci set network.{}=interface'.format(self.pppname))

        os.system('uci set network.{}.proto=pppoe'.format(self.pppname))
        os.system('uci set network.{}.ifname={}'.format(self.pppname, self.ifname))
        os.system('uci set network.{}.username={}'.format(self.pppname, self.username))
        os.system('uci set network.{}.password={}'.format(self.pppname, self.password))
        os.system('uci set network.{}.macaddr={}'.format(self.pppname, self.macaddr))
        os.system('uci set network.{}.auto=0'.format(self.pppname))  # 设置不自动启动，因为待会会启动

        # 获取wan域防火墙，添加pppname接口
        # firewall.cfg06dc81.network=wan wan6 wwan  ==>  ['wan', 'wan6', 'wwan'],
        networks = os.popen("uci show firewall.cfg06dc81.network").read().strip().split('=')[1].split(' ')
        if self.pppname not in networks:
            networks.append(self.pppname)
            os.system("uci set firewall.cfg06dc81.network='{}'".format(' '.join(networks)))
            os.system("uci commit firewall")

        os.system("uci commit network")

    def _uci_remove_pppname(self):
        """
        不使用本服务或仅使用校园网时，删除专门pppoe拨号的接口pppname
        :return:
        """
        # 删除校园外网的pppname接口
        os.system("uci delete network.{}".format(self.pppname))

        # 获取wan域防火墙，删除防火墙中的pppname接口
        # firewall.cfg06dc81.network=wan wan6 wwan  ==>  ['wan', 'wan6', 'wwan'],
        networks = os.popen("uci show firewall.cfg06dc81.network").read().strip().split('=')[1].split(' ')
        if self.pppname in networks:
            networks = [dev for dev in networks if dev != self.pppname]
            os.system("uci set firewall.cfg06dc81.network='{}'".format(' '.join(networks)))
            os.system("uci commit firewall")

        os.system("uci commit network")

    def _uci_parse(self):
        """
        解析uci文件中的配置，例如：
        root@OpenWrt:~# uci show ipclient
        ipclient.wan=interface
        ipclient.wan.ifname=eth0.2
        ipclient.wan.pppname=gxnu
        ipclient.wan.proto=dhcp
        ipclient.wan.macaddr=28:28:28:28:28:28
        ipclient.wan.password=12
        ipclient.wan.cnproto=2
        ipclient.wan.username=123323
        ipclient.wan.gateway=0.0.0.0
        ipclient.wan.cnusername=16666666666
        ipclient.wan.cnpassword=88888888
        ipclient.wan.ipaddr=xx.xx.xx.xx
        ipclient.wan.netmask=255.255.255.0
        ipclient.wan.dns=xx.xx.xx.xx xx.xx.xx.xx

        其中cnproto：-1表示不使用ipclient，0表示校园网，1为联通，2为电信，3为移动
        :return: 解析后存在日志的信息
        """
        self.interface = os.popen('uci show ipclient|grep interface').read().strip().split('=')[0].split('.')[1]
        self.ifname = os.popen('uci show ipclient.{}.ifname'.format(self.interface)).read().strip().split('=')[1]
        self.pppname = os.popen('uci show ipclient.{}.pppname'.format(self.interface)).read().strip().split('=')[1]
        self.proto = os.popen('uci show ipclient.{}.proto'.format(self.interface)).read().strip().split('=')[1]
        self.cnproto = int(os.popen('uci show ipclient.{}.cnproto'.format(self.interface)).read().strip().split('=')[1])
        self.macaddr = os.popen('uci show ipclient.{}.macaddr'.format(self.interface)).read().strip().split('=')[1]
        self.username = os.popen('uci show ipclient.{}.username'.format(self.interface)).read().strip().split('=')[1]
        self.password = os.popen('uci show ipclient.{}.password'.format(self.interface)).read().strip().split('=')[1]
        self.cn_gw = os.popen('uci show ipclient.{}.gateway'.format(self.interface)).read().strip().split('=')[1]
        self.cnusername = os.popen('uci show ipclient.{}.cnusername'.format(self.interface)).read().strip().split('=')[1]
        self.cnpassword = os.popen('uci show ipclient.{}.cnpassword'.format(self.interface)).read().strip().split('=')[1]
        self.ipaddr = os.popen('uci show ipclient.{}.ipaddr'.format(self.interface)).read().strip().split('=')[1]
        self.netmask = os.popen('uci show ipclient.{}.netmask'.format(self.interface)).read().strip().split('=')[1]
        self.dns = os.popen('uci show ipclient.{}.dns'.format(self.interface)).read().strip().split('=')[1]
        if self.cnproto == -1:
            return 'IPClient service is disable.'
        elif self.cnproto == 0:
            return u'proto:{}, username:{}, password:{}'.format(
                self.proto_names[0], self.cnusername, self.cnpassword)
        else:
            return u'proto:{}, mac:{}'.format(
                self.proto_names[self.cnproto], self.macaddr)

    LOGGING = {
        'version': 1,
        'disable_existing_loggers': True,
        'formatters': {
            'default': {
                'class': 'logging.Formatter',
                'format': '%(asctime)s %(name)s %(levelname)s: %(message)s'
            },
            'detailed': {
                'class': 'logging.Formatter',
                'format': '%(asctime)s %(name)-15s %(levelname)s pid:%(process)d tid:%(thread)d : %(message)s'
            },
            'simple': {
                'class': 'logging.Formatter',
                'format': '%(asctime)s %(levelname)-8s %(message)s'
            },
        },
        'handlers': {
            'console': {
                'class': 'logging.StreamHandler',
                'level': 'DEBUG',
                'formatter': 'default',
            },
            'file': {
                'class': 'logging.FileHandler',
                'filename': 'IPClient.log',
                'mode': 'w',
                'level': 'DEBUG',
                'formatter': 'default',
            },
            # 'rotate': {
            #     'class': 'logging.handlers.RotatingFileHandler',
            #     'filename': os.path.join(DIR, 'IPClient(a).log'),
            #     'mode': 'a',
            #     'maxBytes': 1024 * 8,
            #     'backupCount': 8,
            #     'encoding': None,
            #     'delay': False,
            #     'level': 'DEBUG',
            #     'formatter': 'default',
            # },
            'mail': {
                'class': 'logging.handlers.SMTPHandler',
                'mailhost': 'smtp.163.com',
                'fromaddr': 'send@163.com',
                'toaddrs': ['recv@163.com', ],
                'subject': 'Online',
                'credentials': ('send@163.com', 'yourpin'),
                'secure': None,
                'level': 'DEBUG',
                'formatter': 'default',
            }
        },
        'loggers': {
            'IPClient': {
                'propagate': False,
                'level': 'DEBUG',
                'handlers': ['console', 'file']
            },
            'IPClient.mail': {
                'propagate': False,
                'level': 'DEBUG',
                'handlers': ['mail']
            }
        },
        'root': {
            'propagate': False,
            'level': 'DEBUG',
            'handlers': ['console']
        },
    }

if __name__ == '__main__':
    IPClientService()





