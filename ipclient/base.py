# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

import socket

from .cmdpacket import CmdPacket
from .pppoepacket import PPPOEPacket
from .tools import get_mac_from_ip, get_ip, get_ip_linux, get_mac_linux, period_task

from ipclient.refpacket import RefreshPacket


# 时间
TIME_SOCK_TIMEOUT = 3
TIME_TIMEOUT_FOR_RE_LOGIN = 80

# 服务器的ip及端口
SERVER_IPADDR = '202.193.160.123'
SERVER_CONTROL_PORT = 5300
SERVER_REFRESH_PORT = 5301
SERVER_PPPOE_PORT = 20015
# 官方软件本机的端口（经检测，端口可随意，选择随意以防本地端口被占用）
# LOCAL_CONTROL_PORT = 5200
# LOCAL_REFRESH_PORT = 5201
LOCAL_CONTROL_PORT = 0
LOCAL_REFRESH_PORT = 0

MSG_ERROR_INITSOCK = 'Fail to initialize sockets，please check if the ports is occupied.'
MSG_ERROR_CONNECT = 'Fail to connect server，please check if you have obtained a right ip.'
MSG_ERROR_TIMEOUT = 'Connection timed out.'
MSG_ERROR_ETH = 'Can not to get mac or ip of the eth.'


class IPClientBase:
    """
    IPClient基类
    """   

    def __init__(self):
        """
        初始化，一开始发送get_news包获取最新公告和本机的校园网ip
        :return:
        """
        self.ip = '0.0.0.0'
        self.mac = '00-00-00-00-00-00'

        # sockets
        self.refresh_sock = self.cmd_sock = None
        # udp包工厂类
        self.refresh_packet_factory = self.cmd_packet_factory = self.pppoe_packet_factory = None

        self.b_connect_router = False  # 上游是否连接着一个拥有校园网ip的路由器
        self.b_server_connected = False  # 是否可以连接服务器
        self.news_from_server = ''  # 服务器最新公告

        # 尝试连接服务器确认是否能连接到服务器并获取更精确的ip
        self._init_refresh()
        self.update_news_ip()

    def submit(self, *args, **kwargs):
        """
        填充登录所需要的字段，并初始化包工厂类和socket
        :param args:
        :param kwargs:
        :return:
        """
        raise NotImplementedError

    def login(self, *args, **kwargs):
        raise NotImplementedError

    def heart_beat(self, *args, **kwargs):
        """
        循环发送心跳包，该函数可以用来在线程中调用
        :return:
        """
        raise NotImplementedError

    def refresh_online(self, *args, **kwargs):
        """
        发送心跳包
        :return:
        """
        raise NotImplementedError

    def logout(self, *args, **kwargs):
        raise NotImplementedError

    def _init_refresh(self):
        """
        初始化有关refresh的packet实例和socket实例，此处不对RefreshPacket实例传入userid和password
        因为应用启动时要向服务器发送get_news包以确认是否能连接到服务器并获取正确的ip，随后再更新userid和password字段
        :return:
        """
        self.refresh_packet_factory = RefreshPacket('', '')
        self.refresh_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.refresh_sock.settimeout(TIME_SOCK_TIMEOUT)
        self.refresh_sock.bind(('0.0.0.0', LOCAL_REFRESH_PORT))
        self.refresh_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    def update_news_ip(self):
        """
        连接服务器，并更新信息
        :return:
        """
        packet = self.refresh_packet_factory.get_refresh_get_news_packet()
        try:
            self.refresh_sock.sendto(packet,
                                     (SERVER_IPADDR, SERVER_REFRESH_PORT))
            packet = self.refresh_sock.recv(RefreshPacket.PACKET_LENGTH)
            res, t = self.refresh_packet_factory.check_refresh_get_news_reply(packet)
            if res:
                self.news_from_server, ip = t
                self.b_server_connected = True

                if self.ip != ip:
                    self.ip = ip
                    try:
                        self.mac = get_mac_from_ip(self.ip)  # 更新mac地址
                        self.b_connect_router = False
                    except AttributeError:
                        # 假如上级连接了路由，在本地可以更新正确的校园网ip，但是在本地获取不到上级的mac
                        print('Caution: did you make your device connected to a router?')
                        self.b_connect_router = True
        except socket.timeout:
            self.b_server_connected = False
            print(MSG_ERROR_TIMEOUT)
        except socket.error as ex:
            self.b_server_connected = False
            print(ex.strerror)

    def clean(self):
        """
        关闭正在使用的sockets并清空packet_factory
        :return:
        """
        if isinstance(self.refresh_sock, socket.socket):
            self.refresh_sock.close()
            self.refresh_sock = None
        if isinstance(self.cmd_sock, socket.socket):
            self.cmd_sock.close()
            self.cmd_sock = None

        self.refresh_packet_factory = self.cmd_packet_factory = self.pppoe_packet_factory = None


class IPClientCN(IPClientBase):
    def __init__(self):
        """
        初始化，一开始发送get_news包获取最新公告和本机的校园网ip
        :return:
        """
        IPClientBase.__init__(self)

    def get_flow(self):
        """
        :return: 获取开放ip以来所用的流量
        """
        return self.refresh_packet_factory.flow

    def get_money(self):
        """
        :return: 获取当前用户所剩的金额
        """
        return self.refresh_packet_factory.money

    def get_flow_string(self):
        """
        :return: 使用流量: {0:.2f}KB
        """
        return self.refresh_packet_factory.get_flow_money_strings()[0]

    def get_money_string(self):
        """
        :return: 剩余金额: {0:.2f}元
        """
        return self.refresh_packet_factory.get_flow_money_strings()[1]

    def print_info(self):
        """
        打印使用流量和剩余金额
        :return:
        """
        print('{0[0]}\n{0[1]}'.format(self.refresh_packet_factory.get_flow_money_strings()))

    def submit(self, userid, password):
        """
        初始化有关refresh、cmd的packet_factory实例和socket实例（用于校园网）
        :param userid:
        :param password:
        :return: (bool, error) (是否初始化成功, 错误消息)
        """
        self.refresh_packet_factory.set_user(userid, password)

        self.cmd_packet_factory = CmdPacket(userid, password, self.mac)
        self.cmd_sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.cmd_sock.settimeout(TIME_SOCK_TIMEOUT)
        try:
            self.cmd_sock.bind(('0.0.0.0', LOCAL_CONTROL_PORT))
        except socket.error:  # 端口占用
                return False, MSG_ERROR_INITSOCK
        self.cmd_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return True, ''

    def login(self, getnews=False):
        """
        开放ip
        :param getnews: 是否需要getnews更新最新公告和ip地址
        :return: (bool, strs)，(是否成功开放,服务器返回的一句话（文本字符串）)
        """
        if getnews:
            self.update_news_ip()

        packet = self.cmd_packet_factory.get_login_userid_packet()
        try:
            self.cmd_sock.sendto(packet,
                                 (SERVER_IPADDR, SERVER_CONTROL_PORT))
            packet = self.cmd_sock.recv(CmdPacket.PACKET_LENGTH)
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        res = self.cmd_packet_factory.check_login_userid_reply(packet)
        if res is False:
            return False, CmdPacket.MSG_INVALID_PACKET
        packet = self.cmd_packet_factory.get_login_password_packet()
        try:
            self.cmd_sock.sendto(packet,
                                 (SERVER_IPADDR, SERVER_CONTROL_PORT))
            packet = self.cmd_sock.recv(CmdPacket.PACKET_LENGTH)
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        res, reply_msg = self.cmd_packet_factory.check_login_password_reply(packet)
        if res is True:
            self.refresh_packet_factory.set_key(self.cmd_packet_factory.get_key())

        # 发送0A包，之后可以开始定时发送心跳包
        self._refresh_0A()

        return res, reply_msg

    def logout(self, new=True):
        """
        关闭ip
        :param new: 是否是新版本，只用发送0x23号数据包就可以关闭ip
        :return: (bool, strs)，(是否成功关闭,服务器返回的一句话（文本字符串）)
        """
        if new:
            packet = self.cmd_packet_factory.get_logout_new_packet()
            try:
                self.cmd_sock.sendto(packet,
                                     (SERVER_IPADDR, SERVER_CONTROL_PORT))
                packet = self.cmd_sock.recv(CmdPacket.PACKET_LENGTH)
            except socket.timeout:
                return False, MSG_ERROR_TIMEOUT
            except socket.error as ex:
                return False, ex.strerror
            res, reply_msg = self.cmd_packet_factory.check_logout_new_reply(packet)
            return res, reply_msg
        else:
            packet = self.cmd_packet_factory.get_logout_userid_packet()
            try:
                self.cmd_sock.sendto(packet,
                                     (SERVER_IPADDR, SERVER_CONTROL_PORT))
                packet = self.cmd_sock.recv(CmdPacket.PACKET_LENGTH)
            except socket.timeout:
                return False, MSG_ERROR_TIMEOUT
            except socket.error as ex:
                return False, ex.strerror
            res = self.cmd_packet_factory.check_logout_userid_reply(packet)
            if res is False:
                return False, CmdPacket.MSG_INVALID_PACKET
            packet = self.cmd_packet_factory.get_logout_password_packet()
            try:
                self.cmd_sock.sendto(packet,
                                     (SERVER_IPADDR, SERVER_CONTROL_PORT))
                packet = self.cmd_sock.recv(CmdPacket.PACKET_LENGTH)
            except socket.timeout:
                return False, MSG_ERROR_TIMEOUT
            except socket.error as ex:
                return False, ex.strerror
            res, reply_msg = self.cmd_packet_factory.check_logout_password_reply(packet)
            return res, reply_msg

    def heart_beat(self, condition=lambda: True, condition_args=(), condition_kwargs={}, callback=lambda a_tuple: None):
        """
        循环发送心跳包（一开始就发送一条，以立即获取流量余额信息），该函数可以用来在线程中调用
        :param condition: 循环中判断循环是否要继续的判断函数
        :param condition_args:
        :param condition_kwargs:
        :param callback: 心跳包发送并确认服务器回复（更新流量和余额信息）后进行的回调函数，该函数将接受的
        参数为一个元组(bool, flow, money)(是否成功获取服务器返回的使用流量和余额数据,使用流量,剩余金额)
        :return:
        """
        callback(self.refresh_online())
        period_task(
            seconds=self.refresh_packet_factory.TIME_REFRESH_ONLINE_INTERVAL,
            condition=condition,
            condition_args=condition_args,
            condition_kwargs=condition_kwargs,
            task=lambda: callback(self.refresh_online())
        )

    def refresh_online(self):
        """
        发送心跳包并接收服务器返回的包
        :return: (bool,str,str)，(是否成功获取服务器返回的使用流量和余额数据,使用流量,剩余金额)
        """
        packet = self.refresh_packet_factory.get_refresh_online_packet()
        try:
            self.refresh_sock.sendto(packet, (SERVER_IPADDR, SERVER_REFRESH_PORT))
            packet = self.refresh_sock.recv(RefreshPacket.PACKET_LENGTH)
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT, ''
        except socket.error as ex:
            return False, ex.strerror, ''
        res = self.refresh_packet_factory.check_refresh_online_reply(packet)
        if res is False:
            return False, RefreshPacket.MSG_INVALID_PACKET, ''
        else:
            return True, self.refresh_packet_factory.flow, self.refresh_packet_factory.money

    def _refresh_0A(self):
        """
        发送0x0a数据包并接收0x0b数据包
        :return: (bool, '')，(是否成功得到服务器回复,'')
        """
        packet = self.refresh_packet_factory.get_refresh_0a_packet()
        try:
            self.refresh_sock.sendto(packet, (SERVER_IPADDR, SERVER_REFRESH_PORT))
            packet = self.refresh_sock.recv(RefreshPacket.PACKET_LENGTH)
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        res = self.refresh_packet_factory.check_refresh_0a_reply(packet)
        if res is False:
            return False, RefreshPacket.MSG_INVALID_PACKET
        else:
            return True, ''


class IPClientPPPOE(IPClientBase):
    def __init__(self):
        """
        初始化，一开始发送get_news包获取最新公告和本机的校园网ip
        :return:
        """
        IPClientBase.__init__(self)
        self.pppoe_keep_packet = None  # 用来保存udp心跳包
        self.isp = None
        # 由于本地端口是随意的，故直接使用refresh_sock
        self.pppoe_sock = self.refresh_sock

    def submit(self, isp):
        """
        初始化有关pppoe的packet实例和socket实例（用于校园外网），由于本地端口是随意的，故直接使用refresh_sock
        :param isp: ISP类型，1为联通、2为电信、3为移动
        :return:
        """
        self.isp = isp
        self.pppoe_packet_factory = PPPOEPacket()
        self.pppoe_keep_packet = self.pppoe_packet_factory.get_keepperm_packet(
            self.ip,
            self.mac,
            isp,
        )      # 保存维持权限的udp包，以定时发送

    def login(self, getnews=False):
        """
        开放ip
        :param getnews: 是否需要getnews更新最新公告和ip地址
        :return: (bool, strs)，(是否成功开放,服务器返回的一句话（文本字符串）)
        """
        if getnews:
            self.update_news_ip()
        try:
            self.pppoe_sock.sendto(self.pppoe_packet_factory.get_getperm_packet(self.ip, self.mac, self.isp),
                                   (SERVER_IPADDR, SERVER_PPPOE_PORT))
            reply = self.pppoe_sock.recv(5)
            # reply = b'\x00\x01\x5e\x7e\x00' 发现返回值会改变，故此处服务器有返回即表示获取权限成功
            if reply is not None:
                return True, reply
            else:
                return False, 'Fail to get permisson'
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        except ValueError:  # ip为None时的错误
            return False, MSG_ERROR_ETH

    def logout(self):
        """
        释放pppoe拨号权限，保留（基本上用不到，因为拨号成功后默认路由变为isp的网关而不是校园网网关，
        不设置静态路由的话，该包将发送不到服务器，官方软件只是关闭pppoe而已）
        """
        try:
            self.pppoe_sock.sendto(self.pppoe_packet_factory.get_releaseperm_packet(self.ip, self.mac, self.isp),
                                   (SERVER_IPADDR, SERVER_PPPOE_PORT))
            return True, 'Succeed to release permisson'
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        except ValueError:  # ip为None时的错误
            return False, MSG_ERROR_ETH

    def heart_beat(self):
        """
        循环发送心跳包，该函数可以用来在线程中调用，保留（基本上用不到，因为拨号成功后默认路由变为isp的网关而不是校园网网关，
        不设置静态路由的话，心跳包将发送不到服务器，官方软件每30s发送一次，其实都是发送不到服务器的）
        :return:
        """
        period_task(seconds=self.pppoe_packet_factory.TIME_REFRESH_ONLINE_INTERVAL, task=self.refresh_online)

    def refresh_online(self):
        """
        发送心跳包，该函数传递给线程使用,维持pppoe拨号权限，保留（基本上用不到，因为拨号成功后默认路由变为isp
        的网关而不是校园网网关，不设置静态路由的话，心跳包将发送不到服务器，官方软件每30s发送一次，其实都是发送不到服务器的）
        """
        try:
            self.pppoe_sock.sendto(self.pppoe_packet_factory,
                                   (SERVER_IPADDR, SERVER_PPPOE_PORT))
            return True, ''
        except socket.timeout:
            return False, MSG_ERROR_TIMEOUT
        except socket.error as ex:
            return False, ex.strerror
        except ValueError:  # ip为None时的错误
            return False, MSG_ERROR_ETH


def get_perm_mac(isp, mac):
    """
    仅仅获取权限，可用作帮助其他设备的wan进行获取权限
    :param isp: ISP类型，1为联通、2为电信、3为移动
    :param mac:
    :return: (bool,msg) 结果元组
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cn_help = None
    try:
        cn_help = IPClientCN()
        if not cn_help.b_server_connected:
            return False, MSG_ERROR_CONNECT
        sock.sendto(PPPOEPacket().get_getperm_packet(cn_help.ip, mac, isp),
                    (SERVER_IPADDR, SERVER_PPPOE_PORT))
        reply = sock.recv(5)
        if reply is not None:
            return True, reply
        else:
            return False, 'fail'
    except socket.timeout:
        return False, MSG_ERROR_TIMEOUT
    except socket.error as ex:
        return False, ex.strerror
    except ValueError:
        return False, MSG_ERROR_ETH
    finally:
        cn_help.clean()
        sock.close()


def get_perm(isp):
    """
    仅仅获取本地拨号权限（自动获取ip和mac）
    :param isp: ISP类型，1为联通、2为电信、3为移动
    :return: (bool,msg) 结果元组
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    cn_help = None
    try:
        cn_help = IPClientCN()
        if not cn_help.b_server_connected:
            return False, MSG_ERROR_CONNECT
        sock.sendto(PPPOEPacket().get_getperm_packet(cn_help.ip, cn_help.mac, isp),
                    (SERVER_IPADDR, SERVER_PPPOE_PORT))
        reply = sock.recv(5)
        if reply is not None:
            return True, reply
        else:
            return False, 'Fail'
    except socket.timeout:
        return False, MSG_ERROR_TIMEOUT
    except socket.error as ex:
        return False, ex.strerror
    except ValueError:
        return False, MSG_ERROR_ETH
    finally:
        cn_help.clean()
        sock.close()


def get_perm_eth(isp, eth):
    """
    指定要获取权限的网卡（用于linux）来获取权限
    :param isp:
    :param eth:
    :return: (bool,msg) 结果元组
    """
    ip = get_ip_linux(eth)
    mac = get_mac_linux(eth)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        sock.sendto(PPPOEPacket().get_getperm_packet(ip, mac, isp),
                    (SERVER_IPADDR, SERVER_PPPOE_PORT))
        reply = sock.recv(5)
        if reply is not None:
            return True, reply
        else:
            return False, 'Fail'
    except socket.timeout:
        return False, MSG_ERROR_TIMEOUT
    except socket.error as ex:
        return False, ex.strerror
    except ValueError:
        return False, MSG_ERROR_ETH
    finally:
        sock.close()


def muti_wans(isp=(), eth=()):
    """
    openwrt多播，eth的个数需要与isp相同
    :param isp: isp元组   (ints)
    :param eth: 网络设备字符串元组   (strs)
    :return: 每个设备的结果元组列表  [(bool,msg)]
    """
    if len(eth) != len(isp):
        raise Exception("len(eth) != len(isp)")
    if len(eth) == 0:
        raise Exception("len(eth) == 0")

    udp_maker = PPPOEPacket()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(3)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    res = []
    for i in range(len(eth)):
        try:
            ip = get_ip_linux(eth[i])
            mac = get_mac_linux(eth[i])
            sock.sendto(udp_maker.get_getperm_packet(ip, mac, isp[i]),
                        (SERVER_IPADDR, SERVER_PPPOE_PORT))
            reply = sock.recv(5)
            # reply = b'\x00\x01\x5e\x7e\x00' 发现返回值会改变，故此处服务器有返回即表示获取权限成功
            if reply is not None:
                res.append((True, reply))
            else:
                res.append((False, 'Fail to get permission'))
        except socket.timeout:
            res.append((False, TIME_SOCK_TIMEOUT))
        except socket.error as ex:
            res.append((False, ex.strerror))
        except ValueError:
            res.append((False, MSG_ERROR_ETH))

    sock.close()
    return res
