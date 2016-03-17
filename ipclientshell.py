#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from ipclient import IPClientCN, IPClientPPPOE, MSG_ERROR_CONNECT, get_perm, get_perm_mac, get_perm_eth
from platform import python_version
from getpass import getpass
import argparse
import textwrap
import signal
import sys


def cn_login(userid, password):
    """
    校园网开放ip，开放完后将在本线程发送心跳包
    :param userid:
    :param password:
    :return:
    """
    cn_helper = IPClientCN()

    def clean(signum, stack):
        """
        关闭ip并退出程序
        :param signum:
        :param stack:
        :return:
        """
        res, info = cn_helper.logout()
        cn_helper.clean()
        if res:
            try:
                print(u'\n{0}\n退出成功!'.format(info))
            except UnicodeEncodeError:  # openwrt上的python2对Unicode支持出现异常
                print('\nSucceed to close this ip!')
        else:
            print('\nFail to logout,server will close your ip after several minutes automatically.')
        sys.exit()

    signal.signal(signal.SIGINT, clean)
    signal.signal(signal.SIGTERM, clean)

    succeeded, msg = cn_helper.submit(userid, password)
    if not succeeded:
        print(msg)
        return
    succeeded, msg = cn_helper.login()
    if not succeeded:
        print(msg)
        return
    try:
        print(msg)  # 打印服务器返回的一句话
    except UnicodeEncodeError:  # openwrt上的python2出现异常
        print('Succeed to login.')

    def heart_beat_callback(arg):
        """
        发送心跳包后的回调
        :param arg:(bool, flow, money)(是否成功获取服务器返回的使用流量和余额数据,使用流量,剩余金额)
        :return:
        """
        res, flow, money = arg
        if res:
            print('data traffic: {0:.2f}KB\nbalance: {1:.2f}yuan\n'.format(flow / 1024.0, money))
        else:
            print('Can not to connect to server')
    cn_helper.heart_beat(callback=heart_beat_callback)  # loop!
    clean(None, None)


def pppoe_login(isp, mac=None, eth=None):
    """
    获取校园外网pppoe权限
    :param isp: ISP类型，1为联通、2为电信、3为移动
    :param mac: 指定要获取权限的网卡的mac
    :param eth: 指定要获取权限的网卡（用于linux）指定后mac参数将无效
    :return:
    """
    succeeded = msg = None
    if mac is None and eth is None:
        succeeded, msg = get_perm(isp)
    elif mac and eth is None:
        succeeded, msg = get_perm_mac(isp, mac)
    elif eth:
        succeeded, msg = get_perm_eth(isp, eth)

    if succeeded:
        print("You have fetched permission already and are able to dial up by pppoe!")
    else:
        print("{}\nFail to fetch permission ╯﹏╰ ".format(msg))


class IPClientShell:
    def __init__(self, status=0):
        """
        IPClient的shell应用
        :param status: 初始化后进入的状态，0：询问校园网还是校园外网，1：校园网模式：询问用户名和密码，2：校园网外网模式，询问isp
        :return:
        """
        self.flag = 0  # 1为校园网，2为校园外网
        self.error_input = False  # 输入是否错误

        # 状态：
        # 0：询问模式，校园网还是校园外网
        # 1：若是校园网，则询问用户名和密码，若是校园外网则询问isp
        # 2：联网成功，若是校园网，则发送心跳包，若是校园外网则直接退出诚信
        self.step = 0
        self.isp = None

        if status == 1:  # 1：校园网模式：询问用户名和密码
            self.flag = 1
            self.step = 1
        elif status == 2:  # 2：校园网外网模式，询问isp
            self.flag = 2
            self.step = 1

        self.pppoe_helper = None
        self.cn_helper = IPClientCN()
        self._set_signal_handle()

        if self.cn_helper.b_server_connected:  # 连接服务器成功
            try:
                print(u'最新公告: {}'.format(self.cn_helper.news_from_server))
            except UnicodeEncodeError:
                print('news: hoo~')  # openwrt上的python2出现异常
            self.interact()
        else:
            print(MSG_ERROR_CONNECT)

    def get_input(self, prompt):
        """
        获取用户输入，python2.X不能将prompt直接放入 raw_input() 中，因为raw_input内会进行str()操作，将出现UnicodeEncodeError
        :param prompt: 提示输入，
        :return:
        """
        print(prompt, end='')
        return input() if python_version()[0] == '3' else raw_input()  # 兼容python2和3

    def get_pass(self, prompt):
        """
        获取密码，python2.X不能将prompt直接放入 getpass() 中，因为getpass内会进行str()操作，将出现UnicodeEncodeError
        而python3.X则不能先print(prompt)，再进行getpass，测试发现有问题
        :param prompt:
        :return:
        """
        if python_version()[0] == '3':
            return getpass(prompt).strip()
        else:
            print(prompt, end='')
            return getpass('').strip()

    def interact(self):
        print('Welcome to use IPClientShell!\nYour IP:  {}\nYour MAC: {}\n'.format(
            self.cn_helper.ip,
            self.cn_helper.mac,
        ))

        while 1:
            if self.step == 0:
                if self.error_input:
                    self.error_input = False
                    reply = \
                        self.get_input("Wrong input,number '1' for campus network, " +
                                       "number'2' for pppoe(q for exit): ").strip()
                else:
                    reply = self.get_input("number '1' for campus network, number'2' for pppoe(q for exit): ").strip()

                if reply.find('q') > -1:
                    self.clean()
                    break

                if reply.find('1') == reply.find('2') == -1:
                    self.error_input = True
                    continue
                elif reply == '1':
                    self.flag = 1
                    self.step = 1
                elif reply == '2':
                    self.flag = 2
                    self.step = 1
            elif self.step == 1:
                if self.flag == 1:  # 校园网
                    userid = self.get_input("Please input your userid(q for exit,b for last step): ").strip()
                    if userid == 'q':
                        self.clean()
                        break

                    if userid == 'b':
                        self.step = 0
                        continue

                    password = self.get_pass('Please input your password: ').strip()

                    succeeded, msg = self.cn_helper.submit(userid, password)
                    if not succeeded:  # 初始化socket失败
                        print(msg)
                        break
                    succeeded, msg = self.cn_helper.login()
                    if succeeded:
                        self.step = 2

                    try:
                        print(msg)  # 打印服务器返回的一句话
                    except UnicodeEncodeError:  # openwrt上的python2出现异常
                        print('Succeed to login.')

                else:  # 校园外网
                    if self.error_input:
                        self.error_input = False
                        isp = self.get_input("Wrong input!number'1' for LIANTONG, number'2' for DIANXIN, " +
                                             "number'3' for YIDONG(q for exit,b for last step): ").strip()
                    else:
                        isp = self.get_input("number'1' for LIANTONG, number'2' for DIANXIN," +
                                             "number'3' for YIDONG(q for exit,b for last step): ").strip()

                    if isp == 'q':
                        self.clean()
                        break

                    if isp == 'b':
                        self.step = 0
                        continue

                    if isp != '1' and isp != '2' and isp != '3':
                        self.error_input = True
                        continue
                    else:
                        self.pppoe_helper = IPClientPPPOE()
                        self.pppoe_helper.submit(int(isp))
                        succeeded, msg = self.pppoe_helper.login()
                        if succeeded:
                            print("You have fetched permission already and are able to dial up by pppoe!")
                        else:
                            print("{}\nFail to fetch permission ╯﹏╰ ".format(msg))
                        break
            elif self.step == 2:
                if self.flag == 1:  # 发送心跳包
                    print('Now I am  keeping your ip opening,type in Ctrl+C will logout and exit.')
                    self.cn_helper.heart_beat(callback=self.heart_beat_callback)  # loop！
                    self._exit(None, None)

    def heart_beat_callback(self, arg):
        """
        发送心跳包后的回调
        :param arg:(bool, flow, money)(是否成功获取服务器返回的使用流量和余额数据,使用流量,剩余金额)
        :return:
        """
        succeeded, flow, money = arg
        if succeeded:
            print('data traffic: {0:.2f}KB\nbalance: {1:.2f}yuan\n'.format(flow / 1024.0, money))
        else:
            print('Can not to connect to server')

    def _set_signal_handle(self):
        signal.signal(signal.SIGINT, self._exit)
        signal.signal(signal.SIGTERM, self._exit)

    def _exit(self, signum, stack):
        """
        关闭ip并退出程序
        :param signum:
        :param stack:
        :return:
        """
        if self.step == 2:
            succeeded, msg = self.cn_helper.logout()

            self.clean()
            if succeeded:
                try:
                    print(u'\n{0}\n退出成功!'.format(msg))
                except UnicodeEncodeError:  # openwrt上的python2对Unicode支持出现异常
                    print('\nSucceed to close this ip!')
            else:
                print('\nFail to logout,server will close your ip after several minutes automatically.')
            sys.exit()

    def clean(self):
        if self.cn_helper:
            self.cn_helper.clean()
        if self.pppoe_helper:
            self.pppoe_helper.clean()


def run():
    """
    程序主入口
    """
    # fromfile_prefix_chars='@'表明命令行可以使用@file直接读取file文件中的命令参数，但是file
    # 中的参数需要一个一行（ -t 5 -s foo 则文件中的字符串应为 '-t\n5\n-s\nfoo'）
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=textwrap.dedent(u"""\
            IPClient by python
            --------------------------------
            欢迎使用IPClientShell!
            1、交互模式：ipclientshell.py -a
            2、校园网交互模式：ipclientshell.py -ac
            3、校园外网交互模式：ipclientshell.py -ae
            4、校园网模式：ipclientshell.py -c -u userid -p password
            5、校园外网模式：ipclientshell.py -e -i isptype -w ethname -m mac
            """),
        fromfile_prefix_chars='@'
    )

    # 添加交互参数组
    interact_group = parser.add_argument_group(
        title=None,
        description=u'当不提供任何以下参数时将默认进入交互模式：'
    )
    interact_group.add_argument(
        '-a', '--ask', action='store_true',
        help=u'是否进行交互',
    )
    # 交互参数组中添加类型互斥参数组 -c 校园网 -e 校园外网
    type_group = interact_group.add_mutually_exclusive_group(required=False)
    type_group.add_argument(
        '-c', '--campus', action='store_true', dest='campus',
        help=u'使用校园网，开放ip以联网',
    )
    type_group.add_argument(
        '-e', '--pppoe', action='store_true', dest='pppoe',
        help=u'使用校园外网，获取拨号权限',
    )

    # 校园网参数组
    cn_group = parser.add_argument_group(
        title=u'-c 校园网登录',
        description=u'-u和-p选项是必须的'
    )
    cn_group.add_argument(
        '-u', '--userid', nargs='?', type=str,
        help=u'校园网账号',
    )
    cn_group.add_argument(
        '-p', '--password', nargs='?', type=str,
        help=u'校园网密码',
    )

    # 校园外网参数组
    pppoe_group = parser.add_argument_group(
        title=u'-e 获取校园外网拨号权限',
        description=u'-i选项是必须的，若-w和-m都未提供，将自动获取本机获取到校园网的mac地址'
    )
    pppoe_group.add_argument(
        '-w', '--wan', nargs='?', type=str,
        help=u'wan口设备名称ethx，选择该选项将会使-m选项无效',
    )
    pppoe_group.add_argument(
        '-m', '--mac', nargs='?', type=str,
        help=u'要获取权限的网络设备的mac地址',
    )
    pppoe_group.add_argument(
        '-i', '--isp', nargs='?', type=int, choices=[1, 2, 3],
        help=u'ISP类型，1：联通，2：电信，3：移动',
    )

    # 是否详细输出
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')
    parser.add_argument('-q', '--quiet', action='store_false', dest='verbose')

    # 测试解析
    # parser.print_help()
    # print(parser.parse_args('-a'.split()))
    # print(parser.parse_args('-ac'.split()))
    # print(parser.parse_args('-ae'.split()))
    # print(parser.parse_args('-c -uliu -p123456'.split()))
    # print(parser.parse_args('-e -weth0.1 -i3'.split()))

    ns = parser.parse_args()
    if ns.ask:  # 交互
        if ns.campus:  # 校园网
            IPClientShell(1)
        elif ns.pppoe:  # 校园外网
            IPClientShell(2)
        else:  # 未选择模式
            IPClientShell(0)
    else:  # 交互选项未指定
        if ns.campus:  # 校园网
            if ns.userid is None and ns.password is None:
                print('the following arguments are required: -u/--userid, -p/--password.Try -h to look for help.')
            elif ns.userid is None:
                print('the following arguments are required: -u/--userid.Try -h to look for help.')
            elif ns.password is None:
                print('the following arguments are required: -p/--password.Try -h to look for help.')
            else:  # 校园网登录
                cn_login(ns.userid, ns.password)

        elif ns.pppoe:  # 校园外网
            if ns.isp is None:
                print('the following arguments are required: -i/--isp.Try -h to look for help.')
            elif ns.wan:
                pppoe_login(isp=ns.isp, eth=ns.wan)
            elif ns.wan:
                pppoe_login(isp=ns.isp, mac=ns.mac)
            else:
                pppoe_login(isp=ns.isp)

        else:  # 未选择模式，此时默认进入交互模式
            IPClientShell(0)


def start():
    """
    程序主入口（版本二）
    """
    # fromfile_prefix_chars='@'表明命令行可以使用@file直接读取file文件中的命令参数，但是file
    # 中的参数需要一个一行（ -t 5 -s foo 则文件中的字符串应为 '-t\n5\n-s\nfoo'）
    parser = argparse.ArgumentParser(
        formatter_class=argparse.RawTextHelpFormatter,
        description=textwrap.dedent("""\
            IPClient by python
            --------------------------------
            Welcome to use IPClientShell!
            1.interact mode: ipclientshell.py or ipclientshell.py i
            2.campus network interact mode: ipclientshell.py i -c
            3.pppoe interact mode: ipclientshell.py i -p
            4.campus network mode: ipclientshell.py c -u userid -p password
            5.pppoe mode: ipclientshell.py p -i isp -e eth -m mac
            """),
        fromfile_prefix_chars='@'
    )
    # 主parser的参数：
    # 是否详细输出
    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose')
    parser.add_argument('-q', '--quiet', action='store_false', dest='verbose')

    # subparsers:
    subparsers = parser.add_subparsers(dest='mode')

    # 交互模式
    interact_subparser = subparsers.add_parser('i',
                                               help=textwrap.dedent("""\
                                               [-h] [-c | -e]
                                               interact mode
                                               """))
    # 添加类型互斥参数组 -c 校园网 -e 校园外网
    type_group = interact_subparser.add_mutually_exclusive_group(required=False)
    type_group.add_argument(
        '-c', '--campus', action='store_true', dest='c',
        help='campus network,login and keep online',
    )
    type_group.add_argument(
        '-p', '--pppoe', action='store_true', dest='p',
        help='pppoe,get permission for dial up',
    )

    # 校园网模式
    cn_subparser = subparsers.add_parser('c',
                                         help=textwrap.dedent("""\
                                         [-h] -u [USERID] -p [PASSWORD]
                                         campus network mode
                                         """))
    cn_subparser.add_argument(
        '-u', '--userid', nargs='?', type=str, required=True,
        help='account',
    )
    cn_subparser.add_argument(
        '-p', '--password', nargs='?', type=str, required=True,
        help='password',
    )

    # 校园外网模式
    pppoe_subparser = subparsers.add_parser('p',
                                            help=textwrap.dedent("""\
                                            [-h] [-e [ETH]] [-m [MAC]] -i [{1,2,3}]
                                            pppoe mode
                                            """))
    pppoe_subparser.add_argument(
        '-e', '--eth', nargs='?', type=str,
        help='device name of wan:ethx,choosing this option will disable -m',
    )
    pppoe_subparser.add_argument(
        '-m', '--mac', nargs='?', type=str,
        help='mac of interface which will be dial up by pppoe',
    )
    pppoe_subparser.add_argument(
        '-i', '--isp', nargs='?', type=int, choices=[1, 2, 3], required=True,
        help='ISP.1:LIANTONG,2:DIANXIN,3:YIDONG',
    )

    # 测试解析
    # parser.print_help()
    # print(parser.parse_args('i'.split()))
    # print(parser.parse_args('i -c'.split()))
    # print(parser.parse_args('i -p'.split()))
    # print(parser.parse_args('c -uliu -p123456'.split()))
    # print(parser.parse_args('p -eeth0.1 -i3'.split()))

    ns = parser.parse_args()
    # print(ns)

    if ns.mode is None:  # 默认为交互模式
        IPClientShell(0)

    if ns.mode == 'i':  # 交互模式
        if ns.c:  # 校园网
            IPClientShell(1)
        elif ns.p:  # 校园外网
            IPClientShell(2)
        else:  # 未选择模式
            IPClientShell(0)
    elif ns.mode == 'c':  # 校园网模式
        cn_login(ns.userid, ns.password)
    elif ns.mode == 'p':  # 校园外网模式
        pppoe_login(isp=ns.isp, mac=ns.mac, eth=ns.eth)


if __name__ == '__main__':
    # IPClientShell().interact()
    # run()
    start()
