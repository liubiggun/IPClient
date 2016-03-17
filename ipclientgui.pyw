#!/usr/bin/env python
# -*- coding: utf-8 -*-

from __future__ import print_function
from __future__ import division
try:
    from tkinter import *
    from tkinter.ttk import Combobox
    from tkinter.messagebox import showinfo, showerror
    from _tkinter import TclError
    import queue
except ImportError:
    from Tkinter import *
    from ttk import Combobox
    from tkMessageBox import showinfo, showerror
    from _tkinter import TclError
    import Queue as queue

from ipclient import IPClientCN, get_perm, PeriodTask
import os
import pickle
from platform import system
import subprocess
import re
from time import sleep

try:
    import threading
except ImportError:
    import dummy_threading as threading


VERSION = '1.0.0'
PLAT = system()  # 系统类型
DIR = os.path.dirname(os.path.abspath(__file__))
ICON_PATH = os.path.join(DIR, 'ipclient.ico')
SAVE_DATA_PATH = os.path.join(os.path.expanduser('~'), '.IPClient\save_data') or r'C:\.IPClient\save_data'

thread_queue = queue.Queue(maxsize=0)


def thread_checker(widget, delay_sec=100, per_event=1):  # 默认每100毫秒执行一次回调
    """
    tk GUI主线程调用的函数：在主线程里周期性检查队列，并在主线程执行队列里到来的回调函数。模式是一个
    消费者（GUI主线程），多个生产者（长时间任务生产出一个回调函数给消费者使用）
    指定了消费者在一个delay_sec周期内消费的个数per_event（太少可能等待下次消费花的时间多且CPU浪费在
    事件等待中，太多的话，一个时间段消费太多会导致GUI显示不过来造成阻塞），应保证生产者返回的回调函数
    在主线程执行足够快速，因为在这些回调函数执行后会返回主线程的事件循环并触发update方法
    :param widget:
    :param delay_sec:
    :param per_event:
    :return:
    """
    for i in range(per_event):
        try:
            (callback, args) = thread_queue.get(block=False)
        except queue.Empty:
            break
        else:
            callback(*args)  # 执行回调

    widget.after(delay_sec, lambda: thread_checker(widget, delay_sec, per_event))


def do_in_thread(action, args, kwargs, context, on_exit, on_fail, on_progress):
    """
    子线程要执行的逻辑
    :param action:
    :param args:
    :param kwargs:
    :param context:
    :param on_exit:
    :param on_fail:
    :param on_progress:
    :return:
    """
    try:
        if not on_progress:  # 若没有on_progress回调函数，线程直接执行任务
            action(*args, **kwargs)
        else:  # 假如有on_progress回调函数
            def progress(*any_args):
                thread_queue.put((on_progress, any_args + context))
            action(progress=progress, *args, **kwargs)  # 这将要求progress在action的参数列表中处于位置参数之后
    except Exception:  # 捕获异常
        thread_queue.put((on_fail, (sys.exc_info(),) + context))
    else:
        thread_queue.put((on_exit, context))


def start_thread(action, args=(), kwargs={}, context=(), on_exit=lambda: None, on_fail=lambda: None, on_progress=None):
    """
        启动一个工作者线程，运行带args,kwargs参数的action方法，返回相应的回调函数存入共享队列中（生产），
    用来给GUI主线程消费
        线程执行完毕后将回调函数保存到共享队列中，成功则保存on_exit回调函数和context参数，失败则保存
    on_fail回调函数和参数(sys.exc_info(), ) + context)
        on_progress回调函数用来报告该线程任务执行过程中完成状况（如百分比进度），底层实现是这样的(见do_in_thread)：
    on_progress为None时线程开启时直接执行action(*args, **kwargs)，否则将progress(*any_args)回调函数传递给
    action函数，这个progress回调函数仅仅是将on_progress回调函数和参数(any_args + context)保存在队列
    里，返过来让GUI线程调用，所以要想更新百分比进度，就要在action里调用progress函数来实现。
        所以整个实现应该是GUI主线程里写好3个回调函数on_exit，on_fail，on_progress，这三个专门实现
    GUI的界面更新，再写好新线程需要工作的函数action(*args, **kwargs),context是关于这个工作者线程的一些通用
    信息，并且在action顺序过程中不时标记progress(*any_args)函数，这样线程在执行过程中就能不时向队列推送
    on_progress回调提示，主线程就能知道工作线程的进度了。
    :param action: 子线程要执行的任务
    :param args:
    :param kwargs:
    :param context: 子线程的一些通用的信息，回调函数会将其作为参数
    :param on_exit: 正常退出的回调，参数是对context元组解包后的各参数
    :param on_fail: 异常退出的回调，参数是sys.exc_info()和对context元组解包后的各参数
    :param on_progress: 报告进度的回调，参数是对any_args解包后的各参数和对context元组解包后的各参数，
    其中any_args是action中调用progress时传递进来的。注意：要使用on_progress那么action需要有progress参数
    :return:
    """
    t = threading.Thread(
        target=do_in_thread,
        args=(action, args, kwargs, context, on_exit, on_fail, on_progress),
    )
    t.setDaemon(True)
    t.start()


class IPClientGui:
    def __init__(self, parent):
        self.parent = parent
        thread_checker(self.parent)  # 启动检查线程回调队列的事件循环

        # 先尝试读取保存的数据：{'enable': False, 'username': '', 'password': '', 'isp': 0, 'ppp': 0}
        self.save_data = {}
        if os.path.exists(SAVE_DATA_PATH):
            try:
                with open(SAVE_DATA_PATH, 'rb') as f:
                    self.save_data = pickle.load(f)
            except IOError:
                pass

        self.task_thread = None
        self.heart_beat_thread = None  # 校园网心跳包子线程
        self.status = -1  # -1：还未启用； 0：已登录校园网； 1：已拨号校园外网；6：正在登录过程中
        self.b_need_logout = False  # 是否需要关闭ip，用来关闭心跳包thread
        self.succeeded = True  # 记录放送udp数据包后是否成功，需要保证同个时间内只有一个子线程操作它
        self.msg = ''  # 记录发送数据包后得到的信息，需要保证同个时间内只有一个子线程操作它
        self.b_has_task = False  # 记录当前是否有子线程任务（不包括心跳包线程）在运行。本应用同一时间只有一个子线程任务在运行

        # logo
        try:
            self.logo = PhotoImage(file=os.path.join(DIR, 'logo.png'))
            self.label_img = Label(image=self.logo)
            self.label_img.grid(row=0, column=0, columnspan=7)
        except TclError:  # 读取不了图片
            self.label_img = Frame(width=505, height=77)
            self.label_img.grid(row=0, column=0, columnspan=7)

        # 公告
        self.label_new = Label(fg='red', bg='gray', text=u'最新公告：', anchor=W)
        self.label_new.grid(
            row=1, column=0, columnspan=7, sticky=N + S + W + E, padx=5.5, pady=5.5
        )

        # 使用流量状况
        self.label_balance = Label(
            text=u'使用流量：0 KB   剩余金额：0 元', font=("courier", 10), anchor=W, relief=GROOVE, borderwidth=2
        )
        self.label_balance.grid(
            row=2, column=0, columnspan=7, sticky=N + S + W + E, padx=5.5, pady=5.5, ipadx=5.5, ipady=2.5,
        )

        # 用户名
        self.label_username = Label(text=u'用户名')
        self.label_username.grid(
            row=3, column=0, sticky=W, padx=5.5, pady=5.5,
        )
        self.username = StringVar()
        self.entry_username = Entry(textvariable=self.username)
        self.entry_username.grid(
            row=3, column=1, columnspan=2, sticky=W, padx=5.5, pady=5.5,
        )
        if self.save_data and self.save_data['enable']:  # 记忆密码则直接填充
            self.username.set(self.save_data['username'])

        # 密码
        self.label_password = Label(text=u'密码')
        self.label_password.grid(
            row=3, column=2, sticky=W, padx=5.5, pady=5.5,
        )
        self.password = StringVar()
        self.entry_password = Entry(textvariable=self.password, show='*')
        self.entry_password.grid(
            row=3, column=3, columnspan=2, sticky=W, padx=5.5, pady=5.5,
        )
        if self.save_data and self.save_data['enable']:  # 记忆密码则直接填充
            self.password.set(self.save_data['password'])

        # 是否记忆密码
        self.b_remember = BooleanVar()
        self.checkbox_remember = Checkbutton(text=u'记忆密码', variable=self.b_remember)
        self.checkbox_remember.grid(
            row=3, column=4, sticky=W, padx=5.5, pady=5.5,
        )
        if self.save_data and self.save_data['enable']:
            self.b_remember.set(True)

        # 运营商
        self.label_isp = Label(text=u'运营商')
        self.label_isp.grid(
            row=4, column=0, sticky=W, padx=5.5, pady=5.5,
        )
        self.combobox_isp = Combobox(values=(u'校园网', u'联通', u'电信', u'移动'), state='readonly')
        self.combobox_isp.grid(
            row=4, column=1, columnspan=1, sticky=W, padx=5.5, pady=5.5,
        )
        if self.save_data and self.save_data['enable']:  # 记忆密码则直接选择原来的isp
            self.combobox_isp.current(self.save_data['isp'])
        else:
            self.combobox_isp.current(0)

        # 选择的ppp连接
        self.label_ppp = Label(text=u'宽带连接')
        self.label_ppp.grid(
            row=4, column=2, sticky=W, padx=5.5, pady=5.5,
        )
        self.pppname = StringVar()
        self.combobox_ppp = Combobox(textvariable=self.pppname, state='readonly')
        self.combobox_ppp.grid(
            row=4, column=3, columnspan=2, sticky=W, padx=5.5, pady=5.5,
        )
        combobox_ppp_values = []

        if PLAT == 'Windows':  # 如果是Windows系统则读取注册表，获取可用的宽带连接
            try:
                from winreg import OpenKey, EnumKey, EnumValue, QueryInfoKey, QueryValueEx, HKEY_LOCAL_MACHINE
            except ImportError:
                from _winreg import OpenKey, EnumKey, EnumValue, QueryInfoKey, QueryValueEx, HKEY_LOCAL_MACHINE

            key_base = r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\NetworkList\Profiles'
            key_list = []
            with OpenKey(HKEY_LOCAL_MACHINE, key_base) as profiles:

                # 获取连接的个数
                key_count = QueryInfoKey(profiles)[0]
                for i in range(key_count):
                    name = EnumKey(profiles, i)  # 获取子键名
                    key_list.append(name)

            for key in key_list:  # 遍历每个键，找到ppp连接，并将其添加入combobox_ppp_values选项列表
                with OpenKey(HKEY_LOCAL_MACHINE, '{}\\{}'.format(key_base, key)) as sub:
                    value, _ = QueryValueEx(sub, "NameType")  # 6是dhcp有线， 71是无线， 23是ppp连接
                    if value == 23:
                        name, _ = QueryValueEx(sub, "ProfileName")  # 获取接口名称
                        combobox_ppp_values.append(name)
        elif PLAT == 'Linux':
            """
            如果是linux则查看/etc/ppp/peers下的pppoe配置文件，配置文件比较重要地是：
            user 15678382004
            pty "/usr/sbin/pppoe -I eth0 -T 80 -m 1452"
            其相应密码在/etc/ppp/pap-secrets中："your account" pppoe "your pin"
            """
            combobox_ppp_values = os.listdir('/etc/ppp/peers')

        if combobox_ppp_values:  # 有ppp连接的话则添加选项并默认选择
            self.combobox_ppp['values'] = combobox_ppp_values
            if self.save_data and self.save_data['enable']:  # 记忆密码则直接选择原来的ppp连接
                self.combobox_ppp.current(self.save_data['ppp'])
            else:
                self.combobox_ppp.current(0)

        # 版本与IP地址
        self.label_ip = Label(
            text=u'版本：{}      IP地址：'.format(VERSION),
            font=("courier", 10), anchor=W, relief=GROOVE, borderwidth=2
        )
        self.label_ip.grid(
            row=5, column=0, columnspan=3, sticky=W, padx=5.5, pady=3,
        )

        # 连接按钮和断开按钮
        self.button_login = Button(text=u'连接', command=self.login, width=10)  # 这里的宽度单位不是像素
        self.button_login.grid(
            row=5, column=3,
        )
        self.button_logout = Button(text=u'断开', command=self.logout, width=10, state='disable')  # 这里的宽度单位不是像素
        self.button_logout.grid(
            row=5, column=4,
        )

        # 状态信息
        self.label_status = Label(
            text=u'连接状态：',
            font=("courier", 10), anchor=E, relief=GROOVE, borderwidth=2
        )
        self.label_status.grid(
            row=6, column=0, columnspan=7, sticky=W + S + E, padx=5.5, pady=3,
        )

        # 初始化ipclient help类
        self.pppoe_helper = get_perm
        self.cn_helper = None

        def init_helper():
            self.cn_helper = IPClientCN()

        def init_helper_on_exit():
            self.b_has_task = False
            if self.cn_helper.b_server_connected:
                self.update_label_news_ip()
                if self.cn_helper.b_connect_router:
                    self.update_label_status(u'警告！当前设备连接了路由器。')
            else:
                self.update_label_status(u'错误！连接服务器失败！')

        def init_helper_on_fail(exc_info):
            self.b_has_task = False
            self.update_label_status(u'错误！连接服务器失败！')

        # 初始化时会连接服务器，延时可能带来阻塞，故使用子线程
        self.b_has_task = True
        start_thread(
            action=init_helper,
            on_exit=init_helper_on_exit,
            on_fail=init_helper_on_fail,
        )

        # 绑定事件
        self.entry_username.bind('<Return>', lambda e: self.login())
        self.entry_password.bind('<Return>', lambda e: self.login())
        self.parent.protocol("WM_DELETE_WINDOW", self.exit)

    def update_label_news_ip(self):
        self.label_new['text'] = u'最新公告：{}'.format(self.cn_helper.news_from_server)
        self.label_ip['text'] = u'版本：{}      IP地址：{}'.format(VERSION, self.cn_helper.ip)

    def update_label_status(self, msg):
        self.label_status['text'] = u'连接状态：{}'.format(msg)

    def update_status(self, status):
        """
        更新状态，同时更新各组件的可用性，登录时或登录成功后不允许改动数据，退出登录才可以改动数据
        :param status: -1：还未启用； 0：已登录校园网； 1：已拨号校园外网；6：正在登录过程中
        :return:
        """
        self.status = status
        if status == -1:  # 未启用
            self.button_login['state'] = 'normal'
            self.button_logout['state'] = 'disable'
            self._toggle_form(True)
            self.entry_username.focus_set()
        elif status == 0:  # 已登录校园网
            self.button_login['state'] = 'disable'
            self.button_logout['state'] = 'normal'
            self._toggle_form(False)
        elif status == 1:  # 已使用校园外网
            self.button_login['state'] = 'disable'
            self.button_logout['state'] = 'normal'
            self._toggle_form(False)
        elif status == 6:  # 正在登录过程中
            self.button_login['state'] = 'disable'
            self.button_logout['state'] = 'disable'
            self._toggle_form(False)

    def _toggle_form(self, enable):
        """
        更改各输入框的可用性
        :param enable:
        :return:
        """
        if enable:
            self.entry_username['state'] = 'normal'
            self.entry_password['state'] = 'normal'
            self.checkbox_remember['state'] = 'normal'
            self.combobox_isp['state'] = 'normal'
            self.combobox_ppp['state'] = 'normal'
        else:
            self.entry_username['state'] = 'disable'
            self.entry_password['state'] = 'disable'
            self.checkbox_remember['state'] = 'disable'
            self.combobox_isp['state'] = 'disable'
            self.combobox_ppp['state'] = 'disable'

    def login(self):
        if self.status == -1:
            id_isp = self.combobox_isp.current()

            # 如果选择了外网并且是Linux系统的话，读取配置文件，填充用户名和密码，由于不一定找得到，故此处这两项可以允许为空
            if PLAT == 'Linux' and id_isp != 0:
                pppname = self.pppname.get()
                username = ''
                if pppname == '':
                    showerror(u'错误', u'请先建立一个宽带连接！')
                    return
                with open('/etc/ppp/peers/{}'.format(pppname), 'r') as peer, open('/etc/ppp/pap-secrets') as secret:
                    # 查找宽带用户名：'user xxxxxxxx'
                    pattern = re.compile(r'^(user\s+)(.+)')
                    for line in peer.readlines():
                        m = pattern.match(line.strip())
                        if m:
                            username = m.groups()[-1]
                            self.username.set(username)
                            break
                    # 查找宽带用户名对应的密码：'username pppname password'
                    pattern = re.compile(r'^([\'\"]{}[\'\"]\s+)({}\s+)(.+)'.format(username, pppname))
                    for line in secret.readlines():
                        m = pattern.match(line.strip())
                        if m:
                            self.password.set(m.groups()[-1].strip('\'\"'))
                            break

            else:
                # 判断用户名和密码是否填充
                if self.username.get() == '':
                    showerror(u'错误', u'请填写用户名！')
                    return
                if self.password.get() == '':
                    showerror(u'错误', u'请填写密码！')
                    return

            if id_isp == 0:  # 校园网
                self.succeeded, self.msg = self.cn_helper.submit(self.username.get(), self.password.get())
                if not self.succeeded:
                    self.update_label_status(u'错误！{}'.format(self.msg))
                    return

                # 发送数据包给服务器，延时可能带来阻塞，故使用子线程
                self.update_status(6)  # 开始登录过程
                self.b_has_task = True
                start_thread(
                    action=self._cn_login,
                    on_exit=self._cn_login_on_exit,
                    on_fail=self._cn_login_on_fail
                )

            else:  # pppoe
                if self.pppname.get() == '':
                    showerror(u'错误', u'请先建立一个宽带连接！')
                    return
                # 拨号延时可能带来阻塞，故使用子线程
                self.update_status(6)  # 开始拨号过程
                self.b_has_task = True
                start_thread(
                    action=self._ppp_login,
                    args=(id_isp,),
                    on_exit=self._ppp_login_on_exit,
                    on_fail=self._ppp_login_on_fail,
                    on_progress=self._ppp_login_on_progress,
                )

    def logout(self, need_exit=False):
        """
        退出登录
        :param need_exit: 是否需要成功退出时退出程序
        :return:
        """
        if self.status != -1:
            if self.status == 0:  # 已登录校园网
                # 发送数据包给服务器，延时可能带来阻塞，故使用子线程
                self.update_status(6)  # 开始退出校园网过程
                self.b_has_task = True
                start_thread(
                    action=self._cn_logout,
                    context=(need_exit,),
                    on_exit=self._cn_logout_on_exit,
                    on_fail=self._cn_logout_on_fail,
                )

            elif self.status == 1:  # 校园外网
                # 断开拨号延时可能带来阻塞，故使用子线程
                self.update_status(6)  # 开始断开拨号连接过程
                self.b_has_task = True
                start_thread(
                    action=self._ppp_logout,
                    context=(need_exit,),
                    on_exit=self._ppp_logout_on_exit,
                    on_fail=self._ppp_logout_on_fail,
                    on_progress=self._ppp_logout_on_progress,
                )
        else:
            if need_exit:
                self.parent.quit()

    def _cn_login(self):  # 运行在子线程
        self.succeeded, self.msg = self.cn_helper.login()

    def _cn_login_on_exit(self):  # 运行完成后的回调
        self.b_has_task = False
        if self.succeeded:  # 登录成功
            self.check_save_data()
            self.update_label_status(u'已成功登录校园网')
            self.b_need_logout = False
            self.heart_beat()  # 先获取一次余额
            self.heart_beat_thread = PeriodTask(
                seconds=self.cn_helper.refresh_packet_factory.TIME_REFRESH_ONLINE_INTERVAL,
                task=self.heart_beat,
                condition=self._heart_beat_condition
            )
            self.heart_beat_thread.start()
            self.update_status(0)
        else:  # 登录失败
            self.update_label_status(u'错误！{}'.format(self.msg))
            self.update_status(-1)

    def _cn_login_on_fail(self, exc_info):  # 运行失败后的回调
        self.b_has_task = False
        self.update_label_status(u'错误！连接失败')
        self.update_status(-1)

    def _ppp_login(self, id_isp, progress):  # 运行在子线程
        self.succeeded, self.msg = self.pppoe_helper(id_isp)
        if not self.succeeded:  # 如果获取权限失败，直接退出子线程
            self.msg = u'连接服务器失败！'
            return
        # 否则可以开始拨号了
        if PLAT == 'Windows':  # 如果是Windows系统则使用rasdial命令来拨号
            try:
                cmd = 'rasdial {} {} {}'.format(
                    self.pppname.get(), self.username.get(), self.password.get()
                )
            except UnicodeEncodeError:
                cmd = 'rasdial {} {} {}'.format(
                    self.pppname.get().encode('gbk'), self.username.get(), self.password.get()
                )
            p = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            progress(u'正在进行拨号...')
            if p.wait() != 0:
                self.succeeded = False
                self.msg = u'拨号失败'
        elif PLAT == 'Linux':
            cmd = 'pon {}'.format(self.pppname.get())
            p = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT
            )
            # 查看当前ppp连接号
            pn = os.popen('ifconfig|grep ppp.*|wc -l').read().strip()

            progress(u'正在进行拨号...')
            p.wait()
            sleep(10)

            # 等待10s，如果没有显示新的ppp连接，则说明拨号失败（这个方法需要改进）
            if os.popen('ifconfig|grep ppp.*|wc -l').read().strip() == pn:
                self.succeeded = False
                self.msg = u'拨号失败'

    def _ppp_login_on_progress(self, msg):
        self.update_label_status(msg)

    def _ppp_login_on_exit(self):
        self.b_has_task = False
        if self.succeeded:  # 拨号成功
            self.check_save_data()
            self.update_label_status(u'已成功拨号')
            self.update_status(1)
        else:
            self.update_label_status(u'错误！{}'.format(self.msg))
            self.update_status(-1)

    def _ppp_login_on_fail(self, exc_info):  # 运行失败后的回调
        self.b_has_task = False
        self.update_label_status(u'错误！拨号失败')
        self.update_status(-1)
        print(exc_info[0], exc_info[1])

    def _cn_logout(self):
        self.b_need_logout = True  # 退出心跳包thread的循环
        while self.heart_beat_thread.isAlive():  # 等待心跳包thread退出
            pass
        self.heart_beat_thread = None
        self.succeeded, self.msg = self.cn_helper.logout()
        if not self.succeeded:  # 退出登录失败
            self.msg = u'退出登录失败，过几分钟服务器会自动关闭此IP。'

    def _cn_logout_on_exit(self, need_exit):
        self.b_has_task = False
        if self.succeeded:
            self.update_label_status(u'已成功退出校园网')
            self.update_status(-1)
        else:
            self.update_label_status(u'错误！{}'.format(self.msg))
            self.update_status(-1)
        if need_exit:  # 需要退出程序
            self.parent.quit()

    def _cn_logout_on_fail(self, exc_info, need_exit):  # 运行失败后的回调
        self.b_has_task = False
        self.update_label_status(u'错误！退出登录失败，过几分钟服务器会自动关闭此IP。')
        self.update_status(-1)
        if need_exit:  # 需要退出程序
            self.parent.quit()

    def _ppp_logout(self, progress):  # 运行在子线程
        if PLAT == 'Windows':  # 如果是Windows系统则使用rasdial命令来关闭拨号
            try:
                cmd = 'rasdial {} /d'.format(self.pppname.get())
            except UnicodeEncodeError:
                cmd = 'rasdial {} /d'.format(self.pppname.get().encode('gbk'))
            p = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            progress(u'正在关闭拨号连接...')
            if p.wait() != 0:
                self.succeeded = False
                self.msg = u'关闭拨号连接失败，请手动关闭'
        elif PLAT == 'Linux':
            cmd = 'poff {}'.format(self.pppname.get())
            p = subprocess.Popen(
                cmd,
                shell=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE
            )
            progress(u'正在关闭拨号连接...')
            if p.wait() != 0:
                self.succeeded = False
                self.msg = u'关闭拨号连接失败，请手动关闭'

    def _ppp_logout_on_progress(self, msg, need_exit):
        self.update_label_status(msg)

    def _ppp_logout_on_exit(self, need_exit):
        self.b_has_task = False
        if self.succeeded:  # 拨号成功
            self.update_label_status(u'已成功关闭拨号连接')
            self.update_status(-1)
        else:
            self.update_label_status(u'错误！{}'.format(self.msg))
            self.update_status(-1)
        if need_exit:  # 需要退出程序
            self.parent.quit()

    def _ppp_logout_on_fail(self, exc_info, need_exit):  # 运行失败后的回调
        self.b_has_task = False
        self.update_label_status(u'错误！关闭拨号连接失败，请手动关闭')
        self.update_status(-1)
        if need_exit:  # 需要退出程序
            self.parent.quit()

    def heart_beat(self):
        """
        发送校园网心跳包的任务
        :return:
        """
        succeeded, traffic, balance = self.cn_helper.refresh_online()
        if succeeded:
            self.label_balance['text'] = u'使用流量：{0:.2f} KB   剩余金额：{1:.2f} 元'.format(
                traffic / 1024.0, balance
            )

    def _heart_beat_condition(self):
        """
        发送校园网心跳包的线程停止的判断函数
        :return:
        """
        return not self.b_need_logout

    def check_save_data(self):
        """
        检查是否要保存数据
        :return:
        """
        if self.b_remember.get():  # 选择了记忆密码
            if os.path.exists(SAVE_DATA_PATH):  # 如果之前已经创建了文件，则修改之
                self.save_data['enable'] = True
                self.save_data['username'] = self.username.get()
                self.save_data['password'] = self.password.get()
                self.save_data['isp'] = self.combobox_isp.current()
                self.save_data['ppp'] = self.combobox_ppp.current()
                with open(SAVE_DATA_PATH, 'wb') as f:
                    pickle.dump(self.save_data, f, protocol=2)
            else:  # 否则创建文件
                dirname = os.path.dirname(SAVE_DATA_PATH)
                if not os.path.exists(dirname):
                    os.mkdir(dirname)
                self.save_data = {
                    'enable': True,
                    'username': self.username.get(),
                    'password': self.password.get(),
                    'isp': self.combobox_isp.current(),
                    'ppp': self.combobox_ppp.current()
                }
                with open(SAVE_DATA_PATH, 'wb') as f:
                    pickle.dump(self.save_data, f, protocol=2)
        else:
            if os.path.exists(SAVE_DATA_PATH):  # 如果之前已经创建了文件，则修改之
                self.save_data['enable'] = False
                self.save_data['username'] = ''
                self.save_data['password'] = ''
                self.save_data['isp'] = -1
                self.save_data['ppp'] = -1
                with open(SAVE_DATA_PATH, 'wb') as f:
                    pickle.dump(self.save_data, f, protocol=2)
            else:  # 否则啥也不做
                pass

    def exit(self):
        """
        退出程序前退出登录
        :return:
        """
        self.logout(True)


if __name__ == '__main__':
    root = Tk()
    root.title('IP出校控制器')
    root.resizable(False, False)  # 不允许放大、缩小窗口

    ipclient = None
    if PLAT == 'Windows':  # 如果是Windows系统则居中显示窗口
        root.withdraw()  # 隐藏窗口
        screen_width = root.winfo_screenwidth()  # 屏幕宽
        screen_height = root.winfo_screenheight() - 100  # 屏幕高，大概去掉任务栏的高度

        # 构造窗口内部部件
        ipclient = IPClientGui(root)

        root.update_idletasks()  # 显示窗口，此时是根据之前构造部件后开始计算窗口大小

        # 根据窗口大小与屏幕大小居中显示窗口
        root.geometry('{}x{}+{}+{}'.format(
            root.winfo_width() + 10,
            root.winfo_height() + 10,
            (screen_width - root.winfo_width()) // 2,
            (screen_height - root.winfo_height()) // 2)
        )

        root.deiconify()
    elif PLAT == 'Linux':  # 测试一些发行版发现进行居中处理会导致GUI不显示
        ipclient = IPClientGui(root)

    try:
        root.iconbitmap(ICON_PATH)
    except TclError:
        pass
    ipclient.entry_username.focus_set()
    root.mainloop()
