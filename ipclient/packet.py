# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

import struct
import hashlib
from random import choice, randint
from ctypes import c_double
from platform import python_version


class Packet:
    """
    与服务器通信的UDP包
    """

    class COMMAND_ID:
        """
        udp数据包的命令字，注释中的序号表示一个开放IP和关闭IP的过程的步骤号
        """
        REFRESH_GET_NEWS = 0x05  # 1.客户端发送0x05数据包，获取最新公告和本地获取到的校园网IP

        REFRESH_GET_NEWS_REPLY = 0x06  # 2.服务器返回0x06数据包，回复最新公告和本地获取到的校园网IP

        LOGIN_USERID = 0x1f  # 3.客户端发送0x1f数据包，请求开放，发送用户名

        LOGIN_USERID_REPLY = 0x20  # 4.服务器返回0x20数据包，服务器返回加密秘钥Key

        LOGIN_PASSWORD = 0x21  # 5.客户端发送0x21数据包，发送密码加密的密文

        LOGIN_PASSWORD_REPLY = 0x22  # 6.服务器返回0x22数据包，服务器回复是否开放成功

        REFRESH_0A = 0x0a  # 7.客户端发送0x0a数据包，未知作用

        REFRESH_0A_REPLY = 0x0b  # 8.服务器返回0x0b数据包，未知作用

        REFRESH_ONLINE = 0x1e  # 9.客户端发送0x1e数据包，通知服务器维持此IP开放状态

        REFRESH_ONLINE_REPLY = 0x1f  # 10.服务器返回0x1f数据包，服务器发送流量和余额数据

        LOGOUT_USERID = 0x14  # 11.客户端发送0x14数据包，请求关闭此IP开放状态

        LOGOUT_USERID_REPLY = 0x15  # 12.服务器返回0x15数据包，服务器返回加密秘钥Key

        LOGOUT_PASSWORD = 0x16  # 13.客户端发送0x16数据包，发送密码加密的密文

        LOGOUT_PASSWORD_REPLY = 0x17  # 14.服务器返回0x17数据包，服务器回复是否关闭成功

        LOGOUT_NEW = 0x23  # 11.更新后可以不用发送0x14包，直接发送0x23请求关闭IP

        LOGOUT_NEW_REPLY = 0x24  # 服务器返回0x24数据包，服务器回复是否关闭成功

    # 心跳包时间配置
    TIME_REFRESH_ONLINE_INTERVAL = 60

    # 提示消息
    MSG_INVALID_PACKET = 'Received an error package'
    MSG_SUCCESS = ''

    def __init__(self):
        # udp包协议中固定的数据
        self.banner = 0x2382
        self.reserved = 0x3ff0

    def _get_packet(self, *args, **kwargs):
        raise NotImplementedError

    def _validate_packet(self, packet, command_id):
        """
        判断包的格式是否正确
        :param packet:
        :param command_id:
        :return:
        """
        banner, cmd = struct.unpack_from('<HB', packet, 0)
        if banner != self.banner or cmd != command_id:
            return False
        else:
            return True

    def _get_bytes(self, strs):
        """
        返回对应ascii文本字符串的二进制字符串，兼容python2和3
        :param strs:
        :return:
        """
        # python3需要进行编码转换为二进制字符串
        return strs.encode() if python_version()[0] == '3' else strs

    def _get_byte(self, val):
        """
        返回对应ascii码值(0~255)的二进制字符，兼容python2和3
        :param val:
        :return:
        """
        # python3默认编码utf-8，python2则是ascii
        return chr(val).encode() if python_version()[0] == '3' else chr(val)

    def _get_ords(self, bs):
        """
        返回指定二进制字符串的ascii码值(0~255)列表，兼容python2和3
        :param bs:
        :return:
        """
        # python3的二进制字符串在索引后表示为ascii码值，不需要ord，添加条件isinstance(abyte, int)以适应python2的bytearray
        return [abyte if python_version()[0] == '3' or isinstance(abyte, int) else ord(abyte) for abyte in bs]

    def _get_ord(self, abyte):
        """
        返回指定二进制字符串的任意一个字符的的ascii码值(0~255)，兼容python2和3
        :param abyte:
        :return:
        """
        # python3的二进制字符串在索引后表示为ascii码值，不需要ord
        return abyte if python_version()[0] == '3' or isinstance(abyte, int) else ord(abyte)

    def _change_bytes(self, bs, delta):
        """
        对字符串bytes各字符添加delta增量
        :param bs: 二进制字符串
        :param delta: 增量（整数）
        :return: 新的二进制字符串
        """
        newstring = b''
        for item in bs:
            newstring += self._get_byte(self._get_ord(item) + delta)
        return newstring

    def _pack_bytes_into(self, buf, offset, bs):
        """
        将字符串长度和字符串从指定偏移处放入buf中（先放长度int32，再放bytes）

        :param buf:
        :param offset: 偏移（整数）
        :param bs: 填充的二进制字符串
        :return: pack的字节数
        """
        n = len(bs)
        # struct.pack_into('<I{}B'.format(n), buf, offset, n, *self._get_ords(bs))
        struct.pack_into('<I{}s'.format(n), buf, offset, n, bs)
        # struct.pack_into('<I', buf, offset, n)  # pack长度
        # # pack字符串，这里若是python3，string[i]会为ascii码，不过直接充即可，不需要转换为二进制字符串
        # for i in range(n):
        #     buf[offset + 4 + i] = bytes[i]
        return n + 4

    def _unpack_bytes_from(self, buf, offset):
        """
        将buf中指定偏移处unpack出数据，先pack出数据（二进制字符串）的长度，再pack出数据
        :param buf:
        :param offset: 偏移（整数）
        :return: (二进制字符串数据，数据加上数据长度所占的buf的字节长度)
        """
        length, = struct.unpack_from('<I', buf, offset)
        bs, = struct.unpack_from('{}s'.format(length), buf, offset + 4)
        # length, = struct.unpack_from('<I', buf, offset)
        # bytes = b''
        # for i in range(length):
        #     bytes += buf[offset + 4 + i]
        return bs, length + 4

    def _md5_bytes(self, bs):
        """
        计算字符串的MD5值:
        :param bs: 二进制字符串
        :return: 二进制字符串的MD5（二进制字符串）
        """
        md5ob = hashlib.md5()
        md5ob.update(bs)
        return self._get_bytes(md5ob.hexdigest())  # python3需要二进制字符串，此处为了兼容

    def _get_a_random_interger(self):
        return randint(11111111, 99999990)

    def _get_a_random_bytes(self, length):
        """
        生成指定长度随机字符串
        :param length: 二进制字符串长度
        :return: 二进制字符串
        """
        bs = b''
        for i in range(length):
            bs += choice('0123456789abcdef').encode()  # python3需要二进制字符串，此处为了兼容
        return bs

    def _get_a_random_double(self):
        db_ran = c_double(self._get_a_random_interger())
        return db_ran.value



