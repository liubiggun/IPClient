# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

import struct

from .packet import Packet


class RefreshPacket(Packet):
    """
    连接服务器或保持连接时（心跳包）所用到的udp包
    :para userid: 用户名，二进制字符串
    :para password: 用户密码，二进制字符串
    :para key:
    udp包的格式如下：
    # +--------------------+---------------------+--------------+--------------+-----------+
    # | (2) banner(0x2382) | (1) command_id      | (8) key      | (8) flow     | (8) money |
    # | (4) len1           | (len1) bytes1/userid| (4) len2     | (len2) bytes2| (4) len3  |
    # | (Len3) msg         | (4) len4            | (len4) bytes4|              |           |
    # +--------------------+---------------------+--------------+--------------+-----------+
    """

    def __init__(self, userid, password):
        """
        连接服务器或保持连接时（心跳包）所用到的udp包(本地udp5200端口与服务器udp5300端口通信的数据包)
        :param userid: 用户名，文本字符串
        :param password: 用户密码，文本字符串
        :return:
        """
        Packet.__init__(self)
        self.refresh_key = 0
        self.userid = userid
        self.password = password
        self.flow = 0.0
        self.money = 0.0
        self.fmt = '<HBQ2dI{}sI{}sI{}sI{}s'

    PACKET_LENGTH = 500  # udp包的长度

    PACKET_FILL_BYTE = b'\xff'  # udp包剩余长度的buf所填充的字节

    PACKET_RANDOM_BYTES_LENGTH = 0x29  # udp包中的中随机字符串的长度

    def get_flow_money_strings(self):
        """
        获取使用流量和金额的显示字符串
        :return: (str,str)，(使用流量的显示字符串,剩余金额的显示字符串)
        """
        str_flow = 'data traffic: {0:.2f}KB'
        str_money = 'balance: {0:.2f}yuan'
        str_flow = str_flow.format(self.flow / 1024.0)
        str_money = str_money.format(self.money)
        return str_flow, str_money

    def set_user(self, userid, password):
        """
        更新RefreshPacket实例的userid和password字段
        :param userid:
        :param password:
        :return:
        """
        self.userid = userid
        self.password = password

    def set_key(self, key):
        """
        在步骤6服务器回复开放成功后，需要将CmdPacket实例在步骤4所获取的key传递给本实例，形成refresh_key，以便构造心跳包
        :param key:
        :return:
        """
        self.refresh_key = key + 1500

    def get_refresh_get_news_packet(self):
        """
        1、连接服务器时，生成客户端需要发送的0x05数据包，请求连接服务器

        该包的command为0x05，key是长度为8的随机int64，flow和money为随机double，byte1固定为0x61（其实可随意），
        byte2固定为0x62（其实可随意）,byte3是0x29（41）位随机字符串，byte4固定为0x00（其实可随意）
        """
        return self._get_packet(
            self.COMMAND_ID.REFRESH_GET_NEWS,
            self._get_a_random_interger(),
            self._get_a_random_double(),
            self._get_a_random_double(),
            b'a',
            b'b',
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'666666'
        )

    def check_refresh_get_news_reply(self, packet):
        """
        2、连接服务器时，解析服务器返回0x06数据包，回复连接
        :param packet:
        :return: (bool, (strs,strs))，(是否成功连接服务器,(服务器返回的一句话（文本字符串）,服务器返回的客户端的ip))

        该包的command为0x06，key按0x06的原样返回，flow和money为随机double，byte1固定为0x61，byte2固定为0x62,
        byte3是服务器返回的一句话，byte4是服务器返回的客户端的ip（如172.16.55.54）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.REFRESH_GET_NEWS_REPLY)
        if res is False:
            return False, self.MSG_INVALID_PACKET
        else:
            str_news = self._get_bytes_from_reply(packet, 3).decode('gbk')
            str_ip = self._get_bytes_from_reply(packet, 4).decode()
            return True, (str_news, str_ip)

    def get_refresh_0a_packet(self):
        """
        7、开放ip后，生成客户端需要发送的0x0a数据包，作用未知但官方客户端在开放成功后会发送一次

        该包的command为0x0a，key是长度为8的随机int64，flow和money为随机double，byte1固定为0x61（其实可随意），
        byte2固定为0x62（其实可随意）,byte3是0x29（41）位随机字符串，byte4固定为0x20（其实可随意）
        """
        return self._get_packet(
            self.COMMAND_ID.REFRESH_0A,
            self._get_a_random_interger(),
            self._get_a_random_double(),
            self._get_a_random_double(),
            b'a',
            b'b',
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'\x20'
        )

    def check_refresh_0a_reply(self, packet):
        """
        8、开放ip后，服务器返回0x0b数据包，回复客户端的0x0a数据包，作用未知
        """
        return self._validate_packet(packet,
                                     self.COMMAND_ID.REFRESH_0A_REPLY)

    def get_refresh_online_packet(self):
        """
        9、心跳包，生成客户端需要发送的0x1e数据包，通知服务器维持此IP开放状态

        该包的command为0x1e，key是计算后的心跳包标志，flow和money为随机double，byte1固定为userid（其实可随意），
        byte2固定为0x62（其实可随意）,byte3是0x29（41）位随机字符串（其实可随意），byte4固定为0x20（其实可随意）
        """
        return self._get_packet(
            self.COMMAND_ID.REFRESH_ONLINE,
            self.refresh_key,
            self._get_a_random_double(),
            self._get_a_random_double(),
            self.userid.encode(),
            b'b',
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'\x20'
        )

    def check_refresh_online_reply(self, packet):
        """
        10、心跳包，解析服务器返回0x1f的数据包，回复流量和余额数据
        :param packet:
        :return: bool，是否成功获取服务器返回的流量和余额数据

        该包的command为0x1f，key是0x1e的原样返回，flow和money为剩余流量和剩余金额
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.REFRESH_ONLINE_REPLY)
        if res is False:
            return False
        else:
            self.flow = self._get_double_from_packet_at(packet, True)
            self.money = self._get_double_from_packet_at(packet, False)
            return True

    def _get_double_from_packet_at(self, packet, isflow=True):
        """
        从udp包的字节流的指定偏移处解析出double值
        :param packet:
        :param isflow: True则解析出流量值
        :return:
        """
        flow, money = struct.unpack_from('<dd', packet, struct.calcsize('<HBQ'))
        return flow if isflow else money

    def _get_bytes_from_reply(self, packet, n):
        """
        从udp包的字节流解析出byteX的值，其中X是参数n
        :param packet:
        :param n:
        :return:
        """
        offset = struct.calcsize('<HBQ2d')
        byten = b''
        for i in range(n):
            byten, ls = self._unpack_bytes_from(packet, offset)
            offset += ls
        return byten

    def _get_packet(self, command_id, key, flow, money, bytes1, bytes2, bytes3, bytes4):
        """
        构造udp包：
        # +--------------------+---------------------+--------------+--------------+-----------+
        # | (2) banner(0x2382) | (1) command_id      | (8) key      | (8) flow     | (8) money |
        # | (4) len1           | (len1) bytes1/userid| (4) len2     | (len2) bytes2| (4) len3  |
        # | (Len3) msg         | (4) len4            | (len4) bytes4|              |           |
        # +--------------------+---------------------+--------------+--------------+-----------+
        1.banner为数据包标示
        2.byte1 byte2 byte3 byte4 按顺序填充，此处这些都可随意填充

        :param command_id: 数据包的序号，不同序号对应不同功能
        :param key: 随机int64或心跳包标志
        :param flow: 随机double（服务器回复心跳包返回来的包才有‘使用流量‘的意义）
        :param money: 随机double（服务器回复心跳包返回来的包才有‘剩余金额‘的意义）
        :param bytes1:
        :param bytes2:
        :param bytes3:
        :param bytes4:
        :return:
        """
        len1 = len(bytes1)
        len2 = len(bytes2)
        len3 = len(bytes3)
        len4 = len(bytes4)
        # '<HBQ2dI{}sI{}sI{}sI{}s'
        fmt = self.fmt.format(len1, len2, len3, len4)
        packet = bytearray(self.PACKET_FILL_BYTE * self.PACKET_LENGTH)
        struct.pack_into(
            fmt,
            packet,
            0,
            self.banner,
            command_id,
            key,
            flow,
            money,
            len1, bytes1,
            len2, bytes2,
            len3, bytes3,
            len4, bytes4,
        )
        return packet