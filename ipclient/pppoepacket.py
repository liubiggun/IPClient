# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

import struct
from ctypes import c_int32

from .packet import Packet


class PPPOEPacket(Packet):
    """
    获取外网pppoe拨号权限时所用到的udp包

    1.获取拨号权限的udp包的格式如下：
    # +----------------------+-----------------------+-------------------------+-----------------------+
    # | (30) 0x00            | (4) ip                | (17) mac                | (3) 0x00              |
    # | (2) isp flag         | (4) checksum          |                         |                       |
    # +----------------------+-----------------------+-------------------------+-----------------------+
     1 至 30 字节:  固定为0x00
    31 至 34 字节:  本机IP字符串(4B)（服务器识别到的校园网ip）
    35 至 51 字节： MAC地址字符串，如 '48:52:72:9C:05:7C'
    52 至 54 字节： 补3个0x00
    55 至 56 字节： ISP类型(int16，小端)，1为联通、2为电信、3为移动
    57 到 60 字节： 校验和

    2.每30s发送的心跳包在'isp'之前的数据都一致，而isp+0x0200（int16，小端）
    3.退出登录的udp包在'isp'之前的数据都一致，但是isp+0x0100（int16，小端）
    """

    def __init__(self):
        Packet.__init__(self)

    TIME_REFRESH_ONLINE_INTERVAL = 30

    PACKET_LENGTH = 60  # udp包的长度

    PACKET_FILL_BYTE = b'\x00'  # udp所填充的字节

    def checksum(self, data):
        """
        计算校验和
        :param data:
        :return:
        """
        checksum = c_int32(0x4e67c6a7)
        for d in data:
            dv = self._get_ord(d)  # 兼容python2和3
            if checksum.value > 0:
                checksum.value ^= (checksum.value >> 2) + (checksum.value << 5) + dv
            else:
                checksum.value ^= ((checksum.value >> 2) | 0xC0000000) + (checksum.value << 5) + dv

        checksum.value &= 0x7fffffff
        return struct.pack('<i', checksum.value)  # 57~60

    def get_getperm_packet(self, ip, mac, isp):
        """
        返回获取外网pppoe登录权限的udp包
        :param ip: 本机IP字符串，文本字符串（服务器识别到的校园网ip）
        :param mac: 本机MAC字符串，文本字符串
        :param isp: ISP类型，1为联通、2为电信、3为移动，整数
        :return:
        """
        ip = list(map(int, ip.split('.')))  # [172, 19, 56, 66]
        mac = self._get_bytes(mac)
        isp = isp
        return self._get_packet(ip, mac, isp, 0, True)

    def get_keepperm_packet(self, ip, mac, isp):
        """
        返回维持pppoe登录权限的udp心跳包
        :param ip: 本机IP字符串，文本字符串（服务器识别到的校园网ip）
        :param mac: 本机MAC字符串，文本字符串
        :param isp: ISP类型，1为联通、2为电信、3为移动，整数
        :return:
        """
        ip = list(map(int, ip.split('.')))  # [172, 19, 56, 66]
        mac = self._get_bytes(mac)
        isp = isp
        return self._get_packet(ip, mac, isp, 2, True)

    def get_releaseperm_packet(self, ip, mac, isp):
        """
        返回释放pppoe登录权限的udp心跳包
        :param ip: 本机IP字符串，文本字符串（服务器识别到的校园网ip）
        :param mac: 本机MAC字符串，文本字符串
        :param isp: ISP类型，1为联通、2为电信、3为移动，整数
        :return:
        """
        ip = list(map(int, ip.split('.')))  # [172, 19, 56, 66]
        mac = self._get_bytes(mac)
        isp = isp
        return self._get_packet(ip, mac, isp, 1, True)

    def _get_packet(self, ip, mac, isp, ptype=0, haschecksum=True):
        """
        构造udp包
        # +----------------------+-----------------------+-------------------------+-----------------------+
        # | (30) 0x00            | (4) ip                | (17) mac                | (3) 0x00              |
        # | (2) isp flag         | (4) checksum          |                         |                       |
        # +----------------------+-----------------------+-------------------------+-----------------------+
         1 至 30 字节:  固定为0x00
        31 至 34 字节:  本机IP字符串(4B)
        35 至 51 字节： MAC地址字符串，如 '48:52:72:9C:05:7C'
        52 至 54 字节： 补3个0x00
        55 至 56 字节： ISP类型(int16，小端)，1为联通、2为电信、3为移动
        57 到 60 字节： 校验和

        :param ip: 本机IP字符串，文本字符串
        :param mac: 本机MAC字符串，文本字符串
        :param isp: ISP类型，1为联通、2为电信、3为移动，整数
        :param ptype: 0 为 获取外网pppoe登录权限的udp包；1 为 释放pppoe登录权限的udp包；2 为 维持pppoe登录权限的udp心跳包
        :param haschecksum:
        :return:
        """
        packet = bytearray(self.PACKET_FILL_BYTE * (self.PACKET_LENGTH - 4))  # 生成指定长度的buf
        struct.pack_into(
            '4B17s',
            packet,
            30,
            ip[0], ip[1], ip[2], ip[3],
            mac,
        )
        if ptype == 1:
            isp += 0x0100
        elif ptype == 2:
            isp += 0x0200
        struct.pack_into(
            '<H',
            packet,
            struct.calcsize('30B4B17s3B'),
            isp
        )

        if haschecksum:
            packet.extend(self.checksum(packet))
        return packet
