# -*- coding: utf-8 -*-
from __future__ import absolute_import, division, print_function, with_statement

import struct

from .packet import Packet


class CmdPacket(Packet):
    """
    开放或关闭ip时所用到的udp包（本地udp5200端口与服务器udp5300端口通信的数据包）
    :para userid: 用户名，二进制字符串
    :para password: 用户密码，二进制字符串
    udp包的格式如下：
    # +----------------------+-----------------------+-------------------------+-----------------------+
    # | (2) banner(0x2382)   | (1) command_id        | (4) result              | (4) unused_1(const:0) |
    # | (4) len1             | (len1) bytes1/userid  | (4) len2                | (len2) bytes2/passwd  |
    # | (4) len3             | (len3) bytes3/mac     | (4) Key                 | (4) unused2(const:0)  |
    # | (4) reserved(0x3ff0) | (4) len4              | (len4) bytes4/result msg|                       |
    # +----------------------+-----------------------+-------------------------+-----------------------+
    """

    def __init__(self, userid, password, mac):
        """
        开放或关闭ip时所用到的udp包
        :param userid: 用户名，文本字符串
        :param password: 用户密码，文本字符串
        :param mac: 本机mac，文本字符串
        :return:
        """
        Packet.__init__(self)
        self.userid = self._get_bytes(userid)
        self.password = self._get_bytes(password)
        self.local_mac = self._get_bytes(mac)
        self.key = 0
        self.en_key = 0
        self.fmt = '<HB2II{}sI{}sI{}s3II{}s'
        self.result = 0
        self.unused1 = self.unused2 = 0

    # 服务器返回的result字段对应的消息
    REPLY_RESULTS = {
        0x1: 'Your ip needn\'t use IPClient.',
        0xa: 'Your account is expired.',
        0xb: 'Your account is disabled.',
        0x14: 'Your account has not enough money.',
        0x15: 'Your account has not available hours in this month.',
        0x16: 'Your account has not available flow in this mouth.',
        0x19: 'Your account cannot be used in this IP.',
        0x1e: 'Your account cannot be used in this time.',
        0x1f: 'Please dial later.',
        0x20: 'There are too many users using this account now.',
        0x21: 'IPClient cannot be used for your account.',
        0x22: 'Please dial later.',
        0x63: 'Userid or password error.'
    }

    PACKET_LENGTH = 300  # udp包的长度

    PACKET_FILL_BYTE = b'\xff'  # udp包剩余长度的buf所填充的字节

    PACKET_RANDOM_BYTES_LENGTH = 0x13  # udp包中的中随机字符串的长度

    def set_user(self, userid, password):
        """
        更新RefreshPacket实例的userid和password字段
        :param userid:
        :param password:
        :return:
        """
        self.userid = userid
        self.password = password

    def get_key(self):
        """
        在步骤6服务器回复开放成功后，需要将步骤4所获取的key传递给RefreshPacket实例，以便其构造心跳包
        :return:
        """
        return self.key

    def get_login_userid_packet(self):
        """
        3、开放过程，生成客户端需要发送的0x1f数据包，请求开放，发送用户名

        该包的command_id为0x1f，result为0，byte1为用户名（每个字节的ASCII码减0x0A），byte2是长度为0x13（19）的随机字符串,
        byte3固定为0x61，key是随机32位整数，byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会
        reserved（int32）
        """
        return self._get_packet(
            self.COMMAND_ID.LOGIN_USERID,
            0,
            self._change_bytes(self.userid, -0x0A),
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'a',
            b'b',
            self._get_a_random_interger()
        )

    def check_login_userid_reply(self, packet):
        """
        4、开放过程，解析服务器返回0x20的数据包，服务器返回加密秘钥Key
        :param packet:
        :return: bool，是否成功获取服务器返回的秘钥

        该包的command为0x20，result为0，byte1和byte2按0x1f包原样返回，byte3固定为0x61，key是服务器返回的32位整数秘钥，
        byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.LOGIN_USERID_REPLY)
        if res is True:
            self.key = self._get_key_from_reply(packet) - 3344  # 获取要加密计算的key
        return res

    def get_login_password_packet(self):
        """
        5、开放过程，生成客户端需要发送的0x21数据包，发送密码加密的密文

        该包的command为0x21，result为0，byte1是长度为0x13（19）的随机字符串，byte2是长度为0x1e（30）的由秘钥Key与用户
        密码、用户名经过两次MD5转换得到的密文摘要的前30字节，byte3是长度为0x11（17）将六字节的MAC转换为“XX-XX-XX-XX-XX-XX”
        形式的二进制字符串，key是随机32位整数，byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）
        之前将会有0和reserved（int32）
        """
        return self._get_packet(
            self.COMMAND_ID.LOGIN_PASSWORD,
            0,
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            self._get_login_encrypt_password(),
            self.local_mac,
            b'b',
            self._get_a_random_interger()
        )

    def check_login_password_reply(self, packet):
        """
        6、开放过程，解析服务器返回0x22的数据包，服务器回复是否开放成功
        :param packet:
        :return: (bool, strs)，(是否成功开放,服务器返回的一句话（文本字符串）)

        该包的command为0x22，result为开放是否成功返回码，byte1是长度为0x12（18）的字符串，作用未知，byte2是长度为
        0x1e（30）的字符串，按0x21的密文原样返回，byte3为mac字符串，按0x21原样返回，key是随机32位整数，byte4是服务
        器返回的一段话，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.LOGIN_PASSWORD_REPLY)
        if res is False:
            return False, self.MSG_INVALID_PACKET
        else:
            reply_msg = ''
            result = self._get_result_from_reply(packet)
            if result is not 0:
                res = False
                reply_msg += self.REPLY_RESULTS[result] + '\n'
            else:
                res = True
            reply_msg += self._get_str4_from_reply(packet).decode('gbk')
            return res, reply_msg

    def get_logout_userid_packet(self):
        """
        11、关闭过程，生成客户端需要发送的0x14数据包，请求关闭此IP开放状态

        该包的command为0x14，result为0，byte1为用户名（每个字节的ASCII码减0x0F），byte2是长度为0x13（19）的随机字符串，
        byte3固定为0x61，key是随机32位整数，byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会
        有0和reserved（int32）
        """
        return self._get_packet(
            self.COMMAND_ID.LOGOUT_USERID,
            0,
            self._change_bytes(self.userid, 0x0F),
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'a',
            b'b',
            self._get_a_random_interger()
        )

    def check_logout_userid_reply(self, packet):
        """
        12、关闭过程，解析服务器返回0x15的数据包，服务器返回加密秘钥Key
        :param packet:
        :return: bool，是否成功获取服务器返回的秘钥

        该包的command为0x15，result为0，byte1和byte2按0x14包原样返回，byte3固定为0x61，key是服务器返回的32位整数秘钥，
        byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.LOGOUT_USERID_REPLY)
        if res is True:
            self.en_key = self._get_key_from_reply(packet) - 0x2382  # 获取要加密计算的key
        return res

    def get_logout_password_packet(self):
        """
        13、关闭过程，客户端发送0x16数据包，发送密码加密的密文

        该包的command为0x16，result为0，byte1是长度为0x13（19）的随机字符串，byte2是长度0x06的根据秘钥Key计算出来的密文，
        byte3是长度为0x11（17）将六字节的MAC转换为“ XX-XX-XX-XX-XX-XX”形式的二进制字符串，key是和密文和密文长度有关的int32，
        byte4固定为0x62，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        return self._get_packet(
            self.COMMAND_ID.LOGOUT_PASSWORD,
            0,
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            self._flow_encrypt(self.password, self.en_key),
            self.local_mac,
            b'b',
            (self.en_key % 10000) * 2 + len(self.password)
        )

    def check_logout_password_reply(self, packet):
        """
        14、关闭过程，解析服务器返回0x17的数据包，服务器回复是否关闭成功
        :param packet:
        :return: (bool, bytestrs)，(是否成功关闭,服务器返回的一句话（文本字符串）)

        该包的command为0x17，result为0，byte1是长度为0x12（18）的字符串，原样返回0x16数据包的byte1[:-1]，byte2是长度为
        0x06的字符串，按0x16的密文原样返回，byte3为mac字符串，按0x16原样返回，key是随机32位整数，byte4是服务
        器返回的一段话，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.LOGOUT_PASSWORD_REPLY)
        if res is False:
            return False, self.MSG_INVALID_PACKET
        else:
            reply_msg = self._get_str4_from_reply(packet).decode('gbk')
            return True, reply_msg

    def get_logout_new_packet(self):
        """
        11、关闭过程，更新后的关闭方式，客户端发送0x23数据包，请求关闭ip

        该包的command为0x23，result为0，byte1是长度为0x13（19）的随机字符串，byte2也是长度为0x13（19）的随机字符串，
        byte3固定为0x61，key是随机32位整数，byte4固定为0x62，其余填充0xff。。
        每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        return self._get_packet(
            self.COMMAND_ID.LOGOUT_NEW,
            0,
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            self._get_a_random_bytes(self.PACKET_RANDOM_BYTES_LENGTH),
            b'a',
            b'b',
            self._get_a_random_interger()
        )

    def check_logout_new_reply(self, packet):
        """
        12、关闭过程，解析服务器返回0x24的数据包，服务器回复是否关闭成功
        :param packet:
        :return: (bool, bytestrs)，(是否成功关闭,服务器返回的一句话（文本字符串）)

        该包的command为0x24，result为0，byte1是长度为0x12（18）的字符串，原样返回0x23数据包的byte1[:-1]，
        byte2是长度为0x12（18）的字符串，原样返回0x23数据包的byte2[:-1]，byte3按0x23原样返回，key按0x23原样返回，byte4是服务
        器返回的一段话，其余填充0xff。。每个bytes前面会有len，byte4（len4）之前将会有0和reserved（int32）
        """
        res = self._validate_packet(packet,
                                    self.COMMAND_ID.LOGOUT_NEW_REPLY)
        if res is False:
            return False, self.MSG_INVALID_PACKET
        else:
            reply_msg = self._get_str4_from_reply(packet).decode('gbk')
            return True, reply_msg

    def _get_key_from_reply(self, packet):
        """
        从udp包中获取key的值。开放过程中获取后需要自行减去0x0d10（3344）再加密；而关闭过程中获取后则要减去0x2382（9090）再加密
        :param packet:
        :return:
        """
        offset = struct.calcsize('<HB2I')
        # 跳过byte1 byte2 byte3 后即为 key
        for i in range(3):
            _, length = self._unpack_bytes_from(packet, offset)
            offset += length
        key, = struct.unpack_from('<I', packet, offset)
        return key

    def _get_str4_from_reply(self, packet):
        """
        从udp包中获取str4的值
        :param packet:
        :return:
        """
        offset = struct.calcsize('<HB2I')
        for i in range(3):
            _, length = self._unpack_bytes_from(packet, offset)
            offset += length
        offset += struct.calcsize('<3I')
        str4, length = self._unpack_bytes_from(packet, offset)
        return str4

    def _get_result_from_reply(self, packet):
        """
        从udp包中获取result的值
        :param packet:
        :return:
        """
        result, = struct.unpack_from('<I', packet, struct.calcsize('<HB'))
        return result

    def _get_login_encrypt_password(self):
        """
        开放过程中，生成秘钥
        """
        en_pswd = self._get_bytes(str(self.key)) + self.password
        en_pswd = self._md5_bytes(en_pswd)
        en_pswd = (en_pswd[:5]).upper() + self.userid
        en_pswd = self._md5_bytes(en_pswd)
        en_pswd = (en_pswd.upper())[:30]
        return en_pswd

    def _get_packet(self, command_id, result, bytes1, bytes2, bytes3, bytes4, key):
        """
        填充udp包，udp包的格式如下：
        # +----------------------+-----------------------+-------------------------+-----------------------+
        # | (2) banner(0x2382)   | (1) command_id        | (4) result              | (4) unused1(const:0)  |
        # | (4) len1             | (len1) bytes1/userid  | (4) len2                | (len2) bytes2/passwd  |
        # | (4) len3             | (len3) bytes3/mac     | (4) Key                 | (4) unused2(const:0)  |
        # | (4) reserved(0x3ff0) | (4) len4              | (len4) bytes4/result msg|                       |
        # +----------------------+-----------------------+-------------------------+-----------------------+
        :param command_id: 命令id, 数字
        :param result:
        :param bytes1:
        :param bytes2:
        :param bytes3:
        :param bytes4:
        :param key:
        :return:
        """
        len1 = len(bytes1)
        len2 = len(bytes2)
        len3 = len(bytes3)
        len4 = len(bytes4)
        # '<HB2II{}sI{}sI{}s3II{}s'
        fmt = self.fmt.format(len1, len2, len3, len4)
        packet = bytearray(self.PACKET_FILL_BYTE * self.PACKET_LENGTH)
        struct.pack_into(
            fmt,
            packet,
            0,
            self.banner,
            command_id,
            result,
            self.unused1,
            len1, bytes1,
            len2, bytes2,
            len3, bytes3,
            key,
            self.unused2,
            self.reserved,
            len4, bytes4,
        )
        return packet

    def _flow_encrypt(self, password, key):
        """
        关闭ip时客户端计算密码与key的加密值
        :param password: 密码
        :param key: 服务器传回来的key
        :return: 加密后的二进制字符串
        """
        n = len(password)
        en_pswd = b''
        vkey = key
        for i in range(n):
            c = self._get_ord(password[i])
            temp = vkey
            temp = (temp & 0xffff) >> 8
            d = temp & 0xff
            c = d ^ c
            en_pswd += self._get_byte(c)  # 兼容python2和3
            c = self._get_ord(en_pswd[i])
            e = vkey & 0xffff
            e = (e + c) & 0xffff
            e = (e * 0xce6d) & 0xffff
            e = (e + 0x58bf) & 0xffff
            vkey = e
        return en_pswd