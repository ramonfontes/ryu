# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""
radius packet parser/serializer
"""

import struct

from ryu.lib import stringify
from ryu.lib import type_desc
from . import packet_base
from . import ether_types


UDP_DST_PORT = 1812
mac = []
mac_ = []
name = []
name_ = []
rule = []
rule1 = {}

class radius(packet_base.PacketBase):

    _HEADER_FMT = "!BBHI"
    _MIN_LEN = struct.calcsize(_HEADER_FMT)

    # 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Code | Identifier | Length |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | |
    # | Authenticator |
    # | |
    # | |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # | Attributes...
    # +-+-+-+-+-+-+-+-+-+-+-+-+-

    ACCESS_REQUEST = 1
    ACCESS_ACCEPT = 2
    ACCESS_REJECT = 3
    ACCOUNTING_REQUEST = 4
    ACCOUNTING_RESPONSE = 5
    ACCESS_CHALLENGE = 11
    STATUS_SERVER = 12
    STATUS_CLIENT = 13
    RESERVED = 255

    USER_NAME_TYPE = 1
    USER_PASSWORD_TYPE = 2
    CHAP_PASSWORD_TYPE = 3
    NAS_IP_ADDRESS_TYPE = 4
    NAS_PORT_TYPE = 5
    SERVICE_TYPE_TYPE = 6
    FRAMED_PROTOCOL_TYPE = 7
    FRAMED_IP_ADDRESS_TYPE = 8
    FRAMED_IP_NETMASK_TYPE = 9
    FRAMED_ROUTING_TYPE = 10
    CALLED_STATION_ID = 30
    CALLING_STATION_ID = 31

    code_names = {ACCESS_REQUEST: "request",
                  ACCESS_ACCEPT: "accept",
                  ACCESS_REJECT: "reject",
                  ACCOUNTING_REQUEST: "acreq",
                  ACCOUNTING_RESPONSE: "acresp",
                  ACCESS_CHALLENGE: "challenge",
                  STATUS_SERVER: "statusserver",
                  STATUS_CLIENT: "statusclient",
                  RESERVED: "reserved"
                  }

    type_names = {USER_NAME_TYPE: "username",
                  USER_PASSWORD_TYPE: "userpasswd",
                  CHAP_PASSWORD_TYPE: "chappasswd",
                  NAS_IP_ADDRESS_TYPE: "nasipaddr",
                  NAS_PORT_TYPE: "nasport",
                  SERVICE_TYPE_TYPE: "tos",
                  FRAMED_PROTOCOL_TYPE: "frameproto",
                  FRAMED_IP_ADDRESS_TYPE: "frameipaddr",
                  FRAMED_IP_NETMASK_TYPE: "frameipnetmask",
                  FRAMED_ROUTING_TYPE: "framerouting",
                  CALLED_STATION_ID: "calledstationid",
                  CALLING_STATION_ID: "callingstationid"
                  }

    def __init__(self, version=0, opt_len=0, flags=0,
                 protocol=ether_types.ETH_TYPE_TEB, vni=None, options=None):
        super(radius, self).__init__()

        self.version = version
        self.opt_len = opt_len
        #assert (flags & 0x3F) == 0
        self.flags = flags
        self.protocol = protocol
        self.vni = vni
        for o in options:
            assert isinstance(o, Option)
        self.options = options

    @classmethod
    def parser(cls, buf):
        (ver_opt_len, flags, protocol,
         vni) = struct.unpack_from(cls._HEADER_FMT, buf)
        version = ver_opt_len >> 6
        # The Opt Len field expressed in four byte multiples.
        opt_len = (ver_opt_len & 0x3F) * 4
        opt_bin = buf[cls._MIN_LEN:cls._MIN_LEN + opt_len]
        options = []
        (code, id, length) \
            = struct.unpack('!BBH', buf[:4])

        if code == radius.ACCESS_REQUEST:
            (type,) \
                = struct.unpack('!B', buf[20:21])
        elif code == radius.ACCESS_ACCEPT:
            (type,) \
                = struct.unpack('!B', buf[20:21])

        mac1 = ''
        i = 0
        for pack in buf:
            (n_type,) = struct.unpack('!B', pack)
            i += 1
            if radius.CALLING_STATION_ID == n_type:
                mac1 = str(buf[i + 1:i + 18])
                if mac1 not in mac and '-0' in mac1:
                    mac.append(mac1)
                    mac_.append(mac1)
                    break

        nam_ = str(buf[22:25])

        if len(mac_) >= 1 and mac1 not in rule1 \
                and nam_ != '' and mac1 != '' and '-0' in mac1:
            name.append(str(nam_))
            name_.append(nam_)
            rule1[mac1] = nam_

        while opt_bin:
            option, opt_bin = Option.parser(opt_bin)
            options.append(option)

        msg = cls(version, opt_len, flags, protocol, vni >> 8, options)

        from . import ethernet
        radius._TYPES = ethernet.ethernet._TYPES
        radius.register_packet_type(ethernet.ethernet,
                                    ether_types.ETH_TYPE_TEB)

        return (msg, radius.get_packet_type(protocol),
                buf[cls._MIN_LEN + opt_len:])

    def serialize(self, payload=None, prev=None):
        tunnel_options = bytearray()
        for o in self.options:
            tunnel_options += o.serialize()
        self.opt_len = len(tunnel_options)
        # The Opt Len field expressed in four byte multiples.
        opt_len = self.opt_len // 4

        return (struct.pack(self._HEADER_FMT,
                            (self.version << 6) | opt_len,
                            self.flags, self.protocol, self.vni << 8)
                + tunnel_options)


class Option(stringify.StringifyMixin, type_desc.TypeDisp):
    """
    Tunnel Options
    """
    _OPTION_PACK_STR = "!BBH"
    _OPTION_LEN = struct.calcsize(_OPTION_PACK_STR)

    #  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |          Option Class         |      Type     |R|R|R| Length  |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    # |                      Variable Option Data                     |
    # +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
    def __init__(self, option_class=None, type_=None, length=0):
        super(Option, self).__init__()
        if option_class is None or type_ is None:
            (option_class, type_) = self._rev_lookup_type(self.__class__)
        self.option_class = option_class
        self.type = type_
        self.length = length

    @classmethod
    def parse_value(cls, buf):
        # Sub-classes should override this method, if needed.
        return {}

    def serialize_value(self):
        # Sub-classes should override this method, if needed.
        return b''

    @classmethod
    def parser(cls, buf):
        (option_class, type_,
         length) = struct.unpack_from(cls._OPTION_PACK_STR, buf[:radius._MIN_LEN/5])
        # The Length field expressed in four byte multiples.
        length *= 4
        subcls = Option._lookup_type((option_class, type_))
        print(option_class)


        return (
            subcls(option_class=option_class, type_=type_, length=length,
                   **subcls.parse_value(
                       buf[cls._OPTION_LEN:cls._OPTION_LEN + length])),
            buf[cls._OPTION_LEN + length:])

    def serialize(self, _payload=None, _prev=None):
        data = self.serialize_value()
        self.length = len(data)
        # The Length field expressed in four byte multiples.
        length = self.length // 4

        return (struct.pack(self._OPTION_PACK_STR, int(self.option_class),
                            self.type, length) + data)


@Option.register_unknown_type()
class OptionDataUnknown(Option):
    """
    Unknown Option Class and Type specific Option
    """
    def __init__(self, buf, option_class=None, type_=None, length=0):
        super(OptionDataUnknown, self).__init__(option_class=option_class,
                                                type_=type_,
                                                length=length)
        self.buf = buf

    @classmethod
    def parse_value(cls, buf):
        return {"buf": buf}

    def serialize_value(self):
        return self.buf
