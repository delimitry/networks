# -*- coding: utf-8 -*-

# References:
# -----------
# https://tools.ietf.org/html/rfc2131 - Dynamic Host Configuration Protocol
# https://tools.ietf.org/html/rfc2132 - DHCP Options and BOOTP Vendor Extensions

import ctypes
import random
import socket
import struct
import sys
from io import BytesIO
from ctypes import BigEndianStructure, c_char_p, c_ubyte, c_uint16, c_uint32
from uuid import getnode

PY3 = sys.version_info[0] == 3

opcodes = {
    1: 'BOOTREQUEST',
    2: 'BOOTREPLY',
}

hw_types = {
    1: 'Ethernet',
}

dhcp_message_types = {
    1: 'DHCPDISCOVER',
    2: 'DHCPOFFER',
    3: 'DHCPREQUEST',
    4: 'DHCPDECLINE',
    5: 'DHCPACK',
    6: 'DHCPNAK',
    7: 'DHCPRELEASE',
    8: 'DHCPINFORM',
}

DHCP_BOOTREQUEST = 1

DHCP_MAGIC_COOKIE = b'\x63\x82\x53\x63'

# DHCP message type codes
DHCP_DISCOVER = 1

# DHCP option codes (tags)
DHCP_PAD_OPTION = 0
DHCP_SUBNET_MASK = 1
DHCP_ROUTER_OPTION = 3
DHCP_DOMAIN_NAME_SERVER_OPTION = 6
DHCP_IP_ADDRESS_LEASE_TIME = 51
DHCP_MESSAGE_TYPE = 53
DHCP_SERVER_IDENTIFIER = 54
DHCP_PARAMETER_REQUEST_LIST = 55
DHCP_END_OPTION = 255


class DHCPSubnetMask(BigEndianStructure):
    """DHCP Subnet Mask Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('subnet_mask', c_uint32),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] == 'subnet_mask':
                out += indent_verbose_fmt.format(k[0], value, int_to_ip(value))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPRouterOption(BigEndianStructure):
    """DHCP Router Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('address_1', c_uint32),
    ]

    def set_address_number(self, number):
        if number <= 1:
            return
        for i in range(2, number + 1):
            name = 'address_{}'.format(i)
            DHCPRouterOption._fields_.append((name, c_uint32))
            setattr(self, name, 0)

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0].startswith('address_'):
                out += indent_verbose_fmt.format(k[0], value, int_to_ip(value))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPDomainNameServerOption(BigEndianStructure):
    """DHCP Domain Name Server Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('address_1', c_uint32),
    ]

    def set_address_number(self, number):
        if number <= 1:
            return
        for i in range(2, number + 1):
            name = 'address_{}'.format(i)
            DHCPDomainNameServerOption._fields_.append((name, c_uint32))
            setattr(self, name, 0)

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0].startswith('address_'):
                out += indent_verbose_fmt.format(k[0], value, int_to_ip(value))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPIPAddressLeaseTime(BigEndianStructure):
    """DHCP IP Address Lease Time Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('lease_time', c_uint32),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] == 'lease_time':
                out += indent_verbose_fmt.format(k[0], value, hex(value).rstrip('L'))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPMessageType(BigEndianStructure):
    """DHCP Message Type Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('message_type', c_ubyte),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] == 'message_type':
                out += indent_verbose_fmt.format(k[0], value, dhcp_message_types.get(value, '?'))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPServerIdentifier(BigEndianStructure):
    """DHCP Server Identifier Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('address', c_uint32),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] == 'address':
                out += indent_verbose_fmt.format(k[0], value, int_to_ip(value))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPParameterRequestList(BigEndianStructure):
    """DHCP Parameter Request List Option"""

    _pack_ = 1
    _fields_ = [
        ('length', c_ubyte),
        ('values', c_ubyte),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        # indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            out += indent_fmt.format(k[0], value)
        return out.rstrip()


class DHCPHeader(BigEndianStructure):
    """
    DHCP header
    """
    _pack_ = 1
    _fields_ = [
        ('op', c_ubyte),
        ('htype', c_ubyte),
        ('hlen', c_ubyte),
        ('hops', c_ubyte),
        ('xid', c_uint32),
        ('secs', c_uint16),
        ('flags', c_uint16),
        ('ciaddr', c_uint32),
        ('yiaddr', c_uint32),
        ('siaddr', c_uint32),
        ('giaddr', c_uint32),
        ('chaddr', c_ubyte * 16),
        ('sname', c_ubyte * 64),
        ('file', c_ubyte * 128),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] in ('chaddr', 'sname', 'file'):
                value = ctypes.cast(value, c_char_p).value
                out += indent_fmt.format(k[0], value.hex() if PY3 else value.encode('hex'))
            elif k[0] in ('xid'):
                out += indent_verbose_fmt.format(k[0], value, hex(value).rstrip('L'))
            elif k[0] in ('flags'):
                out += indent_verbose_fmt.format(k[0], value, 'broadcast' if value & 0x8000 else hex(value))
            elif k[0] in ('op'):
                out += indent_verbose_fmt.format(k[0], value, opcodes.get(value, '?'))
            elif k[0] in ('htype'):
                out += indent_verbose_fmt.format(k[0], value, hw_types.get(value, '?'))
            elif k[0] in ('ciaddr', 'yiaddr', 'siaddr', 'giaddr'):
                out += indent_verbose_fmt.format(k[0], value, int_to_ip(value))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


def ip_to_int(ip):
    """Encode IP address string as integer"""
    return struct.unpack('!I', socket.inet_aton(ip))[0]


def int_to_ip(value):
    """Decode integer to IP address string"""
    return socket.inet_ntoa(struct.pack('!I', value))


def set_bytes(obj, value):
    """Convert string value to ctypes byte array for attribute"""
    value = value.encode('latin') if PY3 else value
    return (ctypes.c_ubyte * len(obj)).from_buffer_copy(value.ljust(len(obj), b'\x00'))


def parse_dhcp_options(stream):
    """Parse and print DHCP options from stream"""
    magic_cookie = stream.read(4)
    if magic_cookie != DHCP_MAGIC_COOKIE:
        print('DHCP Magic cookie is not found!')
        return
    print('=====================================================')
    print('DHCP options')
    print('=====================================================')
    while True:
        byte = stream.read(1)
        if not byte:
            break
        option_code = ord(byte)
        print('option_code = {0} (0x{0:02X})'.format(option_code))
        if option_code == DHCP_PAD_OPTION:
            print('=====================================================')
            print('DHCP Pad Option')
            print('=====================================================')
            print('')
        elif option_code == DHCP_SUBNET_MASK:
            print('=====================================================')
            print('DHCP Subnet Mask:')
            print('=====================================================')
            dhcp_subnet_mask = DHCPSubnetMask()
            stream.readinto(dhcp_subnet_mask)
            print(dhcp_subnet_mask)
        elif option_code == DHCP_ROUTER_OPTION:
            print('=====================================================')
            print('DHCP Router Option:')
            print('=====================================================')
            offset = stream.tell()
            length = ord(stream.read(1))
            assert length % 4 == 0, 'length must always be a multiple of 4'
            stream.seek(offset)
            dhcp_router_option = DHCPRouterOption()
            dhcp_router_option.set_address_number(length // 4)
            stream.readinto(dhcp_router_option)
            print(dhcp_router_option)
        elif option_code == DHCP_DOMAIN_NAME_SERVER_OPTION:
            print('=====================================================')
            print('DHCP Domain Name Server Option:')
            print('=====================================================')
            offset = stream.tell()
            length = ord(stream.read(1))
            assert length % 4 == 0, 'length must always be a multiple of 4'
            stream.seek(offset)
            dhcp_domain_name_server_option = DHCPRouterOption()
            dhcp_domain_name_server_option.set_address_number(length // 4)
            stream.readinto(dhcp_domain_name_server_option)
            print(dhcp_domain_name_server_option)
        elif option_code == DHCP_IP_ADDRESS_LEASE_TIME:
            print('=====================================================')
            print('DHCP IP Address Lease Time:')
            print('=====================================================')
            dhcp_ip_address_lease_time = DHCPIPAddressLeaseTime()
            stream.readinto(dhcp_ip_address_lease_time)
            print(dhcp_ip_address_lease_time)
        elif option_code == DHCP_MESSAGE_TYPE:
            print('=====================================================')
            print('DHCP Message Type:')
            print('=====================================================')
            dhcp_message_type = DHCPMessageType()
            stream.readinto(dhcp_message_type)
            print(dhcp_message_type)
        elif option_code == DHCP_SERVER_IDENTIFIER:
            print('=====================================================')
            print('DHCP Server Identifier:')
            print('=====================================================')
            dhcp_server_identifier = DHCPServerIdentifier()
            stream.readinto(dhcp_server_identifier)
            print(dhcp_server_identifier)
        elif option_code == DHCP_PARAMETER_REQUEST_LIST:
            print('=====================================================')
            print('DHCP Parameter Request List:')
            print('=====================================================')
            dhcp_parameter_request_list = DHCPParameterRequestList()
            stream.readinto(dhcp_parameter_request_list)
            print(dhcp_parameter_request_list)
        elif option_code == DHCP_END_OPTION:
            print('=====================================================')
            print('DHCP End Option')
            print('=====================================================')
            print('')
            return
        print('-----------------------------------------------------')


def main():
    mac_bytes = [((getnode() >> 8 * i) & 0xff) for i in range(5, -1, -1)]

    dhcp_header = DHCPHeader()
    dhcp_header.op = DHCP_BOOTREQUEST
    dhcp_header.htype = 1  # Ethernet
    dhcp_header.hlen = 6  # 6 for Ethernet
    dhcp_header.hops = 0
    dhcp_header.xid = random.randint(0, 0xffffffff)
    dhcp_header.secs = 0
    dhcp_header.flags = 0x8000  # first bit = 1 (broadcast), all other bits = 0
    dhcp_header.ciaddr = ip_to_int('0.0.0.0')  # client IP
    dhcp_header.yiaddr = ip_to_int('0.0.0.0')  # your (client) IP
    dhcp_header.siaddr = ip_to_int('0.0.0.0')  # next server IP
    dhcp_header.giaddr = ip_to_int('0.0.0.0')  # relay agent IP
    dhcp_header.chaddr = set_bytes(dhcp_header.chaddr, ''.join(map(chr, mac_bytes)))  # client HW address (MAC)
    dhcp_header.sname = set_bytes(dhcp_header.sname, '')  # server host name
    dhcp_header.file = set_bytes(dhcp_header.file, '')  # boot file name
    print(dhcp_header)

    # prepare DHCP header payload
    dhcp_header_bytes = BytesIO()
    dhcp_header_bytes.write(dhcp_header)
    dhcp_header_bytes.seek(0)
    dhcp_header_payload = dhcp_header_bytes.read()

    # prepare DHCP options payload
    dhcp_options_payload = DHCP_MAGIC_COOKIE

    # DHCP Message
    # code = 53 (DHCP_MESSAGE_TYPE)
    # len = 1
    # type = 1 (DHCP_DISCOVER)
    dhcp_options_payload += struct.pack('BBB', DHCP_MESSAGE_TYPE, 1, DHCP_DISCOVER)

    # Parameter Request List
    # code = 55 (DHCP_PARAMETER_REQUEST_LIST)
    # len = 1
    # option codes = 1 (DHCP_SUBNET_MASK)
    dhcp_options_payload += struct.pack('BBB', DHCP_PARAMETER_REQUEST_LIST, 1, DHCP_SUBNET_MASK)

    # End Option
    dhcp_options_payload += struct.pack('B', DHCP_END_OPTION)

    # write to bytes
    dhcp_options_bytes = BytesIO()
    dhcp_options_bytes.write(dhcp_options_payload)
    dhcp_options_bytes.seek(0)

    # parse and print DHCP options
    parse_dhcp_options(dhcp_options_bytes)

    full_payload = dhcp_header_payload + dhcp_options_payload
    print('request: {}'.format(full_payload.hex() if PY3 else full_payload.encode('hex')))

    # create socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.settimeout(3)
    try:
        s.bind(('', 68))
    except (OSError, socket.error):
        print('Unable to bind to port 68')
        s.close()
        return

    # send DHCP payload
    s.sendto(full_payload, ('<broadcast>', 67))

    response = ''
    try:
        response = s.recv(4096)
    except (OSError, socket.error) as ex:
        print(ex)
        return
    finally:
        s.close()

    print('response: {}'.format(response.hex() if PY3 else response.encode('hex')))

    # read DHCP header
    response_bytes = BytesIO(response)
    dhcp_response_header = DHCPHeader()
    response_bytes.readinto(dhcp_response_header)

    print('=====================================================')
    print('DHCP header')
    print('=====================================================')
    print(dhcp_response_header)

    # parse and print DHCP options
    parse_dhcp_options(response_bytes)


if __name__ == '__main__':
    main()
