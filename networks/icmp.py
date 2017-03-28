# -*- coding: utf8 -*-

# References:
# -----------
# https://tools.ietf.org/html/rfc791 - Internet Protocol
# https://tools.ietf.org/html/rfc792 - Internet Control Message Protocol (ICMP)

import random
import socket
import struct
import sys
import time
from io import BytesIO
from ctypes import BigEndianStructure, c_ubyte, c_uint16, c_uint32

PY3 = sys.version_info[0] == 3
if PY3:
    from io import StringIO
else:
    from StringIO import StringIO


protocols = {
    1: 'ICMP',
}

icmp_types = {
    0: 'Echo (ping) reply',
    8: 'Echo (ping) request',
}


class IPv4Header(BigEndianStructure):
    """
    IPv4 header
    """
    _pack_ = 1
    _fields_ = [
        ('version', c_ubyte, 4),
        ('ihl', c_ubyte, 4),
        ('dscp', c_ubyte, 6),
        ('ecn', c_ubyte, 2),
        ('total_length', c_uint16),
        ('identification', c_uint16),
        ('flags', c_uint16, 3),
        ('fragment_offset', c_uint16, 13),
        ('ttl', c_ubyte),
        ('protocol', c_ubyte),
        ('header_checksum', c_uint16),
        ('source_ip', c_uint32),
        ('destination_ip', c_uint32),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] in ('source_ip', 'destination_ip'):
                out += indent_fmt.format(k[0], int_to_ip(value))
            elif k[0] in ('identification', 'header_checksum'):
                out += indent_verbose_fmt.format(k[0], value, hex(value))
            elif k[0] in ('protocol'):
                out += indent_verbose_fmt.format(k[0], value, protocols.get(value, '?'))
            else:
                out += indent_fmt.format(k[0], getattr(self, k[0]))
        return out.rstrip()


class ICMPEchoHeader(BigEndianStructure):
    """
    ICMP Echo header
    """
    _pack_ = 1
    _fields_ = [
        ('type', c_ubyte),
        ('code', c_ubyte),
        ('checksum', c_uint16),
        ('identifier', c_uint16),
        ('sequence_number', c_uint16),
    ]

    def __str__(self):
        longest_name = max([len(k[0]) for k in self._fields_])
        indent_fmt = '{{:>{}s}}: {{}}\n'.format(longest_name)
        indent_verbose_fmt = '{{:>{}s}}: {{}} ({{}})\n'.format(longest_name)
        out = ''
        for k in self._fields_:
            value = getattr(self, k[0])
            if k[0] in ('identifier', 'checksum'):
                out += indent_verbose_fmt.format(k[0], value, hex(value))
            elif k[0] in ('type'):
                out += indent_verbose_fmt.format(k[0], value, icmp_types.get(value, '?'))
            else:
                out += indent_fmt.format(k[0], value)
        return out.rstrip()


def ip_to_int(ip):
    """Encode IP address string as integer"""
    return struct.unpack('!I', socket.inet_aton(ip))[0]


def int_to_ip(value):
    """Decode integer to IP address string"""
    return socket.inet_ntoa(struct.pack('!I', value))


def print_hex(data):
    """Print data in hex format"""
    out = ''
    for i, x in enumerate(data):
        if i and i % 16 == 0:
            out += '\n'
        out += '%02x ' % ord(x)
    print(out)


def icmp_checksum(message):
    """Compute ICMP message checksum"""
    res = 0
    for value in message:
        res += value
        res = (res & 0xffff) + (res >> 16)
    return ~res & 0xffff


def make_ping_request():
    """Make ping request"""
    type_value = 8  # echo (ping) request
    code_value = 0
    checksum_value = 0
    id_value = random.randint(0, 0xffff)
    seq_num_value = 1
    data = struct.pack('>BBHHI', type_value, code_value, checksum_value, id_value, seq_num_value)
    str_buffer = StringIO(data.decode('latin') if PY3 else data)
    # update checksum
    chunks_16bits = []
    while True:
        value = str_buffer.read(2)
        if not value:
            break
        chunks_16bits.append(struct.unpack('H', value.encode('latin') if PY3 else value)[0])
    checksum_value = icmp_checksum(chunks_16bits)
    lst_data = list(data)
    if lst_data:
        lst_data[2:4] = struct.pack('H', checksum_value)
    return bytes(lst_data) if PY3 else ''.join(lst_data)


def ping(addr):
    """Send echo request (ping) to addr and get reply"""
    dest = ''
    try:
        dest = socket.gethostbyname(addr)
    except socket.gaierror:
        print('unknown host: {}'.format(addr))
        return

    print('PING {} ({})'.format(addr, dest))
    icmp_header = make_ping_request()

    # prepare payload
    icmp_header_bytes = BytesIO()
    icmp_header_bytes.write(icmp_header)
    icmp_header_bytes.seek(0)

    full_payload = icmp_header_bytes.read()
    print('request: {}'.format(full_payload.hex() if PY3 else full_payload.encode('hex')))

    response = ''
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.getprotobyname('icmp'))
        s.settimeout(1)
        start_time = time.time()
        s.sendto(full_payload, (dest, 0))
        response, _ = s.recvfrom(256)
        end_time = time.time()
    except Exception as ex:
        print(ex)
        return
    if not response:
        return
    print('response: {}'.format(response.hex() if PY3 else response.encode('hex')))
    print('time = {:.2f} ms'.format((end_time - start_time) * 1000))

    # read IPv4 header
    response_bytes = BytesIO(response)
    ipv4_header = IPv4Header()
    response_bytes.readinto(ipv4_header)

    # read ICMP header
    icmp_echo_header = ICMPEchoHeader()
    response_bytes.readinto(icmp_echo_header)

    print('=====================================================')
    print('IPv4 header')
    print('=====================================================')
    print(ipv4_header)

    print('=====================================================')
    print('ICMP Echo header')
    print('=====================================================')
    print(icmp_echo_header)


def main():
    address = 'www.google.com'
    ping(address)


if __name__ == '__main__':
    main()
