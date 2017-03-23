# -*- coding: utf8 -*-

import datetime
import socket
import struct
from ctypes import c_ubyte, c_byte, c_uint32, c_uint64, BigEndianStructure
from io import BytesIO


class NTPv4Header(BigEndianStructure):
    """NTPv4 header"""
    _pack_ = 1
    _fields_ = [
        ('leap_indicator', c_ubyte, 2),
        ('version_number', c_ubyte, 3),
        ('mode', c_ubyte, 3),
        ('stratum', c_ubyte),
        ('poll', c_ubyte),
        ('precision', c_byte),
        ('root_delay', c_uint32),
        ('root_dispersion', c_uint32),
        ('reference_id', c_uint32),
        ('reference_timestamp', c_uint64),
        ('origin_timestamp', c_uint64),
        ('receive_timestamp', c_uint64),
        ('transmit_timestamp', c_uint64),
    ]


leap_indicators = {
    0: 'no warning',
    1: 'last minute of the day has 61 seconds',
    2: 'last minute of the day has 59 seconds',
    3: 'unknown (clock unsynchronized)',
}


modes = {
    0: 'reserved',
    1: 'symmetric active',
    2: 'symmetric passive',
    3: 'client',
    4: 'server',
    5: 'broadcast',
    6: 'NTP control message',
    7: 'reserved for private use',
}


reference_ids = {
    'GOES': 'Geosynchronous Orbit Environment Satellite',
    'GPS': 'Global Position System',
    'GAL': 'Galileo Positioning System',
    'PPS': 'Generic pulse-per-second',
    'IRIG': 'Inter-Range Instrumentation Group',
    'WWVB': 'LF Radio WWVB Ft. Collins, CO 60 kHz',
    'DCF': 'LF Radio DCF77 Mainflingen, DE 77.5 kHz',
    'HBG': 'LF Radio HBG Prangins, HB 75 kHz',
    'MSF': 'LF Radio MSF Anthorn, UK 60 kHz',
    'JJY': 'LF Radio JJY Fukushima, JP 40 kHz, Saga, JP 60 kHz',
    'LORC': 'MF Radio LORAN C station, 100 kHz',
    'TDF': 'MF Radio Allouis, FR 162 kHz',
    'CHU': 'HF Radio CHU Ottawa, Ontario',
    'WWV': 'HF Radio WWV Ft. Collins, CO',
    'WWVH': 'HF Radio WWVH Kauai, HI',
    'NIST': 'NIST telephone modem',
    'ACTS': 'NIST telephone modem',
    'USNO': 'USNO telephone modem',
    'PTB': 'European telephone modem',
}


def packet_stratum(value):
    """Get packet stratum meaning"""
    if value == 0:
        return 'unspecified or invalid'
    elif value == 1:
        return 'primary server (e.g., equipped with a GPS receiver)'
    elif 2 <= value <= 15:
        return 'secondary server (via NTP)'
    elif value == 16:
        return 'unsynchronized'
    elif 17 <= value <= 255:
        return 'reserved'
    raise Exception('Unknown packet stratum value')


def precision_to_sec(value):
    """Precision to seconds"""
    return '{:e} sec'.format(2 ** value)


def print_ntpv4_header(header):
    """Print NTPv4 header"""
    longest_name = max(len(field[0]) for field in header._fields_)
    indent_fmt = '{{:>{}s}}'.format(longest_name)
    print('{}: {} - {}'.format(
        indent_fmt.format('leap_indicator'), header.leap_indicator, leap_indicators[int(header.leap_indicator)]))
    print('{}: {}'.format(indent_fmt.format('version_number'), header.version_number))
    print('{}: {} - {}'.format(indent_fmt.format('mode'), header.mode, modes[int(header.mode)]))
    print('{}: {} - {}'.format(indent_fmt.format('stratum'), header.stratum, packet_stratum(int(header.stratum))))
    print('{}: {}'.format(indent_fmt.format('poll'), header.poll))
    print('{}: {} = {}'.format(indent_fmt.format('precision'), header.precision, precision_to_sec(header.precision)))
    print('{}: {}'.format(indent_fmt.format('root_delay'), header.root_delay))
    print('{}: {}'.format(indent_fmt.format('root_dispersion'), header.root_dispersion))
    ref_id_val = struct.pack('>I', header.reference_id).decode('ascii').strip('\x00')
    if ref_id_val in reference_ids:
        print('{}: {} - {}'.format(indent_fmt.format('reference_id'), ref_id_val, reference_ids.get(ref_id_val)))
    else:
        print('{}: {}'.format(indent_fmt.format('reference_id'), header.reference_id))
    print('{}: {}'.format(indent_fmt.format('reference_timestamp'), header.reference_timestamp))
    print('{}: {}'.format(indent_fmt.format('origin_timestamp'), header.origin_timestamp))
    print('{}: {}'.format(indent_fmt.format('receive_timestamp'), header.receive_timestamp))
    print('{}: {}'.format(indent_fmt.format('transmit_timestamp'), header.transmit_timestamp))


def main():
    host = '0.pool.ntp.org'
    host = 'ntp1.stratum1.ru'
    port = 123

    # connect to server
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(5)

    # prepare packet
    ntpv4_header = NTPv4Header()
    ntpv4_header.leap_indicator = 0
    ntpv4_header.version_number = 4
    ntpv4_header.mode = 3  # client
    # leave all other fields empty

    # get packet bytes
    ntpv4_header_bytes = BytesIO()
    ntpv4_header_bytes.write(ntpv4_header)
    ntpv4_header_bytes.seek(0)
    payload = ntpv4_header_bytes.read()

    # send payload
    s.sendto(payload, (host, port))
    response, address = s.recvfrom(256)

    # read response bytes into NTPv4 header
    bytes_obj = BytesIO(response)
    bytes_obj.readinto(ntpv4_header)

    print('=' * 80)
    print('NTPv4 header')
    print('=' * 80)

    # print NTPv4 header
    print_ntpv4_header(ntpv4_header)

    # get time
    JAN_1970 = 2208988800  # 1970 - 1900 in seconds
    secs = ((ntpv4_header.transmit_timestamp >> 32) & 0xffffffff) - JAN_1970
    print('=' * 80)
    print('NTP secs: {}'.format(secs))
    print('NTP time: {:02d}:{:02d}:{:02d} (UTC)'.format((secs % 86400) // 3600, (secs % 3600) // 60, (secs % 60)))
    print('Local date: {}'.format(datetime.datetime.fromtimestamp(secs)))
    print('=' * 80)


if __name__ == '__main__':
    main()
