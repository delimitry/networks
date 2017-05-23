# -*- coding: utf-8 -*-

# References:
# -----------
# https://tools.ietf.org/html/rfc1157 - A Simple Network Management Protocol (SNMP)
# https://tools.ietf.org/html/rfc1441 - Introduction to SNMPv2
# https://tools.ietf.org/html/rfc1592 - SNMP Distributed Protocol Interface Version 2.0
# https://tools.ietf.org/html/rfc2578 - Structure of Management Information Version 2 (SMIv2)

from __future__ import print_function

import argparse
import socket
import string
import struct
import sys
try:
    from StringIO import StringIO
except ImportError:
    from io import StringIO

PY3 = sys.version_info[0] == 3
string_types = str if PY3 else basestring

DEBUG = False

# ASN.1 tags
ASN1_BOOLEAN = 0x01
ASN1_INTEGER = 0x02
ASN1_OCTET_STRING = 0x04
ASN1_NULL = 0x05
ASN1_OBJECT_IDENTIFIER = 0x06
ASN1_PRINTABLE_STRING = 0x13
ASN1_SEQUENCE = 0x30
ASN1_IPADDRESS = 0x40
ASN1_COUNTER32 = 0x41
ASN1_GAUGE32 = 0x42
ASN1_TIMETICKS = 0x43
ASN1_OPAQUE = 0x44
ASN1_COUNTER64 = 0x46
ASN1_NO_SUCH_OBJECT = 0x80
ASN1_NO_SUCH_INSTANCE = 0x81
ASN1_END_OF_MIB_VIEW = 0x82
ASN1_GET_REQUEST_PDU = 0xA0
ASN1_GET_NEXT_REQUEST_PDU = 0xA1
ASN1_GET_RESPONSE_PDU = 0xA2

# some ASN.1 opaque special types
ASN1_CONTEXT = 0x80
ASN1_EXTENSION_ID = 0x1F
ASN1_OPAQUE_TAG1 = ASN1_CONTEXT | ASN1_EXTENSION_ID
ASN1_OPAQUE_TAG2 = 0x30
ASN1_APPLICATION = 0x40
ASN1_APP_FLOAT = ASN1_APPLICATION | 8
ASN1_APP_DOUBLE = ASN1_APPLICATION | 9
ASN1_OPAQUE_FLOAT = ASN1_OPAQUE_TAG2 + ASN1_APP_FLOAT
ASN1_OPAQUE_DOUBLE = ASN1_OPAQUE_TAG2 + ASN1_APP_DOUBLE
ASN1_OPAQUE_FLOAT_BER_LEN = 7
ASN1_OPAQUE_DOUBLE_BER_LEN = 11


# SNMP versions
snmp_versions = {
    '1': 1,
    '2': 2,
    '2c': 2,
    '3': 3,
    'v1': 1,
    'v2': 2,
    'v2c': 2,
    'v3': 3,
}


def log(*args):
    """Print with debug"""
    if DEBUG:
        print(*args)


def encode_to_7bit(value):
    """Encode to 7 bit"""
    if value > 0x7f:
        res = []
        res.insert(0, value & 0x7f)
        while value > 0x7f:
            value >>= 7
            res.insert(0, (value & 0x7f) | 0x80)
        return res
    return [value]


def oid_to_bytes(oid):
    """Convert OID str to bytes"""
    if oid.startswith('iso'):
        oid = oid.replace('iso', '1')
    try:
        oid_values = [int(x) for x in oid.split('.') if x]
        first_val = 40 * oid_values[0] + oid_values[1]
    except (ValueError, IndexError):
        raise Exception('Could not parse OID value "{}"'.format(oid))
    result_values = [first_val]
    for x in oid_values[2:]:
        result_values += encode_to_7bit(x)
    return result_values


def bytes_to_oid(data):
    """Convert bytes to OID str"""
    values = [ord(x) for x in data]
    first_val = values.pop(0)
    res = []
    res += divmod(first_val, 40)
    while values:
        x = values.pop(0)
        if x > 0x7f:
            huges = []
            huges.append(x)
            while True:
                y = values.pop(0)
                huges.append(y)
                if y < 0x80:
                    break
            huge = 0
            for i, v in enumerate(huges):
                huge += (v & 0x7f) << (7 * (len(huges) - i - 1))
            res.append(huge)
        else:
            res.append(x)
    return '.'.join(str(x) for x in res)


def timeticks_to_str(ticks):
    """Return "days, hours, minutes, seconds and ms" string from ticks"""
    days, rem1 = divmod(ticks, 24 * 60 * 60 * 100)
    hours, rem2 = divmod(rem1, 60 * 60 * 100)
    minutes, rem3 = divmod(rem2, 60 * 100)
    seconds, ms = divmod(rem3, 100)
    ending = 's' if days > 1 else ''
    days_fmt = '{} day{}, '.format(days, ending) if days > 0 else ''
    return '{}{:-02}:{:-02}:{:-02}.{:-02}'.format(days_fmt, hours, minutes, seconds, ms)


def int_to_ip(value):
    """Int to IP"""
    return socket.inet_ntoa(struct.pack("!I", value))


def make_snmp_get_oid_request(oid, version=1, community='public', get_type=ASN1_GET_REQUEST_PDU):
    """Create ASN.1 SNMP GET OID request payload"""
    if version and isinstance(version, string_types):
        if version.isdigit():
            version = int(version)
        else:
            version = snmp_versions.get(version, -1)
    if not (1 <= version <= 3):
        keys = sorted(snmp_versions.keys())
        raise Exception('Please pass a valid SNMP version [{}] or [{}]'.format(
            ', '.join(keys), ', '.join(str(snmp_versions[k]) for k in keys)
        ))

    # TODO: version 3
    if version == 3:
        raise Exception('TODO: add SNMP v3')

    # SNMP version: (ASN1 integer, length = 1, value = version - 1)
    # ASN1 octet string, length of community name
    # community name (string)
    message = b''
    message += struct.pack('BBB', ASN1_INTEGER, 1, version - 1)
    message += struct.pack('BB', ASN1_OCTET_STRING, len(community))
    message += community.encode('latin') if PY3 else community

    # SNMP request ID: (ASN1 integer, length = 1, ID = 1)
    # SNMP error status: (ASN1 integer, length = 1, error = 0)
    # SNMP index: (ASN1 integer, length = 1, index = 0)
    get_req_pdu = b''
    get_req_pdu += struct.pack('BBB', ASN1_INTEGER, 1, 1)
    get_req_pdu += struct.pack('BBB', ASN1_INTEGER, 1, 0)
    get_req_pdu += struct.pack('BBB', ASN1_INTEGER, 1, 0)

    # ASN1 object identifier, OID length
    # OID value
    # ASN1 NULL, length = 0
    varbind = b''
    oid_value = ''.join(map(chr, oid_to_bytes(oid)))
    varbind += struct.pack('BB', ASN1_OBJECT_IDENTIFIER, len(oid_value))
    varbind += oid_value.encode('latin') if PY3 else oid_value
    varbind += struct.pack('BB', ASN1_NULL, 0)

    varbind_length = len(varbind)
    varbind_list_length = varbind_length + 2  # 2 bytes (Type and Length)
    get_req_pdu_length = len(get_req_pdu) + varbind_list_length + 2  # 2 bytes (Type and Length)

    if get_type == ASN1_GET_NEXT_REQUEST_PDU:
        # SNMP Get next request: (ASN1 GetNextRequest-PDU, length)
        message += struct.pack('BB', ASN1_GET_NEXT_REQUEST_PDU, get_req_pdu_length)
    else:
        # SNMP Get request: (ASN1 GetRequest-PDU, length)
        message += struct.pack('BB', ASN1_GET_REQUEST_PDU, get_req_pdu_length)
    # GetRequest-PDU value
    message += get_req_pdu

    # ASN1 sequence, varbind list length
    # ASN1 sequence, varbind length
    message += struct.pack('BB', ASN1_SEQUENCE, varbind_list_length)
    message += struct.pack('BB', ASN1_SEQUENCE, varbind_length)
    message += varbind

    # ASN1 sequence, SNMP message length, SNMP message
    length = len(message)
    result = struct.pack('BB', ASN1_SEQUENCE, length) + message
    return result


def make_snmp_get_next_oid_request(oid, version=1, community='public'):
    return make_snmp_get_oid_request(oid, version=version, community=community, get_type=ASN1_GET_NEXT_REQUEST_PDU)


def twos_complement(value, bits):
    """Calculate two's complement"""
    mask = 2 ** (bits - 1)
    return -(value & mask) + (value & ~mask)


def _read_byte(stream):
    """Read byte from stream"""
    b = stream.read(1)
    if not b:
        raise Exception('No more bytes!')
    return ord(b)


def _read_int_len(stream, length, signed=False):
    """Read int with length"""
    result = 0
    sign = None
    for _ in range(length):
        value = _read_byte(stream)
        if sign is None:
            sign = value & 0x80
        result = (result << 8) + value
    if signed and sign:
        result = twos_complement(result, 8 ** length)
    return result


def _parse_asn1_length(stream):
    """Parse ASN.1 length"""
    length = _read_byte(stream)
    # handle long length
    if length > 0x7f:
        data_length = length - 0x80
        if not (0 < data_length <= 4):
            raise Exception('Data length must be in [1..4]')
        length = _read_int_len(stream, data_length)
    return length


def _parse_asn1_octet_string(stream):
    """Parse ASN.1 octet string"""
    length = _parse_asn1_length(stream)
    value = stream.read(length)
    # if any char is not printable - convert string to hex
    if any([c not in string.printable for c in value]):
        return ' '.join(['%02X' % ord(x) for x in value])
    return value


def _parse_asn1_opaque_float(stream):
    """Parse ASN.1 opaque float"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length)
    # convert int to float
    float_value = struct.unpack('>f', struct.pack('>l', value))[0]
    log('ASN1_OPAQUE_FLOAT', round(float_value, 5))
    return 'FLOAT', round(float_value, 5)


def _parse_asn1_opaque_double(stream):
    """Parse ASN.1 opaque double"""
    length = _parse_asn1_length(stream)
    value = _read_int_len(stream, length)
    # convert long long to double
    double_value = struct.unpack('>d', struct.pack('>q', value))[0]
    log('ASN1_OPAQUE_DOUBLE', round(double_value, 5))
    return 'DOUBLE', round(double_value, 5)


def _parse_asn1_opaque(stream):
    """Parse ASN.1 opaque"""
    length = _parse_asn1_length(stream)
    opaque_tag = _read_byte(stream)
    opaque_type = _read_byte(stream)
    if (length == ASN1_OPAQUE_FLOAT_BER_LEN and
            opaque_tag == ASN1_OPAQUE_TAG1 and
            opaque_type == ASN1_OPAQUE_FLOAT):
        return _parse_asn1_opaque_float(stream)
    elif (length == ASN1_OPAQUE_DOUBLE_BER_LEN and
            opaque_tag == ASN1_OPAQUE_TAG1 and
            opaque_type == ASN1_OPAQUE_DOUBLE):
        return _parse_asn1_opaque_float(stream)
    # for simple opaque - rewind 2 bytes back (opaque tag and type)
    stream.seek(stream.tell() - 2)
    return stream.read(length)


def _parse_asn1(stream):
    """Parse ASN.1"""
    result = []
    wait_oid_value = False
    while True:
        b = stream.read(1)
        if not b:
            return result
        tag = ord(b)
        if tag == ASN1_SEQUENCE:
            length = _parse_asn1_length(stream)
            log('ASN1_SEQUENCE', 'length = {}'.format(length))
        elif tag == ASN1_INTEGER:
            length = _read_byte(stream)
            value = _read_int_len(stream, length, True)
            if wait_oid_value:
                result.append(('INTEGER', value))
                wait_oid_value = False
        elif tag == ASN1_OCTET_STRING:
            value = _parse_asn1_octet_string(stream)
            log('ASN1_OCTET_STRING', value)
            if wait_oid_value:
                result.append(('STRING', value))
                wait_oid_value = False
        elif tag == ASN1_OBJECT_IDENTIFIER:
            length = _read_byte(stream)
            value = stream.read(length)
            log('ASN1_OBJECT_IDENTIFIER', bytes_to_oid(value))
            result.append(('OID', bytes_to_oid(value)))
            wait_oid_value = True
        elif tag == ASN1_PRINTABLE_STRING:
            length = _parse_asn1_length(stream)
            value = stream.read(length)
            log('ASN1_PRINTABLE_STRING', value)
        elif tag == ASN1_GET_RESPONSE_PDU:
            length = _parse_asn1_length(stream)
            log('ASN1_GET_RESPONSE_PDU', 'length = {}'.format(length))
        elif tag == ASN1_TIMETICKS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            log('ASN1_TIMETICKS', value, timeticks_to_str(value))
            if wait_oid_value:
                result.append(('TIMETICKS', '({}) {}'.format(value, timeticks_to_str(value))))
                wait_oid_value = False
        elif tag == ASN1_IPADDRESS:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            log('ASN1_IPADDRESS', value, int_to_ip(value))
            if wait_oid_value:
                result.append(('IPADDRESS', int_to_ip(value)))
                wait_oid_value = False
        elif tag == ASN1_COUNTER32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            log('ASN1_COUNTER32', value)
            if wait_oid_value:
                result.append(('COUNTER32', value))
                wait_oid_value = False
        elif tag == ASN1_GAUGE32:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            log('ASN1_GAUGE32', value)
            if wait_oid_value:
                result.append(('GAUGE32', value))
                wait_oid_value = False
        elif tag == ASN1_OPAQUE:
            value = _parse_asn1_opaque(stream)
            log('ASN1_OPAQUE', value)
            if wait_oid_value:
                result.append(('OPAQUE', value))
                wait_oid_value = False
        elif tag == ASN1_COUNTER64:
            length = _read_byte(stream)
            value = _read_int_len(stream, length)
            log('ASN1_COUNTER64', value)
            if wait_oid_value:
                result.append(('COUNTER64', value))
                wait_oid_value = False
        elif tag == ASN1_NULL:
            value = _read_byte(stream)
            log('ASN1_NULL', value)
        elif tag == ASN1_NO_SUCH_OBJECT:
            value = _read_byte(stream)
            log('ASN1_NO_SUCH_OBJECT', value)
            result.append('No Such Object')
        elif tag == ASN1_NO_SUCH_INSTANCE:
            value = _read_byte(stream)
            log('ASN1_NO_SUCH_INSTANCE', value)
            result.append('No Such Instance with OID')
        elif tag == ASN1_END_OF_MIB_VIEW:
            value = _read_byte(stream)
            log('ASN1_END_OF_MIB_VIEW', value)
            return (('', ''), ('', ''))
        else:
            log('?', hex(ord(b)))
    return result


def parse_snmp(message):
    """Parse SNMP message using ASN.1 parser"""
    stream = StringIO(message.decode('latin'))
    return _parse_asn1(stream)


def snmp_get(ip, port, oid, version=1, community='public'):
    """SNMP get OID value from SNMP agent with IP"""
    try:
        res = make_snmp_get_oid_request(oid, version=version, community=community)
    except Exception as ex:
        print(ex)
        return
    log('SNMP get OID request:')
    log(res.hex() if PY3 else res.encode('hex'))
    host = ip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.connect((host, port))
    try:
        sock.send(res)
        response = sock.recv(4096)
        log('Response:')
        log(response.hex() if PY3 else response.encode('hex'))
        log('Parse SNMP:')
        return parse_snmp(response)
    except socket.timeout as ex:
        raise ex
    except Exception as ex:
        print(ex)
    return '', ''


def snmp_get_next(ip, port, oid, version=1, community='public'):
    """SNMP get OID value or subtree of OIDs from SNMP agent with IP"""
    res = make_snmp_get_next_oid_request(oid, version=version, community=community)
    log('SNMP get next OID request:')
    log(res.hex() if PY3 else res.encode('hex'))
    host = ip
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.settimeout(5)
    sock.connect((host, port))
    try:
        sock.send(res)
        response = sock.recv(4096)
        log('Response:')
        log(response.hex() if PY3 else response.encode('hex'))
        log('Parse SNMP:')
        return parse_snmp(response)
    except socket.timeout as ex:
        raise ex
    except Exception as ex:
        raise ex
    return '', ''


def main():
    # prepare argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', dest='version', help='SNMP version', default='2c')
    parser.add_argument('-c', '--community', dest='community', help='community for versions 1 and 2c', default='public')
    parser.add_argument('ip', help='SNMP agent IP[:port] address')
    parser.add_argument('oid', help='OID')

    args = parser.parse_args()
    if (args.version in ['1', 'v1', '2', '2c', 'v2', 'v2c'] and not args.community) or (not args.ip or not args.oid):
        parser.print_help()
        exit(1)

    # get ip and port if present
    agent_address = args.ip
    ip = agent_address
    port = 161
    if ':' in agent_address:
        if agent_address.count(':') == 1:
            try:
                ip, port = agent_address.split(':')
                port = int(port)
            except ValueError:
                ip = agent_address.split(':')[0]
        else:
            print('Invalid SNMP agent address')
            parser.print_help()
            exit(1)

    # update oid value
    orig_oid = args.oid
    if orig_oid.startswith('iso'):
        orig_oid = orig_oid.replace('iso', '1')
    orig_oid = orig_oid.rstrip('.')
    try:
        oid = orig_oid
        while True:
            next_oid, type_value = snmp_get_next(ip, port, oid, version=args.version, community=args.community)
            if not next_oid or not isinstance(next_oid, (tuple, list)) or len(next_oid) < 2:
                break
            # handle next OID request get (stop on full OID's sub tree scan)
            if not next_oid[1].startswith(orig_oid + '.'):
                # print('{} = No Such Object with this OID'.format(args.oid))
                break
            if oid == next_oid[1]:
                break
            oid = next_oid[1]
            # if no next OID value - stop
            if not oid:
                break
            if len(type_value) == 2:
                if isinstance(type_value[1], (tuple, list)) and len(type_value[1]) == 2:
                    type_value_str = '{}: {}: {}'.format(type_value[0], *type_value[1])
                else:
                    type_value_str = '{}: {}'.format(type_value[0], type_value[1])
            print(oid, '=', type_value_str)
    except socket.timeout:
        print('Timeout: No Response from {}'.format(args.ip))
    except KeyboardInterrupt:
        pass
    except Exception:
        pass


if __name__ == '__main__':
    main()
