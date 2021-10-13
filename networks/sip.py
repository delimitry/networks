# -*- coding: utf-8 -*-

import argparse
import socket

CRLF = '\r\n'


def send_sip_options(server_host, server_port, client_host, client_port, verbose=True):
    """Sends SIP OPTIONS.

    :param str server_host: SIP server host (IP address).
    :param int server_port: SIP server port.
    :param str client_host: Local client host (IP address).
    :param int client_port: Local client port.
    :param bool verbose: If True prints out the request payload.

    :return: SIP server response.
    :rtype: str
    """
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((server_host, server_port))
        payload_fields = (
            'OPTIONS sip:127.0.0.1:5060 SIP/2.0',
            f'Via: SIP/2.0/UDP {client_host}:{client_port};rport;branch=BRANCH',
            'Max-Forwards: 70',
            f'From: <sip:{client_host}>;tag=TAG',
            'To: <sip:127.0.0.1>',
            'Call-ID: 1',
            'CSeq: 1 OPTIONS',
            'Content-Length: 0',
        )
        payload = CRLF.join(payload_fields).encode('utf-8')
        if verbose:
            print('===================')
            print('SIP server request:')
            print('===================')
            print(payload.decode().strip())
            print('--------------------')
            print()
        sock.send(payload)
        return sock.recv(4096).decode('utf-8')


def main():
    # prepare argument parser
    parser = argparse.ArgumentParser()
    parser.add_argument('server_host', help='SIP server hostname or IP address')
    parser.add_argument('server_port', nargs='?', default=5060, help='SIP server port (default=5060)')

    args = parser.parse_args()

    hostname = socket.gethostname()
    local_ip = socket.gethostbyname(hostname)

    client = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    client.bind((local_ip, 0))  # get random port
    client_host, client_port = client.getsockname()

    response = send_sip_options(args.server_host, int(args.server_port), client_host, client_port)
    print('====================')
    print('SIP server response:')
    print('====================')
    print(response.strip())
    print('--------------------')


if __name__ == '__main__':
    main()
