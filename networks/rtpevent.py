"""
Implementation of sending RTP packets according to RFC 2833: RTP Payload for DTMF Digits, Telephony Tones and Telephony Signals.
"""

import random
import socket
import struct
import time


DTMF_EVENTS = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9,
               '*': 10, '#': 11, 'A': 12, 'B': 13, 'C': 14, 'D': 15, 'Flash': 16}

SEQUENCE_NUMBER = 0
SSRC = random.randint(0, 0xffffffff)
EVENT_STEP = 160


def encode_dtmf_event(event: str) -> int:
    """Encodes DTMF to int for RFC 2833 RTP event payload."""
    if event.capitalize() not in DTMF_EVENTS:
        raise Exception(f'DTMF event "{event}" is unsupported!')
    return DTMF_EVENTS.get(event)


def create_rtp_event(dtmf: str, duration_ms: int, volume: int = 7) -> list[bytes]:
    """Create packets with RFC 2833 RTP event payload.

    :param str dtmf: DTMF.
    :param int duration_ms: Duration of DTMF in ms.
    :param int volume: DTMF volume (by default = 7).

    :return: List with RFC 2833 RTP event payloads.
    :rtype: list[bytes]
    """
    global SEQUENCE_NUMBER, ssrc
    packets = []
    event_duration = duration_ms * 8
    for index in range(event_duration // EVENT_STEP + 3):
        payload = b''
        payload += struct.pack('>B', 0b10000000)  # version=2, padding=0, extension=0, CSRC count=0
        payload += struct.pack('>B', 0b01100101)  # marker=0, payload type=101
        payload += struct.pack('>H', SEQUENCE_NUMBER)  # sequence number
        SEQUENCE_NUMBER += 1
        payload += struct.pack('>I', int(time.time()))  # timestamp
        payload += struct.pack('>I', SSRC)  # SSRC
        # RFC 2833 RTP event payload
        payload += struct.pack('>B', encode_dtmf_event(dtmf))  # DTMF event
        last_packet = index >= event_duration // EVENT_STEP
        e_r_volume = 0b00000111  # end bit=0 or 1, reserved=0, volume=7
        duration = index * EVENT_STEP
        if last_packet:
            e_r_volume = 0b10000111
            duration = event_duration
        payload += struct.pack('>B', e_r_volume)  # end bit=0 or 1, reserved=0, volume=7
        payload += struct.pack('>H', duration)  # event duration
        payload += struct.pack('>H', 0)
        packets.append(payload)
    return packets


def send_rtp_event(host: str, port: int, dtmf: str, duration_ms: int) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.connect((server_host, server_port))
        packets = create_rtp_event(dtmf, duration_ms)
        for packet in packets:
            sock.send(packet)


def main():
    # TODO: add CLI
    pass


if __name__ == '__main__':
    main()
