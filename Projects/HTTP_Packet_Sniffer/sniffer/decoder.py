from dataclasses import dataclass
import socket
import struct
from typing import Optional


@dataclass
class IPv4Header:
    version: int
    ihl: int  
    tos: int
    total_length: int
    identification: int
    ttl: int
    protocol: int
    checksum: int
    src_ip: str
    dst_ip: str


@dataclass
class TCPHeader:
    src_port: int
    dst_port: int
    seq_num: int
    ack_num: int
    data_offset: int  
    flags: int
    window_size: int
    checksum: int
    urgent_ptr: int


@dataclass
class DecodedPacket:
    timestamp: float
    ip: IPv4Header
    tcp: TCPHeader
    payload: bytes


def decode_ipv4_header(raw_ip_packet: bytes) -> Optional[IPv4Header]:
    """
    Decodes the IPv4 header from raw bytes using struct.unpack.
    Standard IPv4 header is at least 20 bytes: !BBHHHBBH4s4s
    """
    if len(raw_ip_packet) < 20:
        return None

    (
        ver_ihl,
        tos,
        total_length,
        identification,
        _flags_frag,
        ttl,
        protocol,
        checksum,
        src_addr,
        dst_addr,
    ) = struct.unpack("!BBHHHBBH4s4s", raw_ip_packet[:20])

    version = ver_ihl >> 4
    ihl = (ver_ihl & 0x0F) * 4

    if version != 4 or ihl < 20 or len(raw_ip_packet) < ihl:
        return None

    return IPv4Header(
        version=version,
        ihl=ihl,
        tos=tos,
        total_length=total_length,
        identification=identification,
        ttl=ttl,
        protocol=protocol,
        checksum=checksum,
        src_ip=socket.inet_ntoa(src_addr),
        dst_ip=socket.inet_ntoa(dst_addr),
    )


def decode_tcp_header(raw_tcp_segment: bytes) -> Optional[TCPHeader]:
    """
    Decodes the TCP header from raw bytes using struct.unpack.
    Standard TCP header is at least 20 bytes: !HHLLBBHHH
    """
    if len(raw_tcp_segment) < 20:
        return None

    (
        src_port,
        dst_port,
        seq_num,
        ack_num,
        offset_reserved,
        flags,
        window_size,
        checksum,
        urgent_ptr,
    ) = struct.unpack("!HHLLBBHHH", raw_tcp_segment[:20])

    # Data offset is the upper 4 bits of offset_reserved, measured in 32-bit (4-byte) words
    data_offset = (offset_reserved >> 4) * 4

    if data_offset < 20 or len(raw_tcp_segment) < data_offset:
        return None

    return TCPHeader(
        src_port=src_port,
        dst_port=dst_port,
        seq_num=seq_num,
        ack_num=ack_num,
        data_offset=data_offset,
        flags=flags,
        window_size=window_size,
        checksum=checksum,
        urgent_ptr=urgent_ptr,
    )


def decode_packet(timestamp: float, raw_ip_packet: bytes) -> Optional[DecodedPacket]:
    """
    Decodes both IPv4 and TCP headers and extracts the application-layer TCP payload.
    """
    ip_header = decode_ipv4_header(raw_ip_packet)
    if ip_header is None or ip_header.protocol != 6:
        return None

    tcp_segment = raw_ip_packet[ip_header.ihl :]
    tcp_header = decode_tcp_header(tcp_segment)
    if tcp_header is None:
        return None

    payload = tcp_segment[tcp_header.data_offset :]

    return DecodedPacket(
        timestamp=timestamp,
        ip=ip_header,
        tcp=tcp_header,
        payload=payload,
    )
