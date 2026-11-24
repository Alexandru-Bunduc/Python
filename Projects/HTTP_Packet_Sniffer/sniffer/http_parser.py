from dataclasses import dataclass, field
from typing import Dict, Optional
from sniffer.decoder import DecodedPacket

HTTP_METHODS = (
    b"GET ",
    b"POST ",
    b"PUT ",
    b"DELETE ",
    b"HEAD ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
)

TCP_FLAG_NAMES = [
    (0x01, "FIN"),
    (0x02, "SYN"),
    (0x04, "RST"),
    (0x08, "PSH"),
    (0x10, "ACK"),
    (0x20, "URG"),
    (0x40, "ECE"),
    (0x80, "CWR"),
]


def format_tcp_flags(flags: int) -> str:
    active = [name for bit, name in TCP_FLAG_NAMES if flags & bit]
    return ", ".join(active) if active else f"0x{flags:02x}"


@dataclass
class HTTPRequest:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    method: str
    path: str
    version: str
    host: str
    url: str
    headers: Dict[str, str] = field(default_factory=dict)
    body: str = ""
    raw_size: int = 0
   
    ip_ttl: int = 64
    ip_total_length: int = 0
    tcp_seq: int = 0
    tcp_ack: int = 0
    tcp_flags: int = 0x18  
    tcp_window: int = 0

    @property
    def tcp_flags_str(self) -> str:
        return format_tcp_flags(self.tcp_flags)

    @property
    def request_mode(self) -> str:
        """
        Returns descriptive request mode metadata (e.g. Connection persistence, Content-Type, Transfer mode).
        """
        lower_headers = {k.lower(): v for k, v in self.headers.items()}
        conn = lower_headers.get("connection", "keep-alive" if self.version == "HTTP/1.1" else "close")
        transfer = lower_headers.get("transfer-encoding", "identity")
        content_type = lower_headers.get("content-type", "none")
        return f"Connection={conn} | Transfer={transfer} | Content-Type={content_type}"


def is_http_request(payload: bytes) -> bool:
    """
    Fast check to determine if a TCP payload starts with an HTTP request line.
    """
    if not payload:
        return False
    return payload.startswith(HTTP_METHODS)


def parse_http_request(packet: DecodedPacket) -> Optional[HTTPRequest]:
    """
    Identifies and parses an HTTP request from a decoded TCP packet.
    Returns None if the packet does not contain a valid HTTP request.
    """
    payload = packet.payload
    if not is_http_request(payload):
        return None


    if b"\r\n\r\n" in payload:
        header_bytes, body_bytes = payload.split(b"\r\n\r\n", 1)
        lines = header_bytes.decode("iso-8859-1", errors="replace").split("\r\n")
    elif b"\n\n" in payload:
        header_bytes, body_bytes = payload.split(b"\n\n", 1)
        lines = header_bytes.decode("iso-8859-1", errors="replace").split("\n")
    else:
        header_bytes = payload
        body_bytes = b""
        lines = header_bytes.decode("iso-8859-1", errors="replace").splitlines()

    if not lines:
        return None

    
    request_line_parts = lines[0].strip().split(" ")
    if len(request_line_parts) < 2:
        return None

    method = request_line_parts[0].upper()
    path = request_line_parts[1]
    version = request_line_parts[2] if len(request_line_parts) >= 3 else "HTTP/1.1"

    if not version.startswith("HTTP/"):
        return None


    headers: Dict[str, str] = {}
    for line in lines[1:]:
        if ":" in line:
            key, value = line.split(":", 1)
            headers[key.strip()] = value.strip()

    host = headers.get("Host") or headers.get("host") or f"{packet.ip.dst_ip}:{packet.tcp.dst_port}"
    if path.startswith("http://") or path.startswith("https://"):
        url = path
    else:
        url = f"http://{host}{path}"

    body = body_bytes.decode("utf-8", errors="replace")

    return HTTPRequest(
        timestamp=packet.timestamp,
        src_ip=packet.ip.src_ip,
        src_port=packet.tcp.src_port,
        dst_ip=packet.ip.dst_ip,
        dst_port=packet.tcp.dst_port,
        method=method,
        path=path,
        version=version,
        host=host,
        url=url,
        headers=headers,
        body=body,
        raw_size=len(payload),
        ip_ttl=packet.ip.ttl,
        ip_total_length=packet.ip.total_length,
        tcp_seq=packet.tcp.seq_num,
        tcp_ack=packet.tcp.ack_num,
        tcp_flags=packet.tcp.flags,
        tcp_window=packet.tcp.window_size,
    )
