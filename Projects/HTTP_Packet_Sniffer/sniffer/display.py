import datetime
import os
import sys
from typing import List, Optional
from sniffer.filter import RequestFilter
from sniffer.http_parser import HTTPRequest


def _enable_windows_ansi() -> bool:
    """
    Enables ANSI escape sequences on Windows 10/11 consoles if supported.
    """
    if os.name != "nt":
        return sys.stdout.isatty()
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_ulong()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        # ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | 0x0004)
        return True
    except Exception:
        return False


class Colors:
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    CYAN = "\033[36m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    RED = "\033[31m"
    WHITE = "\033[37m"


METHOD_COLORS = {
    "GET": Colors.GREEN,
    "POST": Colors.YELLOW,
    "PUT": Colors.BLUE,
    "PATCH": Colors.MAGENTA,
    "DELETE": Colors.RED,
    "HEAD": Colors.CYAN,
    "OPTIONS": Colors.CYAN,
}


class ConsoleDisplay:
    """
    Phase 3, 4, 5 & 6: Real-Time Display, Filter Status, and Detailed Request Inspection.
    """

    def __init__(self, use_colors: bool = True):
        self.use_colors = use_colors and _enable_windows_ansi()

    def _color(self, text: str, color_code: str) -> str:
        if not self.use_colors:
            return text
        return f"{color_code}{text}{Colors.RESET}"

    def print_banner(
        self,
        is_windows: bool,
        interface_ip: Optional[str] = None,
        req_filter: Optional[RequestFilter] = None,
        web_url: Optional[str] = None,
    ):
        line = "=" * 112
        print(self._color(line, Colors.CYAN))
        title = " HTTP PACKET SNIFFER - Real-Time Capture, Filtering & Detailed Inspection"
        print(self._color(title, Colors.BOLD + Colors.WHITE))
        if is_windows:
            info = f" Platform: Windows (SOCK_RAW) | Interface IP: {interface_ip}"
        else:
            info = " Platform: Linux (AF_PACKET)  | Capturing on all interfaces"
        print(self._color(info, Colors.DIM))

        if req_filter is not None:
            filter_color = Colors.YELLOW if req_filter.is_active else Colors.GREEN
            print(
                self._color(" Active Filters : ", Colors.BOLD)
                + self._color(req_filter.summary(), Colors.BOLD + filter_color)
            )

        if web_url:
            print(
                self._color(" Web Dashboard  : ", Colors.BOLD)
                + self._color(web_url, Colors.BOLD + Colors.CYAN)
                + self._color(" (Open in browser for live UI)", Colors.DIM)
            )

        print(
            self._color(
                " Press Ctrl+C at any time to pause capture and inspect individual HTTP requests (#).",
                Colors.DIM,
            )
        )
        print(self._color(line, Colors.CYAN))

    def print_table_header(self):
        sep = "-" * 112
        header = (
            f" {'#':<4} | {'TIMESTAMP':<12} | {'METHOD':<7} | "
            f"{'SOURCE IP:PORT':<21} | {'DESTINATION IP:PORT':<21} | {'URL'}"
        )
        print(self._color(header, Colors.BOLD))
        print(self._color(sep, Colors.DIM))

    def format_request_row(self, index: int, req: HTTPRequest, max_url_len: int = 34) -> str:
        time_str = datetime.datetime.fromtimestamp(req.timestamp).strftime("%H:%M:%S.%f")[:-3]
        src = f"{req.src_ip}:{req.src_port}"
        dst = f"{req.dst_ip}:{req.dst_port}"

        url_display = req.url
        if max_url_len and len(url_display) > max_url_len:
            url_display = url_display[: max_url_len - 3] + "..."

        method_padded = f"{req.method:<7}"
        method_color = METHOD_COLORS.get(req.method, Colors.WHITE)
        method_colored = self._color(method_padded, Colors.BOLD + method_color)

        idx_str = self._color(f"{index:<4}", Colors.DIM)
        time_colored = self._color(f"{time_str:<12}", Colors.CYAN)
        url_colored = self._color(url_display, Colors.WHITE)

        return (
            f" {idx_str} | {time_colored} | {method_colored} | "
            f"{src:<21} | {dst:<21} | {url_colored}"
        )

    def print_request(self, index: int, req: HTTPRequest):
        print(self.format_request_row(index, req), flush=True)

    def format_request_details(self, index: int, req: HTTPRequest) -> str:
        """
        Phase 5: Formats full details of a selected HTTP request (metadata, request mode, headers, payload).
        """
        dt_str = datetime.datetime.fromtimestamp(req.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        method_color = METHOD_COLORS.get(req.method, Colors.WHITE)
        border = "=" * 112
        sub_border = "-" * 112

        lines: List[str] = [
            "",
            self._color(border, Colors.CYAN),
            self._color(f" DETAILED HTTP REQUEST INSPECTION - Request #{index}", Colors.BOLD + Colors.WHITE),
            self._color(border, Colors.CYAN),
            self._color(" [1] Request Line & Mode Metadata", Colors.BOLD + Colors.YELLOW),
            f"   Timestamp       : {dt_str}",
            f"   Method          : {self._color(req.method, Colors.BOLD + method_color)}",
            f"   Full URL        : {self._color(req.url, Colors.BOLD + Colors.WHITE)}",
            f"   Request URI     : {req.path}",
            f"   HTTP Version    : {req.version}",
            f"   Request Mode    : {req.request_mode}",
            self._color(sub_border, Colors.DIM),
            self._color(" [2] Network (IPv4) & Transport (TCP) Metadata", Colors.BOLD + Colors.YELLOW),
            f"   Source          : {req.src_ip}:{req.src_port}",
            f"   Destination     : {req.dst_ip}:{req.dst_port} (Host: {req.host})",
            f"   IPv4 Metadata   : TTL={req.ip_ttl} | Total IP Length={req.ip_total_length} bytes",
            f"   TCP Metadata    : Flags=[{req.tcp_flags_str}] | Seq={req.tcp_seq} | Ack={req.tcp_ack} | Window={req.tcp_window}",
            f"   HTTP Payload Sz : {req.raw_size} bytes",
            self._color(sub_border, Colors.DIM),
            self._color(f" [3] HTTP Request Headers ({len(req.headers)} fields)", Colors.BOLD + Colors.YELLOW),
        ]

        if req.headers:
            for k, v in req.headers.items():
                key_fmt = self._color(f"{k:<22}", Colors.CYAN)
                lines.append(f"   {key_fmt}: {v}")
        else:
            lines.append("   (No headers present)")

        lines.append(self._color(sub_border, Colors.DIM))
        body_len = len(req.body.encode("utf-8", errors="replace")) if req.body else 0
        lines.append(self._color(f" [4] HTTP Request Payload / Body ({body_len} bytes)", Colors.BOLD + Colors.YELLOW))

        if req.body:
            for body_line in req.body.splitlines():
                lines.append(f"   {body_line}")
        else:
            lines.append(self._color("   (Empty Payload / No Request Body)", Colors.DIM))

        lines.append(self._color(border, Colors.CYAN))
        return "\n".join(lines)

    def print_request_details(self, index: int, req: HTTPRequest):
        print(self.format_request_details(index, req), flush=True)

    def print_statistics(
        self,
        total_packets: int,
        tcp_packets: int,
        total_http_requests: int,
        matched_http_requests: int,
        dropped_packets: int,
    ):
        line = "=" * 112
        print("\n" + self._color(line, Colors.CYAN))
        print(self._color(" Capture Summary Statistics", Colors.BOLD + Colors.WHITE))
        print(self._color("-" * 45, Colors.DIM))
        print(f"  Total Raw Packets Captured   : {self._color(str(total_packets), Colors.BOLD)}")
        print(f"  TCP Packets Filtered         : {self._color(str(tcp_packets), Colors.BOLD)}")
        print(f"  Total HTTP Requests Seen     : {self._color(str(total_http_requests), Colors.BOLD)}")
        print(
            f"  HTTP Requests Matched Filter : "
            f"{self._color(str(matched_http_requests), Colors.GREEN + Colors.BOLD)}"
        )
        drop_color = Colors.GREEN if dropped_packets == 0 else Colors.RED
        print(f"  Dropped Packets (Queue)      : {self._color(str(dropped_packets), drop_color + Colors.BOLD)}")
        print(self._color(line, Colors.CYAN))
