import argparse
import sys
from typing import List
from sniffer.capture import RawPacketCapture
from sniffer.decoder import decode_packet
from sniffer.display import ConsoleDisplay
from sniffer.filter import RequestFilter
from sniffer.http_parser import HTTPRequest, parse_http_request
from sniffer.web_dashboard import WebDashboardServer


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="HTTP Packet Sniffer - Capture, decode, filter, and inspect real-time HTTP requests."
    )
    parser.add_argument(
        "-m",
        "--method",
        type=str,
        default=None,
        help="Filter by HTTP method(s), comma-separated (e.g., GET or GET,POST,DELETE)",
    )
    parser.add_argument(
        "--src-ip",
        type=str,
        default=None,
        help="Filter by source IPv4 address (e.g., 192.168.1.13)",
    )
    parser.add_argument(
        "--dst-ip",
        type=str,
        default=None,
        help="Filter by destination IPv4 address (e.g., 93.184.216.34)",
    )
    parser.add_argument(
        "--ip",
        type=str,
        default=None,
        help="Filter by IPv4 address matching either source OR destination",
    )
    parser.add_argument(
        "-i",
        "--inspect-all",
        action="store_true",
        help="Automatically display full detailed inspection for every captured request in real-time",
    )
    parser.add_argument(
        "--interface-ip",
        type=str,
        default=None,
        help="Override local interface IP for Windows raw socket binding",
    )
    parser.add_argument(
        "--web-port",
        type=int,
        default=8050,
        help="Port for the local live Web Dashboard (default: 8050)",
    )
    parser.add_argument(
        "--no-web",
        action="store_true",
        help="Disable the local Web Dashboard",
    )
    parser.add_argument(
        "--no-prompt",
        action="store_true",
        help="Start immediately without interactive filter prompt",
    )
    return parser.parse_args()


def build_filter_from_args_or_prompt(args: argparse.Namespace) -> RequestFilter:
    methods = set(args.method.split(",")) if args.method else set()
    req_filter = RequestFilter(
        methods=methods,
        src_ip=args.src_ip,
        dst_ip=args.dst_ip,
        any_ip=args.ip,
    )

    if req_filter.is_active or args.no_prompt or not sys.stdin.isatty():
        return req_filter

    print("=" * 112)
    print(" Configure Request Filters (Phase 4) - Press Enter to leave any filter empty (capture all)")
    print("-" * 112)
    try:
        m_input = input("  Filter by HTTP Method(s) [e.g. GET, POST, DELETE] : ").strip()
        src_input = input("  Filter by Source IP      [e.g. 192.168.1.13]      : ").strip()
        dst_input = input("  Filter by Destination IP [e.g. 93.184.216.34]     : ").strip()
    except (EOFError, KeyboardInterrupt):
        print()
        return req_filter

    return RequestFilter(
        methods=set(m_input.split(",")) if m_input else set(),
        src_ip=src_input or None,
        dst_ip=dst_input or None,
    )


def run_interactive_inspector(display: ConsoleDisplay, captured_requests: List[HTTPRequest]):
    """
    Phase 5: Interactive console menu allowing users to inspect any captured HTTP request by its # ID.
    """
    total = len(captured_requests)
    if total == 0 or not sys.stdin.isatty():
        return

    print(
        f"\n[Phase 5: Detailed Request Inspector] {total} HTTP request(s) available for inspection."
    )
    print("Commands: [1-{0}] Inspect request # | [l] List table | [a] Inspect all | [q / Enter] Quit".format(total))

    while True:
        try:
            choice = input(f"\nInspect request # (1-{total}, l=list, a=all, q=quit): ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            print()
            break

        if choice in ("", "q", "quit", "exit"):
            break
        elif choice in ("l", "list"):
            print()
            display.print_table_header()
            for idx, req in enumerate(captured_requests, start=1):
                display.print_request(idx, req)
        elif choice in ("a", "all"):
            for idx, req in enumerate(captured_requests, start=1):
                display.print_request_details(idx, req)
        elif choice.isdigit():
            req_num = int(choice)
            if 1 <= req_num <= total:
                display.print_request_details(req_num, captured_requests[req_num - 1])
            else:
                print(f"[!] Invalid request number. Please enter a number between 1 and {total}.")
        else:
            print("[!] Unknown command. Enter a request number, 'l' (list), 'a' (all), or 'q' (quit).")


def main():
    args = parse_args()
    req_filter = build_filter_from_args_or_prompt(args)

    sniffer = RawPacketCapture(interface_ip=args.interface_ip)
    display = ConsoleDisplay()

    total_http_requests = 0
    captured_requests: List[HTTPRequest] = []

    dashboard = None
    web_url = None
    if not args.no_web:
        dashboard = WebDashboardServer(
            sniffer=sniffer,
            req_filter=req_filter,
            captured_requests=captured_requests,
            get_total_http_fn=lambda: total_http_requests,
            port=args.web_port,
        )
        if dashboard.start():
            web_url = f"http://localhost:{args.web_port}"

    display.print_banner(sniffer.is_windows, sniffer.interface_ip, req_filter, web_url=web_url)
    display.print_table_header()

    try:
        sniffer.start()

        for timestamp, raw_ip_packet in sniffer.get_tcp_packets():
            
            decoded_pkt = decode_packet(timestamp, raw_ip_packet)
            if decoded_pkt is None:
                continue

            
            if dashboard and (
                decoded_pkt.tcp.dst_port == args.web_port
                or decoded_pkt.tcp.src_port == args.web_port
            ):
                continue

        
            http_req = parse_http_request(decoded_pkt)
            if http_req is None:
                continue

            total_http_requests += 1

           
            if not req_filter.matches(http_req):
                continue

           
            captured_requests.append(http_req)
            req_index = len(captured_requests)
            display.print_request(req_index, http_req)

            if args.inspect_all:
                display.print_request_details(req_index, http_req)

    except PermissionError:
        print("\n[!] EROARE: Permisiuni insuficiente pentru Raw Socket!")
        print("    Ruleaza in Docker (cu NET_RAW) sau deschide terminalul ca Administrator/sudo.")
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    finally:
        sniffer.stop()
        display.print_statistics(
            total_packets=sniffer.total_packets,
            tcp_packets=sniffer.tcp_packets,
            total_http_requests=total_http_requests,
            matched_http_requests=len(captured_requests),
            dropped_packets=sniffer.dropped_packets,
        )

   
    try:
        run_interactive_inspector(display, captured_requests)
    finally:
        if dashboard:
            dashboard.stop()


if __name__ == "__main__":
    main()
