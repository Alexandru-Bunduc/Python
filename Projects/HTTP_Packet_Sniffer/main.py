import datetime
import socket
import struct
from sniffer.capture import RawPacketCapture


def main():
    sniffer = RawPacketCapture()
    print("=" * 65)
    print(" Starting HTTP Packet Sniffer - Phase 1: Raw TCP Packet Capture")
    if sniffer.is_windows:
        print(f" Platform: Windows | Interface IP: {sniffer.interface_ip}")
    else:
        print(" Platform: Linux (AF_PACKET) | Capturing on all interfaces")
    print(" Press Ctrl+C to stop capture and view statistics.")
    print("=" * 65)

    try:
        sniffer.start()

        for timestamp, ip_packet in sniffer.get_tcp_packets():
            time_str = datetime.datetime.fromtimestamp(timestamp).strftime("%H:%M:%S.%f")[:-3]
            src_ip = socket.inet_ntoa(ip_packet[12:16])
            dst_ip = socket.inet_ntoa(ip_packet[16:20])
            ihl = (ip_packet[0] & 0x0F) * 4
            if len(ip_packet) < ihl + 4:
                continue
            src_port, dst_port = struct.unpack("!HH", ip_packet[ihl : ihl + 4])
            print(
                f"[{time_str}] TCP  {src_ip}:{src_port:<5} -> {dst_ip}:{dst_port:<5} "
                f"| Size: {len(ip_packet)} bytes"
            )
    except PermissionError:
        print("\n[!] EROARE: Permisiuni insuficiente pentru Raw Socket!")
        print("    Ruleaza in Docker (cu NET_RAW) sau deschide terminalul ca Administrator/sudo.")
    except KeyboardInterrupt:
        print("\n[*] Stopping packet capture...")
    finally:
        sniffer.stop()
        print("\n" + "=" * 65)
        print(" Capture Statistics (Phase 1)")
        print(f" Total Raw Packets Captured : {sniffer.total_packets}")
        print(f" TCP Packets Filtered       : {sniffer.tcp_packets}")
        print(f" Dropped Packets (Queue)    : {sniffer.dropped_packets}")
        print("=" * 65)
if __name__ == "__main__":
    main()