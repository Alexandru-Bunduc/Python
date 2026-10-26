import os
import queue
import socket
import struct
import threading
import time

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
IPPROTO_TCP_CODE = 6


def _get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


class RawPacketCapture:
    def __init__(self, interface_ip=None, queue_size=10000):
        self.is_windows = (os.name == "nt")
        self.interface_ip = interface_ip or (_get_local_ip() if self.is_windows else None)
        self.packet_queue = queue.Queue(maxsize=queue_size)
        self.running = False
        self.sock = None
        self.capture_thread = None
        self.total_packets = 0
        self.tcp_packets = 0
        self.dropped_packets = 0

    def _create_socket(self):
        if not self.is_windows:
            self.sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(ETH_P_ALL))
        elif self.is_windows:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            self.sock.bind((self.interface_ip, 0))
            self.sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 4 * 1024 * 1024)
        self.sock.settimeout(1.0)

    def _capture_loop(self):
        while self.running is True:
            try:
                raw_data, _ = self.sock.recvfrom(65535)
                timestamp = time.time()
                self.total_packets += 1
                self.packet_queue.put_nowait((timestamp, raw_data))
            except socket.timeout:
                continue
            except queue.Full:
                self.dropped_packets += 1
                continue
            except OSError:
                if not self.running:
                    break

    def start(self):
        self._create_socket()
        self.running = True
        self.capture_thread = threading.Thread(target=self._capture_loop, daemon=True)
        self.capture_thread.start()

    def stop(self):
        self.running = False
        if self.capture_thread:
            self.capture_thread.join(timeout=2.0)
        if self.sock:
            if self.is_windows:
                self.sock.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)
            self.sock.close()

    def get_tcp_packets(self):
        while self.running or not self.packet_queue.empty():
            try:
                timestamp, raw_data = self.packet_queue.get(timeout=0.5)
            except queue.Empty:
                continue
            if not self.is_windows:
                if len(raw_data) < 34:
                    continue
                _, _, eth_proto = struct.unpack("!6s6sH", raw_data[:14])
                if eth_proto != ETH_P_IP:
                    continue
                ip_packet = raw_data[14:]
            else:
                if len(raw_data) < 20:
                    continue
                ip_packet = raw_data
            if ip_packet[9] == IPPROTO_TCP_CODE:
                self.tcp_packets += 1
                yield timestamp, ip_packet
