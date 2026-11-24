import socket
import struct
import time
import unittest
from sniffer.capture import RawPacketCapture
from sniffer.decoder import decode_ipv4_header, decode_packet, decode_tcp_header
from sniffer.display import ConsoleDisplay
from sniffer.filter import RequestFilter
from sniffer.http_parser import is_http_request, parse_http_request


def build_raw_ip_tcp_packet(
    src_ip: str = "192.168.1.13",
    dst_ip: str = "93.184.216.34",
    src_port: int = 54321,
    dst_port: int = 80,
    protocol: int = 6,
    flags: int = 0x18,
    payload: bytes = b"",
    ip_options: bytes = b"",
    tcp_options: bytes = b"",
) -> bytes:
    ihl_words = 5 + (len(ip_options) // 4)
    ver_ihl = (4 << 4) | ihl_words
    data_offset_words = 5 + (len(tcp_options) // 4)
    offset_reserved = data_offset_words << 4

    total_len = ihl_words * 4 + data_offset_words * 4 + len(payload)
    ip_header = (
        struct.pack(
            "!BBHHHBBH4s4s",
            ver_ihl,
            0,
            total_len,
            1234,
            0,
            64,
            protocol,
            0,
            socket.inet_aton(src_ip),
            socket.inet_aton(dst_ip),
        )
        + ip_options
    )
    tcp_header = (
        struct.pack(
            "!HHLLBBHHH",
            src_port,
            dst_port,
            1000,
            2000,
            offset_reserved,
            flags,
            64240,
            0,
            0,
        )
        + tcp_options
    )
    return ip_header + tcp_header + payload


class TestHTTPPacketSniffer(unittest.TestCase):
    """
    Phase 6: Comprehensive Unit, Robustness, and High-Volume Performance Tests
    covering Phases 1 through 6.
    """

    def test_phase2_ipv4_and_tcp_header_decoding(self):
        raw_pkt = build_raw_ip_tcp_packet(
            src_ip="10.0.0.5",
            dst_ip="172.16.0.10",
            src_port=49152,
            dst_port=8080,
            payload=b"GET /test HTTP/1.1\r\nHost: 172.16.0.10\r\n\r\n",
            ip_options=b"\x01\x01\x01\x01", 
            tcp_options=b"\x02\x04\x05\xb4\x01\x03\x03\x08",  
        )
        decoded = decode_packet(1700000000.0, raw_pkt)
        self.assertIsNotNone(decoded)
        self.assertEqual(decoded.ip.version, 4)
        self.assertEqual(decoded.ip.ihl, 24)
        self.assertEqual(decoded.ip.src_ip, "10.0.0.5")
        self.assertEqual(decoded.ip.dst_ip, "172.16.0.10")
        self.assertEqual(decoded.tcp.src_port, 49152)
        self.assertEqual(decoded.tcp.dst_port, 8080)
        self.assertEqual(decoded.tcp.data_offset, 28)
        self.assertTrue(decoded.payload.startswith(b"GET /test HTTP/1.1"))

    def test_phase2_http_identification_and_separation(self):
        # 1. Valid HTTP GET Request
        http_pkt = decode_packet(
            time.time(),
            build_raw_ip_tcp_packet(
                payload=b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: PyTest\r\n\r\n"
            ),
        )
        req = parse_http_request(http_pkt)
        self.assertIsNotNone(req)
        self.assertEqual(req.method, "GET")
        self.assertEqual(req.url, "http://example.com/index.html")
        self.assertEqual(req.headers["User-Agent"], "PyTest")

     
        syn_pkt = decode_packet(time.time(), build_raw_ip_tcp_packet(flags=0x02, payload=b""))
        self.assertIsNone(parse_http_request(syn_pkt))

    
        tls_pkt = decode_packet(
            time.time(),
            build_raw_ip_tcp_packet(dst_port=443, payload=b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc"),
        )
        self.assertIsNone(parse_http_request(tls_pkt))

  
        resp_pkt = decode_packet(
            time.time(),
            build_raw_ip_tcp_packet(
                src_port=80, payload=b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK"
            ),
        )
        self.assertIsNone(parse_http_request(resp_pkt))

    def test_phase4_filter_accuracy(self):
        pkt_get = parse_http_request(
            decode_packet(
                time.time(),
                build_raw_ip_tcp_packet(
                    src_ip="192.168.1.13",
                    dst_ip="93.184.216.34",
                    payload=b"GET /items HTTP/1.1\r\nHost: example.com\r\n\r\n",
                ),
            )
        )
        pkt_post = parse_http_request(
            decode_packet(
                time.time(),
                build_raw_ip_tcp_packet(
                    src_ip="192.168.1.13",
                    dst_ip="184.194.160.148",
                    payload=b"POST /post HTTP/1.1\r\nHost: httpbin.org\r\n\r\nuser=alex",
                ),
            )
        )
        pkt_delete = parse_http_request(
            decode_packet(
                time.time(),
                build_raw_ip_tcp_packet(
                    src_ip="10.0.0.99",
                    dst_ip="184.194.160.148",
                    payload=b"DELETE /item/42 HTTP/1.1\r\nHost: httpbin.org\r\n\r\n",
                ),
            )
        )

     
        f_post = RequestFilter(methods={"POST"})
        self.assertFalse(f_post.matches(pkt_get))
        self.assertTrue(f_post.matches(pkt_post))
        self.assertFalse(f_post.matches(pkt_delete))

    
        f_combo = RequestFilter(methods={"GET", "DELETE"}, src_ip="10.0.0.99")
        self.assertFalse(f_combo.matches(pkt_get))
        self.assertFalse(f_combo.matches(pkt_post))
        self.assertTrue(f_combo.matches(pkt_delete))

      
        f_dst = RequestFilter(dst_ip="93.184.216.34")
        self.assertTrue(f_dst.matches(pkt_get))
        self.assertFalse(f_dst.matches(pkt_post))

    def test_phase5_detailed_request_inspection_correctness(self):
        raw_pkt = build_raw_ip_tcp_packet(
            src_ip="192.168.1.13",
            dst_ip="184.194.160.148",
            src_port=1164,
            dst_port=80,
            flags=0x18,  
            payload=(
                b"POST /api/login HTTP/1.1\r\n"
                b"Host: httpbin.org\r\n"
                b"Content-Type: application/json\r\n"
                b"Connection: keep-alive\r\n\r\n"
                b'{"user": "alex", "role": "student"}'
            ),
        )
        req = parse_http_request(decode_packet(1700000000.0, raw_pkt))
        display = ConsoleDisplay(use_colors=False)
        details = display.format_request_details(1, req)

        self.assertIn("DETAILED HTTP REQUEST INSPECTION - Request #1", details)
        self.assertIn("http://httpbin.org/api/login", details)
        self.assertIn("Connection=keep-alive", details)
        self.assertIn("Content-Type=application/json", details)
        self.assertIn("Flags=[PSH, ACK]", details)
        self.assertIn('{"user": "alex", "role": "student"}', details)

    def test_phase6_robustness_against_malformed_packets(self):
      
        malformed_inputs = [
            b"",
            b"\x45\x00\x00",
            b"\xff" * 20, 
            b"\x42" + b"\x00" * 30,  
            build_raw_ip_tcp_packet(protocol=17), 
            build_raw_ip_tcp_packet(payload=b"GET \xff\xfe\xfd invalid_utf8 HTTP/1.1\r\n\r\n\x80\x81"),
            build_raw_ip_tcp_packet(payload=b"GET /not_http_version FTP/1.0\r\n\r\n"),
        ]
        for data in malformed_inputs:
            decoded = decode_packet(time.time(), data)
            if decoded is not None:
                _ = parse_http_request(decoded)

    def test_phase6_high_volume_zero_packet_loss_and_performance(self):
        """
        Simulates a high-volume burst of 10,000 packets through the Producer-Consumer queue,
        decoder, HTTP parser, and filter to verify 0 packet loss and high throughput.
        """
        num_packets = 10000
        sniffer = RawPacketCapture(queue_size=25000)
        sniffer.is_windows = True 

        sample_http_pkt = build_raw_ip_tcp_packet(
            src_ip="192.168.1.13",
            dst_ip="93.184.216.34",
            payload=b"GET /benchmark HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )

        start_time = time.perf_counter()

      
        now = time.time()
        for _ in range(num_packets):
            sniffer.total_packets += 1
            sniffer.packet_queue.put_nowait((now, sample_http_pkt))

        req_filter = RequestFilter(methods={"GET"}, src_ip="192.168.1.13")
        matched_count = 0

        for ts, raw_ip in sniffer.get_tcp_packets():
            decoded = decode_packet(ts, raw_ip)
            if decoded:
                req = parse_http_request(decoded)
                if req and req_filter.matches(req):
                    matched_count += 1

        elapsed = time.perf_counter() - start_time
        throughput = num_packets / elapsed if elapsed > 0 else float("inf")

        self.assertEqual(sniffer.dropped_packets, 0, "Zero packet loss required under 10k burst!")
        self.assertEqual(sniffer.tcp_packets, num_packets)
        self.assertEqual(matched_count, num_packets)
        print(
            f"\n[Phase 6 Benchmark] Processed {num_packets:,} HTTP packets in {elapsed:.3f}s "
            f"({throughput:,.0f} packets/sec) | Dropped: {sniffer.dropped_packets}"
        )


if __name__ == "__main__":
    unittest.main(verbosity=2)
