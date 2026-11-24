# HTTP Packet Sniffer

Low-level real-time HTTP packet sniffer built in Python using only the Python Standard Library (`socket`, `struct`, `ctypes`, `threading`, `queue`, `http.server`), supporting both **Windows (`SOCK_RAW` + `SIO_RCVALL`)** and **Linux / Docker (`AF_PACKET`)**.

---

## Architecture & Development Phases

```text
HTTP_Packet_Sniffer/
├── main.py                  # Entry point, CLI arguments, interactive filter & Phase 5 inspector
├── Dockerfile               # Lightweight Alpine Linux container
├── docker-compose.yml       # Docker configuration with NET_RAW & NET_ADMIN capabilities
├── PHASES.md                # Full project requirements by phase
├── sniffer/
│   ├── __init__.py
│   ├── capture.py           # [Phase 1] Raw Socket capture & Producer-Consumer queue (zero packet loss)
│   ├── decoder.py           # [Phase 2] IPv4 & TCP binary header decoding using struct.unpack
│   ├── http_parser.py       # [Phase 2 & 5] HTTP request identification, parsing & metadata extraction
│   ├── display.py           # [Phase 3 & 5] Real-time structured console table & detailed request view
│   ├── filter.py            # [Phase 4] Filtering by HTTP method(s), Source IP, and Destination IP
│   └── web_dashboard.py     # [Bonus] Local real-time Web Dashboard (http://localhost:8050)
└── tests/
    └── test_sniffer.py      # [Phase 6] Unit tests, robustness validation & 10,000-packet benchmark
```

---

## How to Run

### Option 1: Run Natively on Windows (PowerShell as Administrator)
```powershell
python main.py
```
Or pass filters directly via CLI arguments:
```powershell
python main.py --method GET,POST --src-ip 192.168.1.13
```

### Option 2: Run in Linux via Docker
```powershell
docker compose up --build
```

---

## Live Web Dashboard (`http://localhost:8050`)
When `python main.py` runs, it automatically starts a local web server at:
- **`http://localhost:8050`**

Features in the browser:
- Real-time packet counters (`Total Raw Packets`, `TCP Packets`, `HTTP Requests`, `Dropped Packets`)
- Interactive UI filtering by HTTP Method (`GET`, `POST`, `PUT`, `DELETE`), Source IP, Destination IP, and URL search
- Click any captured request row to view its **Phase 5 Detailed Request Inspection** (Request Mode, IPv4/TCP metadata, full HTTP headers, and payload body).

---

## Running Phase 6 Tests & Performance Benchmark
```powershell
python -m unittest discover -s tests -v
```
Includes unit tests for header decoding, HTTP separation, filter accuracy, detailed inspection formatting, malformed packet resilience, and a **10,000-packet burst benchmark (~45,000+ packets/sec with 0 dropped packets)**.
