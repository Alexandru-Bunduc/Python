from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from typing import List
from sniffer.capture import RawPacketCapture
from sniffer.filter import RequestFilter
from sniffer.http_parser import HTTPRequest

DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>HTTP Packet Sniffer - Live Web Dashboard</title>
<style>
  :root {
    --bg: #0f172a;
    --panel: #1e293b;
    --border: #334155;
    --text: #f8fafc;
    --muted: #94a3b8;
    --accent: #38bdf8;
    --get: #22c55e;
    --post: #eab308;
    --put: #3b82f6;
    --delete: #ef4444;
    --patch: #a855f7;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
    background: var(--bg);
    color: var(--text);
    padding: 20px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    background: var(--panel);
    padding: 16px 24px;
    border-radius: 12px;
    border: 1px solid var(--border);
    margin-bottom: 18px;
  }
  header h1 { font-size: 1.35rem; display: flex; align-items: center; gap: 10px; }
  .dot {
    width: 10px; height: 10px; border-radius: 50%;
    background: #22c55e;
    box-shadow: 0 0 10px #22c55e;
    animation: pulse 1.5s infinite;
  }
  @keyframes pulse { 0%, 100% { opacity: 1; } 50% { opacity: 0.4; } }
  .stats-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
    gap: 14px;
    margin-bottom: 18px;
  }
  .stat-card {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
  }
  .stat-label { font-size: 0.8rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
  .stat-value { font-size: 1.6rem; font-weight: 700; margin-top: 4px; color: var(--accent); }
  .filters-bar {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 14px 18px;
    margin-bottom: 18px;
    align-items: center;
  }
  .filters-bar input, .filters-bar select {
    background: var(--bg);
    color: var(--text);
    border: 1px solid var(--border);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 0.9rem;
  }
  .btn {
    background: var(--accent);
    color: #0f172a;
    border: none;
    padding: 8px 14px;
    border-radius: 6px;
    font-weight: 600;
    cursor: pointer;
    font-size: 0.88rem;
  }
  .btn:hover { opacity: 0.9; }
  .main-layout {
    display: grid;
    grid-template-columns: 1.35fr 1fr;
    gap: 18px;
  }
  @media (max-width: 1024px) { .main-layout { grid-template-columns: 1fr; } }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 12px;
    overflow: hidden;
    display: flex;
    flex-direction: column;
    max-height: 68vh;
  }
  .panel-header {
    padding: 12px 18px;
    border-bottom: 1px solid var(--border);
    font-weight: 600;
    display: flex;
    justify-content: space-between;
    background: rgba(15, 23, 42, 0.5);
  }
  .table-container { overflow-y: auto; flex: 1; }
  table { width: 100%; border-collapse: collapse; font-size: 0.88rem; }
  th, td { padding: 10px 14px; text-align: left; border-bottom: 1px solid var(--border); }
  th { position: sticky; top: 0; background: #162032; color: var(--muted); font-size: 0.78rem; text-transform: uppercase; }
  tbody tr { cursor: pointer; transition: background 0.12s; }
  tbody tr:hover { background: rgba(56, 189, 248, 0.08); }
  tbody tr.selected { background: rgba(56, 189, 248, 0.18); }
  .badge {
    padding: 3px 8px;
    border-radius: 4px;
    font-weight: 700;
    font-size: 0.75rem;
    display: inline-block;
  }
  .method-GET { background: rgba(34, 197, 94, 0.18); color: var(--get); }
  .method-POST { background: rgba(234, 179, 8, 0.18); color: var(--post); }
  .method-PUT { background: rgba(59, 130, 246, 0.18); color: var(--put); }
  .method-DELETE { background: rgba(239, 68, 68, 0.18); color: var(--delete); }
  .method-PATCH { background: rgba(168, 85, 247, 0.18); color: var(--patch); }
  .inspector-body { padding: 16px; overflow-y: auto; flex: 1; font-size: 0.88rem; }
  .section-title {
    color: var(--accent);
    font-size: 0.8rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    margin: 14px 0 8px 0;
    border-bottom: 1px solid var(--border);
    padding-bottom: 4px;
  }
  .section-title:first-child { margin-top: 0; }
  .kv-row { display: flex; margin-bottom: 5px; word-break: break-all; }
  .kv-key { width: 155px; flex-shrink: 0; color: var(--muted); font-family: monospace; }
  .kv-val { color: var(--text); font-family: monospace; }
  pre {
    background: var(--bg);
    padding: 12px;
    border-radius: 8px;
    border: 1px solid var(--border);
    overflow-x: auto;
    color: #e2e8f0;
    font-family: Consolas, monospace;
    font-size: 0.84rem;
    white-space: pre-wrap;
  }
  .empty-state { padding: 40px; text-align: center; color: var(--muted); }
</style>
</head>
<body>
  <header>
    <h1><span class="dot"></span> HTTP Packet Sniffer — Live Web Dashboard</h1>
    <div style="font-size: 0.88rem; color: var(--muted);" id="platform-info">Connecting...</div>
  </header>

  <div class="stats-grid">
    <div class="stat-card">
      <div class="stat-label">Total Raw Packets</div>
      <div class="stat-value" id="stat-raw">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">TCP Packets</div>
      <div class="stat-value" id="stat-tcp">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">HTTP Requests Seen</div>
      <div class="stat-value" id="stat-http-total">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Matched HTTP Requests</div>
      <div class="stat-value" id="stat-http-matched" style="color: #22c55e;">0</div>
    </div>
    <div class="stat-card">
      <div class="stat-label">Dropped Packets</div>
      <div class="stat-value" id="stat-dropped" style="color: #22c55e;">0</div>
    </div>
  </div>

  <div class="filters-bar">
    <strong style="font-size: 0.9rem;">Phase 4 UI Filters:</strong>
    <select id="filter-method">
      <option value="">All Methods</option>
      <option value="GET">GET</option>
      <option value="POST">POST</option>
      <option value="PUT">PUT</option>
      <option value="DELETE">DELETE</option>
      <option value="HEAD">HEAD</option>
      <option value="OPTIONS">OPTIONS</option>
    </select>
    <input type="text" id="filter-src" placeholder="Filter Source IP (e.g. 192.168.1.13)" />
    <input type="text" id="filter-dst" placeholder="Filter Dest IP" />
    <input type="text" id="filter-url" placeholder="Search URL / Host..." />
    <button class="btn" onclick="resetFilters()">Reset UI Filters</button>
  </div>

  <div class="main-layout">
    <div class="panel">
      <div class="panel-header">
        <span>Phase 3: Real-Time Captured HTTP Requests</span>
        <span id="visible-count" style="color: var(--muted); font-size: 0.85rem;">0 shown</span>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>#</th>
              <th>Time</th>
              <th>Method</th>
              <th>Source</th>
              <th>Destination</th>
              <th>URL</th>
            </tr>
          </thead>
          <tbody id="requests-tbody">
            <tr><td colspan="6" class="empty-state">Waiting for HTTP requests... (Try running: curl.exe -4 http://example.com)</td></tr>
          </tbody>
        </table>
      </div>
    </div>

    <div class="panel">
      <div class="panel-header">
        <span>Phase 5: Detailed Request Inspection</span>
        <span id="selected-id" style="color: var(--accent); font-size: 0.85rem;">None selected</span>
      </div>
      <div class="inspector-body" id="inspector-content">
        <div class="empty-state">Click on any HTTP request row on the left to inspect its full headers, network metadata, request mode, and payload.</div>
      </div>
    </div>
  </div>

<script>
  let allRequests = [];
  let selectedIndex = null;

  function resetFilters() {
    document.getElementById('filter-method').value = '';
    document.getElementById('filter-src').value = '';
    document.getElementById('filter-dst').value = '';
    document.getElementById('filter-url').value = '';
    renderTable();
  }

  ['filter-method', 'filter-src', 'filter-dst', 'filter-url'].forEach(id => {
    document.getElementById(id).addEventListener('input', renderTable);
  });

  function formatTime(ts) {
    const d = new Date(ts * 1000);
    return d.toTimeString().split(' ')[0] + '.' + String(d.getMilliseconds()).padStart(3, '0');
  }

  function escapeHtml(str) {
    if (!str) return '';
    return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  }

  function selectRequest(idx) {
    selectedIndex = idx;
    renderTable();
    renderInspector();
  }

  function renderInspector() {
    const container = document.getElementById('inspector-content');
    const label = document.getElementById('selected-id');
    if (selectedIndex === null || !allRequests[selectedIndex - 1]) {
      return;
    }
    const req = allRequests[selectedIndex - 1];
    label.textContent = 'Request #' + selectedIndex;

    let headersHtml = '';
    const entries = Object.entries(req.headers || {});
    if (entries.length > 0) {
      entries.forEach(([k, v]) => {
        headersHtml += `<div class="kv-row"><div class="kv-key">${escapeHtml(k)}:</div><div class="kv-val">${escapeHtml(v)}</div></div>`;
      });
    } else {
      headersHtml = '<div style="color: var(--muted);">No headers</div>';
    }

    const bodyText = req.body ? escapeHtml(req.body) : '(Empty Payload / No Request Body)';

    container.innerHTML = `
      <div class="section-title">[1] Request Line & Mode Metadata</div>
      <div class="kv-row"><div class="kv-key">Timestamp</div><div class="kv-val">${formatTime(req.timestamp)}</div></div>
      <div class="kv-row"><div class="kv-key">Method</div><div class="kv-val"><span class="badge method-${escapeHtml(req.method)}">${escapeHtml(req.method)}</span></div></div>
      <div class="kv-row"><div class="kv-key">Full URL</div><div class="kv-val" style="color: var(--accent);">${escapeHtml(req.url)}</div></div>
      <div class="kv-row"><div class="kv-key">Request URI</div><div class="kv-val">${escapeHtml(req.path)}</div></div>
      <div class="kv-row"><div class="kv-key">HTTP Version</div><div class="kv-val">${escapeHtml(req.version)}</div></div>
      <div class="kv-row"><div class="kv-key">Request Mode</div><div class="kv-val">${escapeHtml(req.request_mode)}</div></div>

      <div class="section-title">[2] Network (IPv4) & Transport (TCP) Metadata</div>
      <div class="kv-row"><div class="kv-key">Source</div><div class="kv-val">${escapeHtml(req.src_ip)}:${req.src_port}</div></div>
      <div class="kv-row"><div class="kv-key">Destination</div><div class="kv-val">${escapeHtml(req.dst_ip)}:${req.dst_port} (${escapeHtml(req.host)})</div></div>
      <div class="kv-row"><div class="kv-key">IPv4 Metadata</div><div class="kv-val">TTL=${req.ip_ttl} | Total IP Length=${req.ip_total_length} bytes</div></div>
      <div class="kv-row"><div class="kv-key">TCP Metadata</div><div class="kv-val">Flags=[${escapeHtml(req.tcp_flags_str)}] | Seq=${req.tcp_seq} | Ack=${req.tcp_ack} | Window=${req.tcp_window}</div></div>
      <div class="kv-row"><div class="kv-key">HTTP Payload Sz</div><div class="kv-val">${req.raw_size} bytes</div></div>

      <div class="section-title">[3] HTTP Request Headers (${entries.length})</div>
      ${headersHtml}

      <div class="section-title">[4] HTTP Request Payload / Body</div>
      <pre>${bodyText}</pre>
    `;
  }

  function renderTable() {
    const tbody = document.getElementById('requests-tbody');
    const fMethod = document.getElementById('filter-method').value.trim().toUpperCase();
    const fSrc = document.getElementById('filter-src').value.trim().toLowerCase();
    const fDst = document.getElementById('filter-dst').value.trim().toLowerCase();
    const fUrl = document.getElementById('filter-url').value.trim().toLowerCase();

    const filtered = allRequests.map((r, i) => ({ req: r, idx: i + 1 })).filter(({ req }) => {
      if (fMethod && req.method !== fMethod) return false;
      if (fSrc && !req.src_ip.toLowerCase().includes(fSrc)) return false;
      if (fDst && !req.dst_ip.toLowerCase().includes(fDst)) return false;
      if (fUrl && !req.url.toLowerCase().includes(fUrl)) return false;
      return true;
    });

    document.getElementById('visible-count').textContent = `${filtered.length} shown`;

    if (filtered.length === 0) {
      tbody.innerHTML = '<tr><td colspan="6" class="empty-state">No matching HTTP requests yet...</td></tr>';
      return;
    }

    tbody.innerHTML = filtered.slice().reverse().map(({ req, idx }) => `
      <tr class="${selectedIndex === idx ? 'selected' : ''}" onclick="selectRequest(${idx})">
        <td>${idx}</td>
        <td style="font-family: monospace; color: var(--accent);">${formatTime(req.timestamp)}</td>
        <td><span class="badge method-${escapeHtml(req.method)}">${escapeHtml(req.method)}</span></td>
        <td style="font-family: monospace;">${escapeHtml(req.src_ip)}:${req.src_port}</td>
        <td style="font-family: monospace;">${escapeHtml(req.dst_ip)}:${req.dst_port}</td>
        <td style="max-width: 280px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${escapeHtml(req.url)}</td>
      </tr>
    `).join('');
  }

  async function pollState() {
    try {
      const res = await fetch('/api/state');
      const data = await res.json();
      document.getElementById('platform-info').textContent =
        `Platform: ${data.platform} | Active CLI Filter: ${data.active_filter}`;
      document.getElementById('stat-raw').textContent = data.stats.total_packets;
      document.getElementById('stat-tcp').textContent = data.stats.tcp_packets;
      document.getElementById('stat-http-total').textContent = data.stats.total_http_requests;
      document.getElementById('stat-http-matched').textContent = data.stats.matched_http_requests;
      document.getElementById('stat-dropped').textContent = data.stats.dropped_packets;

      if (data.requests.length !== allRequests.length) {
        const wasEmpty = allRequests.length === 0;
        allRequests = data.requests;
        if (wasEmpty && allRequests.length > 0 && selectedIndex === null) {
          selectedIndex = 1;
        }
        renderTable();
        if (selectedIndex !== null) renderInspector();
      }
    } catch (e) {}
  }

  setInterval(pollState, 600);
  pollState();
</script>
</body>
</html>
"""


class WebDashboardServer:
    """
    Local HTTP Web Dashboard for viewing captured packets, statistics, filters, and detailed inspection in real-time.
    Uses only Python's standard library (http.server).
    """

    def __init__(
        self,
        sniffer: RawPacketCapture,
        req_filter: RequestFilter,
        captured_requests: List[HTTPRequest],
        get_total_http_fn,
        host: str = "0.0.0.0",
        port: int = 8050,
    ):
        self.sniffer = sniffer
        self.req_filter = req_filter
        self.captured_requests = captured_requests
        self.get_total_http_fn = get_total_http_fn
        self.host = host
        self.port = port
        self._server = None
        self._thread = None

    def start(self):
        dashboard_ref = self

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/" or self.path.startswith("/index.html"):
                    body = DASHBOARD_HTML.encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path.startswith("/api/state"):
                    reqs_serialized = []
                    # Snapshot of captured requests
                    for r in list(dashboard_ref.captured_requests):
                        d = asdict(r)
                        d["tcp_flags_str"] = r.tcp_flags_str
                        d["request_mode"] = r.request_mode
                        reqs_serialized.append(d)

                    payload = {
                        "platform": (
                            f"Windows ({dashboard_ref.sniffer.interface_ip})"
                            if dashboard_ref.sniffer.is_windows
                            else "Linux (AF_PACKET)"
                        ),
                        "active_filter": dashboard_ref.req_filter.summary(),
                        "stats": {
                            "total_packets": dashboard_ref.sniffer.total_packets,
                            "tcp_packets": dashboard_ref.sniffer.tcp_packets,
                            "total_http_requests": dashboard_ref.get_total_http_fn(),
                            "matched_http_requests": len(reqs_serialized),
                            "dropped_packets": dashboard_ref.sniffer.dropped_packets,
                        },
                        "requests": reqs_serialized,
                    }
                    data = json.dumps(payload).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Cache-Control", "no-store")
                    self.send_header("Content-Length", str(len(data)))
                    self.end_headers()
                    self.wfile.write(data)
                else:
                    self.send_response(404)
                    self.end_headers()

            def log_message(self, format, *args):
                # Suppress noisy HTTP server console logs so sniffer console stays clean
                pass

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
            self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
            self._thread.start()
            return True
        except OSError:
            return False

    def stop(self):
        if self._server:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
