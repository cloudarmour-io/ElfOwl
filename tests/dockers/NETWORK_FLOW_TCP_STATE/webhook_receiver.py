#!/usr/bin/env python3
# Minimal mock webhook receiver used by test_flow_tracking_docker.sh.
# Logs every POSTed batch (one JSON array per line) to /data/events.log
# so the test script can grep it for flow_summary events with non-"new" states.

import http.server
import os
import socketserver

PORT = 8888
LOG_PATH = "/data/events.log"
# ANCHOR: Hard cap on captured event log - Bug: 24GB directory growth on a shared host - Aug 14, 2026
# The network/tcp_state eBPF programs attach to the HOST kernel, not just this test's own
# containers -- on a busy shared host, real ambient traffic alone produced 44,803 flows from a
# 10-request test run. The test only needs to observe a handful of non-"new" states to pass;
# once the log is large enough to have almost certainly captured that, stop writing (still
# return 200 so the agent's webhook push doesn't error/retry-storm).
MAX_LOG_BYTES = 50 * 1024 * 1024  # 50MB


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            current_size = os.path.getsize(LOG_PATH)
        except OSError:
            current_size = 0
        if current_size < MAX_LOG_BYTES:
            with open(LOG_PATH, "ab") as f:
                f.write(body)
                f.write(b"\n")
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"{}")

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, fmt, *args):
        pass  # keep container logs quiet; events.log is the source of truth


if __name__ == "__main__":
    open(LOG_PATH, "ab").close()
    with socketserver.TCPServer(("0.0.0.0", PORT), Handler) as httpd:
        httpd.serve_forever()
