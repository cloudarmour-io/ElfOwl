#!/usr/bin/env python3
# Minimal mock webhook receiver used by test_flow_tracking_docker.sh.
# Logs every POSTed batch (one JSON array per line) to /data/events.log
# so the test script can grep it for flow_summary events with non-"new" states.

import http.server
import socketserver

PORT = 8888
LOG_PATH = "/data/events.log"


class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
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
