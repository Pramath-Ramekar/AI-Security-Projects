"""
Lightweight HTTP event receiver.
POST /events  { ...SecurityEvent fields... }
GET  /health
GET  /stats

Run: python collector/api.py
"""
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))
from collector.collector import collect, event_count
from collector.schema import VALID_EVENT_TYPES, VALID_APPLICATIONS

PORT = 8765


class EventHandler(BaseHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass  # suppress default access log

    def _send(self, code: int, body: dict):
        payload = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", len(payload))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        if self.path == "/health":
            self._send(200, {"status": "ok"})
        elif self.path == "/stats":
            self._send(200, {"events_collected": event_count()})
        else:
            self._send(404, {"error": "not found"})

    def do_POST(self):
        if self.path != "/events":
            self._send(404, {"error": "not found"})
            return
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length)
        try:
            event = json.loads(body)
        except json.JSONDecodeError:
            self._send(400, {"error": "invalid JSON"})
            return
        if "application" not in event or "event_type" not in event or "user_id" not in event:
            self._send(400, {"error": "missing required fields: application, event_type, user_id"})
            return
        stored = collect(event)
        self._send(201, {"status": "collected", "event_id": stored.get("event_id", "?")})


if __name__ == "__main__":
    server = HTTPServer(("0.0.0.0", PORT), EventHandler)
    print(f"[Aegis SOC] Event collector listening on port {PORT}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[Aegis SOC] Collector stopped.")
