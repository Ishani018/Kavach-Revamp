"""Local dashboard for the gateway: live view of calls, where arguments came from, and approve/deny.

Bound to 127.0.0.1. Every API call needs the session token from the dashboard URL, so a web page open in
the same browser cannot approve actions behind the user's back.
"""
from __future__ import annotations

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from .core import Gateway
from .rpc import log

PAGE = Path(__file__).with_name("dashboard.html")


def start(gateway: Gateway, port: int = 8766) -> str:
    token = secrets.token_urlsafe(16)

    class Handler(BaseHTTPRequestHandler):
        def _send(self, status: int, body: bytes, content_type: str = "application/json") -> None:
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _authorised(self) -> bool:
            return secrets.compare_digest(self.headers.get("X-Kavach-Token", ""), token)

        def do_GET(self) -> None:
            path = self.path.split("?", 1)[0]
            if path == "/":
                self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
            elif path == "/api/state" and self._authorised():
                self._send(200, json.dumps(gateway.state()).encode())
            else:
                self._send(403 if path.startswith("/api/") else 404, b"{}")

        def do_POST(self) -> None:
            if not self._authorised():
                return self._send(403, b"{}")
            try:
                body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
                if self.path == "/api/answer":
                    ok = gateway.answer(int(body["id"]), bool(body["approve"]))
                    return self._send(200, json.dumps({"ok": ok}).encode())
                if self.path == "/api/prompt":
                    gateway.user_says(str(body["text"]))
                    return self._send(200, b'{"ok":true}')
            except (KeyError, ValueError, TypeError):
                return self._send(400, b"{}")
            self._send(404, b"{}")

        def log_message(self, *args) -> None:
            pass

    server = None
    for candidate in range(port, port + 20):  # several gateways may run at once
        try:
            server = ThreadingHTTPServer(("127.0.0.1", candidate), Handler)
            break
        except OSError:
            continue
    if server is None:
        log("dashboard: no free port")
        return ""
    threading.Thread(target=server.serve_forever, daemon=True).start()
    url = f"http://127.0.0.1:{server.server_address[1]}/?t={token}"
    log("dashboard:", url)
    return url
