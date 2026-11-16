"""Local demo server. Standard library only.

Run:  cd v2 && python -m demo.server      then open http://127.0.0.1:8765
"""
from __future__ import annotations

import argparse
import json
from functools import lru_cache
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from demo import engine

PAGE = Path(__file__).with_name("index.html")


@lru_cache(maxsize=1)
def _catalog_json() -> bytes:
    return json.dumps(engine.catalog()).encode()


class Handler(BaseHTTPRequestHandler):
    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        if self.path == "/":
            self._send(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif self.path == "/api/catalog":
            self._send(200, _catalog_json(), "application/json")
        else:
            self._send(404, b"not found", "text/plain")

    def do_POST(self) -> None:
        if self.path != "/api/run":
            return self._send(404, b"not found", "text/plain")
        try:
            q = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))))
            goal = q.get("attacker_goal") or None
            result = engine.run(q["suite"], q["user_task"], goal, q["guard"], [bool(x) for x in q.get("human", [])])
            # The same scenario with no guard, for the "without Kavach" line.
            result["without_guard"] = engine.run(q["suite"], q["user_task"], goal, "off")["outcome"]
            self._send(200, json.dumps(result).encode(), "application/json")
        except (KeyError, ValueError) as e:
            self._send(400, json.dumps({"error": f"bad request: {e}"}).encode(), "application/json")

    def log_message(self, *args) -> None:  # keep the terminal quiet
        pass


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8765)
    args = ap.parse_args()
    print(f"Kavach demo: http://127.0.0.1:{args.port}  (loading the benchmark on first request)")
    ThreadingHTTPServer(("127.0.0.1", args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
