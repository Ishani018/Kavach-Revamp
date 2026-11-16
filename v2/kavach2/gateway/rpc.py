"""JSON-RPC 2.0 over newline-delimited JSON, the framing MCP uses on stdio. Standard library only."""
from __future__ import annotations

import json
import sys
import threading
from typing import Any, BinaryIO, Callable, Optional

METHOD_NOT_FOUND, INVALID_PARAMS, INTERNAL_ERROR = -32601, -32602, -32603


class RpcError(Exception):
    def __init__(self, code: int, message: str):
        super().__init__(message)
        self.code, self.message = code, message


def log(*parts: Any) -> None:
    """stdout carries the protocol, so everything human-readable goes to stderr."""
    print("[kavach]", *parts, file=sys.stderr, flush=True)


class Peer:
    """One end of a JSON-RPC connection. Each incoming request is handled on its own thread, so a handler
    may block (for example while waiting for a human) without stalling the connection."""

    def __init__(self, rfile: BinaryIO, wfile: BinaryIO,
                 on_request: Optional[Callable[[str, dict], Any]] = None,
                 on_notification: Optional[Callable[[str, dict], None]] = None):
        self._rfile, self._wfile = rfile, wfile
        self._on_request, self._on_notification = on_request, on_notification
        self._write_lock, self._state_lock = threading.Lock(), threading.Lock()
        self._next_id, self._waiting = 0, {}
        self.closed = threading.Event()

    def _send(self, message: dict) -> None:
        data = (json.dumps(message, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
        with self._write_lock:
            try:
                self._wfile.write(data)
                self._wfile.flush()
            except (BrokenPipeError, ValueError, OSError):
                self.closed.set()

    def notify(self, method: str, params: Optional[dict] = None) -> None:
        message = {"jsonrpc": "2.0", "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)

    def request(self, method: str, params: Optional[dict] = None, timeout: float = 60.0) -> Any:
        with self._state_lock:
            self._next_id += 1
            request_id = f"kavach-{self._next_id}"
            slot = {"event": threading.Event(), "response": None}
            self._waiting[request_id] = slot
        message = {"jsonrpc": "2.0", "id": request_id, "method": method}
        if params is not None:
            message["params"] = params
        self._send(message)
        answered = slot["event"].wait(timeout)
        with self._state_lock:
            self._waiting.pop(request_id, None)
        if not answered:
            raise RpcError(INTERNAL_ERROR, f"no answer to {method} within {timeout:.0f}s")
        response = slot["response"]
        if response is None:
            raise RpcError(INTERNAL_ERROR, f"connection closed while waiting for {method}")
        if "error" in response:
            error = response["error"] or {}
            raise RpcError(int(error.get("code", INTERNAL_ERROR)), str(error.get("message", "error")))
        return response.get("result")

    def _handle_request(self, message: dict) -> None:
        request_id, method = message["id"], message["method"]
        try:
            if self._on_request is None:
                raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")
            result = self._on_request(method, message.get("params") or {})
            self._send({"jsonrpc": "2.0", "id": request_id, "result": result if result is not None else {}})
        except RpcError as e:
            self._send({"jsonrpc": "2.0", "id": request_id, "error": {"code": e.code, "message": e.message}})
        except Exception as e:  # never let a handler bug kill the connection
            log("handler error in", method, repr(e))
            self._send({"jsonrpc": "2.0", "id": request_id,
                        "error": {"code": INTERNAL_ERROR, "message": "internal error"}})

    def serve(self) -> None:
        """Read messages until the stream ends."""
        try:
            for line in iter(self._rfile.readline, b""):
                line = line.strip()
                if not line:
                    continue
                try:
                    message = json.loads(line)
                except ValueError:
                    log("ignoring a line that is not JSON")
                    continue
                if not isinstance(message, dict):
                    continue
                if "method" in message and "id" in message:
                    threading.Thread(target=self._handle_request, args=(message,), daemon=True).start()
                elif "method" in message:
                    if self._on_notification:
                        try:
                            self._on_notification(message["method"], message.get("params") or {})
                        except Exception as e:
                            log("notification handler error", repr(e))
                elif "id" in message:
                    with self._state_lock:
                        slot = self._waiting.get(message["id"])
                    if slot:
                        slot["response"] = message
                        slot["event"].set()
        finally:
            self.closed.set()
            with self._state_lock:
                for slot in self._waiting.values():
                    slot["event"].set()

    def serve_in_background(self) -> threading.Thread:
        thread = threading.Thread(target=self.serve, daemon=True)
        thread.start()
        return thread
