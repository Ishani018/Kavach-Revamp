"""A minimal MCP server over stdio, for the demo tool servers. Standard library only.

Not a general SDK: tools only, which is all the demo servers need.
"""
from __future__ import annotations

import sys
from typing import Any, Callable

from .rpc import INVALID_PARAMS, METHOD_NOT_FOUND, Peer, RpcError

SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")


class MiniServer:
    def __init__(self, name: str, version: str = "0.1.0"):
        self.name, self.version, self._tools = name, version, {}

    def tool(self, description: str, properties: dict, required: list[str], read_only: bool):
        def register(fn: Callable[..., Any]):
            self._tools[fn.__name__] = {
                "fn": fn,
                "spec": {"name": fn.__name__, "description": description,
                         "inputSchema": {"type": "object", "properties": properties, "required": required},
                         "annotations": {"readOnlyHint": read_only}},
            }
            return fn
        return register

    def _on_request(self, method: str, params: dict) -> Any:
        if method == "initialize":
            wanted = params.get("protocolVersion")
            return {"protocolVersion": wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[-1],
                    "capabilities": {"tools": {}}, "serverInfo": {"name": self.name, "version": self.version}}
        if method == "ping":
            return {}
        if method == "tools/list":
            return {"tools": [t["spec"] for t in self._tools.values()]}
        if method == "tools/call":
            tool = self._tools.get(params.get("name"))
            if tool is None:
                raise RpcError(INVALID_PARAMS, f"unknown tool: {params.get('name')}")
            try:
                text = tool["fn"](**(params.get("arguments") or {}))
                return {"content": [{"type": "text", "text": str(text)}], "isError": False}
            except Exception as e:  # tool errors go in the result so the model can see them
                return {"content": [{"type": "text", "text": f"Error: {e}"}], "isError": True}
        raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")

    def run(self) -> None:
        Peer(sys.stdin.buffer, sys.stdout.buffer, self._on_request).serve()
