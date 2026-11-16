"""The Kavach gateway: one MCP server that stands in front of the user's real MCP servers.

The agent connects to the gateway instead of to the tool servers. The gateway forwards every call, records
what each tool returned, and before any state-changing call traces the call's arguments back to where they
came from. If an argument came from tool output and not from the user, the human is asked first.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from typing import Any, Optional

from ..graph import ProvenanceGraph
from ..types import Action, Verdict
from .rpc import INVALID_PARAMS, METHOD_NOT_FOUND, Peer, RpcError, log

VERSION = "0.2.0"
SUPPORTED_VERSIONS = ("2024-11-05", "2025-03-26", "2025-06-18", "2025-11-25")
AGENT = "agent"


class Downstream:
    """One of the user's real MCP servers, run as a child process."""

    def __init__(self, name: str, cfg: dict, cwd: str):
        self.name, self.cfg = name, cfg
        self.trusted = bool(cfg.get("trusted", False))
        self.tools: list[dict] = []
        env = dict(os.environ, **{k: str(v) for k, v in (cfg.get("env") or {}).items()})
        command = sys.executable if cfg["command"] == "python" else cfg["command"]  # same interpreter as the gateway
        self.proc = subprocess.Popen([command, *cfg.get("args", [])], stdin=subprocess.PIPE,
                                     stdout=subprocess.PIPE, stderr=sys.stderr, cwd=cfg.get("cwd") or cwd, env=env)
        self.peer = Peer(self.proc.stdout, self.proc.stdin)
        self.peer.serve_in_background()

    def start(self) -> None:
        self.peer.request("initialize", {"protocolVersion": SUPPORTED_VERSIONS[-1], "capabilities": {},
                                         "clientInfo": {"name": "kavach-gateway", "version": VERSION}}, timeout=30)
        self.peer.notify("notifications/initialized")
        cursor: Optional[str] = None
        while True:
            page = self.peer.request("tools/list", {"cursor": cursor} if cursor else {}, timeout=30) or {}
            self.tools += page.get("tools", [])
            cursor = page.get("nextCursor")
            if not cursor:
                break

    def changes_state(self, tool: dict) -> bool:
        """From the tool's own declaration; the user's config can override it per tool."""
        override = (self.cfg.get("changes_state") or {}).get(tool["name"])
        if override is not None:
            return bool(override)
        return (tool.get("annotations") or {}).get("readOnlyHint") is not True


class Gateway:
    def __init__(self, config: dict, config_dir: str = "."):
        self.mode = config.get("mode", "strict")
        self.ask_timeout = float(config.get("ask_timeout_seconds", 120))
        self.call_timeout = float(config.get("call_timeout_seconds", 300))
        self.graph, self.lock = ProvenanceGraph(), threading.RLock()
        self.events: list[dict] = []
        self.pending: dict[int, dict] = {}
        self.client: Optional[Peer] = None
        self.client_elicits = False
        self.servers: dict[str, Downstream] = {}
        self.routes: dict[str, tuple[Downstream, dict]] = {}
        for name, cfg in (config.get("servers") or {}).items():
            try:
                server = Downstream(name, cfg, config_dir)
                server.start()
            except Exception as e:
                log(f"could not start server '{name}':", repr(e))
                continue
            self.servers[name] = server
            for tool in server.tools:
                self.routes[f"{name}_{tool['name']}"] = (server, tool)
            log(f"server '{name}': {len(server.tools)} tools" + (" (trusted source)" if server.trusted else ""))

    # ---- the MCP server side, facing the agent ----

    def on_request(self, method: str, params: dict) -> Any:
        if method == "initialize":
            self.client_elicits = "elicitation" in (params.get("capabilities") or {})
            wanted = params.get("protocolVersion")
            return {"protocolVersion": wanted if wanted in SUPPORTED_VERSIONS else SUPPORTED_VERSIONS[-1],
                    "capabilities": {"tools": {"listChanged": False}},
                    "serverInfo": {"name": "kavach", "version": VERSION},
                    "instructions": "Tools are provided through the Kavach gateway. Some actions may need the "
                                    "user's approval; if an action is denied, tell the user and do not retry it."}
        if method == "ping":
            return {}
        if method == "tools/list":
            tools = []
            for exposed, (server, tool) in self.routes.items():
                spec = dict(tool, name=exposed)
                spec["description"] = f"[{server.name}] {tool.get('description') or ''}".strip()
                tools.append(spec)
            return {"tools": tools}
        if method == "tools/call":
            return self.call_tool(params)
        raise RpcError(METHOD_NOT_FOUND, f"method not found: {method}")

    def serve(self, rfile, wfile) -> None:
        self.client = Peer(rfile, wfile, self.on_request)
        self.client.serve()

    # ---- reviewing and forwarding one tool call ----

    def call_tool(self, params: dict) -> dict:
        exposed = params.get("name")
        if exposed not in self.routes:
            raise RpcError(INVALID_PARAMS, f"unknown tool: {exposed}")
        server, tool = self.routes[exposed]
        args = params.get("arguments") or {}
        action = Action(exposed, args, changes_state=server.changes_state(tool))

        with self.lock:
            decision = self.graph.review(AGENT, action, self.mode)
            traces = {path: {"origin": t.origin.value,
                             "sources": [self.graph.nodes[i].source for i in t.path],
                             "nodes": list(t.path)}
                      for path, t in self.graph.traces(AGENT, action).items()}
            event = {"id": len(self.events), "time": time.strftime("%H:%M:%S"), "server": server.name,
                     "tool": tool["name"], "args": args, "changes_state": action.changes_state,
                     "verdict": decision.verdict.value, "reason": decision.reason, "traces": traces,
                     "human": None, "executed": False, "output": None, "node": None, "trusted": server.trusted}
            self.events.append(event)

        if decision.verdict is not Verdict.ALLOW and not self.ask_human(event):
            return {"content": [{"type": "text", "text":
                    f"Kavach blocked this action: the user did not approve it. Reason: {decision.reason}. "
                    "Do not retry; tell the user what you were trying to do."}], "isError": True}

        result = server.peer.request("tools/call", dict(params, name=tool["name"]), timeout=self.call_timeout) or {}
        text = "\n".join(b.get("text", "") for b in result.get("content") or [] if b.get("type") == "text")
        if result.get("structuredContent") is not None:
            text += "\n" + json.dumps(result["structuredContent"], ensure_ascii=False)
        with self.lock:
            event["executed"], event["output"] = True, text[:4000]
            if not server.trusted:  # content from a server the user marked trusted is treated as their own
                event["node"] = self.graph.reads(AGENT, f"{server.name}.{tool['name']}", text).id
        return result

    # ---- asking the human ----

    def describe(self, event: dict) -> str:
        lines = [f"The agent wants to run {event['server']}.{event['tool']}."]
        for path, t in event["traces"].items():
            if t["origin"] == "read":
                value = str(_dig(event["args"], path))
                lines.append(f"'{path}' = {value[:120]!r} did not come from you. It came from: {' <- '.join(t['sources'])}.")
        return " ".join(lines) + " Allow it?"

    def ask_human(self, event: dict) -> bool:
        slot = {"event": threading.Event(), "approved": False}
        with self.lock:
            self.pending[event["id"]] = slot
        if self.client_elicits and self.client is not None:
            threading.Thread(target=self._elicit, args=(event, slot), daemon=True).start()
        slot["event"].wait(self.ask_timeout)
        with self.lock:
            self.pending.pop(event["id"], None)
            answered = slot["event"].is_set()
            event["human"] = ("approved" if slot["approved"] else "denied") if answered else "no answer (denied)"
        return answered and slot["approved"]

    def _elicit(self, event: dict, slot: dict) -> None:
        """Ask through the agent's own UI where the client supports it. The dashboard works either way."""
        try:
            answer = self.client.request("elicitation/create", {
                "message": self.describe(event),
                "requestedSchema": {"type": "object", "properties": {}}}, timeout=self.ask_timeout)
        except RpcError:
            return
        self.answer(event["id"], (answer or {}).get("action") == "accept")

    def answer(self, event_id: int, approve: bool) -> bool:
        with self.lock:
            slot = self.pending.get(event_id)
            if slot is None or slot["event"].is_set():
                return False
            slot["approved"] = bool(approve)
            slot["event"].set()
            return True

    def user_says(self, text: str) -> None:
        """Optional: a client hook can report the user's prompt, so values the user typed count as theirs."""
        with self.lock:
            self.graph.user_says(AGENT, text)
            self.events.append({"id": len(self.events), "time": time.strftime("%H:%M:%S"), "prompt": text[:2000]})

    def state(self) -> dict:
        with self.lock:
            return {"mode": self.mode, "pending": sorted(self.pending),
                    "servers": [{"name": s.name, "trusted": s.trusted, "tools": len(s.tools)} for s in self.servers.values()],
                    "events": json.loads(json.dumps(self.events, default=str))}


def _dig(args: Any, path: str) -> Any:
    for part in path.replace("]", "").replace("[", ".").split("."):
        if part == "":
            continue
        args = args[int(part)] if isinstance(args, list) else args[part]
    return args
