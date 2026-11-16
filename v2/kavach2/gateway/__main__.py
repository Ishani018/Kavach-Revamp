"""Run the gateway:  python -m kavach2.gateway --config kavach.json

The agent (VS Code Copilot, Cursor, Claude Desktop, ...) starts this as its one MCP server.
"""
from __future__ import annotations

import argparse
import json
import os
import sys

from . import dashboard
from .core import Gateway
from .rpc import log


def main() -> None:
    ap = argparse.ArgumentParser(description="Kavach MCP gateway")
    ap.add_argument("--config", required=True, help="JSON file listing the MCP servers to protect")
    ap.add_argument("--port", type=int, default=None, help="dashboard port (default 8766)")
    ap.add_argument("--url-file", help="write the dashboard URL to this file")
    args = ap.parse_args()
    with open(args.config, encoding="utf-8") as f:
        config = json.load(f)
    config_dir = os.path.dirname(os.path.abspath(args.config))
    gateway = Gateway(config, config_dir)
    url = dashboard.start(gateway, args.port or int(config.get("dashboard_port", 8766)))
    url_file = args.url_file or config.get("dashboard_url_file")
    if url_file:  # relative paths are relative to the config file, whatever directory the client starts us in
        url_file = os.path.join(config_dir, url_file)
    if url and url_file:
        with open(url_file, "w", encoding="utf-8") as f:
            f.write(url + "\n")
    log(f"ready: {len(gateway.routes)} tools from {len(gateway.servers)} servers, mode={gateway.mode}")
    gateway.serve(sys.stdin.buffer, sys.stdout.buffer)


if __name__ == "__main__":
    main()
