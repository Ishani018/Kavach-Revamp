"""
kavach/api.py
=============

Minimal local HTTP API.

    GET  /health
    POST /check            -> Decision   (alias: POST /hook/parliament)

Run:  python -m uvicorn kavach.api:app --host 127.0.0.1 --port 8088
"""

from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from typing import Any, Optional

from fastapi import FastAPI

from .coordinator import Coordinator
from .schemas import MINISTER_NAMES, Decision, ToolCall

log = logging.getLogger("kavach.api")


def build_default_coordinator() -> Coordinator:
    from .ministers.channel import ChannelMinister
    from .ministers.executor import ExecutorMinister
    from .ministers.navigator import NavigatorMinister
    from .ministers.vault import VaultMinister

    return Coordinator([VaultMinister(), ExecutorMinister(), ChannelMinister(), NavigatorMinister()])


def create_app(coordinator: Optional[Coordinator] = None) -> FastAPI:
    """Pass a coordinator to inject one (tests); otherwise the real four ministers
    are built at startup. A startup failure (e.g. NAVIGATOR cannot load) stops the
    server rather than serving without a required minister."""
    state: dict = {"coordinator": coordinator}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if state["coordinator"] is None:
            state["coordinator"] = build_default_coordinator()
        yield

    app = FastAPI(title="Kavach MVP", version="0.1.0", lifespan=lifespan)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok", "ministers": list(MINISTER_NAMES)}

    def check(call: ToolCall) -> Decision:
        return state["coordinator"].evaluate(call)

    app.post("/check", response_model=Decision)(check)
    app.post("/hook/parliament", response_model=Decision, include_in_schema=False)(check)
    return app


app = create_app()
