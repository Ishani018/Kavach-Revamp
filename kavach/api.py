"""
Kavach's API and small same-origin dashboard.
Supabase credentials are read only from the server environment and never returned to clients.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import time
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any, Optional

import httpx
from fastapi import FastAPI, HTTPException, Query, Request, Response
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field

from .coordinator import Coordinator
from .schemas import MINISTER_NAMES, Decision, ToolCall

log = logging.getLogger("kavach.api")
WEB_INDEX = Path(__file__).resolve().parents[1] / "web" / "index.html"
WEB_LOGO = Path(__file__).resolve().parents[1] / "web" / "assets" / "kavach-shield.png"
SESSION_COOKIE = "kavach_session"
SESSION_MAX_AGE = 8 * 60 * 60
CATALOG_COLUMNS = (
    "id,record_key,minister,definition_type,definition_id,l1_intent,l2_mechanism,"
    "l3_surface,category,source_citation,technique_ids,source_url,source_license,"
    "provenance_flags,repo_path,git_ref,origin_status,review_status,notes"
)
SEARCH_COLUMNS = ("definition_id", "l1_intent", "l2_mechanism", "l3_surface", "category")


class LoginRequest(BaseModel):
    password: str = Field(min_length=1, max_length=512)


def build_default_coordinator() -> Coordinator:
    from .ministers.channel import ChannelMinister
    from .ministers.executor import ExecutorMinister
    from .ministers.navigator import NavigatorMinister
    from .ministers.vault import VaultMinister

    return Coordinator([VaultMinister(), ExecutorMinister(), ChannelMinister(), NavigatorMinister()])


def _dashboard_auth_configured() -> bool:
    return bool(os.getenv("KAVACH_DASHBOARD_PASSWORD") and os.getenv("KAVACH_SESSION_SECRET"))


def _supabase_configured() -> bool:
    return bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SECRET_KEY"))


def _session_token(secret: str, expires_at: int) -> str:
    payload = str(expires_at)
    signature = hmac.new(secret.encode("utf-8"), payload.encode("ascii"), hashlib.sha256).hexdigest()
    return payload + "." + signature


def _valid_session(request: Request) -> bool:
    secret = os.getenv("KAVACH_SESSION_SECRET")
    token = request.cookies.get(SESSION_COOKIE, "")
    if not secret or not token or "." not in token:
        return False
    try:
        expiry_text, supplied_signature = token.split(".", 1)
        expiry = int(expiry_text)
    except (ValueError, TypeError):
        return False
    if expiry <= int(time.time()):
        return False
    expected = _session_token(secret, expiry).split(".", 1)[1]
    return hmac.compare_digest(supplied_signature, expected)


def _count_from_content_range(value: str | None) -> int | None:
    if not value or "/" not in value:
        return None
    total = value.rsplit("/", 1)[1]
    return int(total) if total.isdigit() else None


def _supabase_headers(secret_key: str) -> dict[str, str]:
    # Supabase's modern sb_secret_* keys are not JWTs. Send them only in
    # apikey; using Authorization: Bearer causes Invalid JWT errors.
    return {
        "apikey": secret_key,
        "Accept": "application/json",
    }


def create_app(coordinator: Optional[Coordinator] = None) -> FastAPI:
    """Inject a coordinator in tests; otherwise construct the real ministers on startup."""
    state: dict[str, Any] = {"coordinator": coordinator}

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        if state["coordinator"] is None:
            state["coordinator"] = build_default_coordinator()
        yield

    app = FastAPI(
        title="Kavach Agent Safety Console",
        version="0.2.0",
        description="Evaluate proposed agent tool calls and browse the protected rules catalogue.",
        lifespan=lifespan,
    )

    @app.get("/", include_in_schema=False)
    def dashboard() -> FileResponse:
        if not WEB_INDEX.is_file():
            raise HTTPException(status_code=404, detail="Dashboard assets are not installed.")
        return FileResponse(WEB_INDEX, media_type="text/html")

    @app.get("/assets/kavach-shield.png", include_in_schema=False)
    def dashboard_logo() -> FileResponse:
        if not WEB_LOGO.is_file():
            raise HTTPException(status_code=404, detail="Dashboard logo is not installed.")
        return FileResponse(WEB_LOGO, media_type="image/png", headers={"Cache-Control": "public, max-age=3600"})

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"status": "ok", "ministers": list(MINISTER_NAMES)}

    @app.get("/api/session")
    def session_status(request: Request) -> dict[str, bool]:
        return {
            "authenticated": _valid_session(request),
            "login_configured": _dashboard_auth_configured(),
        }

    @app.post("/api/login")
    def login(payload: LoginRequest, request: Request, response: Response) -> dict[str, bool]:
        configured_password = os.getenv("KAVACH_DASHBOARD_PASSWORD")
        session_secret = os.getenv("KAVACH_SESSION_SECRET")
        if not configured_password or not session_secret:
            raise HTTPException(
                status_code=503,
                detail="Dashboard login is not configured on the server yet.",
            )
        if not hmac.compare_digest(payload.password, configured_password):
            raise HTTPException(status_code=401, detail="Incorrect password.")
        expiry = int(time.time()) + SESSION_MAX_AGE
        is_https = request.url.scheme == "https" or os.getenv("RENDER_EXTERNAL_URL", "").startswith("https://")
        response.set_cookie(
            key=SESSION_COOKIE,
            value=_session_token(session_secret, expiry),
            max_age=SESSION_MAX_AGE,
            httponly=True,
            secure=is_https,
            samesite="lax",
            path="/",
        )
        return {"authenticated": True}

    @app.post("/api/logout")
    def logout(response: Response) -> dict[str, bool]:
        response.delete_cookie(
            key=SESSION_COOKIE, path="/", httponly=True, secure=True, samesite="lax"
        )
        # Also clear a local HTTP cookie used in development.
        response.delete_cookie(
            key=SESSION_COOKIE, path="/", httponly=True, secure=False, samesite="lax"
        )
        return {"authenticated": False}

    @app.get("/api/status")
    async def integration_status() -> dict[str, Any]:
        result: dict[str, Any] = {
            "api": "online",
            "catalog_login_configured": _dashboard_auth_configured(),
            "supabase": {"configured": _supabase_configured(), "connected": False, "records": None},
        }
        if not _supabase_configured():
            return result

        base_url = os.getenv("SUPABASE_URL", "").rstrip("/")
        secret_key = os.getenv("SUPABASE_SECRET_KEY", "")
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                reply = await client.get(
                    base_url + "/rest/v1/minister_definitions",
                    params={"select": "id"},
                    headers={
                        **_supabase_headers(secret_key),
                        "Range-Unit": "items",
                        "Range": "0-0",
                        "Prefer": "count=exact",
                    },
                )
                reply.raise_for_status()
            result["supabase"] = {
                "configured": True,
                "connected": True,
                "records": _count_from_content_range(reply.headers.get("content-range")),
            }
        except (httpx.HTTPError, ValueError):
            # Do not send upstream error bodies or headers to the browser.
            log.warning("Supabase connectivity check failed.")
            result["supabase"] = {"configured": True, "connected": False, "records": None}
        return result

    @app.get("/api/catalog")
    async def catalog(
        request: Request,
        minister: str | None = Query(default=None, pattern="^(VAULT|EXECUTOR|CHANNEL|NAVIGATOR)$"),
        search: str = Query(default="", max_length=100),
        page: int = Query(default=1, ge=1, le=1000),
    ) -> dict[str, Any]:
        if not _dashboard_auth_configured():
            raise HTTPException(
                status_code=503,
                detail="The private rules catalogue is locked until dashboard login is configured.",
            )
        if not _valid_session(request):
            raise HTTPException(status_code=401, detail="Sign in to view the rules catalogue.")
        if not _supabase_configured():
            raise HTTPException(
                status_code=503,
                detail="Supabase is not configured on the server. Add SUPABASE_URL and SUPABASE_SECRET_KEY.",
            )

        base_url = os.getenv("SUPABASE_URL", "").rstrip("/")
        secret_key = os.getenv("SUPABASE_SECRET_KEY", "")
        page_size = 50
        offset = (page - 1) * page_size
        params: dict[str, str] = {
            "select": CATALOG_COLUMNS,
            "order": "minister.asc,definition_type.asc,record_key.asc",
            "limit": str(page_size),
            "offset": str(offset),
        }
        if minister:
            params["minister"] = "eq." + minister
        # Restrict filter characters so user input cannot add PostgREST filter clauses.
        safe_search = re.sub(r"[^a-zA-Z0-9 _./:-]", " ", search).strip()
        if safe_search:
            params["or"] = "(" + ",".join(
                field + ".ilike.*" + safe_search + "*" for field in SEARCH_COLUMNS
            ) + ")"

        try:
            async with httpx.AsyncClient(timeout=12.0) as client:
                reply = await client.get(
                    base_url + "/rest/v1/minister_definitions",
                    params=params,
                    headers={
                        **_supabase_headers(secret_key),
                        "Range-Unit": "items",
                        "Range": str(offset) + "-" + str(offset + page_size - 1),
                        "Prefer": "count=exact",
                    },
                )
                reply.raise_for_status()
                rows = reply.json()
            if not isinstance(rows, list):
                raise ValueError("Unexpected catalogue response.")
        except (httpx.HTTPError, ValueError):
            log.warning("Supabase catalogue query failed.")
            raise HTTPException(status_code=502, detail="Supabase could not complete the catalogue request.")

        return {
            "records": rows,
            "total": _count_from_content_range(reply.headers.get("content-range")),
            "page": page,
            "page_size": page_size,
        }

    def check(call: ToolCall) -> Decision:
        return state["coordinator"].evaluate(call)

    app.post("/check", response_model=Decision)(check)
    app.post("/hook/parliament", response_model=Decision, include_in_schema=False)(check)
    return app


app = create_app()
