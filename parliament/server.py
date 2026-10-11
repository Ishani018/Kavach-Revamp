#!/usr/bin/env python3
"""
parliament/server.py
====================

Kavach Parliament — production HTTP service.

v2.1 changes (hybrid retrieval):
- BM25 indexes built at startup for each minister collection
- run_minister_hybrid() used instead of run_minister() — fuses BM25 + dense
  with Reciprocal Rank Fusion (RRF, k=60) to reduce false positive rate
- Graceful fallback to dense-only if rank_bm25 not installed
- /health now reports retrieval_mode: "hybrid" or "dense"

Default port: 8088 (the OpenClaw plugin defaults to this URL).

Endpoints:
    GET  /health
    POST /hook/seed_intent      — store user intent vector for a session
    POST /hook/check_drift      — COMPASS-only drift check vs stored intent
    POST /hook/parliament       — full pipeline: COMPASS + router + ministers
    GET  /ledger/votes          — recent decisions

Run:
    python -m uvicorn parliament.server:app --host 127.0.0.1 --port 8088
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import sqlite3
import time
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import chromadb
import numpy as np
import uvicorn
import yaml
from chromadb.config import Settings
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, Field
from sentence_transformers import SentenceTransformer

try:
    from .ministers import (
        MinisterScan,
        run_minister,
        run_minister_dual,
        run_minister_hybrid,
        run_minister_dual_hybrid,
        build_bm25_index,
    )
    from .speaker import SpeakerVerdict, combine_verdicts
    from . import trajectory as traj
    from . import provenance as prov
    from . import prefilters
    from . import channel_taint
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
    from parliament.ministers import (
        MinisterScan,
        run_minister,
        run_minister_dual,
        run_minister_hybrid,
        run_minister_dual_hybrid,
        build_bm25_index,
    )
    from parliament.speaker import SpeakerVerdict, combine_verdicts
    from parliament import trajectory as traj
    from parliament import provenance as prov
    from parliament import prefilters
    from parliament import channel_taint

# ──────────────────────────────────────────────────────────────────────────────
# Configuration loading
# ──────────────────────────────────────────────────────────────────────────────

ROOT = Path(__file__).resolve().parent
CONFIG_PATH = ROOT / "config.yaml"
ROUTER_PATH = ROOT.parent / "kavach_router_config.json"
DB_PATH = ROOT / "kavach_parliament.db"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)-7s %(name)s: %(message)s",
)
log = logging.getLogger("kavach.parliament")


def _load_config() -> dict:
    if CONFIG_PATH.exists():
        return yaml.safe_load(CONFIG_PATH.read_text())
    log.warning("config.yaml missing, using defaults")
    return {
        "embed_model": "BAAI/bge-base-en-v1.5",
        "chroma_path": str(ROOT / ".chroma_kavach"),
        "router_config_path": str(ROUTER_PATH),
        "thresholds": {
            "block":          0.65,
            "grey":           0.50,
            "compass_drift":  0.40,
            "router_min":     0.40,
        },
        "query_prefix":
            "Represent this sentence for searching relevant passages: ",
        "ministers": ["EXECUTOR", "VAULT", "CHANNEL", "NAVIGATOR"],
        "compass_collection": "COMPASS",
        "host": "127.0.0.1",
        "port": 8088,
    }


CFG = _load_config()

# KAVACH_EMBED_MODEL overrides config.yaml's embed_model when set, so the server
# can be started against a non-default embedding model (e.g. for the §4.6
# embedding-comparison workstream) without editing the YAML. Unset → no change.
_embed_override = os.environ.get("KAVACH_EMBED_MODEL")
if _embed_override:
    log.info("embed_model overridden via KAVACH_EMBED_MODEL: %s", _embed_override)
    CFG["embed_model"] = _embed_override
    # Auto-set the query prefix to match the overridden model, so an
    # embedding-comparison run queries with the model's OWN convention rather than
    # BGE's (e.g. e5 wants "query: ", gte wants none). Reuses the loader's map so
    # the query-side and index-side prefixes stay in sync. Only fires on override;
    # the default path keeps config.yaml's query_prefix untouched.
    try:
        from corpus_loader import _prefixes_for as _pf
        _qp, _ = _pf(_embed_override)
        CFG["query_prefix"] = _qp
        log.info("query_prefix auto-set for %s: %r", _embed_override, _qp)
    except Exception as _e:  # pragma: no cover — never break startup on this
        log.warning("could not auto-set query_prefix (%s); using config value", _e)

# KAVACH_CHROMA_PATH likewise overrides config.yaml's chroma_path — so a run can
# point the server at a scratch ChromaDB (e.g. an embedding-comparison index)
# without editing the YAML. Unset → no change (production .chroma_kavach).
_chroma_override = os.environ.get("KAVACH_CHROMA_PATH")
if _chroma_override:
    log.info("chroma_path overridden via KAVACH_CHROMA_PATH: %s", _chroma_override)
    CFG["chroma_path"] = _chroma_override


# ──────────────────────────────────────────────────────────────────────────────
# Global state
# ──────────────────────────────────────────────────────────────────────────────

from collections import defaultdict

_state: dict[str, Any] = {
    "model":      None,
    "chroma":     None,
    "collections": {},      # minister name → chroma Collection (v1 semantic corpus)
    "tech_collections": {},  # minister name → chroma Collection (technical precision corpus)
    "bm25_indexes": {},      # minister name → bm25 index dict (built at startup)
    "router":     None,
    "intents":    {},    # session_id → np.ndarray (BGE vector of user intent)
    "history":    defaultdict(traj.new_history),  # session_id → deque[ActionRecord]
    "channel_taint": defaultdict(channel_taint.new_taint_state),  # session_id → SessionTaint
    "channel_provenance": defaultdict(channel_taint.new_provenance_state),  # session_id → SessionProvenance (independent of channel_taint -- see composition rule in channel_taint.py)
}


def _embed_query(text: str) -> np.ndarray:
    """BGE query-side embedding with the asymmetric instruction prefix."""
    prefix = CFG["query_prefix"]
    vec = _state["model"].encode(
        prefix + text,
        normalize_embeddings=True,
        show_progress_bar=False,
    )
    return np.asarray(vec, dtype=np.float32)


def _embed_doc(text: str) -> np.ndarray:
    """BGE document-side embedding — no prefix."""
    vec = _state["model"].encode(
        text,
        normalize_embeddings=True,
        show_progress_bar=False,
    )
    return np.asarray(vec, dtype=np.float32)


def _cosine(a: np.ndarray, b: np.ndarray) -> float:
    return float(np.dot(a, b))   # both normalized


# ──────────────────────────────────────────────────────────────────────────────
# Routing
# ──────────────────────────────────────────────────────────────────────────────

def _route(text: str) -> list[str]:
    """Return the list of ministers to activate for this text."""
    q = _embed_query(text)
    activated: list[str] = []
    threshold = CFG["thresholds"]["router_min"]

    for minister, descriptions in _state["router"].items():
        max_sim = 0.0
        for desc in descriptions:
            doc_vec = _embed_doc(desc)
            sim = _cosine(q, doc_vec)
            if sim > max_sim:
                max_sim = sim
        if max_sim >= threshold:
            activated.append(minister)

    if not activated:
        log.info("router: no minister crossed %.2f, falling back to all four", threshold)
        return list(_state["router"].keys())

    return activated


# ──────────────────────────────────────────────────────────────────────────────
# Per-minister threshold helper (issue #3)
# ──────────────────────────────────────────────────────────────────────────────

def _get_minister_thresholds(minister: str, call_thresholds: dict) -> dict:
    """Return per-minister thresholds with trajectory/COMPASS modulation applied.

    The base block value comes from config per_minister (if set), falling back
    to the global block. The modulation delta already baked into call_thresholds
    (trajectory risk + COMPASS drift adjustment) is preserved by computing the
    delta and applying it to the per-minister base.
    """
    per = CFG["thresholds"].get("per_minister", {})
    if minister not in per:
        return call_thresholds  # no override — use the already-modulated base

    minister_base  = float(per[minister])
    global_base    = float(CFG["thresholds"]["block"])
    modulated_base = float(call_thresholds["block"])
    delta          = modulated_base - global_base  # trajectory + COMPASS adjustment

    effective_block = float(np.clip(minister_base + delta, 0.30, 0.90))
    return {**call_thresholds, "block": effective_block}


# ──────────────────────────────────────────────────────────────────────────────
# COMPASS drift — cosine between session intent vector and proposed action
# ──────────────────────────────────────────────────────────────────────────────

def _compass_drift(session_id: str, action_text: str,
                   action_vec: np.ndarray | None = None) -> tuple[bool, float]:
    """Return (drift_detected, similarity). If no intent stored, returns (False, 1.0).

    `action_vec`: optional precomputed BGE vector for `action_text` (embed-once
    path). When None, embeds internally (legacy behaviour).
    """
    intent_vec = _state["intents"].get(session_id)
    if intent_vec is None:
        return (False, 1.0)
    if action_vec is None:
        action_vec = _embed_query(action_text)
    sim = _cosine(intent_vec, action_vec)
    drift = sim < CFG["thresholds"]["compass_drift"]
    return (drift, sim)


# ──────────────────────────────────────────────────────────────────────────────
# SQLite ledger
# ──────────────────────────────────────────────────────────────────────────────

def _init_db() -> None:
    conn = sqlite3.connect(DB_PATH)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS votes (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            ts              TEXT NOT NULL,
            session_id      TEXT NOT NULL,
            correlation_id  TEXT,
            stage           TEXT,
            input_text      TEXT,
            verdict         TEXT,
            decided_by      TEXT,
            confidence      REAL,
            reason          TEXT,
            ministers_json  TEXT,
            compass_sim     REAL,
            traj_risk       REAL,
            latency_ms      REAL,
            provenance_json TEXT,
            retrieval_mode  TEXT,
            short_circuited INTEGER,
            prev_hash       TEXT,
            entry_hash      TEXT
        )
    """)
    # Migrate older DBs: add columns the table may predate.
    cols = {row[1] for row in conn.execute("PRAGMA table_info(votes)")}
    if "traj_risk" not in cols:
        conn.execute("ALTER TABLE votes ADD COLUMN traj_risk REAL")
    if "prev_hash" not in cols:
        conn.execute("ALTER TABLE votes ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in cols:
        conn.execute("ALTER TABLE votes ADD COLUMN entry_hash TEXT")
    if "provenance_json" not in cols:
        conn.execute("ALTER TABLE votes ADD COLUMN provenance_json TEXT")
    if "retrieval_mode" not in cols:
        conn.execute("ALTER TABLE votes ADD COLUMN retrieval_mode TEXT")
    if "short_circuited" not in cols:
        # Pipeline-reordering optimization: marks ledger rows written by
        # the short-circuit response path (VAULT/EXECUTOR/CHANNEL
        # confident BLOCK, COMPASS/routing/NAVIGATOR skipped on the
        # response path and backfilled asynchronously afterward via a
        # separate stage="parliament_async_completion" row with the same
        # correlation_id). NULL/0 for every row written before this
        # optimization existed or by the full synchronous pipeline.
        conn.execute("ALTER TABLE votes ADD COLUMN short_circuited INTEGER")
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Tamper-evident hash chain
# ──────────────────────────────────────────────────────────────────────────────
# Each ledger row stores entry_hash = SHA-256(prev_hash || canonical_row). Any
# edit, deletion, or reordering of a historical row breaks every subsequent
# entry_hash, so /ledger/verify detects tampering in O(n). This makes the
# production SQLite ledger tamper-EVIDENT (not tamper-proof — an attacker with
# write access can recompute the whole chain; defeating that needs an external
# anchor, noted as future work). Matches the browser-lab hash chain so the two
# are now consistent.

GENESIS_HASH = "0" * 64


def _entry_hash(prev_hash: str, row: dict) -> str:
    """SHA-256 over the previous hash plus a canonical serialization of the
    content-bearing fields (id/autoincrement excluded — it is not content)."""
    fields = ["ts", "session_id", "correlation_id", "stage", "input_text",
              "verdict", "decided_by", "confidence", "reason", "ministers_json",
              "compass_sim", "traj_risk", "latency_ms"]
    # Backward-compatible: provenance_json only enters the hash when present, so
    # rows written before provenance existed (and rows with no provenance) hash
    # identically under both old and new code. (June-10 self-audit fix.)
    if row.get("provenance_json") is not None:
        fields.append("provenance_json")
    # Same backward-compatible pattern for short_circuited (pipeline-
    # reordering optimization): only enters the hash when explicitly set,
    # so every row written before this optimization existed hashes
    # identically under old and new code.
    if row.get("short_circuited") is not None:
        fields.append("short_circuited")
    canonical = json.dumps(
        {k: row[k] for k in fields},
        sort_keys=True, separators=(",", ":"), default=str,
    )
    return hashlib.sha256((prev_hash + canonical).encode("utf-8")).hexdigest()


def _last_hash(conn) -> str:
    row = conn.execute(
        "SELECT entry_hash FROM votes ORDER BY id DESC LIMIT 1").fetchone()
    return row[0] if row and row[0] else GENESIS_HASH


def _log_vote(
    session_id: str,
    correlation_id: str,
    stage: str,
    input_text: str,
    verdict: str,
    decided_by: str,
    confidence: float,
    reason: str,
    ministers: dict,
    compass_sim: float | None,
    latency_ms: float,
    traj_risk: float | None = None,
    provenance: dict | None = None,
    retrieval_mode: str = "dense",
    short_circuited: bool | None = None,
) -> None:
    conn = sqlite3.connect(DB_PATH)
    row = {
        "ts":             datetime.now(timezone.utc).isoformat(),
        "session_id":     session_id,
        "correlation_id": correlation_id,
        "stage":          stage,
        "input_text":     input_text[:500],
        "verdict":        verdict,
        "decided_by":     decided_by,
        "confidence":     confidence,
        "reason":         reason[:500],
        "ministers_json": json.dumps(ministers),
        "compass_sim":    compass_sim,
        "traj_risk":      traj_risk,
        "latency_ms":     latency_ms,
        "provenance_json": json.dumps(provenance, sort_keys=True) if provenance else None,
        "short_circuited": (1 if short_circuited else 0) if short_circuited is not None else None,
    }
    prev_hash  = _last_hash(conn)
    entry_hash = _entry_hash(prev_hash, row)
    conn.execute(
        """INSERT INTO votes
           (ts, session_id, correlation_id, stage, input_text, verdict,
            decided_by, confidence, reason, ministers_json, compass_sim,
            traj_risk, latency_ms, provenance_json, retrieval_mode,
            short_circuited, prev_hash, entry_hash)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (*[row[k] for k in (
            "ts", "session_id", "correlation_id", "stage", "input_text",
            "verdict", "decided_by", "confidence", "reason", "ministers_json",
            "compass_sim", "traj_risk", "latency_ms", "provenance_json")],
         retrieval_mode, row["short_circuited"], prev_hash, entry_hash),
    )
    conn.commit()
    conn.close()


# ──────────────────────────────────────────────────────────────────────────────
# Lifespan — load model, chroma collections, BM25 indexes, router
# ──────────────────────────────────────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("loading BGE model: %s", CFG["embed_model"])
    _state["model"] = SentenceTransformer(CFG["embed_model"])

    chroma_path = Path(CFG["chroma_path"])
    if not chroma_path.is_absolute():
        chroma_path = (ROOT.parent / chroma_path).resolve()
    log.info("opening Chroma at: %s", chroma_path)
    chroma_path.mkdir(parents=True, exist_ok=True)
    _state["chroma"] = chromadb.PersistentClient(
        path=str(chroma_path),
        settings=Settings(anonymized_telemetry=False),
    )

    _COLL_NAMES = {
        "EXECUTOR":  "kavach_executor",
        "VAULT":     "kavach_vault",
        "CHANNEL":   "kavach_channel",
        "NAVIGATOR": "kavach_navigator",
        "COMPASS":   "kavach_compass_calibration",
    }
    for minister in CFG["ministers"] + [CFG["compass_collection"]]:
        try:
            coll_name = _COLL_NAMES.get(minister, f"kavach_{minister.lower()}")
            _state["collections"][minister] = (
                _state["chroma"].get_collection(name=coll_name)
            )
            log.info("collection loaded: %s → %s (%d docs)",
                     minister, coll_name, _state["collections"][minister].count())
        except Exception as e:
            log.error(
                "collection %s (name=%s) missing: %s — run corpus_loader.py first",
                minister, _COLL_NAMES.get(minister, "?"), e,
            )
            raise

    # Load technical precision collections (non-fatal if absent)
    _TECH_NAMES = {
        "EXECUTOR":  "kavach_executor_tech",
        "VAULT":     "kavach_vault_tech",
        "CHANNEL":   "kavach_channel_tech",
        "NAVIGATOR": "kavach_navigator_tech",
    }
    for _minister in CFG["ministers"]:
        _tname = _TECH_NAMES.get(_minister)
        if not _tname:
            continue
        try:
            _state["tech_collections"][_minister] = (
                _state["chroma"].get_collection(name=_tname)
            )
            log.info("tech collection loaded: %s (%d docs)",
                     _minister, _state["tech_collections"][_minister].count())
        except Exception:
            _state["tech_collections"][_minister] = None
            log.info("tech collection %s not found — using v1 only", _minister)

    # ── Build BM25 indexes for hybrid retrieval (FPR fix) ────────────────────
    log.info("building BM25 indexes for hybrid retrieval...")
    _hybrid_available = False
    for minister in CFG["ministers"]:
        try:
            idx = build_bm25_index(_state["collections"][minister])
            _state["bm25_indexes"][minister] = idx
            if idx:
                log.info("BM25 index built: %s (%d docs)",
                         minister, idx["bm25"].corpus_size)
                _hybrid_available = True
            else:
                log.warning(
                    "BM25 index skipped for %s (rank_bm25 not installed — "
                    "run: pip install rank-bm25)", minister
                )
        except Exception as e:
            log.warning("BM25 index build failed for %s: %s", minister, e)
            _state["bm25_indexes"][minister] = None

    retrieval_mode = "hybrid" if _hybrid_available else "dense"
    log.info("retrieval mode: %s", retrieval_mode)
    _state["retrieval_mode"] = retrieval_mode

    log.info("loading router config: %s", CFG["router_config_path"])
    with open(CFG["router_config_path"]) as f:
        _router_full = json.load(f)
    _state["router"] = _router_full.get("routing_corpus", _router_full)
    _state["router"].pop("COMPASS", None)
    log.info("router loaded ministers: %s", list(_state["router"].keys()))

    _init_db()
    log.info("parliament ready on %s:%d  [retrieval=%s]",
             CFG["host"], CFG["port"], retrieval_mode)
    yield
    log.info("parliament shutting down")


# ──────────────────────────────────────────────────────────────────────────────
# FastAPI app
# ──────────────────────────────────────────────────────────────────────────────

app = FastAPI(
    title="Kavach Parliament API",
    version="2.1.0",
    description="Semantic firewall for LLM agents — hybrid BM25+dense retrieval",
    lifespan=lifespan,
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


# ──────────────────────────────────────────────────────────────────────────────
# Request / response models
# ──────────────────────────────────────────────────────────────────────────────

class IntentRequest(BaseModel):
    text:       str
    session_id: str = "default"


class ParliamentRequest(BaseModel):
    text:       str
    session_id: str = "default"
    context:    dict[str, Any] = Field(default_factory=dict)


class MinisterResult(BaseModel):
    verdict:        str
    confidence:     float
    matched_id:     str | None = None
    matched_text:   str | None = None
    retrieval_mode: str = "dense"


class ParliamentResponse(BaseModel):
    verdict:        str
    speaker:        dict[str, Any]
    ministers:      dict[str, MinisterResult]
    pattern:        str
    provenance:     dict[str, Any] | None = None
    compass_sim:    float | None
    traj_risk:      float | None = None
    activated:      list[str]
    retrieval_mode: str
    correlation_id: str
    latency_ms:     float
    ts:             str
    short_circuited: bool = False


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@app.get("/health")
async def health() -> dict[str, Any]:
    return {
        "status":         "ok",
        "service":        "Kavach Parliament API",
        "version":        "2.1.0",
        "host":           CFG["host"],
        "port":           CFG["port"],
        "model":          CFG["embed_model"],
        "ministers":      list(CFG["ministers"]),
        "thresholds":     CFG["thresholds"],
        "retrieval_mode": _state.get("retrieval_mode", "dense"),
        "doc_counts": {
            m: _state["collections"][m].count()
            for m in CFG["ministers"] + [CFG["compass_collection"]]
        },
        "active_sessions": len(_state["intents"]),
    }


@app.post("/hook/seed_intent")
async def seed_intent(req: IntentRequest) -> dict[str, Any]:
    vec = _state["intents"][req.session_id] = _embed_query(req.text)
    return {"ok": True, "session_id": req.session_id, "dim": int(vec.shape[0])}


@app.post("/hook/check_drift")
async def check_drift(req: ParliamentRequest) -> dict[str, Any]:
    drift, sim = _compass_drift(req.session_id, req.text)
    return {
        "session_id":     req.session_id,
        "compass_sim":    sim,
        "drift_detected": drift,
        "threshold":      CFG["thresholds"]["compass_drift"],
        "verdict":        "BLOCK" if drift else "ALLOW",
    }


# ──────────────────────────────────────────────────────────────────────────────
# Cosine as ESCALATE-ONLY triage for VAULT/EXECUTOR (Kavach-PB Part 3)
# ──────────────────────────────────────────────────────────────────────────────
# SAFETY CONTRACT (mirrors CHANNEL's provenance "cannot BLOCK" guarantee):
# This is the ONE AND ONLY place a cosine-derived MinisterScan is constructed
# for VAULT or EXECUTOR. Its verdict is HARDCODED to "ESCALATE" -- it is
# structurally incapable of returning BLOCK or ALLOW, independent of any
# similarity score or threshold. It runs ONLY on the deterministic-miss
# residual (see the caller: skipped entirely when a prefilter already fired
# for that minister), so it can never override a deterministic BLOCK and can
# only add an ESCALATE to a call the deterministic rules let through. This
# makes it impossible to reintroduce the original cosine-BLOCK FPR problem:
# cosine here cannot block anything, only flag-for-review the long tail.
_COSINE_TRIAGE_ESCALATE_THRESHOLD = 0.45  # only ESCALATE on a non-trivial similarity; below this, stay silent (ALLOW-by-omission)


def _cosine_triage_escalate(minister: str, req_text: str, action_vec) -> MinisterScan | None:
    """Query minister's cosine collection and return a HARDCODED-ESCALATE scan
    if similarity clears a floor, else None. Never BLOCK, never ALLOW-scan --
    the only two outcomes are (ESCALATE, None). See the safety contract above.
    Only called for minister in {VAULT, EXECUTOR} on the deterministic-miss
    residual."""
    assert minister in ("VAULT", "EXECUTOR"), "cosine triage is VAULT/EXECUTOR-only"
    bm25_idx = _state["bm25_indexes"].get(minister)
    coll = _state["collections"].get(minister)
    if coll is None:
        return None
    # Reuse the existing hybrid scorer purely to obtain a similarity + nearest
    # pattern; we DISCARD its verdict entirely and impose our own. Thresholds
    # passed are irrelevant to the outcome (we ignore raw.verdict), but we pass
    # the real ones so confidence/matched_id are populated normally.
    raw = run_minister_hybrid(
        minister, req_text, coll, bm25_idx, _embed_query,
        _get_minister_thresholds(minister, dict(CFG["thresholds"])), 10, action_vec,
    )
    if raw is None or raw.confidence < _COSINE_TRIAGE_ESCALATE_THRESHOLD:
        return None
    # THE hardcoded verdict. Not derived from raw.verdict. Cannot be BLOCK.
    return MinisterScan(
        minister=minister,
        verdict="ESCALATE",
        confidence=raw.confidence,
        matched_id=f"{minister}-COSINE-TRIAGE:{raw.matched_id or 'nearest'}",
        matched_text=f"cosine triage (ESCALATE-only, never blocks): nearest "
                     f"{raw.matched_id!r} at sim {raw.confidence:.3f} on deterministic-miss residual",
        matched_level="triage",
        source=raw.source,
        retrieval_mode="cosine-triage",
    )


def _run_deterministic_ministers(
    req_text: str, session_id: str, account_email: str | None,
    user_instruction: str | None = None, tool_output: str | None = None,
) -> list[MinisterScan]:
    """VAULT/EXECUTOR/CHANNEL's deterministic verdicts — unconditional,
    synchronous, no embedding, no ChromaDB query (Stage 2). Factored out
    of the main handler so both the short-circuit path and the full
    pipeline call the exact same logic — no risk of the two diverging.
    A None result from any checker becomes an explicit ALLOW MinisterScan
    so none of the three ever silently disappears from minister_results/
    minister_dict/the ledger, same fail-open discipline as before this
    refactor.

    CHANNEL contributes up to TWO independent scans here (taint +
    provenance, both named "CHANNEL" — see channel_taint.py's composition-
    rule docstring for why this is intentional, not a naming collision to
    fix). combine_verdicts() correctly considers both; server.py's
    minister_dict-building step keeps whichever is more restrictive on a
    same-name collision (see the _VERDICT_RANK comment at that call site).

    user_instruction / tool_output: optional, forwarded to
    channel_taint.check_provenance() — see that function's docstring for
    what happens when a caller never supplies them (provenance simply
    never fires, not a silent failure)."""
    parsed_call = prefilters.parse_call(req_text)

    vault_scan = prefilters.check_vault(parsed_call) if parsed_call is not None else None
    if vault_scan is None:
        vault_scan = MinisterScan(
            minister="VAULT", verdict="ALLOW", confidence=0.0,
            matched_id=None, matched_text=None, matched_level="deterministic",
            source=None, retrieval_mode="deterministic",
        )

    executor_scan = prefilters.check_executor(parsed_call) if parsed_call is not None else None
    if executor_scan is None:
        executor_scan = MinisterScan(
            minister="EXECUTOR", verdict="ALLOW", confidence=0.0,
            matched_id=None, matched_text=None, matched_level="deterministic",
            source=None, retrieval_mode="deterministic",
        )

    taint_state = _state["channel_taint"][session_id]
    channel_scan = channel_taint.check_channel_taint(req_text, taint_state, account_email=account_email)
    if channel_scan is None:
        channel_scan = MinisterScan(
            minister="CHANNEL", verdict="ALLOW", confidence=0.0,
            matched_id=None, matched_text=None, matched_level="deterministic",
            source=None, retrieval_mode="deterministic",
        )

    provenance_state = _state["channel_provenance"][session_id]
    provenance_scan, provenance_records = channel_taint.check_provenance(
        req_text, provenance_state, account_email=account_email,
        user_instruction=user_instruction, tool_output=tool_output,
    )

    # Composition fix: taint's BLOCK is a structural default ("tainted,
    # destination not on the static allowlist"), not positive evidence the
    # destination is actually illegitimate -- confirmed via a direct
    # false-positive measurement (335-case obfuscation study's sibling
    # check on genuine benign two-step read-then-send actions, see
    # §limitations): with no account_email/user_instruction context wired
    # through, a legitimate self-forward blocked 32/32 times. Provenance
    # runs on this same call and has positive evidence when it does fire:
    # if every one of this call's destination values is classified SELF
    # (matches the session's own verified identity) or USER_SUPPLIED
    # (present in the user's own original instruction), that is a
    # confirmed-legitimate destination, and taint's structural-default
    # BLOCK should not override a positive finding. OUTPUT_DERIVED and
    # NOVEL are deliberately left alone (still BLOCK): OUTPUT_DERIVED is
    # the genuinely ambiguous read-then-send case this project's NAVIGATOR
    # authorization work has not yet resolved, and NOVEL is
    # indistinguishable from an attacker-injected value -- suppressing
    # taint there would reopen exactly the exfiltration gap the mechanism
    # exists to close.
    if channel_scan.verdict == "BLOCK" and provenance_records and all(
        r.classification in ("SELF", "USER_SUPPLIED") for r in provenance_records
    ):
        channel_scan = MinisterScan(
            minister="CHANNEL", verdict="ALLOW", confidence=0.0,
            matched_id=None, matched_text=None, matched_level="deterministic",
            source=None, retrieval_mode="deterministic",
        )

    results = [vault_scan, executor_scan, channel_scan]
    if provenance_scan is not None:
        results.append(provenance_scan)
    return results


def _short_circuit_candidate(deterministic_results: list[MinisterScan]) -> MinisterScan | None:
    """Returns the first deterministic MinisterScan that both (a) confidently
    BLOCKs and (b) is short-circuit-eligible (prefilters.is_short_circuit_
    eligible — the denylist of newest/least-validated rules that must
    still go through the full synchronous pipeline). None if no such scan
    exists, meaning the caller falls through to the full pipeline exactly
    as before this optimization existed."""
    for scan in deterministic_results:
        if scan.verdict == "BLOCK" and scan.confidence >= 1.0 and prefilters.is_short_circuit_eligible(scan.matched_id):
            return scan
    return None


async def _complete_ledger_async(
    session_id: str,
    correlation_id: str,
    req_text: str,
    action_vec: np.ndarray,
    deterministic_results: list[MinisterScan],
    speaker_v: SpeakerVerdict,
    traj_risk: float,
) -> None:
    """Fire-and-forget task kicked off AFTER a short-circuited response has
    already been returned to the caller. Runs the skipped COMPASS drift
    check, router, and NAVIGATOR's cosine scan purely to complete the
    ledger's provenance picture — never changes the verdict already sent
    to the caller (which is final the moment the response goes out).
    Writes a SEPARATE follow-up ledger row (same correlation_id, a
    distinct `stage` value) rather than mutating the original row, since
    the hash chain is append-only/content-addressed by design — editing
    an already-hashed row would break every subsequent entry_hash.
    Exceptions here are logged, never raised — a failure to complete the
    ledger's async half must never look like a live-request failure,
    since by construction no live request is waiting on this."""
    try:
        drift, compass_sim = _compass_drift(session_id, req_text, action_vec)
        activated = _route(req_text)

        navigator_scan: MinisterScan | None = None
        if "NAVIGATOR" in activated:
            m_thresholds = _get_minister_thresholds("NAVIGATOR", dict(CFG["thresholds"]))
            bm25_idx  = _state["bm25_indexes"].get("NAVIGATOR")
            tech_coll = _state["tech_collections"].get("NAVIGATOR")
            loop = asyncio.get_event_loop()
            if tech_coll:
                navigator_scan = await loop.run_in_executor(
                    None, run_minister_dual_hybrid, "NAVIGATOR", req_text,
                    _state["collections"]["NAVIGATOR"], tech_coll, bm25_idx,
                    _embed_query, m_thresholds, 10, action_vec,
                )
            else:
                navigator_scan = await loop.run_in_executor(
                    None, run_minister_hybrid, "NAVIGATOR", req_text,
                    _state["collections"]["NAVIGATOR"], bm25_idx,
                    _embed_query, m_thresholds, 10, action_vec,
                )

        completion_ministers = {
            r.minister: {
                "verdict": r.verdict, "confidence": r.confidence,
                "matched_id": r.matched_id, "retrieval_mode": r.retrieval_mode,
            }
            for r in deterministic_results
        }
        if navigator_scan is not None:
            completion_ministers["NAVIGATOR"] = {
                "verdict": navigator_scan.verdict, "confidence": navigator_scan.confidence,
                "matched_id": navigator_scan.matched_id, "retrieval_mode": navigator_scan.retrieval_mode,
            }

        _log_vote(
            session_id=session_id,
            correlation_id=correlation_id,
            stage="parliament_async_completion",
            input_text=req_text,
            verdict=speaker_v.verdict,
            # Same convention as every other ledger row: decided_by is
            # always the MINISTER name (e.g. "VAULT"), never a matched_id
            # — matches speaker_v.decided_by, which the original
            # synchronous row already used, so the two rows for one
            # correlation_id agree on who decided.
            decided_by=speaker_v.decided_by,
            confidence=speaker_v.confidence,
            reason=f"async completion of short-circuited call — original verdict unchanged, "
                   f"this row fills in compass_sim/NAVIGATOR for ledger completeness only",
            ministers=completion_ministers,
            compass_sim=compass_sim,
            latency_ms=0.0,
            traj_risk=traj_risk,
            provenance=None,
            retrieval_mode=_state.get("retrieval_mode", "dense"),
            short_circuited=True,
        )
    except Exception:
        log.exception(
            "async ledger completion failed for correlation_id=%s (short-circuited "
            "response was already returned and is unaffected)", correlation_id,
        )


@app.post("/hook/parliament", response_model=ParliamentResponse)
async def parliament(req: ParliamentRequest) -> ParliamentResponse:
    """Full pipeline: COMPASS drift + router + activated ministers + speaker.

    PIPELINE SHORT-CIRCUIT (response-latency optimization): VAULT/EXECUTOR/
    CHANNEL's deterministic checks are microseconds; COMPASS's drift check
    and the embedding router are the measured bottleneck (BGE embedding
    cost, ~2.9-3.7s p50 CPU-only — see README's latency-correction
    section). Validated via a feasibility/safety check against this
    session's full evaluation data before being built: a confident
    deterministic BLOCK is genuinely common (98/267 = 36.7% on the Type B
    malicious set) and COMPASS/`_route()` were confirmed to be pure reads
    with no cross-call session-state writes (trajectory.py's
    record_action() only consumes action_vec/verdict/confidence/
    decided_by/is_denial — none of which come from COMPASS or NAVIGATOR),
    so skipping them cannot corrupt trajectory's session-risk
    accumulation. The one real cost identified: the ledger currently logs
    compass_sim and NAVIGATOR's score on every row regardless of who
    decided — short-circuiting would lose that provenance UNLESS it's
    backfilled, which is exactly what _complete_ledger_async() above does
    as a fire-and-forget task after the response is already sent.
    Eligibility is denylist-gated (prefilters.SHORT_CIRCUIT_INELIGIBLE_
    RULE_NAMES) so the newest/least-validated rules still get full
    COMPASS+NAVIGATOR confirmation synchronously, same as before this
    optimization existed, until they've earned more real-world
    confidence."""
    t0 = time.perf_counter()
    correlation_id = req.context.get("correlation_id") or str(uuid.uuid4())

    # Step 0: embed the action ONCE. Shared across COMPASS, ministers, and the
    # trajectory deque — replaces up to 9 redundant embeds of the same text.
    action_vec = _embed_query(req.text)

    # Step 0b: trajectory risk from PRIOR calls in this session (current call
    # not yet appended). Pure cosine math over cached vectors — no embed.
    hist = _state["history"][req.session_id]
    traj_res = traj.trajectory_risk(hist, intent_vec=_state["intents"].get(req.session_id), current_vec=action_vec)

    # Step 0d: VAULT/EXECUTOR/CHANNEL's deterministic verdicts, computed
    # BEFORE COMPASS/routing (moved up from their old Step 3a2-3a4
    # position) specifically so the short-circuit check below can run
    # before paying the embedding+routing cost. Fail-open discipline is
    # unchanged: these three run unconditionally regardless of what
    # happens next, exactly as they did before this optimization existed.
    account_email = req.context.get("account_email")
    # user_instruction/tool_output: optional provenance inputs, same
    # open-ended `context` extension point account_email already uses —
    # see channel_taint.check_provenance()'s docstring for the
    # DATA-AVAILABILITY GAP this works around (Kavach's wire format never
    # carried tool outputs before this).
    user_instruction = req.context.get("user_instruction")
    tool_output = req.context.get("tool_output")
    deterministic_results = _run_deterministic_ministers(
        req.text, req.session_id, account_email,
        user_instruction=user_instruction, tool_output=tool_output,
    )

    short_circuit_scan = _short_circuit_candidate(deterministic_results)
    if short_circuit_scan is not None:
        call_thresholds = dict(CFG["thresholds"])
        speaker_v: SpeakerVerdict = combine_verdicts(
            deterministic_results,
            compass_drift=False,
            compass_sim=1.0,  # no intent-drift signal available on the short-circuit path
            thresholds=call_thresholds,
            traj_risk=traj_res.risk,
        )

        traj.record_action(
            hist,
            action_vec=action_vec,
            verdict=speaker_v.verdict,
            confidence=speaker_v.confidence,
            decided_by=speaker_v.decided_by,
            is_denial=(speaker_v.verdict == "BLOCK"),
        )

        latency_ms = (time.perf_counter() - t0) * 1000.0
        ts = datetime.now(timezone.utc).isoformat()

        minister_dict: dict[str, MinisterResult] = {
            r.minister: MinisterResult(
                verdict=r.verdict, confidence=r.confidence,
                matched_id=r.matched_id, matched_text=r.matched_text,
                retrieval_mode=r.retrieval_mode,
            )
            for r in deterministic_results
        }
        provenance = prov.resolve(short_circuit_scan.source, short_circuit_scan.minister)
        provenance_dict = provenance.to_dict()

        _log_vote(
            session_id=req.session_id,
            correlation_id=correlation_id,
            stage="parliament",
            input_text=req.text,
            verdict=speaker_v.verdict,
            decided_by=speaker_v.decided_by,
            confidence=speaker_v.confidence,
            reason=speaker_v.reason,
            ministers={
                r.minister: {
                    "verdict": r.verdict, "confidence": r.confidence,
                    "matched_id": r.matched_id, "retrieval_mode": r.retrieval_mode,
                }
                for r in deterministic_results
            },
            compass_sim=None,
            latency_ms=latency_ms,
            traj_risk=round(traj_res.risk, 4),
            provenance=provenance_dict,
            retrieval_mode=_state.get("retrieval_mode", "dense"),
            short_circuited=True,
        )

        # Fire-and-forget: completes the ledger's compass_sim/NAVIGATOR
        # picture asynchronously, AFTER the response below has already
        # been returned. Never awaited, never blocks the response —
        # errors are caught and logged inside the task itself.
        asyncio.create_task(_complete_ledger_async(
            session_id=req.session_id,
            correlation_id=correlation_id,
            req_text=req.text,
            action_vec=action_vec,
            deterministic_results=deterministic_results,
            speaker_v=speaker_v,
            traj_risk=round(traj_res.risk, 4),
        ))

        return ParliamentResponse(
            verdict=speaker_v.verdict,
            speaker={
                "decided_by": speaker_v.decided_by,
                "confidence": speaker_v.confidence,
                "reason":     speaker_v.reason,
            },
            ministers=minister_dict,
            pattern=short_circuit_scan.matched_id or "none",
            provenance=provenance_dict,
            compass_sim=None,
            traj_risk=round(traj_res.risk, 4),
            retrieval_mode=_state.get("retrieval_mode", "dense"),
            activated=[],
            correlation_id=correlation_id,
            latency_ms=round(latency_ms, 2),
            ts=ts,
            short_circuited=True,
        )

    # Step 0c: modulate this call's block threshold by COMPASS + trajectory.
    # A suspicious build-up lowers the bar to BLOCK on this call.
    call_thresholds = dict(CFG["thresholds"])
    call_thresholds["block"] = traj.modulate_threshold(
        base=CFG["thresholds"]["block"],
        compass_sim=None,  # filled after COMPASS below
        traj_risk=traj_res.risk,
    )

    # Step 1: COMPASS drift (reuses action_vec, no re-embed).
    drift, compass_sim = _compass_drift(req.session_id, req.text, action_vec)

    # Recompute the modulated threshold now that compass_sim is known.
    call_thresholds["block"] = traj.modulate_threshold(
        base=CFG["thresholds"]["block"],
        compass_sim=compass_sim if _state["intents"].get(req.session_id) is not None else None,
        traj_risk=traj_res.risk,
    )

    # Step 2: Router
    activated = _route(req.text)

    # Step 3: Run activated ministers in parallel — hybrid BM25+dense retrieval
    # when an index exists, sharing action_vec (embed-once) and the
    # trajectory-modulated per-minister thresholds for this call.
    #
    # STAGE 2 (VAULT + EXECUTOR + CHANNEL swaps, docs/status/REARCHITECTURE_PLAN.md):
    # VAULT, EXECUTOR, and CHANNEL are EXCLUDED from this cosine-similarity
    # dispatch loop entirely — their ChromaDB collections are no longer
    # queried for verdicts at request time (still loaded at startup;
    # corpus_loader.py untouched). Their deterministic detectors
    # (prefilters.check_vault / check_executor / channel_taint.check_
    # channel_taint) are now each minister's ONLY source of truth, scored
    # synchronously below, unconditionally (regardless of routing — a router
    # miss must never skip a deterministic minister, same fail-open
    # discipline as Stage 1's additive pre-filters). NAVIGATOR is
    # unchanged: still dispatched through the normal cosine path when the
    # router activates it.
    loop = asyncio.get_event_loop()
    minister_tasks = []
    for minister in activated:
        if minister in ("VAULT", "EXECUTOR", "CHANNEL"):
            continue  # Stage 2: VAULT/EXECUTOR/CHANNEL no longer run the cosine path at all.
        bm25_idx  = _state["bm25_indexes"].get(minister)
        tech_coll = _state["tech_collections"].get(minister)
        m_thresholds = _get_minister_thresholds(minister, call_thresholds)

        if tech_coll:
            task = loop.run_in_executor(
                None,
                run_minister_dual_hybrid,
                minister,
                req.text,
                _state["collections"][minister],
                tech_coll,
                bm25_idx,
                _embed_query,
                m_thresholds,
                10,
                action_vec,
            )
        else:
            task = loop.run_in_executor(
                None,
                run_minister_hybrid,
                minister,
                req.text,
                _state["collections"][minister],
                bm25_idx,
                _embed_query,
                m_thresholds,
                10,
                action_vec,
            )
        minister_tasks.append(task)

    minister_results: list[MinisterScan] = await asyncio.gather(*minister_tasks)

    # Step 3a: Stage 2 — VAULT/EXECUTOR/CHANNEL's deterministic verdicts.
    # Already computed once at Step 0d (before the short-circuit check
    # above), factored into _run_deterministic_ministers() so both the
    # short-circuit path and this full-pipeline fallthrough path use the
    # exact same logic — reused here rather than recomputed, same
    # unconditional/fail-open semantics as before this refactor.
    minister_results = minister_results + deterministic_results

    # Step 3b: Cosine ESCALATE-only triage for VAULT/EXECUTOR (Part 3).
    # Runs ONLY on the deterministic-miss residual: for each of VAULT/EXECUTOR
    # whose deterministic check did NOT already fire (BLOCK/ESCALATE), query
    # cosine and possibly add a HARDCODED-ESCALATE scan (see
    # _cosine_triage_escalate's safety contract -- it cannot BLOCK). This is
    # additive: it never removes or downgrades a deterministic verdict, only
    # flags-for-review a long-tail call the rules let through. Skipped on the
    # short-circuit path above (that path only fires on a confident
    # deterministic BLOCK, which by definition is not a miss).
    _fired_ministers = {
        r.minister for r in minister_results if r.verdict in ("BLOCK", "ESCALATE")
    }
    for _m in ("VAULT", "EXECUTOR"):
        if _m in _fired_ministers:
            continue  # deterministic rule already caught it -- no triage needed
        _triage = await loop.run_in_executor(
            None, _cosine_triage_escalate, _m, req.text, action_vec
        )
        if _triage is not None:
            minister_results.append(_triage)

    # Step 4: Speaker combines verdicts (under the modulated thresholds).
    speaker_v: SpeakerVerdict = combine_verdicts(
        minister_results,
        compass_drift=drift,
        compass_sim=compass_sim,
        thresholds=call_thresholds,
        traj_risk=traj_res.risk,
    )

    # Step 4b: record THIS action into the session trajectory (reuses the
    # vector; appended after scoring so risk reflects only prior calls).
    traj.record_action(
        hist,
        action_vec=action_vec,
        verdict=speaker_v.verdict,
        confidence=speaker_v.confidence,
        decided_by=speaker_v.decided_by,
        is_denial=(speaker_v.verdict == "BLOCK"),
    )

    latency_ms = (time.perf_counter() - t0) * 1000.0
    ts = datetime.now(timezone.utc).isoformat()

    # Two independent scans can share a minister name (CHANNEL's taint
    # tracker and CHANNEL's provenance check both report as "CHANNEL" --
    # see channel_taint.py's composition-rule docstring). A plain
    # dict-assignment loop would silently let whichever scan is iterated
    # LAST overwrite the other in this response, even though
    # combine_verdicts() above already correctly considered both when
    # deciding the actual verdict -- that's a real loss of audit
    # information, not just a cosmetic gap, so on a same-name collision
    # this keeps whichever scan is more restrictive (BLOCK > ESCALATE >
    # ALLOW), matching the Speaker's own most-restrictive-wins philosophy
    # rather than an arbitrary "last one wins."
    _VERDICT_RANK = {"BLOCK": 2, "ESCALATE": 1, "ALLOW": 0}
    minister_dict: dict[str, MinisterResult] = {}
    for r in minister_results:
        existing = minister_dict.get(r.minister)
        if existing is not None and _VERDICT_RANK.get(existing.verdict, 0) >= _VERDICT_RANK.get(r.verdict, 0):
            continue
        minister_dict[r.minister] = MinisterResult(
            verdict=r.verdict,
            confidence=r.confidence,
            matched_id=r.matched_id,
            matched_text=r.matched_text,
            retrieval_mode=r.retrieval_mode,
        )

    pattern = (
        "intent_drift" if drift and speaker_v.verdict == "BLOCK"
        else (
            minister_results[0].matched_id
            if minister_results and minister_results[0].verdict == "BLOCK"
            else "none"
        )
    )

    # Provenance
    if speaker_v.decided_by == "TRAJECTORY":
        provenance = prov.trajectory_provenance()
    elif minister_results:
        blockers = [r for r in minister_results if r.verdict == "BLOCK"]
        winner = max(blockers or minister_results, key=lambda r: r.confidence)
        provenance = prov.resolve(winner.source, winner.minister)
    else:
        provenance = prov.resolve(None, "")
    provenance_dict = provenance.to_dict()
    active_retrieval = _state.get("retrieval_mode", "dense")

    _log_vote(
        session_id=req.session_id,
        correlation_id=correlation_id,
        stage="parliament",
        input_text=req.text,
        verdict=speaker_v.verdict,
        decided_by=speaker_v.decided_by,
        confidence=speaker_v.confidence,
        reason=speaker_v.reason,
        # Keyed by r.minister (not positionally zipped with `activated`) so
        # Stage 1 pre-filter hits — which run regardless of routing and can
        # name a minister the router didn't activate — are logged under
        # their own correct minister name rather than silently mispaired
        # with whatever minister the old positional zip(activated, ...)
        # happened to line up against.
        ministers={
            r.minister: {
                "verdict":        r.verdict,
                "confidence":     r.confidence,
                "matched_id":     r.matched_id,
                "retrieval_mode": r.retrieval_mode,
            }
            for r in minister_results
        },
        compass_sim=compass_sim,
        latency_ms=latency_ms,
        traj_risk=round(traj_res.risk, 4),
        provenance=provenance_dict,
        retrieval_mode=active_retrieval,
        short_circuited=False,
    )

    return ParliamentResponse(
        verdict=speaker_v.verdict,
        speaker={
            "decided_by": speaker_v.decided_by,
            "confidence": speaker_v.confidence,
            "reason":     speaker_v.reason,
        },
        ministers=minister_dict,
        pattern=pattern,
        provenance=provenance_dict,
        compass_sim=compass_sim if drift or _state["intents"].get(req.session_id) is not None else None,
        traj_risk=round(traj_res.risk, 4),
        retrieval_mode=active_retrieval,
        activated=activated,
        correlation_id=correlation_id,
        latency_ms=round(latency_ms, 2),
        ts=ts,
        short_circuited=False,
    )


@app.get("/ledger/verify")
async def verify_ledger() -> dict[str, Any]:
    """Re-walk the hash chain and report whether the ledger is intact.

    Recomputes entry_hash for every row in id order from the stored prev_hash
    and compares to the stored entry_hash. The first mismatch is the point of
    tampering (an edited/deleted/reordered row). O(n), no model calls."""
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT id, ts, session_id, correlation_id, stage, input_text,
                  verdict, decided_by, confidence, reason, ministers_json,
                  compass_sim, traj_risk, latency_ms, provenance_json,
                  prev_hash, entry_hash, short_circuited
           FROM votes ORDER BY id ASC""").fetchall()
    conn.close()

    expected_prev = GENESIS_HASH
    checked = 0
    chain_started = False
    for r in rows:
        # Hash columns are NULL only for genuine legacy rows written before the
        # chain feature existed. Those legacy rows must all PRECEDE the first
        # chained row. A NULL hash appearing AFTER the chain has started is
        # treated as tampering (an attacker nulling hashes to drop rows from
        # the chain), not as a benign legacy row. (June-10 audit hardening.)
        if r[16] is None:
            if chain_started:
                return {
                    "intact": False,
                    "entries_checked": checked,
                    "tampered_at_id": r[0],
                    "reason": "null hash after chain start — possible hash "
                              "stripping to drop a row from the chain",
                }
            expected_prev = GENESIS_HASH
            continue
        chain_started = True
        row = {
            "ts": r[1], "session_id": r[2], "correlation_id": r[3],
            "stage": r[4], "input_text": r[5], "verdict": r[6],
            "decided_by": r[7], "confidence": r[8], "reason": r[9],
            "ministers_json": r[10], "compass_sim": r[11],
            "traj_risk": r[12], "latency_ms": r[13], "provenance_json": r[14],
            # Found during the overnight GPT-4o expansion's ledger check:
            # this SELECT never fetched short_circuited, so _entry_hash()'s
            # `row.get("short_circuited") is not None` always saw None here
            # regardless of what was stored -- silently omitting the field
            # from every recomputed hash from the row it was introduced on
            # (id 795) onward, while the WRITE path (log_vote, above) always
            # included it once set. That mismatch, not real tampering, was
            # what /ledger/verify was reporting as "entry_hash mismatch" at
            # id 795. Fixed by including the column here to match the write
            # path exactly.
            "short_circuited": r[17],
        }
        stored_prev, stored_entry = r[15], r[16]
        recomputed = _entry_hash(stored_prev, row)
        if stored_prev != expected_prev or recomputed != stored_entry:
            return {
                "intact": False,
                "entries_checked": checked,
                "tampered_at_id": r[0],
                "reason": ("prev_hash discontinuity"
                           if stored_prev != expected_prev
                           else "entry_hash mismatch — row content altered"),
            }
        expected_prev = stored_entry
        checked += 1

    return {"intact": True, "entries_checked": checked,
            "head_hash": expected_prev}


@app.get("/ledger/votes")
async def ledger(limit: int = 100) -> dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    rows = conn.execute(
        """SELECT ts, session_id, correlation_id, stage, input_text, verdict,
                  decided_by, confidence, reason, ministers_json, compass_sim,
                  traj_risk, latency_ms, retrieval_mode
           FROM votes ORDER BY id DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()

    votes = [
        {
            "ts":             r[0],
            "session_id":     r[1],
            "correlation_id": r[2],
            "stage":          r[3],
            "input":          r[4],
            "verdict":        r[5],
            "decided_by":     r[6],
            "confidence":     r[7],
            "reason":         r[8],
            "ministers":      json.loads(r[9]) if r[9] else {},
            "compass_sim":    r[10],
            "traj_risk":      r[11],
            "latency_ms":     r[12],
            "retrieval_mode": r[13] or "dense",
        }
        for r in rows
    ]

    return {
        "total":    len(votes),
        "blocked":  sum(1 for v in votes if v["verdict"] == "BLOCK"),
        "allowed":  sum(1 for v in votes if v["verdict"] == "ALLOW"),
        "escalated": sum(1 for v in votes if v["verdict"] == "ESCALATE"),
        "votes":    votes,
    }


# ──────────────────────────────────────────────────────────────────────────────
# Entrypoint
# ──────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    uvicorn.run(
        "parliament.server:app",
        host=CFG["host"],
        port=CFG["port"],
        log_level="info",
        reload=False,
    )
