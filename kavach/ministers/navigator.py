"""
NAVIGATOR: semantic attack detection.

Hybrid retrieval (dense BGE + BM25, RRF selection, lexical gate) over the
NAVIGATOR section of kavach/data/kavach_corpus_v1.json, via retrieval.py
(unchanged scoring from parliament/ministers.py). Thresholds are the live
values from parliament/config.yaml: per-minister block 0.70, grey 0.50.

The ChromaDB collection is built from the corpus on first use (and rebuilt if
its document count no longer matches the corpus). Needs the BGE model
(BAAI/bge-base-en-v1.5, ~440MB, downloaded by sentence-transformers on first run).
"""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Optional

import numpy as np

from . import scan_to_result
from .retrieval import build_bm25_index, run_minister_hybrid
from ..schemas import MinisterResult, ToolCall

log = logging.getLogger("kavach.navigator")
# chromadb's telemetry client logs a harmless error on some versions even when disabled.
logging.getLogger("chromadb.telemetry.product.posthog").setLevel(logging.CRITICAL)

ROOT = Path(__file__).resolve().parents[2]
CORPUS_PATH = Path(__file__).resolve().parents[1] / "data" / "kavach_corpus_v1.json"
DEFAULT_CHROMA_PATH = Path(os.environ.get("KAVACH_CHROMA_PATH", ROOT / ".chroma_navigator"))

EMBED_MODEL = "BAAI/bge-base-en-v1.5"
QUERY_PREFIX = "Represent this sentence for searching relevant passages: "
THRESHOLDS = {"block": 0.7, "grey": 0.5}
TOP_K = 10
LEVELS = ("L1_intent", "L2_mechanism", "L3_surface")


class NavigatorMinister:
    name = "NAVIGATOR"

    def __init__(self, chroma_path: Optional[Path] = None, corpus_path: Path = CORPUS_PATH) -> None:
        import chromadb
        from chromadb.config import Settings
        from sentence_transformers import SentenceTransformer

        corpus = json.loads(Path(corpus_path).read_text())
        coll_name = corpus.get("collections", {}).get("NAVIGATOR", "kavach_navigator")
        patterns = corpus["NAVIGATOR"]["patterns"]

        log.info("loading embedding model %s", EMBED_MODEL)
        self._model = SentenceTransformer(EMBED_MODEL)

        path = Path(chroma_path or DEFAULT_CHROMA_PATH)
        path.mkdir(parents=True, exist_ok=True)
        client = chromadb.PersistentClient(path=str(path), settings=Settings(anonymized_telemetry=False))
        self._collection = self._ensure_collection(client, coll_name, patterns)
        self._bm25 = build_bm25_index(self._collection)
        if self._bm25 is None:
            log.warning("rank-bm25 unavailable: NAVIGATOR falls back to dense-only retrieval")

    def _ensure_collection(self, client, name: str, patterns: list):
        ids, docs, metas = [], [], []
        for pat in patterns:
            for level in LEVELS:
                text = pat.get(level)
                if not text:
                    continue
                ids.append(f"{pat['id']}_{level}")
                docs.append(text)
                metas.append({
                    "minister": "NAVIGATOR", "pattern_id": pat["id"],
                    "category": pat.get("category", "uncategorized"), "level": level,
                    "source": pat.get("source", ""), "rationale": pat.get("rationale", ""),
                })
        if not ids:
            raise ValueError("NAVIGATOR corpus has no documents")
        try:
            coll = client.get_collection(name)
            if coll.count() == len(ids):
                return coll
            log.info("NAVIGATOR collection stale (%d != %d docs); rebuilding", coll.count(), len(ids))
            client.delete_collection(name)
        except Exception:
            pass
        log.info("building NAVIGATOR collection (%d docs)", len(ids))
        coll = client.create_collection(name=name, metadata={"hnsw:space": "cosine"})
        embeddings = self._model.encode(docs, normalize_embeddings=True, show_progress_bar=False, batch_size=32)
        coll.add(ids=ids, documents=docs, metadatas=metas, embeddings=embeddings.tolist())
        return coll

    def _embed_query(self, text: str) -> np.ndarray:
        vec = self._model.encode(QUERY_PREFIX + text, normalize_embeddings=True, show_progress_bar=False)
        return np.asarray(vec, dtype=np.float32)

    def check(self, call: ToolCall) -> MinisterResult:
        scan = run_minister_hybrid(
            self.name, call.to_wire_text(), self._collection, self._bm25,
            self._embed_query, dict(THRESHOLDS), TOP_K,
        )
        result = scan_to_result(scan, self.name)
        if scan.verdict == "ALLOW":
            result.reason = f"NAVIGATOR: nearest attack pattern below grey threshold (score {scan.confidence:.3f})"
        else:
            # Corpus pattern text, not caller input, so it is safe to show.
            result.reason = (
                f"NAVIGATOR matched {scan.matched_id} ({scan.matched_level}) "
                f"score {scan.confidence:.3f}: {(scan.matched_text or '')[:160]}"
            )
        return result
