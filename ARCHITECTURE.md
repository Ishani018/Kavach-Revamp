# Kavach architecture (original implementation preserved)

This document is a map of the existing code, not a replacement architecture. The implementation modules below are the source of truth. Do not copy their logic into a second implementation or replace them with simplified heuristics.

## Request flow

```text
POST /hook/parliament
        |
        v
parliament/server.py  (request orchestration)
        |
        +--> TRAJECTORY: score the prior session history
        |      parliament/trajectory.py
        |
        +--> Deterministic checks run first, on every request
        |      VAULT     -> parliament/prefilters.py :: check_vault()
        |      EXECUTOR  -> parliament/prefilters.py :: check_executor()
        |      CHANNEL   -> parliament/channel_taint.py :: check_channel_taint()
        |                  + check_provenance()
        |
        +--> Eligible high-confidence deterministic BLOCK?
        |      yes -> Speaker decision and response; ledger completion continues async
        |      no  -> continue full pipeline
        |
        +--> COMPASS: compare action with stored user intent
        |      parliament/server.py :: _compass_drift()
        |
        +--> Semantic router: parliament/server.py :: _route()
        |      Uses kavach_router_config.json + router_min threshold
        |      NAVIGATOR is the semantic retrieval minister in the live path
        |      If nothing crosses the threshold, router falls back to all configured names
        |
        +--> NAVIGATOR retrieval (hybrid BM25 + dense when available)
        |      parliament/ministers.py
        |
        +--> Merge semantic and deterministic results
        |
        +--> Speaker: parliament/speaker.py :: combine_verdicts()
        |
        +--> Append session history + hash-chained vote ledger
               parliament/trajectory.py + parliament/server.py
```

## Where each minister lives

| Minister / mechanism | Authoritative implementation | What it does |
|---|---|---|
| **VAULT** | `parliament/prefilters.py` → `check_vault()` | Deterministic checks for sensitive data and credential access. Shared call parsing and helpers are in the same original module. |
| **EXECUTOR** | `parliament/prefilters.py` → `check_executor()` | Deterministic execution and AST-related checks. Shared parsing helpers remain in the original module. |
| **CHANNEL** | `parliament/channel_taint.py` → `check_channel_taint()` | Session taint and source-to-destination checks. The same module also owns provenance tracking. |
| **NAVIGATOR** | `parliament/ministers.py` | Corpus-backed semantic detection; dense retrieval and BM25+dense hybrid retrieval functions live here. |
| **COMPASS** | `parliament/server.py` → `_compass_drift()` | Compares the proposed action with the session's stored intent vector. |
| **TRAJECTORY** | `parliament/trajectory.py` | Tracks action history and session-level risk. |
| **Speaker** | `parliament/speaker.py` → `combine_verdicts()` | Combines minister results, COMPASS drift, and trajectory risk into BLOCK / ESCALATE / ALLOW. |

## Supporting modules

- `parliament/ast_parse.py`, `parliament/struct_parse.py`: parsers used by the original deterministic checks.
- `parliament/provenance.py`: provenance resolution and ledger-facing metadata.
- `parliament/denial_shield.py`: denial-related protection.
- `parliament/navigator_authflow.py`: NAVIGATOR auth-flow logic.
- `parliament/speaker_bayesian.py`: Bayesian Speaker-related implementation.
- `parliament/config.yaml`: model, threshold, service, and collection configuration.
- `kavach_router_config.json`: semantic routing descriptions and risk configuration.
- `parliament/test_*.py`: original focused tests.

## Important behavior to preserve

1. **Do not route away deterministic safety checks.** VAULT, EXECUTOR, and CHANNEL deterministic checks run unconditionally before the semantic router.
2. **Keep the short-circuit.** Eligible confident deterministic BLOCKs can return before synchronous COMPASS/NAVIGATOR work; the ledger is completed asynchronously.
3. **Keep NAVIGATOR selective.** The semantic router determines whether the NAVIGATOR retrieval path is activated. Do not replace it with an unconditional expensive scan.
4. **Keep the Speaker unchanged.** Its asymmetric BLOCK behavior, threshold modulation, and trajectory ceiling are part of the real implementation.
5. **Keep the original data and dependencies.** The semantic path expects configured ChromaDB collections and the embedding model; installing Python requirements alone does not create those resources.

## Validation

From the repository root:

```bash
pip install -r requirements.txt
python -m pytest parliament/test_*.py
```

These commands describe how to validate the project; they are not a claim that the tests or a fully configured live service have already passed in this environment.
