# Kavach

Kavach is a tool-call security monitor built around the original Kavach minister detectors and Speaker decision mechanism.

## Core flow

```text
Tool call
   |
   +--> VAULT / EXECUTOR deterministic checks (prefilters.py)
   +--> NAVIGATOR semantic retrieval (ministers.py + retrieval state)
   +--> CHANNEL session taint checks (channel_taint.py)
   +--> COMPASS intent-alignment checks (server.py)
   +--> TRAJECTORY session-risk checks (trajectory.py)
   |
   v
Speaker (speaker.py)
   |
   v
BLOCK / ESCALATE / ALLOW
```

## Where to read the code

| Component | Original implementation |
|---|---|
| VAULT and EXECUTOR | [`parliament/prefilters.py`](parliament/prefilters.py) |
| Structural and AST parsing used by VAULT / EXECUTOR | [`parliament/struct_parse.py`](parliament/struct_parse.py), [`parliament/ast_parse.py`](parliament/ast_parse.py) |
| NAVIGATOR semantic minister retrieval | [`parliament/ministers.py`](parliament/ministers.py) |
| CHANNEL session-level taint | [`parliament/channel_taint.py`](parliament/channel_taint.py) |
| COMPASS and live request wiring | [`parliament/server.py`](parliament/server.py) |
| TRAJECTORY session risk | [`parliament/trajectory.py`](parliament/trajectory.py) |
| Speaker verdict fusion | [`parliament/speaker.py`](parliament/speaker.py) |
| Provenance and denial protection | [`parliament/provenance.py`](parliament/provenance.py), [`parliament/denial_shield.py`](parliament/denial_shield.py) |

The files above are copied from the original `Ishani018/Kavach` repository without rewriting their implementation logic. Their existing imports and supporting files are retained because they are part of the original behaviour.

## Setup

Use Python compatible with the original project and install its dependencies:

```bash
pip install -r requirements.txt
```

The live FastAPI service is in `parliament/server.py`; its router descriptions are in [`kavach_router_config.json`](kavach_router_config.json). The service also expects the configured ChromaDB collections and embedding model to be available. Installing Python dependencies alone does not build or configure those external resources.

## Tests

Run the original focused tests from the repository root:

```bash
python -m pytest parliament/test_*.py
```

Tests are retained from the original project. No claim is made here that the full live service has been started or end-to-end validated in this environment.
