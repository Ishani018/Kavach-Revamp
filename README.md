# Kavach

Kavach is a tool-call security monitor. This repository preserves the original `Ishani018/Kavach` minister implementations, routing behavior, Speaker mechanism, support modules, and tests.

## Start here

- **Want to understand the whole pipeline?** Read [`ARCHITECTURE.md`](ARCHITECTURE.md).
- **Want the final decision logic?** Open [`parliament/speaker.py`](parliament/speaker.py) and find `combine_verdicts()`.
- **Want VAULT or EXECUTOR?** Open [`parliament/prefilters.py`](parliament/prefilters.py) and find `check_vault()` or `check_executor()`.
- **Want CHANNEL?** Open [`parliament/channel_taint.py`](parliament/channel_taint.py) and find `check_channel_taint()`.
- **Want NAVIGATOR's semantic retrieval?** Open [`parliament/ministers.py`](parliament/ministers.py).
- **Want routing, COMPASS, or the HTTP request flow?** Open [`parliament/server.py`](parliament/server.py).
- **Want session risk/history?** Open [`parliament/trajectory.py`](parliament/trajectory.py).

## Run

The FastAPI service entry point is `parliament.server:app`:

```bash
pip install -r requirements.txt
python -m uvicorn parliament.server:app --host 127.0.0.1 --port 8088
```

The live service also needs the configured embedding model and ChromaDB collections. Installing dependencies alone does not create those external resources.

## Tests

```bash
python -m pytest parliament/test_*.py
```

Original implementation modules are intentionally kept in their existing locations. The architecture is documented around the code rather than replacing working code with new stubs or duplicating detector logic.
