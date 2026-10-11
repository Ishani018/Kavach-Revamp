# Kavach

**Six small security ministers. One Speaker.**

Each minister checks one kind of risk in a proposed tool action and returns a vote. The Speaker combines those votes into one verdict. The Monitor only wires them together.

```mermaid
flowchart TD
    A["Proposed Tool Action"] --> M["Monitor"]

    M --> V["VAULT"]
    M --> E["EXECUTOR"]
    M --> C["CHANNEL"]
    M --> CO["COMPASS"]
    M --> N["NAVIGATOR"]
    M --> T["TRAJECTORY"]

    V --> S["Speaker"]
    E --> S
    C --> S
    CO --> S
    N --> S
    T --> S

    S --> D{"Final Verdict"}
    D --> AL["ALLOW"]
    D --> BL["BLOCK"]
    D --> R["REVIEW"]
    D --> I["INDETERMINATE"]

    classDef core fill:#eee8ff,stroke:#8268c9,color:#30234b
    classDef minister fill:#f8f1e7,stroke:#b99b73,color:#493a2b
    classDef verdict fill:#e6f3e8,stroke:#78a482,color:#24472b
    class M,S core
    class V,E,C,CO,N,T minister
    class AL,BL,R,I verdict
```

## The ministers

| File | Responsibility | Current mechanism |
|---|---|---|
| `ministers/vault.py` | Secret and credential access | Explicit credential-path and secret-format rules |
| `ministers/executor.py` | Dangerous command execution | Explicit command/code-execution patterns |
| `ministers/channel.py` | Sensitive read followed by external send | Session-local taint tracking |
| `ministers/compass.py` | Action versus user intent | Small lexical-overlap heuristic; REVIEW only |
| `ministers/navigator.py` | Prompt-injection indicators | Explicit instruction-hijack patterns |
| `ministers/trajectory.py` | Risk across a sequence of actions | Small session-history heuristic |

## Where the logic lives

- `src/kavach/ministers/` — one readable file per minister.
- `src/kavach/speaker.py` — the only place that combines votes.
- `src/kavach/monitor.py` — runs all six ministers, then calls the Speaker.
- `src/kavach/models.py` — shared action and vote types.
- `tests/` — malicious and benign examples.

## Speaker rules

1. Any `BLOCK` vote means `BLOCK`.
2. Otherwise, any `REVIEW` vote means `REVIEW`.
3. Otherwise, any `ABSTAIN` vote means `INDETERMINATE`.
4. `ALLOW` requires every minister to explicitly allow.

## Run the tests

```bash
python -m pip install -e .
python -m unittest discover -s tests -v
```

## Important limitation

This revamp uses intentionally small, inspectable rules. In particular, NAVIGATOR is **not** the original embedding/retrieval detector, and COMPASS is **not** a semantic intent model. These are first-pass heuristics, not production-validated security coverage. Each rule needs broader attack and benign regression tests before deployment.
