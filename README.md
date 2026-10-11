# Kavach

**A small set of security ministers, one Speaker.**

Each minister checks one kind of risk in a proposed tool action. The Speaker collects their votes and produces one final verdict. That's the whole architecture.

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

## Where to look

- `src/kavach/ministers/` — one small, readable file per minister.
- `src/kavach/speaker.py` — the only place that combines votes.
- `src/kavach/monitor.py` — calls the ministers and passes their votes to the Speaker.
- `src/kavach/models.py` — the shared input, vote, and verdict types.
- `tests/` — checks the Speaker's decision rules.

Each minister is intentionally a stub right now. Its job and extension point are visible, but no detection capability is claimed until it has implementation and tests.

No agent framework, web server, database, embeddings, LLM judge, or orchestration layer in the core.
