# Scope

Kavach has three moving parts:

1. **Ministers** inspect one proposed tool action and return a vote.
2. **Speaker** combines votes using simple, explicit rules.
3. **Monitor** runs the ministers and passes their votes to the Speaker.

## Current ministers

- **VAULT:** explicit credential-path and secret-format rules.
- **EXECUTOR:** explicit dangerous command and code-execution patterns.
- **CHANNEL:** per-session sensitive-read-to-external-send taint.
- **COMPASS:** lexical action/intent overlap; can only request review.
- **NAVIGATOR:** explicit prompt-injection phrase rules.
- **TRAJECTORY:** simple per-session high-impact action sequence heuristic.

These are small first-pass implementations. They are not equivalent to the original semantic embedding/retrieval pipeline and have not been validated for production use.

## Votes

A minister returns one of:

- `ALLOW` — its current checks found no reason to intervene.
- `BLOCK` — it found a configured policy violation.
- `REVIEW` — it wants the action paused for explicit review.
- `ABSTAIN` — it could not make a decision.

The Speaker returns:

- `BLOCK` if any minister votes BLOCK.
- `REVIEW` if no minister blocks and at least one votes REVIEW.
- `INDETERMINATE` if no minister blocks/reviews and at least one abstains.
- `ALLOW` only when every minister explicitly votes ALLOW.

## Keep it simple

- One minister per file, one responsibility per minister.
- Ministers do not call each other.
- Ministers do not decide the final verdict.
- Only the Speaker combines votes.
- No framework-specific code, embedding model, database, or LLM judge in the core.
- Every rule needs malicious and benign tests before it is trusted.
