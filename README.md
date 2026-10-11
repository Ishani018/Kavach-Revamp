# Kavach

A small, runtime-agnostic monitor for proposed AI-agent tool actions.

Kavach receives a structured event describing an action, evaluates explicit security policies, and returns a decision before the host runtime executes the action. The core does not run the agent, choose its goals, or assume that every runtime exposes the same context.

## Status

**Scaffold only.** The repository defines the intended boundaries; no detector or runtime integration is claimed to be production-ready yet.

## Architecture

```text
Agent runtime
    │
    ▼
Runtime adapter
    │  versioned ActionEvent
    ▼
Kavach core
    ├── schema validation
    ├── deterministic policy checks
    └── decision: ALLOW / BLOCK / REVIEW / INDETERMINATE
    │
    ├──────────────► Decision returned to adapter
    └──────────────► Minimal audit record
```

## Principles

- **Core first:** the policy engine has no dependency on a particular agent framework.
- **Explicit visibility:** unavailable, omitted, redacted, and sanitized context are not treated as equivalent to observed values.
- **Small and deterministic:** start with a small set of inspectable rules. No embeddings, vector database, LLM judge, or trajectory model in the core.
- **Honest enforcement claims:** a verdict only prevents execution if the adapter can reliably intercept and enforce it.
- **Test before expanding:** every policy needs malicious and benign examples.

## Development

The first milestone is the event and decision contract, with tests. Detector implementations and adapters come later, after their interfaces and safety behavior are tested.

See [SCOPE.md](SCOPE.md) for the initial boundary and non-goals.
