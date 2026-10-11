# Scope

## Goal
Build the smallest useful runtime-agnostic monitor for proposed AI-agent tool actions. The first version is a library with a stable event/decision contract and a small deterministic policy interface.

## In scope
1. Versioned structured event for one proposed tool action.
2. Explicit field visibility metadata.
3. Deterministic policy interface.
4. Decisions: `ALLOW`, `BLOCK`, `REVIEW`, `INDETERMINATE`.
5. Minimal audit records that avoid raw arguments by default.
6. Tests for policy behavior, missing information, and adapter enforcement.

## Out of scope
- Detecting every form of prompt injection or running/orchestrating agents.
- Embeddings, vector databases, retrieval pipelines, LLM judges, or multi-step trajectory scoring.
- Cross-session taint tracking until a concrete event contract and broad benign test set justify it.
- Multiple runtime adapters before the core contract is stable.
- Claims about runtime paths that have not been tested.

## Decision semantics
- `ALLOW`: applicable checks ran with sufficient required evidence and found no intervention condition.
- `BLOCK`: a configured policy identified a violation.
- `REVIEW`: suspicious or ambiguous action requires explicit resolution.
- `INDETERMINATE`: required evidence is missing, unusable, or outside supported scope.

The adapter defines behavior if Kavach is unavailable. Validation errors or missing required fields must never silently become `ALLOW`.

## Implementation order
1. Define and test event and decision schemas.
2. Implement a framework-independent policy interface.
3. Add one deterministic policy at a time, each with positive and benign tests.
4. Add a thin service wrapper only after the library works directly.
5. Add one real adapter and prove `BLOCK` is enforced at its claimed interception point.
6. Expand only when held-out attack and benign tests demonstrate incremental value.
