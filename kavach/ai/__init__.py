"""
kavach/ai
=========

AI as *evidence*, never as the verdict.

Ministers stay deterministic: their rules and the Speaker decide. An AI model
may only contribute structured evidence, and every use follows one of two
shapes, so a wrong or manipulated answer cannot make Kavach more permissive:

1. AI proposes, code verifies. The answer is a claim Kavach checks with
   deterministic code before using it (e.g. a de-obfuscation is replayed with
   pure transforms and must reproduce the claimed plaintext exactly; claimed
   argument names must exist in the call).
2. AI can only add caution. The answer can raise ALLOW to ESCALATE but never
   lower anything (e.g. "this unknown tool sends data out"; "this token looks
   like a secret").

Determinism: current Claude models do not take a temperature, so repeatability
comes from this layer instead. Each question is keyed by a hash of (task,
task version, model, payload); answers are cached and can be recorded to a
local file and replayed, so a recorded run reproduces identical verdicts with
no network access. A timeout, refusal, schema mismatch or any error yields no
evidence, which leaves the deterministic result unchanged.

Configuration (environment):
  KAVACH_AI          off (default) | live | replay
  KAVACH_AI_RECORD   path of a JSONL answer record (written in live, read in replay)
  KAVACH_AI_MODEL    model id (default claude-opus-5-5)
  KAVACH_AI_TIMEOUT  seconds per question (default 4)
"""

from .evidence import AIEvidence, Answer, Task, from_env

__all__ = ["AIEvidence", "Answer", "Task", "from_env"]
