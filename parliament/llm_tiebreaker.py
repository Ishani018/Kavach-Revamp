"""
parliament/llm_tiebreaker.py
=============================

RARE escalation tier for VAULT/EXECUTOR's narrative-phrasing gap
(docs/status/REARCHITECTURE_PLAN.md's EXECUTOR §2.2 "resolved-call-name tracing" gap,
extended to VAULT). Confirmed this session: VAULT/EXECUTOR's deterministic
regex/AST rules catch literal code/command syntax (`os.system(`, `.ssh/`)
but miss the SAME techniques described in prose ("append to
~/.ssh/authorized_keys for persistence") -- a 267-case real red-team set
showed VAULT/EXECUTOR caught only 2/96 and 3/60 of their own-domain
attacks when phrased narratively, versus catching them reliably when
phrased as literal syntax.

Two feasibility pilots were run before this was wired in (per
docs/status/REARCHITECTURE_PLAN.md's discipline of not shipping unvalidated escalation
tiers):
  1. Holistic judgment ("is this malicious or benign?") -- qwen2.5:7b
     scored 14/17 (82.4%), with 3 dangerous false negatives where the
     model had to WEIGH competing signals and defaulted charitable
     (missed an explicit "not associated with the workload" mismatch
     phrase entirely).
  2. Split extraction from judgment -- ask qwen ONLY for 3 narrow factual
     flags (does it, does it not, extract don't judge), then a
     DETERMINISTIC rule (not the LLM) decides the verdict. This scored
     16/17 (94.1%), correctly resolving both cases the holistic design
     missed. This is the design implemented here.

ARCHITECTURE (rare escalation, never a per-call gate -- confirmed
~35-40s/call latency for the qwen round-trip, which is why this must
never sit on the fast path):
  1. VAULT/EXECUTOR's EXISTING deterministic regex/AST rules
     (prefilters.py) run first, unchanged. If they already produce a
     verdict, this module is never consulted at all.
  2. A NARROW entity+verb-window pre-flag (this module's
     `should_escalate()`) decides ONLY whether a call is worth escalating
     to the LLM tier -- not a verdict. Reuses the exact entity lists
     already in VAULT_PATTERNS/EXECUTOR_DENYLIST (fixed before this
     tier existed, not tuned to any test set) plus a small, generic
     action-verb list. A benign_probe.json regression run against the
     entity+verb-window check ALONE (no LLM, no rule on top) found 7
     false positives (bitsadmin/certutil/IEX/mshta/.env.example legit
     cases) -- this is exactly why the entity+verb match is now scoped to
     "worth asking the LLM" rather than "verdict," and why step 3 exists.
  3. Only for calls the pre-flag marks worth escalating: call qwen2.5:7b
     with the validated 3-flag extraction prompt (target_scope_mismatch,
     explicit_legitimacy_marker, non_standard_source) -- same prompt
     structure as the pilot, not redesigned.
  4. A deterministic rule (not the LLM) converts the 3 flags to a verdict:
       target_scope_mismatch OR non_standard_source -> BLOCK
       elif explicit_legitimacy_marker                -> ALLOW
       else                                            -> ESCALATE
  5. Hard timeout + fail-open-to-prior-behavior: if the qwen call fails,
     times out, or returns unparseable JSON, this tier contributes
     nothing (returns None) -- the caller falls back to whatever
     verdict the deterministic layer would have produced without this
     tier (i.e. ALLOW, since we only reach this tier when the existing
     regex/AST rules found no hit).
"""
from __future__ import annotations

import json
import logging
import re
from dataclasses import dataclass

import requests

from .ministers import MinisterScan
from .prefilters import VAULT_PATTERNS, EXECUTOR_DENYLIST

log = logging.getLogger("kavach.llm_tiebreaker")

OLLAMA_URL = "http://localhost:11434/api/generate"
MODEL = "qwen2.5:7b"
# 90s: pilot runs observed calls ranging 22.9s-74.7s (cold-start-adjacent
# calls run long); 45s produced two real near-miss timeouts (47.2s) on
# correctly-triggered cases. Still bounded, never hangs the request --
# just wide enough to not fail open on slow-but-legitimate responses.
TIMEOUT_S = 90.0


# ──────────────────────────────────────────────────────────────────────────
# Step 2 — narrow escalation trigger (NOT a verdict). Reuses the entity
# lists already in prefilters.py's VAULT_PATTERNS/EXECUTOR_DENYLIST
# (fixed before this tier existed), plus a small generic action-verb list
# not tuned to any test set.
# ──────────────────────────────────────────────────────────────────────────

# Bare substring form of each VAULT/EXECUTOR entity, for a loose "does the
# text mention this at all" pre-check -- separate from the precise regexes
# in prefilters.py, which already run first and would have caught a
# literal-syntax match before this module is ever consulted.
_VAULT_ENTITY_SUBSTRINGS = [
    ".env", ".aws/credentials", ".aws\\credentials", "id_rsa", "id_dsa",
    "id_ecdsa", "id_ed25519", ".ssh/", ".ssh\\", ".pem", "AKIA",
    "service_account", "PRIVATE KEY", "secrets.json", "secrets.yaml",
    "secrets.yml", "credentials.json", "credentials.yaml", "credentials.yml",
]

_EXECUTOR_ENTITY_SUBSTRINGS = [
    "curl", "wget", "certutil", "mshta", "rundll32", "regsvr32", "cmstp",
    "powershell", "Invoke-Expression", "IEX", "Net.WebClient", "bitsadmin",
    "ruby -e", "php -r", "eval(", "exec(", "os.system", "subprocess.run",
    "subprocess.Popen", "subprocess.call", "base64.b64decode", "atob(",
    "gdb ", "lldb ", "nc ",
]

_ACTION_VERBS = [
    "read", "reads", "reading", "write", "writes", "writing", "written",
    "append", "appends", "appending", "load", "loads", "loading",
    "fetch", "fetches", "fetching", "retrieve", "retrieves", "retrieving",
    "access", "accesses", "accessing", "open", "opens", "opening",
    "exfiltrate", "exfiltrates", "exfiltrating", "exfiltration",
    "decode", "decodes", "decoding", "execute", "executes", "executing",
    "execution", "run", "runs", "running", "grep", "search", "searches",
    "searching", "extract", "extracts", "extracting", "dump", "dumps",
    "dumping", "invoke", "invokes", "invoking", "invocation", "create",
    "creates", "creating", "creation", "modify", "modifies", "modifying",
    "modification", "install", "installs", "installing", "transfer",
    "transfers", "transferring", "send", "sends", "sending", "download",
    "downloads", "downloading", "upload", "uploads", "uploading", "copy",
    "copies", "copying", "call", "calls", "calling",
]

_WINDOW_CHARS = 60


def _entity_near_verb(text: str, entities: list[str]) -> str | None:
    text_lower = text.lower()
    for entity in entities:
        entity_lower = entity.lower()
        start = 0
        while True:
            idx = text_lower.find(entity_lower, start)
            if idx == -1:
                break
            window_start = max(0, idx - _WINDOW_CHARS)
            window_end = min(len(text), idx + len(entity) + _WINDOW_CHARS)
            window = text_lower[window_start:window_end]
            for verb in _ACTION_VERBS:
                if re.search(r"\b" + re.escape(verb) + r"\b", window):
                    return entity
            start = idx + 1
    return None


def should_escalate_vault(text: str) -> str | None:
    """Returns the matched entity name if `text` is worth escalating to the
    LLM tiebreaker for VAULT, else None. Caller is responsible for having
    already run prefilters.check_vault() and confirmed it returned None --
    this function does not re-check the literal regexes itself."""
    return _entity_near_verb(text, _VAULT_ENTITY_SUBSTRINGS)


def should_escalate_executor(text: str) -> str | None:
    """Same as should_escalate_vault, for EXECUTOR's entity list."""
    return _entity_near_verb(text, _EXECUTOR_ENTITY_SUBSTRINGS)


# ──────────────────────────────────────────────────────────────────────────
# Step 3-4 — LLM extraction (3 narrow factual flags) + deterministic rule.
# Same prompt structure as the validated pilot, not redesigned.
# ──────────────────────────────────────────────────────────────────────────

_PROMPT_TEMPLATE = (
    "You are extracting specific factual signals from an action description, for "
    "a security monitoring pipeline. Do NOT decide whether the action is malicious "
    "or benign -- only answer the three factual questions below, based strictly on "
    "what the text states or clearly implies.\n\n"
    "ACTION DESCRIPTION: {text}\n\n"
    "1. target_scope_mismatch: Does the text state or imply the action's target "
    "does NOT match who/what it should normally belong to (e.g. phrases like "
    "'not associated with', 'outside', 'different account/workload/owner than "
    "expected', or an explicit attacker-controlled destination like an "
    "'attacker'-named domain/IP)?\n"
    "2. explicit_legitimacy_marker: Does the text contain an explicit "
    "legitimate-purpose phrase (e.g. approved, vetted, routine, verification, "
    "integrity check, internal, official, signed)?\n"
    "3. non_standard_source: Does the text describe the entity coming from a "
    "non-default, non-standard, unsigned, or untrusted-sounding location "
    "(e.g. 'non-vendor-signed', 'writable location', 'attacker_dir', a "
    "suspiciously-named path)? IMPORTANT: a script or file described as "
    "internally-authored, homegrown, in-house, written by the team, or "
    "simply stored/kept on the local disk or local machine is a NORMAL, "
    "TRUSTED source -- do NOT mark this true unless the text also mentions "
    "an external URL, a remote/unfamiliar host, a writable temp directory, "
    "or another explicitly untrusted origin. Locally-authored and "
    "locally-stored is the default, expected case, not a non-standard "
    "one.\n\n"
    "Return ONLY valid JSON with this exact shape, no other text:\n"
    '{{"target_scope_mismatch": true or false, "explicit_legitimacy_marker": true or false, "non_standard_source": true or false}}'
)


@dataclass
class TiebreakerFlags:
    target_scope_mismatch: bool
    explicit_legitimacy_marker: bool
    non_standard_source: bool


def _extract_json(text: str) -> dict | None:
    text = text.replace("```json", " ").replace("```", " ")
    depth = 0
    start = -1
    in_str = False
    esc = False
    for i, ch in enumerate(text):
        if start == -1:
            if ch == "{":
                start = i
                depth = 1
            continue
        if in_str:
            if esc:
                esc = False
            elif ch == "\\":
                esc = True
            elif ch == '"':
                in_str = False
        else:
            if ch == '"':
                in_str = True
            elif ch == "{":
                depth += 1
            elif ch == "}":
                depth -= 1
                if depth == 0:
                    try:
                        return json.loads(text[start : i + 1])
                    except json.JSONDecodeError:
                        return None
    return None


def _call_qwen_extract(text: str) -> TiebreakerFlags | None:
    """Calls qwen2.5:7b for the 3-flag extraction. Returns None on ANY
    failure (network error, timeout, unparseable response, missing keys)
    -- caller fails open to prior deterministic-layer behavior, never
    crashes the request."""
    prompt = _PROMPT_TEMPLATE.format(text=text)
    try:
        resp = requests.post(
            OLLAMA_URL,
            json={"model": MODEL, "prompt": prompt, "stream": False, "format": "json"},
            timeout=TIMEOUT_S,
        )
        resp.raise_for_status()
        raw = resp.json().get("response", "")
    except Exception as e:
        log.warning("llm_tiebreaker: qwen call failed, failing open: %s", e)
        return None

    parsed = _extract_json(raw)
    if parsed is None:
        log.warning("llm_tiebreaker: unparseable qwen response, failing open: %r", raw[:200])
        return None

    required = ("target_scope_mismatch", "explicit_legitimacy_marker", "non_standard_source")
    if not all(k in parsed for k in required):
        log.warning("llm_tiebreaker: qwen response missing required keys, failing open: %r", parsed)
        return None

    return TiebreakerFlags(
        target_scope_mismatch=bool(parsed["target_scope_mismatch"]),
        explicit_legitimacy_marker=bool(parsed["explicit_legitimacy_marker"]),
        non_standard_source=bool(parsed["non_standard_source"]),
    )


def _apply_rule(flags: TiebreakerFlags) -> str:
    if flags.target_scope_mismatch or flags.non_standard_source:
        return "BLOCK"
    if flags.explicit_legitimacy_marker:
        return "ALLOW"
    return "ESCALATE"


# ──────────────────────────────────────────────────────────────────────────
# Public entry points
# ──────────────────────────────────────────────────────────────────────────

def check_vault_tiebreaker(text: str) -> MinisterScan | None:
    """Full pipeline for VAULT: pre-flag -> LLM extraction -> deterministic
    rule. Returns None if the pre-flag doesn't trigger (not worth escalating)
    OR if the LLM call fails (fails open). Caller is responsible for only
    invoking this when prefilters.check_vault() already returned None."""
    entity = should_escalate_vault(text)
    if entity is None:
        return None

    flags = _call_qwen_extract(text)
    if flags is None:
        return None  # fail open -- prior (no-hit) deterministic behavior stands

    verdict = _apply_rule(flags)
    if verdict == "ESCALATE" and not flags.target_scope_mismatch and not flags.non_standard_source and not flags.explicit_legitimacy_marker:
        # No signal fired at all -- genuinely ambiguous, matches the
        # VAULT-034 pilot case. ESCALATE is a real verdict value already
        # used elsewhere in Kavach (grey-zone), not a new one.
        pass

    return MinisterScan(
        minister="VAULT",
        verdict=verdict,
        confidence=1.0 if verdict != "ESCALATE" else 0.55,
        matched_id=f"VAULT-LLM-TIEBREAKER:{entity}",
        matched_text=(
            f"LLM tiebreaker escalation on entity {entity!r}: "
            f"target_scope_mismatch={flags.target_scope_mismatch}, "
            f"explicit_legitimacy_marker={flags.explicit_legitimacy_marker}, "
            f"non_standard_source={flags.non_standard_source}"
        ),
        matched_level="llm_tiebreaker",
        source=None,
        retrieval_mode="llm_tiebreaker",
    )


def check_executor_tiebreaker(text: str) -> MinisterScan | None:
    """Same pipeline as check_vault_tiebreaker, for EXECUTOR."""
    entity = should_escalate_executor(text)
    if entity is None:
        return None

    flags = _call_qwen_extract(text)
    if flags is None:
        return None

    verdict = _apply_rule(flags)

    return MinisterScan(
        minister="EXECUTOR",
        verdict=verdict,
        confidence=1.0 if verdict != "ESCALATE" else 0.55,
        matched_id=f"EXECUTOR-LLM-TIEBREAKER:{entity}",
        matched_text=(
            f"LLM tiebreaker escalation on entity {entity!r}: "
            f"target_scope_mismatch={flags.target_scope_mismatch}, "
            f"explicit_legitimacy_marker={flags.explicit_legitimacy_marker}, "
            f"non_standard_source={flags.non_standard_source}"
        ),
        matched_level="llm_tiebreaker",
        source=None,
        retrieval_mode="llm_tiebreaker",
    )
