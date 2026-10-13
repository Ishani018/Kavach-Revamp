#!/usr/bin/env python3
"""VS Code Local-harness hook that checks with Kavach before tool execution.

The hook intentionally talks only to a loopback HTTP address. It never calls a
hosted Kavach URL, never persists raw tool arguments, and fails closed when the
local policy service cannot produce a valid decision.
"""
from __future__ import annotations

import hashlib
import json
import os
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, Request, build_opener

MAX_STDIN_BYTES = 2 * 1024 * 1024
MAX_PROMPT_CHARS = 12_000
MAX_REASON_CHARS = 500
CONTEXT_TTL_SECONDS = 8 * 60 * 60
DEFAULT_API_URL = "http://127.0.0.1:8088"
API_TIMEOUT_SECONDS = 5.0

class _NoRedirectHandler(HTTPRedirectHandler):
    """Never forward tool arguments to a redirected URL, even from loopback."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


_LOCAL_OPENER = build_opener(ProxyHandler({}), _NoRedirectHandler())
VALID_VERDICTS = {"ALLOW", "BLOCK", "ESCALATE"}
MINISTER_ORDER = ("VAULT", "EXECUTOR", "CHANNEL", "NAVIGATOR")
MAX_REPORT_CHARS = 3_500
MAX_MINISTER_NOTE_CHARS = 220
NAVIGATOR_POLICY_TITLES = {
    "POL-001": "proven-exfil-to-unauthorized-destination",
    "POL-002": "contract-scope-violation",
    "POL-003": "untrusted-content-privilege-induction",
    "POL-004": "decode-execute-structural",
    "POL-005": "specialist-hard-block-preserved",
    "POL-006": "high-impact-without-approval",
    "POL-007": "insufficient-evidence-coverage",
    "POL-008": "explicit-task-restriction-violation",
    "POL-009": "prior-sensitive-artifact-to-unauthorized-destination",
}


def _safe_inline(value: Any, limit: int = MAX_MINISTER_NOTE_CHARS) -> str:
    """Collapse and cap server-provided text before displaying it to a user."""
    if not isinstance(value, str):
        return ""
    normalized = " ".join(ch for ch in value if ch.isprintable()).split()
    text = " ".join(normalized)
    return text if len(text) <= limit else text[: max(0, limit - 1)] + "…"


def _rule_ids(item: dict[str, Any]) -> list[str]:
    """Extract stable rule/policy identifiers without exposing matched input."""
    found: list[str] = []
    matched = item.get("matched_id")
    if isinstance(matched, str) and matched.strip():
        found.append(matched.strip()[:160])
    diagnostics = item.get("diagnostics")
    if isinstance(diagnostics, dict):
        policy_ids = diagnostics.get("policy_ids")
        if isinstance(policy_ids, list):
            for value in policy_ids:
                if isinstance(value, str) and value.strip() and value.strip() not in found:
                    found.append(value.strip()[:160])
    return found[:6]


def _display_rule(rule_id: str) -> str:
    """Add a human-readable title for NAVIGATOR policy IDs when known."""
    for policy_id, title in NAVIGATOR_POLICY_TITLES.items():
        if rule_id == policy_id:
            return f"{policy_id} ({title})"
    return rule_id


def _minister_note(name: str, item: dict[str, Any], verdict: str, rule_ids: list[str]) -> str:
    """Summarize each minister without echoing command text, secrets, or destinations."""
    raw_reason = _safe_inline(item.get("reason"))
    if verdict == "ALLOW" and not rule_ids:
        # No-hit reasons from the current API are fixed, non-sensitive summaries.
        if raw_reason and "no rule matched" in raw_reason.lower():
            return raw_reason
        if name == "NAVIGATOR":
            return "No blocking or escalation policy was returned."
        return {
            "VAULT": "No credential/secret rule was reported as matched.",
            "EXECUTOR": "No dangerous-execution rule was reported as matched.",
            "CHANNEL": "No sensitive-flow/provenance rule was reported as matched.",
        }.get(name, "No matching rule was reported.")

    if name == "VAULT":
        return "Credential/secret rule matched; matched material is withheld."
    if name == "EXECUTOR":
        return "Dangerous-execution rule matched; raw command excerpt is withheld."
    if name == "CHANNEL":
        return "Sensitive-data flow/provenance rule triggered; raw values are withheld."
    # NAVIGATOR uses fixed, high-level reasons; its diagnostics contain policy IDs.
    if raw_reason:
        return raw_reason
    return "NAVIGATOR returned this verdict; see the policy ID above."


def _decision_report(
    result: dict[str, Any],
    *,
    tool_name: str,
    permission: str,
    decided_by: Any,
) -> str:
    """Format a readable, privacy-aware, user-visible report for VS Code Local."""
    verdict = result.get("verdict")
    verdict = verdict if verdict in VALID_VERDICTS else "UNKNOWN"
    actor = _safe_inline(decided_by, 80) or "not reported"
    if permission == "allow":
        action_line = "Enforcement action: ALLOW — Kavach returned ALLOW."
    elif verdict == "BLOCK":
        action_line = "Enforcement action: DENY — Kavach returned BLOCK."
    elif verdict == "ESCALATE":
        action_line = "Enforcement action: DENY — fail-closed because interactive approval is not verified."
    else:
        action_line = "Enforcement action: DENY."

    lines = [
        "KAVACH PRE-TOOL REVIEW",
        "Tool: " + (_safe_inline(tool_name, 128) or "unknown"),
        f"Policy verdict: {verdict} (decided by {actor})",
        action_line,
        "Minister breakdown (raw command text, secret values, and destinations are withheld):",
    ]
    ministers = result.get("ministers")
    if not isinstance(ministers, dict):
        ministers = {}
    for name in MINISTER_ORDER:
        item = ministers.get(name)
        if not isinstance(item, dict):
            lines.append(f"- {name}: NO RESULT | Rule: none reported | Reason: minister result missing.")
            continue
        minister_verdict = item.get("verdict")
        minister_verdict = minister_verdict if minister_verdict in VALID_VERDICTS else "UNKNOWN"
        ids = _rule_ids(item)
        rule_text = "; ".join(_display_rule(rule_id) for rule_id in ids) if ids else "no specific rule ID reported"
        note = _minister_note(name, item, minister_verdict, ids)
        lines.append(f"- {name}: {minister_verdict} | Rule: {rule_text} | Reason: {note}")
    report = "\n".join(lines)
    return report[:MAX_REPORT_CHARS]




def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8", errors="replace")).hexdigest()


def _home(data_home: str | Path | None = None) -> Path:
    if data_home is not None:
        return Path(data_home).expanduser()
    return Path(os.environ.get("KAVACH_VSCODE_HOME", "~/.kavach-vscode")).expanduser()


def _private_dir(path: Path) -> None:
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    if os.name == "posix":
        path.chmod(0o700)


def _session_id(event: dict[str, Any]) -> str | None:
    value = event.get("session_id")
    return value.strip()[:512] if isinstance(value, str) and value.strip() else None


def _session_digest(session_id: str) -> str:
    return _sha(session_id)


def _context_path(data_home: Path, session_id: str) -> Path:
    return data_home / "contexts" / (_session_digest(session_id) + ".json")


def _store_prompt(event: dict[str, Any], data_home: Path) -> None:
    session_id = _session_id(event)
    prompt = event.get("prompt")
    if not session_id or not isinstance(prompt, str) or not prompt.strip():
        return

    contexts = data_home / "contexts"
    _private_dir(contexts)
    payload = {"saved_at": time.time(), "prompt": prompt.strip()[:MAX_PROMPT_CHARS]}
    fd, temp_name = tempfile.mkstemp(prefix=".context-", suffix=".tmp", dir=contexts)
    temp_path = Path(temp_name)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(payload, stream, ensure_ascii=False)
            stream.write("\n")
        temp_path.replace(_context_path(data_home, session_id))
    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass

    # Reap expired context files, keeping user prompts only for the short TTL.
    cutoff = time.time() - CONTEXT_TTL_SECONDS
    for item in contexts.glob("*.json"):
        try:
            if item.stat().st_mtime < cutoff:
                item.unlink(missing_ok=True)
        except OSError:
            continue


def _load_prompt(event: dict[str, Any], data_home: Path) -> str | None:
    session_id = _session_id(event)
    if not session_id:
        return None
    path = _context_path(data_home, session_id)
    try:
        if not path.is_file() or time.time() - path.stat().st_mtime > CONTEXT_TTL_SECONDS:
            path.unlink(missing_ok=True)
            return None
        with path.open("r", encoding="utf-8") as stream:
            payload = json.load(stream)
        prompt = payload.get("prompt") if isinstance(payload, dict) else None
        return prompt[:MAX_PROMPT_CHARS] if isinstance(prompt, str) and prompt.strip() else None
    except (OSError, ValueError, TypeError):
        return None


def _local_check_url() -> str:
    base = os.environ.get("KAVACH_LOCAL_API_URL", DEFAULT_API_URL).strip().rstrip("/")
    parsed = urlsplit(base)
    # Avoid leaking code, prompts, tool inputs, or decisions to a remote endpoint.
    if (
        parsed.scheme not in {"http", "https"}
        or parsed.hostname not in {"127.0.0.1", "localhost", "::1"}
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("KAVACH_LOCAL_API_URL must point to localhost (for example http://127.0.0.1:8088).")
    try:
        _ = parsed.port
    except ValueError as exc:
        raise ValueError("KAVACH_LOCAL_API_URL has an invalid port.") from exc
    return base + "/check"


def _post_check(payload: dict[str, Any]) -> dict[str, Any]:
    url = _local_check_url()
    request = Request(
        url,
        data=json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json", "Accept": "application/json"},
        method="POST",
    )
    try:
        with _LOCAL_OPENER.open(request, timeout=API_TIMEOUT_SECONDS) as response:
            if not 200 <= response.status < 300:
                raise RuntimeError("Kavach local API returned a non-success response.")
            result = json.loads(response.read(1024 * 1024).decode("utf-8"))
    except HTTPError as exc:
        raise RuntimeError("Kavach local API rejected the request (HTTP %s)." % exc.code) from None
    except (URLError, TimeoutError, OSError):
        raise RuntimeError("Kavach local API is unavailable or timed out.") from None
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise RuntimeError("Kavach local API returned an invalid response.") from None
    if not isinstance(result, dict):
        raise RuntimeError("Kavach local API returned an invalid decision.")
    return result


def _fingerprint(tool_name: str, tool_input: dict[str, Any]) -> str:
    canonical = json.dumps(
        {"tool_name": tool_name, "tool_input": tool_input},
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
        default=str,
    )
    return _sha(canonical)


def _audit(data_home: Path, record: dict[str, Any]) -> None:
    audit_path = data_home / "events.jsonl"
    _private_dir(data_home)
    line = (json.dumps(record, ensure_ascii=False, separators=(",", ":")) + "\n").encode("utf-8")
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(audit_path, flags, 0o600)
    try:
        if os.name == "posix":
            os.fchmod(fd, 0o600)
        os.write(fd, line)
    finally:
        os.close(fd)


def _tool_use_digest(event: dict[str, Any]) -> str | None:
    value = event.get("tool_use_id")
    if isinstance(value, str) and value:
        return _sha(value)[:16]
    return None


def _audit_base(event: dict[str, Any], *, data_home: Path, tool_name: str) -> dict[str, Any]:
    sid = _session_id(event)
    tool_input = event.get("tool_input")
    return {
        "timestamp": _now(),
        "hook_event": event.get("hook_event_name"),
        "session_hash": _sha(sid)[:16] if sid else None,
        "tool_use_hash": _tool_use_digest(event),
        "tool_name": tool_name[:128],
        "call_fingerprint": _fingerprint(tool_name, tool_input) if isinstance(tool_input, dict) else None,
    }


def _hook_decision(
    decision: str,
    reason: str,
    *,
    additional_context: str | None = None,
    system_message: str | None = None,
) -> dict[str, Any]:
    output: dict[str, Any] = {
        "hookSpecificOutput": {
            "hookEventName": "PreToolUse",
            "permissionDecision": decision,
            "permissionDecisionReason": reason[:MAX_REASON_CHARS],
        }
    }
    if additional_context:
        output["hookSpecificOutput"]["additionalContext"] = additional_context[:MAX_REPORT_CHARS]
    if system_message:
        # Local hooks render this as a user-visible message; additionalContext
        # separately gives the model the same safe summary for its explanation.
        output["systemMessage"] = system_message[:MAX_REPORT_CHARS]
    return output


def _deny(reason: str) -> dict[str, Any]:
    return _hook_decision("deny", reason, system_message=reason)


def _handle_pre_tool_use(
    event: dict[str, Any],
    data_home: Path,
    api_call: Callable[[dict[str, Any]], dict[str, Any]],
) -> dict[str, Any]:
    tool_name = event.get("tool_name")
    tool_input = event.get("tool_input")
    sid = _session_id(event)
    if not isinstance(tool_name, str) or not tool_name.strip() or len(tool_name) > 128:
        return _deny("Kavach blocked this call because VS Code supplied no valid tool name.")
    tool_name = tool_name.strip()
    if not isinstance(tool_input, dict):
        return _deny("Kavach blocked this call because the tool arguments were not a JSON object.")
    if not sid:
        return _deny("Kavach blocked this call because VS Code supplied no stable session ID.")

    payload: dict[str, Any] = {
        "tool_name": tool_name,
        "arguments": tool_input,
        "session_id": sid,
    }
    prompt = _load_prompt(event, data_home)
    if prompt:
        # VS Code supplies this prompt directly at UserPromptSubmit: it is
        # the trusted user boundary, unlike text extracted from a tool result.
        payload["context"] = {"user_instruction": prompt}

    fingerprint = _fingerprint(tool_name, tool_input)
    try:
        result = api_call(payload)
        verdict = result.get("verdict")
        if verdict not in VALID_VERDICTS:
            raise RuntimeError("Kavach returned no valid verdict.")
        reason = result.get("reason")
        reason = reason.strip() if isinstance(reason, str) and reason.strip() else "No reason provided."
        decided_by = result.get("decided_by")
        ministers = result.get("ministers")
        if not isinstance(ministers, dict):
            ministers = {}
        minister_summary = []
        for name in MINISTER_ORDER:
            item = ministers.get(name)
            if isinstance(item, dict):
                value = item.get("verdict")
                rule_ids = _rule_ids(item)
                if isinstance(value, str):
                    part = name + "=" + value
                    if rule_ids:
                        part += " (" + "; ".join(rule_ids)[:200] + ")"
                    minister_summary.append(part)
        record = _audit_base(event, data_home=data_home, tool_name=tool_name)
        record.update({
            "call_fingerprint": fingerprint,
            "verdict": verdict,
            "decided_by": decided_by if isinstance(decided_by, str) else None,
            "minister_summary": minister_summary,
            "reason": reason[:MAX_REASON_CHARS],
            "execution": "pending" if verdict == "ALLOW" else "blocked",
        })
        try:
            _audit(data_home, record)
        except OSError:
            return _deny("Kavach blocked this call because its private audit log could not be written.")
        if verdict == "ALLOW":
            permission = "allow"
            hook_reason = "Kavach ALLOW: %s" % reason
        elif verdict == "BLOCK":
            permission = "deny"
            actor = " by " + decided_by if isinstance(decided_by, str) and decided_by else ""
            hook_reason = "Kavach BLOCK%s: %s" % (actor, reason)
        else:
            # VS Code 1.141.0 did not surface an approval prompt for native
            # "ask" in the live Local-harness test; the tool ran after an
            # ESCALATE. Fail closed until that host behavior is independently
            # verified, rather than treating ask as a reliable security gate.
            permission = "deny"
            actor = " by " + decided_by if isinstance(decided_by, str) and decided_by else ""
            hook_reason = (
                "Kavach ESCALATE%s: %s. Approval prompting is not verified in this "
                "VS Code session, so this call was denied fail-closed."
                % (actor, reason)
            )
        report = _decision_report(
            result,
            tool_name=tool_name,
            permission=permission,
            decided_by=decided_by,
        )
        return _hook_decision(
            permission,
            hook_reason,
            additional_context=report,
            system_message=report,
        )
    except Exception as exc:
        # Never include request bodies, raw arguments, or upstream response
        # bodies in the hook output; only safe, fixed failure messages escape.
        message = str(exc)
        if not message.startswith("Kavach "):
            message = "Kavach local check failed."
        record = _audit_base(event, data_home=data_home, tool_name=tool_name)
        record.update({
            "call_fingerprint": fingerprint,
            "verdict": "ERROR",
            "execution": "blocked",
            "reason": message[:MAX_REASON_CHARS],
        })
        try:
            _audit(data_home, record)
        except OSError:
            pass
        return _deny(message + " The tool was not allowed to run.")


def process_event(
    event: dict[str, Any],
    *,
    api_call: Callable[[dict[str, Any]], dict[str, Any]] | None = None,
    data_home: str | Path | None = None,
) -> dict[str, Any]:
    """Convert a VS Code Local hook event into the documented decision JSON."""
    home = _home(data_home)
    event_name = event.get("hook_event_name")
    if event_name == "UserPromptSubmit":
        try:
            _store_prompt(event, home)
        except OSError:
            # Missing context can only make policy stricter; never block the prompt itself.
            pass
        return {"continue": True}
    if event_name == "PreToolUse":
        return _handle_pre_tool_use(event, home, api_call or _post_check)
    if event_name == "PostToolUse":
        tool_name = event.get("tool_name")
        if isinstance(tool_name, str) and tool_name:
            record = _audit_base(event, data_home=home, tool_name=tool_name)
            record.update({"verdict": "EXECUTED", "execution": "completed"})
            try:
                _audit(home, record)
            except OSError:
                # The action has already executed; a post-hook cannot undo it.
                pass
        return {"continue": True}
    # This script is registered only for the three events above. If VS Code
    # invokes it with an unknown/malformed event name, never silently permit a
    # potentially pre-execution event.
    return _deny("Kavach blocked this operation because the hook event type was missing or unsupported.")


def main() -> int:
    try:
        raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
        if len(raw) > MAX_STDIN_BYTES:
            sys.stdout.write(json.dumps(_deny("Kavach blocked this call because the hook input was too large.")))
            return 0
        event = json.loads(raw.decode("utf-8"))
        if not isinstance(event, dict):
            raise ValueError("Hook event must be a JSON object.")
        output = process_event(event)
    except Exception:
        # A malformed PreToolUse event must not become an implicit allow. The
        # event name cannot be trusted if the payload itself is malformed, so
        # deny rather than continue.
        output = _deny("Kavach blocked this call because its hook input was invalid.")
    sys.stdout.write(json.dumps(output, ensure_ascii=False, separators=(",", ":")) + "\n")
    sys.stdout.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
