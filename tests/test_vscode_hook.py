from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any, Iterator

import pytest

ROOT = Path(__file__).resolve().parents[1]
HOOK = ROOT / "scripts" / "kavach_vscode_hook.py"


@contextmanager
def fake_kavach_api(result: dict[str, Any]) -> Iterator[tuple[str, list[dict[str, Any]]]]:
    received: list[dict[str, Any]] = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self) -> None:
            if self.path != "/check":
                self.send_error(404)
                return
            size = int(self.headers.get("content-length", "0"))
            received.append(json.loads(self.rfile.read(size).decode("utf-8")))
            body = json.dumps(result).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, _format: str, *_args: Any) -> None:
            return

    server = HTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield "http://127.0.0.1:%d" % server.server_address[1], received
    finally:
        server.shutdown()
        thread.join(timeout=2)
        server.server_close()


def run_hook(event: dict[str, Any], tmp_path: Path, api_url: str) -> dict[str, Any]:
    env = os.environ.copy()
    env["KAVACH_LOCAL_API_URL"] = api_url
    env["KAVACH_VSCODE_HOME"] = str(tmp_path / "kavach-home")
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    assert proc.stdout.strip(), proc.stderr
    return json.loads(proc.stdout)


def pretool_event(
    *,
    session_id: str = "vscode-session-01",
    tool_name: str = "runInTerminal",
    tool_input: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return {
        "hook_event_name": "PreToolUse",
        "timestamp": "2026-10-13T10:00:00Z",
        "cwd": str(ROOT),
        "session_id": session_id,
        "tool_use_id": "tool-use-01",
        "tool_name": tool_name,
        "tool_input": tool_input if tool_input is not None else {"command": "echo PRIVATE_ARG_SHOULD_NOT_PERSIST"},
    }


def api_result(verdict: str, reason: str = "Controlled test verdict.") -> dict[str, Any]:
    return {
        "verdict": verdict,
        "reason": reason,
        "decided_by": "SPEAKER",
        "session_id": "vscode-session-01",
        "ministers": {
            "VAULT": {"verdict": "ALLOW", "matched_id": None},
            "EXECUTOR": {"verdict": verdict if verdict == "BLOCK" else "ALLOW", "matched_id": "EXEC-TEST-01" if verdict == "BLOCK" else None},
            "CHANNEL": {"verdict": "ALLOW", "matched_id": None},
            "NAVIGATOR": {"verdict": "ALLOW", "matched_id": None},
        },
    }


def decision(output: dict[str, Any]) -> str:
    return output["hookSpecificOutput"]["permissionDecision"]


def test_user_prompt_is_sent_as_context_to_kavach(tmp_path: Path) -> None:
    with fake_kavach_api(api_result("ALLOW")) as (url, received):
        prompt_output = run_hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "vscode-session-01",
                "prompt": "Please run the unit tests in this repository.",
            },
            tmp_path,
            url,
        )
        assert prompt_output == {"continue": True}

        output = run_hook(pretool_event(), tmp_path, url)

    assert decision(output) == "allow"
    assert len(received) == 1
    assert received[0]["tool_name"] == "runInTerminal"
    assert received[0]["arguments"] == {"command": "echo PRIVATE_ARG_SHOULD_NOT_PERSIST"}
    assert received[0]["session_id"] == "vscode-session-01"
    assert received[0]["context"]["user_instruction"] == "Please run the unit tests in this repository."


def test_block_decision_prevents_executor_callback_side_effect(tmp_path: Path) -> None:
    """Contract harness: a VS Code-style deny must prevent the executor callback."""
    with fake_kavach_api(api_result("BLOCK", "EXECUTOR matched a dangerous shell pattern.")) as (url, _):
        output = run_hook(pretool_event(), tmp_path, url)

    assert decision(output) == "deny"
    assert "EXECUTOR" in output["hookSpecificOutput"]["permissionDecisionReason"]
    # Model the host's contract: it invokes the real tool only for permissionDecision=allow.
    marker = tmp_path / "tool-side-effect.txt"
    if decision(output) == "allow":
        marker.write_text("the tool ran", encoding="utf-8")
    assert not marker.exists()


def test_escalate_requires_approval_in_vscode(tmp_path: Path) -> None:
    with fake_kavach_api(api_result("ESCALATE", "Intent is unresolved.")) as (url, _):
        output = run_hook(pretool_event(), tmp_path, url)
    assert decision(output) == "ask"
    assert "ESCALATE" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_allow_is_the_only_decision_that_permits_tool_execution(tmp_path: Path) -> None:
    with fake_kavach_api(api_result("ALLOW")) as (url, _):
        output = run_hook(pretool_event(), tmp_path, url)
    assert decision(output) == "allow"


@pytest.mark.parametrize(
    ("bad_result", "reason_fragment"),
    [
        ({"verdict": "UNKNOWN"}, "valid verdict"),
        ({}, "valid verdict"),
    ],
)
def test_malformed_kavach_decision_fails_closed(
    tmp_path: Path, bad_result: dict[str, Any], reason_fragment: str
) -> None:
    with fake_kavach_api(bad_result) as (url, _):
        output = run_hook(pretool_event(), tmp_path, url)
    assert decision(output) == "deny"
    assert reason_fragment in output["hookSpecificOutput"]["permissionDecisionReason"].lower()


def test_api_unavailable_fails_closed(tmp_path: Path) -> None:
    output = run_hook(pretool_event(), tmp_path, "http://127.0.0.1:1")
    assert decision(output) == "deny"
    assert "not allowed to run" in output["hookSpecificOutput"]["permissionDecisionReason"]


def test_remote_kavach_url_is_rejected(tmp_path: Path) -> None:
    output = run_hook(pretool_event(), tmp_path, "https://example.com")
    assert decision(output) == "deny"


def test_missing_stable_session_id_fails_closed(tmp_path: Path) -> None:
    event = pretool_event()
    event.pop("session_id")
    with fake_kavach_api(api_result("ALLOW")) as (url, received):
        output = run_hook(event, tmp_path, url)
    assert decision(output) == "deny"
    assert received == []


def test_audit_does_not_persist_raw_tool_arguments_or_prompt(tmp_path: Path) -> None:
    with fake_kavach_api(api_result("ALLOW")) as (url, _):
        run_hook(
            {
                "hook_event_name": "UserPromptSubmit",
                "session_id": "vscode-session-01",
                "prompt": "PRIVATE_PROMPT_SHOULD_NOT_PERSIST_IN_AUDIT",
            },
            tmp_path,
            url,
        )
        run_hook(pretool_event(), tmp_path, url)

    audit = tmp_path / "kavach-home" / "events.jsonl"
    contents = audit.read_text(encoding="utf-8")
    assert "PRIVATE_ARG_SHOULD_NOT_PERSIST" not in contents
    assert "PRIVATE_PROMPT_SHOULD_NOT_PERSIST_IN_AUDIT" not in contents
    record = json.loads(contents.splitlines()[0])
    assert record["verdict"] == "ALLOW"
    assert record["call_fingerprint"]
    assert record["tool_name"] == "runInTerminal"
    if os.name == "posix":
        assert audit.stat().st_mode & 0o777 == 0o600


def test_post_tool_use_records_execution_without_output_contents(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["KAVACH_VSCODE_HOME"] = str(tmp_path / "kavach-home")
    env["KAVACH_LOCAL_API_URL"] = "http://127.0.0.1:1"  # must not be called for post hooks
    event = pretool_event()
    event.update({
        "hook_event_name": "PostToolUse",
        "tool_response": "PRIVATE_OUTPUT_SHOULD_NOT_PERSIST",
    })
    proc = subprocess.run(
        [sys.executable, str(HOOK)],
        input=json.dumps(event),
        text=True,
        capture_output=True,
        cwd=ROOT,
        env=env,
        timeout=10,
        check=False,
    )
    assert proc.returncode == 0
    assert json.loads(proc.stdout) == {"continue": True}
    audit = tmp_path / "kavach-home" / "events.jsonl"
    contents = audit.read_text(encoding="utf-8")
    assert "EXECUTED" in contents
    assert "PRIVATE_OUTPUT_SHOULD_NOT_PERSIST" not in contents
