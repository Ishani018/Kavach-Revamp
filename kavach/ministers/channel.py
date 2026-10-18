"""
CHANNEL: session-level sensitive-read -> external-send detection.

Wraps channel_taint.py. Per-session state (taint and provenance) lives in this
object, keyed by session_id, so one session's reads never taint another's sends.
The taint/provenance composition rule is the one parliament/server.py used:
a taint BLOCK is overridden to ALLOW only when provenance positively classifies
every destination as SELF or USER_SUPPLIED; provenance never hard-blocks.

Optional ToolCall.context keys: account_email, user_instruction, tool_output.
State is in-memory and unbounded (one entry per session_id); no persistence.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

from . import channel_taint as ct, observed_source, scan_to_result
from ..ai import AIEvidence
from ..schemas import MinisterResult, Observation, ToolCall


def _opt_str(ctx: dict, key: str) -> Optional[str]:
    v = ctx.get(key)
    return v if isinstance(v, str) else None


class ChannelMinister:
    name = "CHANNEL"

    def __init__(self, ai: Optional[AIEvidence] = None) -> None:
        self._taint: Dict[str, ct.SessionTaint] = {}
        self._provenance: Dict[str, ct.SessionProvenance] = {}
        self.ai = ai or AIEvidence("off")

    def check(self, call: ToolCall) -> MinisterResult:
        text = call.to_wire_text()
        taint = self._taint.setdefault(call.session_id, ct.new_taint_state())
        prov = self._provenance.setdefault(call.session_id, ct.new_provenance_state())
        account_email = _opt_str(call.context, "account_email")

        taint_scan = ct.check_channel_taint(text, taint, account_email=account_email)
        prov_scan, prov_records = ct.check_provenance(
            text, prov, account_email=account_email,
            user_instruction=_opt_str(call.context, "user_instruction"),
            tool_output=_opt_str(call.context, "tool_output"),
        )

        if taint_scan is not None and taint_scan.verdict == "BLOCK" and prov_records and all(
            r.classification in ("SELF", "USER_SUPPLIED") for r in prov_records
        ):
            taint_scan = None  # provenance positively confirms a legitimate destination

        chosen = taint_scan if taint_scan is not None else prov_scan
        result = scan_to_result(chosen, self.name)
        if self.ai.enabled and not ct.is_source_tool(call.tool_name) and not ct.is_destination_tool(call.tool_name):
            result = self._unknown_tool(call, result, taint, prov, account_email)
        return result

    def _unknown_tool(self, call: ToolCall, result: MinisterResult, taint, prov, account_email) -> MinisterResult:
        """A tool CHANNEL's name heuristics do not recognise (typically an MCP
        tool). AI evidence describes its role from its name and argument names
        only (never values); recipients it names must be real argument names.
        The role can only add restrictions: a sending tool's recipients get the
        same provenance and taint checks as a known send tool, and a
        private-data reader taints the session."""
        from ..ai import tasks
        args = call.arguments or {}
        if not args:
            return result
        answer = self.ai.ask(tasks.TOOL_ROLE, {
            "tool_name": call.tool_name,
            "argument_types": {k: type(v).__name__ for k, v in sorted(args.items())},
        })
        if answer is None:
            return result
        role = answer.data
        recipients = [k for k in role["recipient_arguments"] if k in args]
        result.diagnostics["ai_tool_role"] = {
            "reads_private_data": role["reads_private_data"],
            "sends_externally": role["sends_externally"],
            "recipient_arguments": recipients,
            **answer.provenance(),
        }

        if result.verdict == "ALLOW" and role["sends_externally"]:
            values = []
            for key in recipients:
                value = args[key]
                if isinstance(value, str):
                    values.append(value)
                elif isinstance(value, list):
                    values.extend(v for v in value if isinstance(v, str))
            for value in values:
                classification, _, _ = ct._classify_destination_value(value, prov, account_email)
                if classification in ("SELF", "USER_SUPPLIED"):
                    continue
                verdict = "BLOCK" if taint.tainted else "ESCALATE"
                matched = "CHANNEL-TAINT-AI:read-then-send" if taint.tainted else f"CHANNEL-PROVENANCE-AI:{classification.lower()}"
                return MinisterResult(
                    minister=self.name, verdict=verdict, matched_id=matched, confidence=1.0,
                    reason=(f"CHANNEL: AI evidence identifies {call.tool_name!r} as sending data; recipient "
                            f"is {classification.lower().replace('_', '-')}"
                            + (" and the session holds sensitive data" if taint.tainted else "")),
                    diagnostics={"level": "deterministic", **result.diagnostics},
                )

        if role["reads_private_data"] and not taint.tainted:
            taint.tainted = True
            taint.source_tool = call.tool_name
            taint.source_matched_id = "CHANNEL-TAINT-SOURCE:ai-tool-role"
        return result

    def observe(self, obs: Observation, prior_results: Dict[str, MinisterResult]) -> Optional[MinisterResult]:
        """Update session state from a hook observation; never blocks on its own.

        UserPromptSubmit: every prompt is trusted user input, so its destination
        values join USER_SUPPLIED (check() alone only reads the first prompt).
        Tool output, a sub-agent's report and the final answer are untrusted:
        their destination values become OUTPUT_DERIVED for later calls,
        attributed to where they came from, and secret material in them (VAULT
        BLOCK) taints the session, so a later send to an unverified destination
        is blocked."""
        if obs.event == "UserPromptSubmit":
            prov = self._provenance.setdefault(obs.session_id, ct.new_provenance_state())
            prov.user_candidates |= ct._extract_candidate_values(obs.text)
            prov.user_instruction_seen = True
            return None
        source = observed_source(obs)
        if source is None:
            return None
        prov = self._provenance.setdefault(obs.session_id, ct.new_provenance_state())
        for cand in ct._extract_candidate_values(obs.text):
            prov.output_candidates.setdefault(cand, (source, max(prov.turn, 0)))

        vault = prior_results.get("VAULT")
        if vault is None or vault.verdict != "BLOCK":
            return None
        taint = self._taint.setdefault(obs.session_id, ct.new_taint_state())
        if not taint.tainted:
            taint.tainted = True
            taint.source_tool = source
            taint.source_matched_id = "CHANNEL-TAINT-SOURCE:secret-in-output"
        return MinisterResult(
            minister=self.name,
            verdict="ALLOW",
            reason="CHANNEL tainted the session: observed content contained secret material",
            matched_id="CHANNEL-TAINT-SOURCE:secret-in-output",
            diagnostics={"level": "deterministic", "tainted": True},
        )

    def summary(self, session_id: str) -> Dict[str, Any]:
        taint = self._taint.get(session_id)
        return {"holds_sensitive_data": bool(taint and taint.tainted)}
