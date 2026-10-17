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
from ..schemas import MinisterResult, Observation, ToolCall


def _opt_str(ctx: dict, key: str) -> Optional[str]:
    v = ctx.get(key)
    return v if isinstance(v, str) else None


class ChannelMinister:
    name = "CHANNEL"

    def __init__(self) -> None:
        self._taint: Dict[str, ct.SessionTaint] = {}
        self._provenance: Dict[str, ct.SessionProvenance] = {}

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
        return scan_to_result(chosen, self.name)

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
