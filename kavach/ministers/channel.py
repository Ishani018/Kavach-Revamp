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

from typing import Dict, Optional

from . import channel_taint as ct, scan_to_result
from ..schemas import MinisterResult, ToolCall


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
