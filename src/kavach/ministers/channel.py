"""CHANNEL: tracks sensitive reads and blocks a later external send in that session."""
import re

from ..models import ActionEvent, Vote, VoteKind


_SENSITIVE_SOURCE = re.compile(
    r"(view|get|search|list|download|access).*(address|payment|holding|genetic|health|password|"
    r"access.?history|prescription|patient|location|credential|secret|saved.?account|private.?key)",
    re.I,
)
_DESTINATIONS = {
    "send_email", "share_file", "send_direct_message", "send_channel_message",
    "invite_user_to_slack", "send_message", "upload_file", "http_post", "post_message",
}
_DESTINATION_PATTERN = re.compile(r"^(send|share|upload|post|invite|publish|email|http_post)(_|$)", re.I)


class ChannelMinister:
    name = "CHANNEL"

    def __init__(self) -> None:
        # Session-local state. The adapter must supply stable, correctly scoped session IDs.
        self._tainted_sessions: dict[str, str] = {}

    def evaluate(self, event: ActionEvent) -> Vote:
        tool = event.tool_name
        normalized = tool.lower()
        if _SENSITIVE_SOURCE.search(tool):
            self._tainted_sessions[event.session_id] = tool
            return Vote(self.name, VoteKind.ALLOW, f"SENSITIVE_READ_RECORDED:{tool}")

        is_destination = normalized in _DESTINATIONS or bool(_DESTINATION_PATTERN.search(normalized))
        source = self._tainted_sessions.get(event.session_id)
        if source and is_destination:
            return Vote(self.name, VoteKind.BLOCK, f"SENSITIVE_DATA_TO_DESTINATION:{source}->{tool}")

        return Vote(self.name, VoteKind.ALLOW, "NO_TAINTED_EXTERNAL_SEND")
