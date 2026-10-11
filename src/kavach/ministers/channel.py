"""CHANNEL: checks sensitive data moving between tools or destinations."""
from ..models import ActionEvent, Vote, VoteKind


class ChannelMinister:
    name = "CHANNEL"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: only implement when source/destination evidence is explicit.
        return Vote(self.name, VoteKind.ABSTAIN, "CHANNEL_NOT_IMPLEMENTED")
