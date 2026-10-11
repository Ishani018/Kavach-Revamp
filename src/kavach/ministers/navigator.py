"""NAVIGATOR: checks an action against known, explicit attack patterns."""
from ..models import ActionEvent, Vote, VoteKind


class NavigatorMinister:
    name = "NAVIGATOR"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: begin with small, explainable rules; no embedding stack in this file.
        return Vote(self.name, VoteKind.ABSTAIN, "NAVIGATOR_NOT_IMPLEMENTED")
