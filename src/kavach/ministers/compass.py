"""COMPASS: checks an action against the declared task intent."""
from ..models import ActionEvent, Vote, VoteKind


class CompassMinister:
    name = "COMPASS"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: define observable inputs and validate usefulness before adding logic.
        return Vote(self.name, VoteKind.ABSTAIN, "COMPASS_NOT_IMPLEMENTED")
