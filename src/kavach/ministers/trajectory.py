"""TRAJECTORY: checks risk across a sequence of actions."""
from ..models import ActionEvent, Vote, VoteKind


class TrajectoryMinister:
    name = "TRAJECTORY"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: add only after the monitor has a tested, explicit session history contract.
        return Vote(self.name, VoteKind.ABSTAIN, "TRAJECTORY_NOT_IMPLEMENTED")
