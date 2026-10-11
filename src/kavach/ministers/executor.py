"""EXECUTOR: checks whether a proposed command is dangerous."""
from ..models import ActionEvent, Vote, VoteKind


class ExecutorMinister:
    name = "EXECUTOR"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: implement explicit command rules with malicious and benign tests.
        return Vote(self.name, VoteKind.ABSTAIN, "EXECUTOR_NOT_IMPLEMENTED")
