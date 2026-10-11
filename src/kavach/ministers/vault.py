"""VAULT: checks for secret and credential exposure."""
from ..models import ActionEvent, Vote, VoteKind


class VaultMinister:
    name = "VAULT"

    def evaluate(self, event: ActionEvent) -> Vote:
        # TODO: implement a deterministic secret-access policy with tests.
        return Vote(self.name, VoteKind.ABSTAIN, "VAULT_NOT_IMPLEMENTED")
