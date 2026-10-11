import unittest

from kavach.models import Verdict, Vote, VoteKind
from kavach.speaker import speak


class SpeakerTests(unittest.TestCase):
    def test_any_block_wins(self):
        votes = [
            Vote("VAULT", VoteKind.ALLOW, "CLEAR"),
            Vote("EXECUTOR", VoteKind.BLOCK, "DANGEROUS_COMMAND"),
            Vote("CHANNEL", VoteKind.REVIEW, "SUSPICIOUS_FLOW"),
        ]
        self.assertEqual(speak(votes), Verdict.BLOCK)

    def test_review_beats_allow(self):
        votes = [
            Vote("VAULT", VoteKind.ALLOW, "CLEAR"),
            Vote("CHANNEL", VoteKind.REVIEW, "NEEDS_REVIEW"),
        ]
        self.assertEqual(speak(votes), Verdict.REVIEW)

    def test_abstain_is_not_allow(self):
        votes = [
            Vote("VAULT", VoteKind.ALLOW, "CLEAR"),
            Vote("EXECUTOR", VoteKind.ABSTAIN, "NOT_IMPLEMENTED"),
        ]
        self.assertEqual(speak(votes), Verdict.INDETERMINATE)

    def test_allow_requires_every_vote_to_allow(self):
        votes = [
            Vote("VAULT", VoteKind.ALLOW, "CLEAR"),
            Vote("EXECUTOR", VoteKind.ALLOW, "CLEAR"),
        ]
        self.assertEqual(speak(votes), Verdict.ALLOW)

    def test_empty_votes_are_indeterminate(self):
        self.assertEqual(speak([]), Verdict.INDETERMINATE)


if __name__ == "__main__":
    unittest.main()
