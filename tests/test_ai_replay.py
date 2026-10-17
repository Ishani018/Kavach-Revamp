"""Recorded AI evidence replays to identical decisions, and is never more
lenient than running without AI. See evaluation/ai_replay/run_replay.py."""

from evaluation.ai_replay import run_replay


def test_replay_matches_expected_and_never_loosens_a_verdict(capsys):
    assert run_replay.main(["--check"]) == 0, capsys.readouterr().err
