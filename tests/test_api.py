from fastapi.testclient import TestClient

from kavach.api import create_app
from kavach.coordinator import Coordinator
from kavach.schemas import MINISTER_NAMES, MinisterResult
from tests.test_coordinator import Stub


def client(**kw):
    ms = [Stub(n, **(kw.get(n) or {})) for n in MINISTER_NAMES]
    return TestClient(create_app(Coordinator(ms)))


BODY = {"tool_name": "bash", "arguments": {"command": "ls"}, "session_id": "s"}


def test_health():
    r = client().get("/health")
    assert r.status_code == 200 and r.json()["ministers"] == list(MINISTER_NAMES)


def test_endpoint_returns_speaker_verdict():
    for verdict in ("ALLOW", "ESCALATE", "BLOCK"):
        r = client(CHANNEL={"verdict": verdict}).post("/check", json=BODY)
        assert r.status_code == 200
        body = r.json()
        assert body["verdict"] == verdict
        assert set(body["ministers"]) == set(MINISTER_NAMES)
        assert body["ministers"]["CHANNEL"]["verdict"] == verdict


def test_failed_minister_fails_closed_over_http():
    r = client(NAVIGATOR={"behavior": "raise"}).post("/check", json=BODY)
    assert r.status_code == 200 and r.json()["verdict"] == "ESCALATE"


def test_invalid_request_rejected():
    assert client().post("/check", json={"tool_name": "", "arguments": {}}).status_code == 422
    assert client().post("/check", json={}).status_code == 422


def test_legacy_endpoint_and_wire_format():
    r = client().post("/hook/parliament", json={"text": 'tool:bash args:{"command": "ls"}', "session_id": "s"})
    assert r.status_code == 200 and r.json()["verdict"] == "ALLOW"
