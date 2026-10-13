from __future__ import annotations

from fastapi.testclient import TestClient

from kavach.api import create_app


def client():
    # The injected coordinator keeps tests from constructing live ministers.
    return TestClient(create_app(coordinator=object()))


def test_dashboard_is_served():
    with client() as c:
        response = c.get("/")
    assert response.status_code == 200
    assert "Kavach" in response.text
    assert "Evaluate a proposed tool call" in response.text


def test_session_status_does_not_require_supabase(monkeypatch):
    for key in (
        "KAVACH_DASHBOARD_PASSWORD",
        "KAVACH_SESSION_SECRET",
        "SUPABASE_URL",
        "SUPABASE_SECRET_KEY",
    ):
        monkeypatch.delenv(key, raising=False)
    with client() as c:
        response = c.get("/api/session")
        status = c.get("/api/status")
    assert response.status_code == 200
    assert response.json() == {"authenticated": False, "login_configured": False}
    assert status.status_code == 200
    assert status.json()["api"] == "online"
    assert status.json()["supabase"]["configured"] is False
    assert status.json()["supabase"]["connected"] is False


def test_catalog_fails_closed_without_login_config(monkeypatch):
    monkeypatch.delenv("KAVACH_DASHBOARD_PASSWORD", raising=False)
    monkeypatch.delenv("KAVACH_SESSION_SECRET", raising=False)
    with client() as c:
        response = c.get("/api/catalog")
    assert response.status_code == 503
    assert "locked" in response.json()["detail"].lower()


def test_login_sets_http_only_session_cookie(monkeypatch):
    monkeypatch.setenv("KAVACH_DASHBOARD_PASSWORD", "test-password-not-for-production")
    monkeypatch.setenv("KAVACH_SESSION_SECRET", "test-session-signing-secret")
    with client() as c:
        response = c.post("/api/login", json={"password": "test-password-not-for-production"})
        session = c.get("/api/session")
    assert response.status_code == 200
    assert response.json() == {"authenticated": True}
    assert "kavach_session" in response.cookies
    assert "httponly" in response.headers.get("set-cookie", "").lower()
    assert session.json()["authenticated"] is True


def test_login_rejects_wrong_password(monkeypatch):
    monkeypatch.setenv("KAVACH_DASHBOARD_PASSWORD", "correct-password")
    monkeypatch.setenv("KAVACH_SESSION_SECRET", "test-session-signing-secret")
    with client() as c:
        response = c.post("/api/login", json={"password": "wrong-password"})
    assert response.status_code == 401


def test_catalog_requires_a_signed_in_session(monkeypatch):
    monkeypatch.setenv("KAVACH_DASHBOARD_PASSWORD", "correct-password")
    monkeypatch.setenv("KAVACH_SESSION_SECRET", "test-session-signing-secret")
    monkeypatch.setenv("SUPABASE_URL", "https://example.supabase.co")
    monkeypatch.setenv("SUPABASE_SECRET_KEY", "not-a-real-key")
    with client() as c:
        response = c.get("/api/catalog")
    assert response.status_code == 401
