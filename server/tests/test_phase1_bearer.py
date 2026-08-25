"""Phase 1 — Bearer baseline (S0).

이 단계의 baseline 은 **의도적으로 취약**하다. 테스트는 "안전함"이 아니라
"설계대로 취약함 + 기본 위생 상태"를 확인한다.
"""

from __future__ import annotations

import pytest


def login(client, username, password, **kwargs):
    return client.post(
        "/auth/login", json={"username": username, "password": password, **kwargs}
    )


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "ok"


def test_config_exposes_public_key_only(client):
    body = client.get("/.well-known/boundauth-config").json()
    jwk = body["signing_public_jwk"]
    assert jwk["kty"] == "EC" and jwk["crv"] == "P-256"
    assert "d" not in jwk, "server must never expose private key material"


def test_login_success_issues_bearer_token(client, user_factory):
    username, password = user_factory()
    response = login(client, username, password)
    assert response.status_code == 200
    body = response.json()
    assert body["token_type"] == "Bearer"
    assert body["jkt"] is None
    assert body["mode"] == "S0"
    assert body["access_token"] and body["refresh_token"]


def test_login_rejects_wrong_password(client, user_factory):
    username, _ = user_factory()
    response = login(client, username, "wrong password")
    assert response.status_code == 401
    assert response.json()["error"] == "AUTH_INVALID_CREDENTIALS"


def test_login_unknown_user_gives_same_error(client):
    response = login(client, "nobody-here", "whatever")
    assert response.status_code == 401
    assert response.json()["error"] == "AUTH_INVALID_CREDENTIALS"


@pytest.mark.parametrize(
    "method,path,payload",
    [
        ("GET", "/api/profile", None),
        ("GET", "/api/history", None),
        ("POST", "/api/settings", {"display_name": "x"}),
        ("POST", "/api/transfer", {"to_account": "ACC-1", "amount": 100}),
    ],
)
def test_protected_endpoints_work_with_bearer(client, user_factory, method, path, payload):
    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    response = client.request(method, path, headers=headers, json=payload)
    assert response.status_code == 200, response.text


@pytest.mark.parametrize("path", ["/api/profile", "/api/history"])
def test_protected_endpoints_require_authorization(client, path):
    response = client.get(path)
    assert response.status_code == 401
    assert response.json()["error"] == "AUTH_HEADER_MISSING"


def test_risk_level_reported_per_endpoint(client, user_factory):
    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/profile", headers=headers).json()["risk"] == "LOW"
    assert client.get("/api/history", headers=headers).json()["risk"] == "LOW"
    assert (
        client.post("/api/settings", headers=headers, json={}).json()["risk"] == "MEDIUM"
    )
    assert (
        client.post(
            "/api/transfer", headers=headers, json={"to_account": "A", "amount": 1}
        ).json()["risk"]
        == "HIGH"
    )


def test_baseline_is_replayable_by_design(client, user_factory):
    """RQ1 baseline: 토큰만 있으면 다른 클라이언트에서도 그대로 통한다.

    이것이 S0 의 취약성이며, 이후 arm 들이 막아야 하는 대상이다.
    """
    from fastapi.testclient import TestClient

    from app.main import create_app

    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]

    # 완전히 별개의 클라이언트(=다른 기기)에서 같은 토큰을 쓴다.
    with TestClient(create_app(), base_url="https://boundauth.test") as attacker:
        stolen = attacker.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert stolen.status_code == 200, "Phase 1 baseline must be replayable"


def test_tampered_token_is_rejected(client, user_factory):
    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]
    header, payload, signature = token.split(".")
    flipped = signature[:-2] + ("AA" if signature[-2:] != "AA" else "AB")
    response = client.get(
        "/api/profile", headers={"Authorization": f"Bearer {header}.{payload}.{flipped}"}
    )
    assert response.status_code == 401
    assert response.json()["error"] in {
        "TOKEN_SIGNATURE_INVALID",
        "TOKEN_MALFORMED",
    }


def test_alg_none_token_is_rejected(client, user_factory):
    """algorithm confusion / alg=none 방어 (지시서 §20)."""
    import base64
    import json

    def b64u(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

    username, password = user_factory()
    real = login(client, username, password).json()["access_token"]
    claims = json.loads(base64.urlsafe_b64decode(real.split(".")[1] + "=="))

    forged = (
        b64u(json.dumps({"alg": "none", "typ": "at+jwt"}).encode())
        + "."
        + b64u(json.dumps(claims).encode())
        + "."
    )
    response = client.get("/api/profile", headers={"Authorization": f"Bearer {forged}"})
    assert response.status_code == 401


def test_refresh_rotates_and_detects_reuse(client, user_factory):
    username, password = user_factory()
    tokens = login(client, username, password).json()
    first = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert first.status_code == 200
    # 회전된 옛 refresh token 재사용 -> 세션 폐기
    reuse = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert reuse.status_code == 401
    assert reuse.json()["error"] == "TOKEN_REVOKED"
    # 세션이 폐기되었으므로 새로 받은 refresh token 도 더 이상 통하지 않는다.
    after = client.post("/auth/refresh", json={"refresh_token": first.json()["refresh_token"]})
    assert after.status_code == 401


def test_access_token_cannot_be_used_as_refresh(client, user_factory):
    username, password = user_factory()
    tokens = login(client, username, password).json()
    response = client.post("/auth/refresh", json={"refresh_token": tokens["access_token"]})
    assert response.status_code == 401
    assert response.json()["error"] == "TOKEN_TYPE_INVALID"


def test_security_events_are_recorded(client, user_factory):
    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    client.get("/api/profile", headers=headers)
    events = client.get("/api/security-events", headers=headers).json()["items"]
    types = {e["event_type"] for e in events}
    assert "LOGIN_SUCCESS" in types
    assert "TOKEN_ISSUED" in types
    assert "API_ALLOWED" in types


def test_security_events_do_not_contain_raw_tokens(client, user_factory):
    from sqlalchemy import select

    from app.core.db import get_sessionmaker
    from app.core.models import SecurityEvent

    username, password = user_factory()
    token = login(client, username, password).json()["access_token"]
    client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})

    session = get_sessionmaker()()
    try:
        rows = session.scalars(select(SecurityEvent)).all()
        blob = " ".join(r.event_metadata or "" for r in rows)
    finally:
        session.close()
    assert token not in blob
    assert token.split(".")[2] not in blob
