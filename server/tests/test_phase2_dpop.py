"""Phase 2 — Software DPoP (S1) server-side verification.

이 테스트는 서버가 RFC 9449 검증 체인을 올바로 수행하는지 직접 확인한다.
공격 재현(BoundAttack)과 별개로, 서버 단위에서 각 실패 사유가 정확한 error code 를
내는지 본다 (지시서 §22 Server Unit Test).
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

import pytest

from app.core import jose


class Key:
    """테스트용 P-256 클라이언트 키."""

    def __init__(self) -> None:
        from cryptography.hazmat.primitives.asymmetric import ec

        self.priv = ec.generate_private_key(ec.SECP256R1())

    @property
    def public_jwk(self):
        return jose.public_jwk_from_key(self.priv.public_key())

    @property
    def thumbprint(self):
        return jose.jwk_thumbprint(self.public_jwk)

    def proof(self, *, htm, htu, ath=None, jti=None, iat=None, nonce=None, extra=None):
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self.public_jwk}
        payload = {
            "jti": jti or base64.urlsafe_b64encode(time.time_ns().to_bytes(8, "big")).rstrip(b"=").decode(),
            "htm": htm,
            "htu": htu,
            "iat": iat if iat is not None else int(time.time()),
        }
        if ath is not None:
            payload["ath"] = ath
        if nonce is not None:
            payload["nonce"] = nonce
        if extra:
            payload.update(extra)
        return jose.sign_es256(header, payload, self.priv)


def ath_of(token: str) -> str:
    return base64.urlsafe_b64encode(hashlib.sha256(token.encode()).digest()).rstrip(b"=").decode()


def register_and_login(client, user_factory, key: Key, arm="S1"):
    username, password = user_factory()
    reg = client.post(
        "/devices/register",
        json={
            "username": username,
            "password": password,
            "public_key_jwk": key.public_jwk,
            "kind": arm,
        },
    )
    assert reg.status_code == 200, reg.text
    device_id = reg.json()["id"]
    login = client.post(
        "/auth/login",
        json={"username": username, "password": password, "mode": arm, "device_id": device_id},
    )
    assert login.status_code == 200, login.text
    return login.json(), device_id


HTU = "https://boundauth.test/api/profile"


def test_login_binds_token_to_jkt(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    assert body["token_type"] == "DPoP"
    assert body["jkt"] == key.thumbprint


def test_valid_dpop_request_succeeds(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=ath_of(token))
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 200, response.text


def test_token_without_proof_is_rejected(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    # DPoP 스킴이지만 proof 헤더 없음
    r1 = client.get("/api/profile", headers={"Authorization": f"DPoP {token}"})
    assert r1.status_code == 401 and r1.json()["error"] == "DPOP_MISSING"
    # Bearer 로 우회 시도 → sender-constrained 토큰은 Bearer 불가
    r2 = client.get("/api/profile", headers={"Authorization": f"Bearer {token}"})
    assert r2.status_code == 401 and r2.json()["error"] == "AUTH_SCHEME_INVALID"


def test_cross_key_gives_jkt_mismatch(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    attacker = Key()
    proof = attacker.proof(htm="GET", htu=HTU, ath=ath_of(token))
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_JKT_MISMATCH"


def test_proof_replay_is_blocked(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=ath_of(token))
    headers = {"Authorization": f"DPoP {token}", "DPoP": proof}
    assert client.get("/api/profile", headers=headers).status_code == 200
    replay = client.get("/api/profile", headers=headers)
    assert replay.status_code == 401
    assert replay.json()["error"] == "DPOP_REPLAY"


def test_htu_mismatch(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    # /api/history 용 proof 를 /api/profile 에 사용
    proof = key.proof(htm="GET", htu="https://boundauth.test/api/history", ath=ath_of(token))
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_HTU_MISMATCH"


def test_htm_mismatch(client, user_factory):
    key = Key()
    body, device_id = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu="https://boundauth.test/api/settings", ath=ath_of(token))
    response = client.post(
        "/api/settings", headers={"Authorization": f"DPoP {token}", "DPoP": proof}, json={}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_HTM_MISMATCH"


def test_ath_mismatch(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=ath_of("some-other-token"))
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_ATH_MISMATCH"


def test_missing_ath_is_rejected(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=None)
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_ATH_MISMATCH"


def test_stale_proof_is_rejected(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=ath_of(token), iat=int(time.time()) - 3600)
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 401
    assert response.json()["error"] == "DPOP_EXPIRED"


def test_dpop_typ_and_alg_enforced(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    # 잘못된 typ
    header = {"typ": "jwt", "alg": "ES256", "jwk": key.public_jwk}
    payload = {"jti": "x1", "htm": "GET", "htu": HTU, "iat": int(time.time()), "ath": ath_of(token)}
    bad = jose.sign_es256(header, payload, key.priv)
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": bad}
    )
    assert response.status_code == 400
    assert response.json()["error"] == "DPOP_TYP_INVALID"


def test_alg_none_proof_rejected(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]

    def b64u(b):
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    header = b64u(json.dumps({"typ": "dpop+jwt", "alg": "none", "jwk": key.public_jwk}).encode())
    payload = b64u(json.dumps({"jti": "n1", "htm": "GET", "htu": HTU, "iat": int(time.time()), "ath": ath_of(token)}).encode())
    forged = f"{header}.{payload}."
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": forged}
    )
    assert response.status_code in (400, 401)
    assert response.json()["error"] != "DPOP_VALID"


def test_oversized_proof_rejected(client, user_factory):
    key = Key()
    body, _ = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="GET", htu=HTU, ath=ath_of(token), extra={"junk": "A" * 5000})
    response = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
    )
    assert response.status_code == 400
    assert response.json()["error"] == "DPOP_MALFORMED"


def test_revoked_device_blocks_new_login(client, user_factory):
    key = Key()
    body, device_id = register_and_login(client, user_factory, key)
    token = body["access_token"]
    proof = key.proof(htm="POST", htu=f"https://boundauth.test/devices/{device_id}/revoke", ath=ath_of(token))
    # settings scope 로 revoke 호출
    revoke = client.post(
        f"/devices/{device_id}/revoke",
        headers={"Authorization": f"DPoP {token}", "DPoP": proof},
    )
    assert revoke.status_code == 200, revoke.text
    assert revoke.json()["status"] == "REVOKED"
    # 폐기된 세션의 access token 은 더 이상 통하지 않는다.
    proof2 = key.proof(htm="GET", htu=HTU, ath=ath_of(token))
    after = client.get(
        "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof2}
    )
    assert after.status_code in (401, 403)
