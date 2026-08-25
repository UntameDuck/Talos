"""클라이언트 crypto <-> 서버 jose 상호운용 테스트.

두 독립 구현(attacker/boundattack/crypto.py, server/app/core/jose.py)이 동일한
RFC 7638 thumbprint 와 ES256 서명/검증 결과를 내는지 확인한다. 어긋나면 정상
요청이 jkt mismatch 로 실패한다.
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "attacker"))
sys.path.insert(0, str(ROOT / "server"))

from app.core import jose  # noqa: E402
from boundattack.crypto import ClientKey, build_dpop_proof  # noqa: E402


def test_thumbprint_matches_between_client_and_server():
    key = ClientKey.generate()
    server_side = jose.jwk_thumbprint(key.public_jwk)
    assert server_side == key.thumbprint


def test_server_verifies_client_proof():
    key = ClientKey.generate()
    proof = build_dpop_proof(
        key, htm="GET", htu="https://x.test/api/profile", access_token="tok"
    )
    public_key = jose.public_key_from_jwk(key.public_jwk)
    header, payload = jose.verify_es256(proof, public_key)
    assert header["typ"] == "dpop+jwt"
    assert payload["htm"] == "GET"


def test_server_rejects_tampered_client_proof():
    key = ClientKey.generate()
    proof = build_dpop_proof(
        key, htm="GET", htu="https://x.test/api/profile", access_token="tok"
    )
    h, p, s = proof.split(".")
    tampered = f"{h}.{p}.{'A' * len(s)}"
    public_key = jose.public_key_from_jwk(key.public_jwk)
    try:
        jose.verify_es256(tampered, public_key)
        assert False, "tampered proof must not verify"
    except jose.JoseError:
        pass


def test_public_jwk_from_jwk_rejects_private_material():
    key = ClientKey.generate()
    jwk = dict(key.public_jwk)
    jwk["d"] = "AAAA"
    try:
        jose.public_key_from_jwk(jwk)
        assert False, "must reject jwk containing private component d"
    except jose.JoseError:
        pass
