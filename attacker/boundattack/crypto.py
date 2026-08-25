"""Client-side crypto for BoundAttack and the SDK reference client.

이 파일은 **정상 클라이언트**가 DPoP proof 를 만드는 참조 구현이자, 동시에 공격자가
자기 키로 proof 를 만드는 데도 쓰인다. 서버가 이 둘을 구분하지 못하도록 (오직
`cnf.jkt` 로만 구분되도록) 동일 코드 경로를 공유한다.

서버 `app/core/jose.py` 와 별도 파일인 이유: 클라이언트와 서버가 서로의 코드를
import 하지 않고 독립적으로 검증되어야 하기 때문이다. 두 구현이 같은 RFC 7638/9449
결과를 내는지가 곧 상호운용성 테스트다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
from dataclasses import dataclass
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

_COORD = 32


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _canonical(obj: dict[str, Any]) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


@dataclass
class ClientKey:
    """P-256 키쌍 래퍼. 정상 클라이언트/공격자 공용."""

    private_key: ec.EllipticCurvePrivateKey

    @classmethod
    def generate(cls) -> "ClientKey":
        return cls(ec.generate_private_key(ec.SECP256R1()))

    @property
    def public_jwk(self) -> dict[str, str]:
        numbers = self.private_key.public_key().public_numbers()
        return {
            "kty": "EC",
            "crv": "P-256",
            "x": b64u(numbers.x.to_bytes(_COORD, "big")),
            "y": b64u(numbers.y.to_bytes(_COORD, "big")),
        }

    @property
    def thumbprint(self) -> str:
        jwk = self.public_jwk
        canonical = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
        return b64u(hashlib.sha256(_canonical(canonical)).digest())

    def sign(self, signing_input: bytes) -> bytes:
        der = self.private_key.sign(signing_input, ec.ECDSA(hashes.SHA256()))
        r, s = asym_utils.decode_dss_signature(der)
        return r.to_bytes(_COORD, "big") + s.to_bytes(_COORD, "big")


def ath(access_token: str) -> str:
    return b64u(hashlib.sha256(access_token.encode("ascii")).digest())


def build_dpop_proof(
    key: ClientKey,
    *,
    htm: str,
    htu: str,
    access_token: str | None = None,
    nonce: str | None = None,
    jti: str | None = None,
    iat: int | None = None,
    include_ath: bool = True,
    override_claims: dict[str, Any] | None = None,
    override_header: dict[str, Any] | None = None,
) -> str:
    """RFC 9449 DPoP proof JWT 를 만든다.

    `override_*` 는 공격 시뮬레이션에서 특정 필드를 조작하기 위한 통로다. 정상
    클라이언트는 사용하지 않는다.
    """
    header: dict[str, Any] = {
        "typ": "dpop+jwt",
        "alg": "ES256",
        "jwk": key.public_jwk,
    }
    if override_header:
        header.update(override_header)

    payload: dict[str, Any] = {
        "jti": jti or secrets.token_urlsafe(16),
        "htm": htm,
        "htu": htu,
        "iat": iat if iat is not None else int(time.time()),
    }
    if include_ath and access_token is not None:
        payload["ath"] = ath(access_token)
    if nonce is not None:
        payload["nonce"] = nonce
    if override_claims:
        payload.update(override_claims)

    signing_input = (
        b64u(json.dumps(header, separators=(",", ":")).encode("utf-8"))
        + "."
        + b64u(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )
    signature = key.sign(signing_input.encode("ascii"))
    return signing_input + "." + b64u(signature)
