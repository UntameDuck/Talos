"""Server-provided DPoP nonce (RFC 9449 §8).

Stateless HMAC nonce: `base64url(random16) . base64url(HMAC(random16 || exp))`.
서버 서명키에서 파생한 HMAC 키로 검증한다. 별도 저장소가 필요 없다.

nonce 는 freshness 를 강제하는 서버 통제 값이다. proof replay 자체는 `jti`
캐시가 막으므로, nonce 는 "서버가 원할 때 최신 proof 를 요구" 하는 수단이다.
"""

from __future__ import annotations

import hmac
import secrets
import struct
import time
from hashlib import sha256

from cryptography.hazmat.primitives import serialization

from ..core import jose
from ..core.config import get_settings
from ..core.keys import get_signing_key


def _hmac_key() -> bytes:
    # 서버 개인키 바이트에서 도메인 분리된 HMAC 키를 파생한다.
    priv = get_signing_key().private_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    return sha256(b"boundauth-dpop-nonce-v1" + priv).digest()


def issue_nonce() -> str:
    settings = get_settings()
    rand = secrets.token_bytes(16)
    exp = int(time.time()) + settings.nonce_ttl_seconds
    body = rand + struct.pack(">Q", exp)
    tag = hmac.new(_hmac_key(), body, sha256).digest()[:16]
    return jose.b64u_encode(body + tag)


def verify_nonce(nonce: str) -> bool:
    try:
        raw = jose.b64u_decode(nonce)
    except jose.JoseError:
        return False
    if len(raw) != 16 + 8 + 16:
        return False
    body, tag = raw[:24], raw[24:]
    expected = hmac.new(_hmac_key(), body, sha256).digest()[:16]
    if not hmac.compare_digest(tag, expected):  # constant-time (지시서 §20)
        return False
    (exp,) = struct.unpack(">Q", body[16:24])
    return exp >= int(time.time())
