"""Strict, minimal JWS/JWK implementation for ES256 (P-256).

일반 목적 JWT 라이브러리 대신 직접 구현한 이유:

* **algorithm confusion 방지** — 검증 함수가 `alg` 를 신뢰하지 않고, 호출자가 지정한
  알고리즘만 허용한다. `none` 은 파싱 단계에서 거부된다 (지시서 §20).
* **strict parsing** — segment 개수, base64url 문자셋, 길이, JSON 타입을 전부 검사한다.
* **공개키/개인키 혼동 방지** — 서명 API 는 private key 타입만, 검증 API 는 public key
  타입만 받는다.

새 암호 알고리즘을 발명하지 않는다 (지시서 §30). 표준 primitive(`cryptography`)만 쓴다.
"""

from __future__ import annotations

import base64
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, utils as asym_utils

__all__ = [
    "JoseError",
    "b64u_encode",
    "b64u_decode",
    "public_jwk_from_key",
    "public_key_from_jwk",
    "jwk_thumbprint",
    "sign_es256",
    "verify_es256",
    "decode_unverified_header",
]

#: JWS compact serialization 의 각 segment 는 padding 없는 base64url 이어야 한다.
_B64U_RE = re.compile(r"^[A-Za-z0-9_-]*$")

_ALLOWED_ALGS = frozenset({"ES256"})
_P256_COORD_BYTES = 32
_MAX_SEGMENT_BYTES = 8192


class JoseError(Exception):
    """JWS/JWK 처리 실패. 호출자가 구체적 error code 로 변환한다."""


# ---------------------------------------------------------------- base64url


def b64u_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64u_decode(value: str) -> bytes:
    """padding 없는 base64url 만 허용한다.

    표준 base64(`+`, `/`, `=`)를 조용히 받아주면 서로 다른 인코딩이 같은 값으로
    해석되어 thumbprint 비교가 흔들릴 수 있다. 따라서 엄격하게 거부한다.
    """
    if not isinstance(value, str):
        raise JoseError("base64url segment must be a string")
    if not _B64U_RE.match(value):
        raise JoseError("invalid base64url alphabet")
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:  # pragma: no cover - defensive
        raise JoseError(f"base64url decode failed: {exc}") from exc


def _json_loads_object(raw: bytes, what: str) -> dict[str, Any]:
    try:
        parsed = json.loads(raw.decode("utf-8"))
    except Exception as exc:
        raise JoseError(f"{what} is not valid JSON: {exc}") from exc
    if not isinstance(parsed, dict):
        raise JoseError(f"{what} must be a JSON object")
    return parsed


def _json_canonical(obj: dict[str, Any]) -> bytes:
    """RFC 7638 lexicographic, no-whitespace serialization."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


# --------------------------------------------------------------------- JWK


def public_jwk_from_key(public_key: ec.EllipticCurvePublicKey) -> dict[str, str]:
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise JoseError("expected an EC public key")
    if not isinstance(public_key.curve, ec.SECP256R1):
        raise JoseError("only P-256 is supported")
    numbers = public_key.public_numbers()
    return {
        "kty": "EC",
        "crv": "P-256",
        "x": b64u_encode(numbers.x.to_bytes(_P256_COORD_BYTES, "big")),
        "y": b64u_encode(numbers.y.to_bytes(_P256_COORD_BYTES, "big")),
    }


def public_key_from_jwk(jwk: Any) -> ec.EllipticCurvePublicKey:
    """JWK dict 를 공개키로 변환한다. 곡선 위의 점인지까지 검증한다.

    `d`(개인키 성분)가 들어 있으면 거부한다. DPoP proof 의 `jwk` 헤더에 개인키가
    실려오는 것은 오구현이거나 공격이므로 조용히 통과시키지 않는다.
    """
    if not isinstance(jwk, dict):
        raise JoseError("jwk must be a JSON object")
    if "d" in jwk:
        raise JoseError("jwk must not contain private key material")
    if jwk.get("kty") != "EC":
        raise JoseError("unsupported jwk kty")
    if jwk.get("crv") != "P-256":
        raise JoseError("unsupported jwk crv")
    x_raw, y_raw = jwk.get("x"), jwk.get("y")
    if not isinstance(x_raw, str) or not isinstance(y_raw, str):
        raise JoseError("jwk x/y must be strings")
    x_bytes, y_bytes = b64u_decode(x_raw), b64u_decode(y_raw)
    if len(x_bytes) != _P256_COORD_BYTES or len(y_bytes) != _P256_COORD_BYTES:
        raise JoseError("jwk coordinate length invalid for P-256")
    try:
        numbers = ec.EllipticCurvePublicNumbers(
            int.from_bytes(x_bytes, "big"),
            int.from_bytes(y_bytes, "big"),
            ec.SECP256R1(),
        )
        # public_key() 가 곡선 위의 점인지 검증한다 (invalid curve attack 방지).
        return numbers.public_key()
    except JoseError:
        raise
    except Exception as exc:
        raise JoseError(f"jwk is not a valid P-256 point: {exc}") from exc


def jwk_thumbprint(jwk: dict[str, Any]) -> str:
    """RFC 7638 JWK Thumbprint (SHA-256, base64url).

    EC 키의 필수 멤버는 `crv`, `kty`, `x`, `y` 뿐이며 사전순으로 직렬화한다.
    """
    required = ("crv", "kty", "x", "y")
    missing = [k for k in required if k not in jwk]
    if missing:
        raise JoseError(f"jwk missing members for thumbprint: {missing}")
    if jwk.get("kty") != "EC":
        raise JoseError("thumbprint supported only for EC keys here")
    canonical = {k: jwk[k] for k in required}
    return b64u_encode(hashlib.sha256(_json_canonical(canonical)).digest())


# --------------------------------------------------------------------- JWS


def _der_to_raw_p256(der_signature: bytes) -> bytes:
    r, s = asym_utils.decode_dss_signature(der_signature)
    return r.to_bytes(_P256_COORD_BYTES, "big") + s.to_bytes(_P256_COORD_BYTES, "big")


def _raw_to_der_p256(raw_signature: bytes) -> bytes:
    if len(raw_signature) != 2 * _P256_COORD_BYTES:
        raise JoseError("ES256 signature must be 64 bytes")
    r = int.from_bytes(raw_signature[:_P256_COORD_BYTES], "big")
    s = int.from_bytes(raw_signature[_P256_COORD_BYTES:], "big")
    return asym_utils.encode_dss_signature(r, s)


def sign_es256(
    header: dict[str, Any],
    payload: dict[str, Any],
    private_key: ec.EllipticCurvePrivateKey,
) -> str:
    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise JoseError("signing requires an EC private key")
    if not isinstance(private_key.curve, ec.SECP256R1):
        raise JoseError("only P-256 is supported")
    full_header = {**header, "alg": "ES256"}
    signing_input = (
        b64u_encode(json.dumps(full_header, separators=(",", ":")).encode("utf-8"))
        + "."
        + b64u_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    )
    der = private_key.sign(signing_input.encode("ascii"), ec.ECDSA(hashes.SHA256()))
    return signing_input + "." + b64u_encode(_der_to_raw_p256(der))


def _split_compact(token: str) -> tuple[str, str, str]:
    if not isinstance(token, str):
        raise JoseError("JWS must be a string")
    parts = token.split(".")
    if len(parts) != 3:
        raise JoseError("JWS compact serialization must have exactly 3 segments")
    for part in parts:
        if len(part) > _MAX_SEGMENT_BYTES:
            raise JoseError("JWS segment too large")
        if not _B64U_RE.match(part):
            raise JoseError("invalid base64url alphabet in JWS segment")
    if not parts[2]:
        # 빈 서명 = alg:none 형태. 명시적으로 거부한다.
        raise JoseError("JWS signature segment must not be empty")
    return parts[0], parts[1], parts[2]


def decode_unverified_header(token: str) -> dict[str, Any]:
    """검증 **전에** 헤더만 읽는다 (proof 의 `jwk` 를 꺼내기 위함).

    이 함수의 반환값으로 인가 결정을 내려서는 안 된다. 반드시 `verify_es256` 이
    뒤따라야 한다.
    """
    header_b64, _, _ = _split_compact(token)
    return _json_loads_object(b64u_decode(header_b64), "JWS header")


def verify_es256(
    token: str,
    public_key: ec.EllipticCurvePublicKey,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """ES256 서명을 검증하고 (header, payload) 를 돌려준다.

    `alg` 는 호출자가 강제한 ES256 만 허용한다. 토큰이 주장하는 다른 알고리즘은
    검증 경로 자체가 없다.
    """
    if not isinstance(public_key, ec.EllipticCurvePublicKey):
        raise JoseError("verification requires an EC public key")
    header_b64, payload_b64, signature_b64 = _split_compact(token)
    header = _json_loads_object(b64u_decode(header_b64), "JWS header")

    alg = header.get("alg")
    if alg not in _ALLOWED_ALGS:
        raise JoseError(f"unsupported or forbidden alg: {alg!r}")
    if "crit" in header:
        # 이해하지 못하는 crit 확장은 RFC 7515 상 거부해야 한다.
        raise JoseError("unsupported crit header")

    signing_input = f"{header_b64}.{payload_b64}".encode("ascii")
    try:
        public_key.verify(
            _raw_to_der_p256(b64u_decode(signature_b64)),
            signing_input,
            ec.ECDSA(hashes.SHA256()),
        )
    except InvalidSignature as exc:
        raise JoseError("signature verification failed") from exc
    except JoseError:
        raise
    except Exception as exc:
        raise JoseError(f"signature verification error: {exc}") from exc

    payload = _json_loads_object(b64u_decode(payload_b64), "JWS payload")
    return header, payload
