"""Access / Refresh token 발급 및 검증.

`cnf.jkt` (RFC 7800 + RFC 9449 §6) 가 sender-constrained 여부를 결정한다.
이 값이 있으면 서버는 **반드시** 유효한 DPoP proof 를 요구한다 (지시서 §4.1).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Any

from ..core import jose
from ..core.config import get_settings
from ..core.errors import ApiError, ErrorCode
from ..core.keys import get_signing_key, get_verifying_key

ACCESS_TYP = "at+jwt"
REFRESH_TYP = "rt+jwt"

#: 지원 scope. login 시 요청 scope 를 이 집합으로 제한한다.
ALL_SCOPES = ("profile", "history", "settings", "transfer")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def access_token_hash(access_token: str) -> str:
    """RFC 9449 `ath`: base64url(SHA-256(ASCII(access_token)))."""
    return jose.b64u_encode(hashlib.sha256(access_token.encode("ascii")).digest())


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_at: datetime


@dataclass(frozen=True)
class VerifiedToken:
    raw: str
    claims: dict[str, Any]

    @property
    def subject(self) -> str:
        return str(self.claims["sub"])

    @property
    def session_id(self) -> str:
        return str(self.claims["sid"])

    @property
    def jkt(self) -> str | None:
        cnf = self.claims.get("cnf")
        if isinstance(cnf, dict):
            value = cnf.get("jkt")
            if isinstance(value, str) and value:
                return value
        return None

    @property
    def scopes(self) -> tuple[str, ...]:
        raw = self.claims.get("scope", "")
        return tuple(raw.split()) if isinstance(raw, str) and raw else ()


def _issue(
    typ: str,
    *,
    subject: str,
    session_id: str,
    ttl_seconds: int,
    extra: dict[str, Any],
) -> IssuedToken:
    settings = get_settings()
    now = _now()
    expires_at = now + timedelta(seconds=ttl_seconds)
    jti = secrets.token_urlsafe(16)  # CSPRNG (지시서 §20)
    payload: dict[str, Any] = {
        "iss": settings.issuer,
        "sub": subject,
        "sid": session_id,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        **extra,
    }
    token = jose.sign_es256({"typ": typ}, payload, get_signing_key())
    return IssuedToken(token=token, jti=jti, expires_at=expires_at)


def issue_access_token(
    *,
    subject: str,
    session_id: str,
    scopes: tuple[str, ...] | list[str],
    mode: str,
    jkt: str | None,
    device_id: str | None = None,
) -> IssuedToken:
    extra: dict[str, Any] = {
        "scope": " ".join(scopes),
        "mode": mode,
    }
    if device_id:
        extra["did"] = device_id
    if jkt:
        # 이 클레임의 존재가 DPoP 강제 여부를 결정한다.
        extra["cnf"] = {"jkt": jkt}
    return _issue(
        ACCESS_TYP,
        subject=subject,
        session_id=session_id,
        ttl_seconds=get_settings().access_token_ttl_seconds,
        extra=extra,
    )


def issue_refresh_token(
    *,
    subject: str,
    session_id: str,
    generation: int,
    jkt: str | None,
) -> IssuedToken:
    extra: dict[str, Any] = {"gen": generation}
    if jkt:
        extra["cnf"] = {"jkt": jkt}
    return _issue(
        REFRESH_TYP,
        subject=subject,
        session_id=session_id,
        ttl_seconds=get_settings().refresh_token_ttl_seconds,
        extra=extra,
    )


def verify_token(raw: str, *, expected_typ: str) -> VerifiedToken:
    """서버 서명 토큰을 검증한다.

    * 서명은 항상 ES256 + 서버 공개키로만 검증한다 (algorithm confusion 불가).
    * `typ` 를 강제해 access token 을 refresh 로 쓰는 혼동을 막는다.
    * 시간 비교는 timezone-aware UTC 로 한다.
    """
    settings = get_settings()
    try:
        header, claims = jose.verify_es256(raw, get_verifying_key())
    except jose.JoseError as exc:
        raise ApiError(
            401,
            ErrorCode.TOKEN_SIGNATURE_INVALID,
            f"token verification failed: {exc}",
        ) from exc

    if header.get("typ") != expected_typ:
        raise ApiError(
            401,
            ErrorCode.TOKEN_TYPE_INVALID,
            f"expected typ={expected_typ!r}, got {header.get('typ')!r}",
        )

    for field in ("iss", "sub", "sid", "jti", "iat", "exp"):
        if field not in claims:
            raise ApiError(401, ErrorCode.TOKEN_MALFORMED, f"missing claim {field}")

    if claims["iss"] != settings.issuer:
        raise ApiError(401, ErrorCode.TOKEN_MALFORMED, "issuer mismatch")

    try:
        exp = int(claims["exp"])
        iat = int(claims["iat"])
    except (TypeError, ValueError) as exc:
        raise ApiError(401, ErrorCode.TOKEN_MALFORMED, "iat/exp must be integers") from exc

    now_ts = int(_now().timestamp())
    if exp <= now_ts:
        raise ApiError(401, ErrorCode.TOKEN_EXPIRED, "token expired")
    if iat > now_ts + settings.dpop_iat_skew_seconds:
        raise ApiError(401, ErrorCode.TOKEN_MALFORMED, "token issued in the future")

    cnf = claims.get("cnf")
    if cnf is not None and not (isinstance(cnf, dict) and isinstance(cnf.get("jkt"), str)):
        raise ApiError(401, ErrorCode.TOKEN_MALFORMED, "malformed cnf claim")

    return VerifiedToken(raw=raw, claims=claims)


def normalize_scopes(requested: list[str] | tuple[str, ...] | None) -> tuple[str, ...]:
    if not requested:
        return ALL_SCOPES
    unknown = [s for s in requested if s not in ALL_SCOPES]
    if unknown:
        raise ApiError(400, ErrorCode.BAD_REQUEST, f"unknown scopes: {unknown}")
    return tuple(dict.fromkeys(requested))
