"""Authentication dependency — 모든 보호 API 의 단일 진입점.

**Fail-closed 원칙 (지시서 §19, §34).** 검증 경로에서 예외가 생기거나 미지원
상황을 만나면 요청을 거부한다. 어떤 조건에서도 "일단 통과"시키지 않는다.

검증 순서:

1. `Authorization` 헤더 존재/개수/스킴
2. Access Token 서명·`typ`·`iss`·`exp`·`iat`
3. 세션 존재/미폐기
4. 디바이스 존재/미폐기 (`did` 클레임이 있을 때)
5. **토큰 바인딩 분기** - `cnf.jkt` 가 있으면 DPoP proof 필수
6. scope
"""

from __future__ import annotations

from dataclasses import dataclass

from fastapi import Depends, Request
from sqlalchemy.orm import Session

from ..core import events
from ..core.config import get_settings
from ..core.db import get_db
from ..core.errors import ApiError, ErrorCode
from ..core.http import request_htu
from ..core.logging_setup import fingerprint
from ..core.models import (
    MODE_TO_ARM,
    AuthMode,
    Device,
    DeviceStatus,
    SessionToken,
    User,
    utcnow,
)
from ..dpop.verifier import verify_dpop_proof
from ..risk.policy import RiskLevel, classify
from ..tokens.service import ACCESS_TYP, VerifiedToken, verify_token


@dataclass
class AuthContext:
    user: User
    session: SessionToken
    device: Device | None
    access: VerifiedToken
    arm: str
    risk: RiskLevel
    htu: str
    method: str
    #: DPoP proof 가 검증된 경우 그 `jti` (로그 상관관계용).
    proof_jti: str | None = None


def _single_header(request: Request, name: str) -> str | None:
    """헤더가 여러 개면 거부한다.

    RFC 9449 §4.3: `DPoP` 헤더가 둘 이상이면 반드시 거부해야 한다. 프록시/파서에
    따라 병합 규칙이 달라 우회로가 될 수 있기 때문이다.
    """
    values = request.headers.getlist(name)
    if not values:
        return None
    if len(values) > 1:
        raise ApiError(400, ErrorCode.DPOP_MULTIPLE, f"multiple {name} headers")
    return values[0]


def _parse_authorization(request: Request) -> tuple[str, str]:
    raw = _single_header(request, "authorization")
    if not raw:
        raise ApiError(
            401,
            ErrorCode.AUTH_HEADER_MISSING,
            "missing Authorization header",
            headers={"WWW-Authenticate": "Bearer"},
        )
    parts = raw.split(" ", 1)
    if len(parts) != 2 or not parts[1].strip():
        raise ApiError(401, ErrorCode.AUTH_SCHEME_INVALID, "malformed Authorization header")
    scheme, token = parts[0], parts[1].strip()
    if scheme not in ("Bearer", "DPoP"):
        raise ApiError(401, ErrorCode.AUTH_SCHEME_INVALID, f"unsupported scheme {scheme!r}")
    return scheme, token


def authenticate(request: Request, db: Session, *, required_scope: str | None) -> AuthContext:
    settings = get_settings()
    method = request.method.upper()
    path = request.url.path
    risk = classify(method, path)

    def deny(error: ApiError, *, user_id: str | None = None, mode: str | None = None) -> ApiError:
        events.record(
            db,
            commit=True,
            event_type=events.event_type_for_code(error.code),
            result=events.Result.DENIED,
            user_id=user_id,
            endpoint=path,
            method=method,
            risk=risk.value,
            error_code=error.code,
            mode=mode,
        )
        return error

    try:
        scheme, raw_token = _parse_authorization(request)
    except ApiError as exc:
        raise deny(exc) from exc

    try:
        access = verify_token(raw_token, expected_typ=ACCESS_TYP)
    except ApiError as exc:
        raise deny(exc) from exc

    mode = str(access.claims.get("mode", AuthMode.BEARER.value))
    arm = MODE_TO_ARM.get(AuthMode(mode), "S0") if mode in AuthMode._value2member_map_ else "S0"
    user_id = access.subject

    session = db.get(SessionToken, access.session_id)
    if session is None or session.user_id != user_id:
        raise deny(
            ApiError(401, ErrorCode.TOKEN_UNKNOWN_SESSION, "unknown session"),
            user_id=user_id,
            mode=mode,
        )
    if session.revoked:
        raise deny(
            ApiError(401, ErrorCode.TOKEN_REVOKED, "session revoked"),
            user_id=user_id,
            mode=mode,
        )

    user = db.get(User, user_id)
    if user is None:
        raise deny(
            ApiError(401, ErrorCode.TOKEN_UNKNOWN_SESSION, "unknown subject"), mode=mode
        )

    device: Device | None = None
    device_id = access.claims.get("did")
    if isinstance(device_id, str) and device_id:
        device = db.get(Device, device_id)
        if device is None or device.user_id != user_id:
            raise deny(
                ApiError(401, ErrorCode.DEVICE_NOT_FOUND, "bound device missing"),
                user_id=user_id,
                mode=mode,
            )
        if device.status == DeviceStatus.REVOKED.value:
            raise deny(
                ApiError(403, ErrorCode.DEVICE_REVOKED, "device revoked"),
                user_id=user_id,
                mode=mode,
            )

    htu = request_htu(request, settings.public_base_url)
    proof_jti: str | None = None
    jkt = access.jkt

    if jkt is None:
        # --- S0: Bearer. 소지만으로 인가된다. 의도적으로 취약한 baseline. ---
        if scheme != "Bearer":
            raise deny(
                ApiError(401, ErrorCode.AUTH_SCHEME_INVALID, "unbound token requires Bearer scheme"),
                user_id=user_id,
                mode=mode,
            )
    else:
        # --- S1/S2/S3: sender-constrained. DPoP proof 필수. ---
        if scheme != "DPoP":
            raise deny(
                ApiError(
                    401,
                    ErrorCode.AUTH_SCHEME_INVALID,
                    "sender-constrained token requires DPoP scheme",
                    headers={"WWW-Authenticate": 'DPoP algs="ES256"'},
                ),
                user_id=user_id,
                mode=mode,
            )
        proof_header = _single_header(request, "dpop")
        if not proof_header:
            raise deny(
                ApiError(
                    401,
                    ErrorCode.DPOP_MISSING,
                    "DPoP proof required for sender-constrained token",
                    headers={"WWW-Authenticate": 'DPoP algs="ES256"'},
                ),
                user_id=user_id,
                mode=mode,
            )
        try:
            result = verify_dpop_proof(
                db,
                proof=proof_header,
                expected_htm=method,
                expected_htu=htu,
                access_token=raw_token,
                bound_jkt=jkt,
            )
        except ApiError as exc:
            raise deny(exc, user_id=user_id, mode=mode) from exc
        proof_jti = result.jti

    if required_scope and required_scope not in access.scopes:
        raise deny(
            ApiError(403, ErrorCode.SCOPE_INSUFFICIENT, f"scope {required_scope!r} required"),
            user_id=user_id,
            mode=mode,
        )

    if device is not None:
        device.last_seen_at = utcnow()

    events.record(
        db,
        event_type=events.EventType.API_ALLOWED,
        result=events.Result.ALLOWED,
        user_id=user_id,
        device_id=device.id if device else None,
        endpoint=path,
        method=method,
        risk=risk.value,
        mode=mode,
        metadata={"at_fp": fingerprint(raw_token), "proof_jti": proof_jti},
    )

    # 보안상 중요한 쓰기(특히 소비된 DPoP `jti`)를 **응답 전에** 확정한다.
    # get_db 의 커밋은 FastAPI 의존성 teardown 에서 응답 이후에 실행되므로, 그것에만
    # 의존하면 동일 proof 를 빠르게 재전송하는 replay 가 jti 커밋 이전에 검사를 통과할
    # 수 있다 (race). 여기서 커밋해 그 창을 없앤다.
    db.commit()

    return AuthContext(
        user=user,
        session=session,
        device=device,
        access=access,
        arm=arm,
        risk=risk,
        htu=htu,
        method=method,
        proof_jti=proof_jti,
    )


def require_scope(scope: str | None = None):
    """FastAPI dependency factory."""

    def _dependency(request: Request, db: Session = Depends(get_db)) -> AuthContext:
        return authenticate(request, db, required_scope=scope)

    return _dependency
