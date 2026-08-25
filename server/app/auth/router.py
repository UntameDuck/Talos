"""Authentication endpoints (지시서 §1 Phase 1)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Request
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core import events
from ..core.config import get_settings
from ..core.db import get_db
from ..core.errors import ApiError, ErrorCode
from ..core.logging_setup import fingerprint
from ..core.models import ARM_TO_MODE, AuthMode, SessionToken, User, new_id
from ..devices import service as device_service
from ..tokens import service as token_service
from .passwords import verify_password
from .schemas import LoginRequest, RefreshRequest, TokenResponse

router = APIRouter(prefix="/auth", tags=["auth"])


def _authenticate_user(db: Session, username: str, password: str) -> User:
    user = db.scalar(select(User).where(User.username == username))
    if not verify_password(password, user.password_hash if user else None):
        events.record(
            db,
            commit=True,
            event_type=events.EventType.LOGIN_FAILURE,
            result=events.Result.DENIED,
            endpoint="/auth/login",
            method="POST",
            error_code=ErrorCode.AUTH_INVALID_CREDENTIALS,
            metadata={"username_fp": fingerprint(username)},
        )
        # 사용자 존재 여부를 구분해 알려주지 않는다.
        raise ApiError(401, ErrorCode.AUTH_INVALID_CREDENTIALS, "invalid username or password")
    assert user is not None
    return user


@router.post("/login", response_model=TokenResponse)
def login(payload: LoginRequest, request: Request, db: Session = Depends(get_db)) -> TokenResponse:
    settings = get_settings()
    user = _authenticate_user(db, payload.username, payload.password)
    scopes = token_service.normalize_scopes(payload.scope)
    mode = ARM_TO_MODE[payload.mode]

    device = None
    jkt = None
    if mode is not AuthMode.BEARER:
        if not payload.device_id:
            raise ApiError(
                400,
                ErrorCode.BAD_REQUEST,
                f"mode {payload.mode} requires a registered device_id",
            )
        device = device_service.get_active_device(db, payload.device_id, user_id=user.id)
        jkt = device.jwk_thumbprint
        device_service.touch(db, device)

    session = SessionToken(
        id=new_id(),
        user_id=user.id,
        device_id=device.id if device else None,
        jkt=jkt,
        scope=" ".join(scopes),
        mode=mode.value,
        expires_at=None,  # 아래에서 access token 만료로 채운다
        refresh_generation=0,
    )

    access = token_service.issue_access_token(
        subject=user.id,
        session_id=session.id,
        scopes=scopes,
        mode=mode.value,
        jkt=jkt,
        device_id=device.id if device else None,
    )
    refresh = token_service.issue_refresh_token(
        subject=user.id, session_id=session.id, generation=0, jkt=jkt
    )
    session.expires_at = refresh.expires_at
    db.add(session)
    db.flush()

    events.record(
        db,
        event_type=events.EventType.LOGIN_SUCCESS,
        result=events.Result.INFO,
        user_id=user.id,
        device_id=device.id if device else None,
        endpoint="/auth/login",
        method="POST",
        mode=mode.value,
    )
    events.record(
        db,
        event_type=events.EventType.TOKEN_ISSUED,
        result=events.Result.INFO,
        user_id=user.id,
        device_id=device.id if device else None,
        endpoint="/auth/login",
        method="POST",
        mode=mode.value,
        metadata={"jkt": jkt, "sid": session.id, "at_fp": fingerprint(access.token)},
    )
    # 클라이언트가 즉시 이 세션으로 API 를 호출하므로, 응답 전에 세션 생성을 확정한다.
    # (get_db 의 커밋은 teardown 에서 응답 이후 실행되어 read-after-write race 를 만든다.)
    db.commit()

    return TokenResponse(
        access_token=access.token,
        refresh_token=refresh.token,
        token_type="DPoP" if jkt else "Bearer",
        expires_in=settings.access_token_ttl_seconds,
        scope=" ".join(scopes),
        mode=payload.mode,
        session_id=session.id,
        device_id=device.id if device else None,
        jkt=jkt,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_tokens(
    payload: RefreshRequest, request: Request, db: Session = Depends(get_db)
) -> TokenResponse:
    settings = get_settings()
    verified = token_service.verify_token(
        payload.refresh_token, expected_typ=token_service.REFRESH_TYP
    )
    session = db.get(SessionToken, verified.session_id)
    if session is None or session.user_id != verified.subject:
        raise ApiError(401, ErrorCode.TOKEN_UNKNOWN_SESSION, "unknown session")
    if session.revoked:
        raise ApiError(401, ErrorCode.TOKEN_REVOKED, "session revoked")

    generation = verified.claims.get("gen")
    if not isinstance(generation, int) or generation != session.refresh_generation:
        # 회전된(구) refresh token 의 재사용 = 탈취 정황. 세션 전체를 폐기한다.
        session.revoked = True
        events.record(
            db,
            commit=True,
            event_type=events.EventType.TOKEN_INVALID,
            result=events.Result.DENIED,
            user_id=session.user_id,
            endpoint="/auth/refresh",
            method="POST",
            error_code=ErrorCode.TOKEN_REVOKED,
            mode=session.mode,
            metadata={"reason": "refresh_generation_mismatch", "sid": session.id},
        )
        # 위 record(commit=True) 가 폐기와 감사기록을 함께 확정한다.
        # (ApiError 로 빠져나가면 요청 트랜잭션은 rollback 된다.)
        raise ApiError(401, ErrorCode.TOKEN_REVOKED, "refresh token reuse detected")

    device = None
    if session.device_id:
        device = device_service.get_active_device(db, session.device_id, user_id=session.user_id)
        device_service.touch(db, device)

    session.refresh_generation += 1
    scopes = tuple(session.scope.split()) if session.scope else ()
    access = token_service.issue_access_token(
        subject=session.user_id,
        session_id=session.id,
        scopes=scopes,
        mode=session.mode,
        jkt=session.jkt,
        device_id=session.device_id,
    )
    new_refresh = token_service.issue_refresh_token(
        subject=session.user_id,
        session_id=session.id,
        generation=session.refresh_generation,
        jkt=session.jkt,
    )
    session.expires_at = new_refresh.expires_at

    events.record(
        db,
        event_type=events.EventType.TOKEN_REFRESHED,
        result=events.Result.INFO,
        user_id=session.user_id,
        device_id=session.device_id,
        endpoint="/auth/refresh",
        method="POST",
        mode=session.mode,
        metadata={"sid": session.id, "gen": session.refresh_generation},
    )

    db.commit()

    from ..core.models import MODE_TO_ARM

    return TokenResponse(
        access_token=access.token,
        refresh_token=new_refresh.token,
        token_type="DPoP" if session.jkt else "Bearer",
        expires_in=settings.access_token_ttl_seconds,
        scope=session.scope,
        mode=MODE_TO_ARM[AuthMode(session.mode)],
        session_id=session.id,
        device_id=session.device_id,
        jkt=session.jkt,
    )
