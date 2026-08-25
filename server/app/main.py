"""BoundAuth server application factory."""

from __future__ import annotations

import logging
import os
from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from sqlalchemy import select

from .api.router import router as api_router
from .auth.passwords import hash_password
from .auth.router import router as auth_router
from .core.config import get_settings
from .core.db import create_all, get_sessionmaker
from .core.errors import ApiError, ErrorCode
from .core.keys import get_verifying_key
from .core.logging_setup import configure_logging
from .core.models import User
from .core.jose import public_jwk_from_key
from .devices.router import router as devices_router

logger = logging.getLogger("boundauth.main")


def _seed_demo_user() -> None:
    """실험 재현성을 위한 데모 계정 생성.

    비밀번호는 `BOUNDAUTH_SEED_PASSWORD` 로만 주입한다. 값이 없으면 계정을 만들지
    않는다 (기본 비밀번호를 코드에 두지 않는다 - 지시서 §34).
    """
    settings = get_settings()
    if not settings.seed_password:
        logger.info(
            "seed skipped",
            extra={"reason": "BOUNDAUTH_SEED_PASSWORD not set"},
        )
        return
    session = get_sessionmaker()()
    try:
        existing = session.scalar(select(User).where(User.username == settings.seed_username))
        if existing is None:
            session.add(
                User(
                    username=settings.seed_username,
                    password_hash=hash_password(settings.seed_password),
                )
            )
            session.commit()
            logger.info("seed user created", extra={"username": settings.seed_username})
    finally:
        session.close()


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(os.getenv("BOUNDAUTH_LOG_LEVEL", "INFO"))
    settings = get_settings()
    create_all()
    _seed_demo_user()
    logger.info(
        "boundauth server ready",
        extra={"env": settings.env, "issuer": settings.issuer},
    )
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    app = FastAPI(
        title="BoundAuth Server",
        version="0.1.0",
        description=(
            "Device-Bound Session Security Framework - research prototype. "
            "TLS is assumed in production deployments."
        ),
        lifespan=lifespan,
    )

    @app.exception_handler(ApiError)
    async def _api_error_handler(request: Request, exc: ApiError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status_code,
            content=exc.public_body(detailed=settings.detailed_errors),
            headers=exc.headers or None,
        )

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        # 예기치 못한 예외에서 내부 정보를 흘리지 않는다. fail closed.
        logger.exception("unhandled error", extra={"path": request.url.path})
        return JSONResponse(
            status_code=500, content={"error": ErrorCode.INTERNAL_ERROR}
        )

    @app.get("/health", tags=["meta"])
    def health() -> dict[str, str]:
        return {"status": "ok", "env": settings.env}

    @app.get("/.well-known/boundauth-config", tags=["meta"])
    def config() -> dict[str, object]:
        """클라이언트/실험 도구가 서버 파라미터를 읽어가는 곳.

        서버 **공개키**만 노출한다.
        """
        return {
            "issuer": settings.issuer,
            "signing_public_jwk": public_jwk_from_key(get_verifying_key()),
            "dpop_signing_alg_values_supported": ["ES256"],
            "dpop_iat_skew_seconds": settings.dpop_iat_skew_seconds,
            "dpop_require_nonce": settings.dpop_require_nonce,
        }

    app.include_router(auth_router)
    app.include_router(devices_router)
    app.include_router(api_router)
    return app


app = create_app()
