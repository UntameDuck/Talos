"""Device registry (지시서 §5.2, §18)."""

from __future__ import annotations

import json
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core import jose
from ..core.errors import ApiError, ErrorCode
from ..core.models import ARM_TO_MODE, Device, DeviceStatus, SessionToken, User, utcnow


def canonical_public_jwk(raw_jwk: Any) -> tuple[dict[str, str], str]:
    """공개 JWK 를 정규화하고 thumbprint 를 계산한다.

    개인키 성분(`d`)이 포함되면 `public_key_from_jwk` 가 거부한다.
    비필수 멤버(kid/use/alg 등)는 저장 전에 제거해 thumbprint 계산과 저장값이
    항상 일치하도록 한다.
    """
    try:
        jose.public_key_from_jwk(raw_jwk)
        canonical = {k: raw_jwk[k] for k in ("crv", "kty", "x", "y")}
        thumbprint = jose.jwk_thumbprint(canonical)
    except jose.JoseError as exc:
        raise ApiError(400, ErrorCode.DEVICE_KEY_INVALID, str(exc)) from exc
    return canonical, thumbprint


def register_device(
    db: Session,
    *,
    user: User,
    public_key_jwk: Any,
    kind_arm: str,
    firmware_version: str | None,
    label: str | None,
) -> Device:
    canonical, thumbprint = canonical_public_jwk(public_key_jwk)

    existing = db.scalar(select(Device).where(Device.jwk_thumbprint == thumbprint))
    if existing is not None:
        if existing.user_id != user.id:
            # 다른 사용자의 키를 재등록하려는 시도. 존재 사실을 노출하지 않는다.
            raise ApiError(409, ErrorCode.DEVICE_ALREADY_REGISTERED, "key already in use")
        if existing.status == DeviceStatus.REVOKED.value:
            raise ApiError(403, ErrorCode.DEVICE_REVOKED, "device key is revoked")
        return existing

    device = Device(
        user_id=user.id,
        public_key_jwk=json.dumps(canonical, sort_keys=True, separators=(",", ":")),
        jwk_thumbprint=thumbprint,
        # MVP 는 인증된 사용자의 등록 요청을 즉시 신뢰한다. 실제 배포에서는
        # PENDING -> 관리자/OOB 승인 -> TRUSTED 전이를 두어야 한다.
        status=DeviceStatus.TRUSTED.value,
        kind=ARM_TO_MODE[kind_arm].value,
        firmware_version=firmware_version,
        label=label,
    )
    db.add(device)
    db.flush()
    return device


def get_active_device(db: Session, device_id: str, *, user_id: str) -> Device:
    device = db.get(Device, device_id)
    if device is None or device.user_id != user_id:
        raise ApiError(404, ErrorCode.DEVICE_NOT_FOUND, "device not found")
    if device.status == DeviceStatus.REVOKED.value:
        raise ApiError(403, ErrorCode.DEVICE_REVOKED, "device is revoked")
    if device.status != DeviceStatus.TRUSTED.value:
        raise ApiError(403, ErrorCode.DEVICE_NOT_TRUSTED, "device is not trusted")
    return device


def revoke_device(db: Session, device: Device) -> int:
    """디바이스를 폐기하고 그 키에 바인딩된 세션을 모두 무효화한다 (지시서 §18)."""
    device.status = DeviceStatus.REVOKED.value
    sessions = db.scalars(
        select(SessionToken).where(
            SessionToken.device_id == device.id, SessionToken.revoked.is_(False)
        )
    ).all()
    for session in sessions:
        session.revoked = True
    db.flush()
    return len(sessions)


def touch(db: Session, device: Device) -> None:
    device.last_seen_at = utcnow()
