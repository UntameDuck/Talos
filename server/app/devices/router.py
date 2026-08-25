"""Device registration / listing / revocation (지시서 §5.2, §18)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..api.deps import AuthContext, require_scope
from ..auth.router import _authenticate_user
from ..auth.schemas import DeviceRegisterRequest, DeviceResponse
from ..core import events
from ..core.db import get_db
from ..core.errors import ApiError, ErrorCode
from ..core.models import Device
from . import service

router = APIRouter(prefix="/devices", tags=["devices"])


def _to_response(device: Device) -> DeviceResponse:
    return DeviceResponse(
        id=device.id,
        user_id=device.user_id,
        jwk_thumbprint=device.jwk_thumbprint,
        status=device.status,
        kind=device.kind,
        firmware_version=device.firmware_version,
        label=device.label,
        created_at=device.created_at.isoformat(),
        last_seen_at=device.last_seen_at.isoformat() if device.last_seen_at else None,
    )


@router.post("/register", response_model=DeviceResponse)
def register(payload: DeviceRegisterRequest, db: Session = Depends(get_db)) -> DeviceResponse:
    """공개키를 등록한다.

    자격증명 재확인을 요구한다. 등록은 이후 발급될 모든 토큰의 바인딩 대상을
    정하는 행위이므로 유효한 access token 만으로 수행하게 두지 않는다.
    """
    user = _authenticate_user(db, payload.username, payload.password)
    device = service.register_device(
        db,
        user=user,
        public_key_jwk=payload.public_key_jwk,
        kind_arm=payload.kind,
        firmware_version=payload.firmware_version,
        label=payload.label,
    )
    events.record(
        db,
        event_type=events.EventType.DEVICE_REGISTERED,
        result=events.Result.INFO,
        user_id=user.id,
        device_id=device.id,
        endpoint="/devices/register",
        method="POST",
        mode=device.kind,
        metadata={"jkt": device.jwk_thumbprint, "kind": device.kind},
    )
    db.commit()  # 클라이언트가 곧바로 이 디바이스로 로그인하므로 응답 전에 확정한다.
    return _to_response(device)


@router.get("", response_model=list[DeviceResponse])
def list_devices(
    ctx: AuthContext = Depends(require_scope("profile")),
    db: Session = Depends(get_db),
) -> list[DeviceResponse]:
    devices = db.scalars(select(Device).where(Device.user_id == ctx.user.id)).all()
    return [_to_response(d) for d in devices]


@router.post("/{device_id}/revoke")
def revoke(
    device_id: str,
    ctx: AuthContext = Depends(require_scope("settings")),
    db: Session = Depends(get_db),
) -> dict[str, object]:
    device = db.get(Device, device_id)
    if device is None or device.user_id != ctx.user.id:
        raise ApiError(404, ErrorCode.DEVICE_NOT_FOUND, "device not found")
    revoked_sessions = service.revoke_device(db, device)
    events.record(
        db,
        event_type=events.EventType.DEVICE_REVOKED,
        result=events.Result.INFO,
        user_id=ctx.user.id,
        device_id=device.id,
        endpoint=f"/devices/{device_id}/revoke",
        method="POST",
        mode=device.kind,
        metadata={"revoked_sessions": revoked_sessions},
    )
    db.commit()
    return {
        "device_id": device.id,
        "status": device.status,
        "revoked_sessions": revoked_sessions,
    }
