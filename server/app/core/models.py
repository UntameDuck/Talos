"""SQLAlchemy models (지시서 §17).

원칙:

* 모든 시각은 **timezone-aware UTC** 로 저장/비교한다 (지시서 §20).
* 토큰 원문, 개인키 재료는 어떤 테이블에도 저장하지 않는다 (§14).
  세션 식별은 `SessionToken.id` (= 토큰의 `sid` 클레임)로 한다.
* 스키마는 PostgreSQL 호환 타입만 쓴다.
"""

from __future__ import annotations

import enum
import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .db import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


def new_id() -> str:
    return str(uuid.uuid4())


class DeviceStatus(str, enum.Enum):
    PENDING = "PENDING"
    TRUSTED = "TRUSTED"
    REVOKED = "REVOKED"


class AuthMode(str, enum.Enum):
    """실험 arm 라벨. **검증 강도를 낮추는 데 쓰지 않는다.**

    서버의 실제 검증 분기는 토큰의 `cnf.jkt` 유무로 결정된다
    (`docs/architecture.md` ADR-1).
    """

    BEARER = "BEARER"                            # S0
    SOFTWARE_DPOP = "SOFTWARE_DPOP"              # S1
    ANDROID_HARDWARE_DPOP = "ANDROID_HARDWARE_DPOP"  # S2
    BOUNDKEY_DPOP = "BOUNDKEY_DPOP"              # S3


#: 실험 arm 코드 <-> AuthMode
ARM_TO_MODE = {
    "S0": AuthMode.BEARER,
    "S1": AuthMode.SOFTWARE_DPOP,
    "S2": AuthMode.ANDROID_HARDWARE_DPOP,
    "S3": AuthMode.BOUNDKEY_DPOP,
}
MODE_TO_ARM = {v: k for k, v in ARM_TO_MODE.items()}


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    username: Mapped[str] = mapped_column(String(64), unique=True, nullable=False)
    password_hash: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )

    devices: Mapped[list["Device"]] = relationship(back_populates="user")


class Device(Base):
    __tablename__ = "devices"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    #: 공개키 JWK 의 canonical JSON. **공개키만** 저장한다.
    public_key_jwk: Mapped[str] = mapped_column(Text, nullable=False)
    jwk_thumbprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(
        String(16), nullable=False, default=DeviceStatus.PENDING.value
    )
    #: 이 디바이스가 어떤 authenticator 유형인지 (실험 라벨).
    kind: Mapped[str] = mapped_column(
        String(32), nullable=False, default=AuthMode.SOFTWARE_DPOP.value
    )
    firmware_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    label: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    user: Mapped[User] = relationship(back_populates="devices")

    __table_args__ = (
        # 같은 사용자가 동일 키를 두 번 등록하지 못하게 한다. 서로 다른 사용자가
        # 같은 thumbprint 를 갖는 것도 사실상 불가능하지만 전역 유니크로 두면
        # 키 재사용 공격 분석이 쉬워진다.
        UniqueConstraint("jwk_thumbprint", name="uq_devices_jkt"),
        Index("ix_devices_user", "user_id"),
    )


class SessionToken(Base):
    """발급된 세션의 메타데이터. 토큰 자체는 저장하지 않는다."""

    __tablename__ = "session_tokens"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    user_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("users.id"), nullable=False
    )
    device_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("devices.id"), nullable=True
    )
    #: sender-constrained 세션이면 바인딩된 JWK thumbprint, Bearer 이면 NULL.
    jkt: Mapped[str | None] = mapped_column(String(64), nullable=True)
    scope: Mapped[str] = mapped_column(Text, nullable=False, default="")
    mode: Mapped[str] = mapped_column(String(32), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)
    revoked: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    #: refresh 회전 횟수 (재사용 탐지용).
    refresh_generation: Mapped[int] = mapped_column(Integer, nullable=False, default=0)

    __table_args__ = (Index("ix_sessions_user", "user_id"),)


class ReplayEntry(Base):
    """사용된 DPoP `jti`. TTL 이 지나면 정리한다."""

    __tablename__ = "replay_entries"

    jti: Mapped[str] = mapped_column(String(128), primary_key=True)
    jkt: Mapped[str] = mapped_column(String(64), nullable=False)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)

    __table_args__ = (Index("ix_replay_expires", "expires_at"),)


class SecurityEvent(Base):
    """구조화 보안 이벤트 (지시서 §14, §17).

    민감값(토큰 원문, 개인키)은 넣지 않는다. 토큰은 fingerprint 만 남긴다.
    """

    __tablename__ = "security_events"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utcnow
    )
    user_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    device_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    event_type: Mapped[str] = mapped_column(String(48), nullable=False)
    endpoint: Mapped[str | None] = mapped_column(String(255), nullable=True)
    method: Mapped[str | None] = mapped_column(String(10), nullable=True)
    risk: Mapped[str | None] = mapped_column(String(10), nullable=True)
    result: Mapped[str] = mapped_column(String(16), nullable=False)
    error_code: Mapped[str | None] = mapped_column(String(48), nullable=True)
    mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    #: 부가 정보 JSON 문자열 (민감값 금지).
    event_metadata: Mapped[str | None] = mapped_column(Text, nullable=True)

    __table_args__ = (
        Index("ix_events_time", "timestamp"),
        Index("ix_events_type", "event_type"),
    )
