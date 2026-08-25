"""Request/response models for auth endpoints."""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

ArmCode = Literal["S0", "S1", "S2", "S3"]


class LoginRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    #: 실험 arm. S1/S2/S3 는 `device_id` 가 필요하다.
    mode: ArmCode = "S0"
    device_id: str | None = Field(default=None, max_length=36)
    scope: list[str] | None = None


class TokenResponse(BaseModel):
    access_token: str
    refresh_token: str
    #: RFC 9449 는 sender-constrained 토큰에 `token_type: DPoP` 를 쓴다.
    token_type: Literal["Bearer", "DPoP"]
    expires_in: int
    scope: str
    mode: ArmCode
    session_id: str
    device_id: str | None = None
    jkt: str | None = None


class RefreshRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    refresh_token: str = Field(min_length=1, max_length=8192)


class DeviceRegisterRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    username: str = Field(min_length=1, max_length=64)
    password: str = Field(min_length=1, max_length=256)
    #: **공개키만** 받는다. `d` 가 포함되면 거부한다 (jose.public_key_from_jwk).
    public_key_jwk: dict[str, Any]
    kind: ArmCode = "S1"
    firmware_version: str | None = Field(default=None, max_length=32)
    label: str | None = Field(default=None, max_length=64)


class DeviceResponse(BaseModel):
    id: str
    user_id: str
    jwk_thumbprint: str
    status: str
    kind: str
    firmware_version: str | None
    label: str | None
    created_at: str
    last_seen_at: str | None
