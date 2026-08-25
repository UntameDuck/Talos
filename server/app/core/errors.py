"""Error codes and the API error type.

지시서 §2 "실패 사유": 내부 디버그 모드에서는 구분 가능한 error code 를 남기고,
실서비스형 응답에서는 상세도를 낮춘다. 실험 계측이 error code 에 의존하므로
`detailed_errors=True` (dev/test) 에서는 항상 코드를 노출한다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


class ErrorCode:
    """Stable string codes. 로그/실험 집계 키로 쓰이므로 값을 바꾸지 않는다."""

    # --- auth / token -------------------------------------------------
    AUTH_INVALID_CREDENTIALS = "AUTH_INVALID_CREDENTIALS"
    AUTH_HEADER_MISSING = "AUTH_HEADER_MISSING"
    AUTH_SCHEME_INVALID = "AUTH_SCHEME_INVALID"
    TOKEN_MALFORMED = "TOKEN_MALFORMED"
    TOKEN_SIGNATURE_INVALID = "TOKEN_SIGNATURE_INVALID"
    TOKEN_EXPIRED = "TOKEN_EXPIRED"
    TOKEN_REVOKED = "TOKEN_REVOKED"
    TOKEN_TYPE_INVALID = "TOKEN_TYPE_INVALID"
    TOKEN_UNKNOWN_SESSION = "TOKEN_UNKNOWN_SESSION"
    SCOPE_INSUFFICIENT = "SCOPE_INSUFFICIENT"

    # --- device -------------------------------------------------------
    DEVICE_NOT_FOUND = "DEVICE_NOT_FOUND"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DEVICE_NOT_TRUSTED = "DEVICE_NOT_TRUSTED"
    DEVICE_KEY_INVALID = "DEVICE_KEY_INVALID"
    DEVICE_ALREADY_REGISTERED = "DEVICE_ALREADY_REGISTERED"

    # --- DPoP (RFC 9449) ---------------------------------------------
    DPOP_MISSING = "DPOP_MISSING"
    DPOP_MULTIPLE = "DPOP_MULTIPLE"
    DPOP_MALFORMED = "DPOP_MALFORMED"
    DPOP_TYP_INVALID = "DPOP_TYP_INVALID"
    DPOP_ALG_INVALID = "DPOP_ALG_INVALID"
    DPOP_JWK_INVALID = "DPOP_JWK_INVALID"
    DPOP_SIGNATURE_INVALID = "DPOP_SIGNATURE_INVALID"
    DPOP_JTI_INVALID = "DPOP_JTI_INVALID"
    DPOP_HTM_MISMATCH = "DPOP_HTM_MISMATCH"
    DPOP_HTU_MISMATCH = "DPOP_HTU_MISMATCH"
    DPOP_ATH_MISMATCH = "DPOP_ATH_MISMATCH"
    DPOP_JKT_MISMATCH = "DPOP_JKT_MISMATCH"
    DPOP_REPLAY = "DPOP_REPLAY"
    DPOP_EXPIRED = "DPOP_EXPIRED"
    DPOP_NONCE_REQUIRED = "DPOP_NONCE_REQUIRED"
    DPOP_NONCE_INVALID = "DPOP_NONCE_INVALID"

    # --- generic ------------------------------------------------------
    BAD_REQUEST = "BAD_REQUEST"
    INTERNAL_ERROR = "INTERNAL_ERROR"


#: 클라이언트에게 보여줄 일반화된 문구. prod 에서는 이것만 나간다.
_GENERIC_MESSAGE = {
    401: "authentication required",
    403: "forbidden",
    400: "bad request",
    404: "not found",
    409: "conflict",
    500: "internal error",
}


@dataclass
class ApiError(Exception):
    """도메인 오류. FastAPI exception handler 가 응답으로 변환한다."""

    status_code: int
    code: str
    #: 개발자용 상세 메시지. prod 응답에는 포함하지 않는다.
    detail: str = ""
    #: `WWW-Authenticate` 등 추가 헤더.
    headers: dict[str, str] = field(default_factory=dict)
    #: 로그/보안이벤트에만 남길 부가 정보 (민감값 금지).
    context: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        super().__init__(f"{self.code}: {self.detail}" if self.detail else self.code)

    def public_body(self, detailed: bool) -> dict[str, Any]:
        if detailed:
            return {"error": self.code, "detail": self.detail}
        return {"error": _GENERIC_MESSAGE.get(self.status_code, "error")}
