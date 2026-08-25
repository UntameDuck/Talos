"""Security event recording (지시서 §14 Server 목록).

DB 에 남기는 동시에 structured log 로도 내보낸다. 실험 도구가 로그 스트림만으로도
집계할 수 있어야 하기 때문이다.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from sqlalchemy.orm import Session

from .models import SecurityEvent

logger = logging.getLogger("boundauth.security")


class EventType:
    LOGIN_SUCCESS = "LOGIN_SUCCESS"
    LOGIN_FAILURE = "LOGIN_FAILURE"
    TOKEN_ISSUED = "TOKEN_ISSUED"
    TOKEN_REFRESHED = "TOKEN_REFRESHED"
    TOKEN_INVALID = "TOKEN_INVALID"
    DEVICE_REGISTERED = "DEVICE_REGISTERED"
    DEVICE_REVOKED = "DEVICE_REVOKED"
    DPOP_VALID = "DPOP_VALID"
    DPOP_REPLAY = "DPOP_REPLAY"
    DPOP_JKT_MISMATCH = "DPOP_JKT_MISMATCH"
    DPOP_HTU_MISMATCH = "DPOP_HTU_MISMATCH"
    DPOP_HTM_MISMATCH = "DPOP_HTM_MISMATCH"
    DPOP_ATH_MISMATCH = "DPOP_ATH_MISMATCH"
    DPOP_INVALID = "DPOP_INVALID"
    NONCE_ISSUED = "NONCE_ISSUED"
    API_ALLOWED = "API_ALLOWED"
    API_DENIED = "API_DENIED"


class Result:
    ALLOWED = "ALLOWED"
    DENIED = "DENIED"
    INFO = "INFO"


#: error code -> 대표 이벤트 타입. 미등록 코드는 DPOP_INVALID/API_DENIED 로 떨어진다.
_CODE_TO_EVENT = {
    "DPOP_REPLAY": EventType.DPOP_REPLAY,
    "DPOP_JKT_MISMATCH": EventType.DPOP_JKT_MISMATCH,
    "DPOP_HTU_MISMATCH": EventType.DPOP_HTU_MISMATCH,
    "DPOP_HTM_MISMATCH": EventType.DPOP_HTM_MISMATCH,
    "DPOP_ATH_MISMATCH": EventType.DPOP_ATH_MISMATCH,
}


def event_type_for_code(code: str | None) -> str:
    if code is None:
        return EventType.API_DENIED
    if code in _CODE_TO_EVENT:
        return _CODE_TO_EVENT[code]
    if code.startswith("DPOP_"):
        return EventType.DPOP_INVALID
    if code.startswith("DEVICE_"):
        return EventType.API_DENIED
    return EventType.API_DENIED


def record(
    db: Session | None = None,
    *,
    commit: bool = False,
    event_type: str,
    result: str,
    user_id: str | None = None,
    device_id: str | None = None,
    endpoint: str | None = None,
    method: str | None = None,
    risk: str | None = None,
    error_code: str | None = None,
    mode: str | None = None,
    metadata: dict[str, Any] | None = None,
) -> None:
    metadata_json = json.dumps(metadata, ensure_ascii=False, default=str) if metadata else None

    if db is not None:
        db.add(
            SecurityEvent(
                event_type=event_type,
                result=result,
                user_id=user_id,
                device_id=device_id,
                endpoint=endpoint,
                method=method,
                risk=risk,
                error_code=error_code,
                mode=mode,
                event_metadata=metadata_json,
            )
        )
        if commit:
            # 거부(DENIED) 경로는 ApiError 로 끝나고 요청 트랜잭션이 rollback 되므로,
            # 정작 남겨야 할 차단 기록이 사라진다. 그래서 즉시 확정한다.
            # (별도 커넥션을 쓰면 SQLite writer lock 으로 교착이 생기므로 같은 세션을 쓴다.)
            db.commit()

    logger.info(
        event_type,
        extra={
            "event": event_type,
            "result": result,
            "user_id": user_id,
            "device_id": device_id,
            "endpoint": endpoint,
            "method": method,
            "risk": risk,
            "error_code": error_code,
            "mode": mode,
            **(metadata or {}),
        },
    )
