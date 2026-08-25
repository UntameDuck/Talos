"""Protected resource endpoints (지시서 §1 Phase 1).

Risk classification (지시서 Phase 1):

```
/api/profile   -> LOW
/api/history   -> LOW
/api/settings  -> MEDIUM
/api/transfer  -> HIGH
```

`/api/transfer` 는 이 연구의 핵심 고위험 엔드포인트다. **실제 금융 기능은 없다**
(지시서 §30). 요청을 기록만 하는 모의 엔드포인트다.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..core.db import get_db
from ..core.models import SecurityEvent
from .deps import AuthContext, require_scope

router = APIRouter(prefix="/api", tags=["api"])


class SettingsUpdate(BaseModel):
    model_config = ConfigDict(extra="forbid")

    display_name: str | None = Field(default=None, max_length=64)
    notifications_enabled: bool | None = None


class TransferRequest(BaseModel):
    model_config = ConfigDict(extra="forbid")

    to_account: str = Field(min_length=1, max_length=32)
    #: 모의 값. 실제 이체는 일어나지 않는다.
    amount: int = Field(gt=0, le=10_000_000)
    memo: str | None = Field(default=None, max_length=140)


@router.get("/profile")
def get_profile(ctx: AuthContext = Depends(require_scope("profile"))) -> dict[str, Any]:
    return {
        "user_id": ctx.user.id,
        "username": ctx.user.username,
        "arm": ctx.arm,
        "risk": ctx.risk.value,
        "device_id": ctx.device.id if ctx.device else None,
    }


@router.get("/history")
def get_history(ctx: AuthContext = Depends(require_scope("history"))) -> dict[str, Any]:
    return {
        "user_id": ctx.user.id,
        "risk": ctx.risk.value,
        "items": [
            {"id": 1, "type": "login", "description": "sample history entry"},
            {"id": 2, "type": "transfer", "description": "sample history entry"},
        ],
    }


@router.post("/settings")
def update_settings(
    payload: SettingsUpdate,
    ctx: AuthContext = Depends(require_scope("settings")),
) -> dict[str, Any]:
    return {
        "user_id": ctx.user.id,
        "risk": ctx.risk.value,
        "applied": payload.model_dump(exclude_none=True),
    }


@router.post("/transfer")
def transfer(
    payload: TransferRequest,
    ctx: AuthContext = Depends(require_scope("transfer")),
) -> dict[str, Any]:
    return {
        "user_id": ctx.user.id,
        "risk": ctx.risk.value,
        "status": "SIMULATED",
        "to_account": payload.to_account,
        "amount": payload.amount,
    }


@router.get("/security-events")
def recent_security_events(
    limit: int = 50,
    ctx: AuthContext = Depends(require_scope("profile")),
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """데모 앱의 "Attack / Security Events" 화면용 (지시서 §15).

    자신의 사용자에 연결된 이벤트만 돌려준다.
    """
    limit = max(1, min(limit, 200))
    rows = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.user_id == ctx.user.id)
        .order_by(SecurityEvent.timestamp.desc())
        .limit(limit)
    ).all()
    return {
        "items": [
            {
                "timestamp": r.timestamp.isoformat(),
                "event_type": r.event_type,
                "result": r.result,
                "endpoint": r.endpoint,
                "method": r.method,
                "risk": r.risk,
                "error_code": r.error_code,
                "mode": r.mode,
            }
            for r in rows
        ]
    }
