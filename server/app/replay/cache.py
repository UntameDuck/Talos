"""DPoP `jti` replay cache (지시서 §4.4).

MVP 는 DB 테이블(`ReplayEntry`)을 쓴다. Redis 확장은 지시서 §6 상 선택 사항.

핵심: `jti` 삽입은 **원자적**이어야 한다. 두 요청이 같은 proof 를 동시에 보내면
정확히 하나만 통과해야 한다. PRIMARY KEY 제약 위반(IntegrityError)을 replay 신호로
사용한다.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from ..core.models import ReplayEntry


def _now() -> datetime:
    return datetime.now(timezone.utc)


def check_and_store(db: Session, *, jti: str, jkt: str, ttl_seconds: int) -> bool:
    """`jti` 를 소비한다. 처음이면 True(통과), 이미 있으면 False(replay).

    만료된 항목이 남아 있으면 재사용을 허용하기 위해 먼저 정리한다. iat 창이
    TTL 보다 짧으므로, 만료된 jti 는 어차피 iat 검사에서 걸러진다.
    """
    now = _now()
    existing = db.get(ReplayEntry, jti)
    if existing is not None:
        if existing.expires_at.replace(tzinfo=timezone.utc) > now:
            return False
        # 만료된 항목: 삭제 후 새로 삽입하도록 진행.
        db.delete(existing)
        db.flush()

    entry = ReplayEntry(
        jti=jti,
        jkt=jkt,
        created_at=now,
        expires_at=now + timedelta(seconds=ttl_seconds),
    )
    db.add(entry)
    try:
        db.flush()
    except IntegrityError:
        # 동시 삽입 경쟁에서 진 경우 = 다른 요청이 먼저 이 jti 를 소비함 = replay.
        db.rollback()
        return False
    return True


def purge_expired(db: Session) -> int:
    """만료된 replay 항목 정리 (운영용; 필수는 아님)."""
    now = _now()
    rows = db.query(ReplayEntry).filter(ReplayEntry.expires_at <= now).all()
    for row in rows:
        db.delete(row)
    db.flush()
    return len(rows)
