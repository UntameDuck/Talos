"""Structured JSON logging (지시서 §14).

토큰/개인키 원문은 절대 기록하지 않는다. 토큰은 `fingerprint()` 로 축약한다.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sys
from datetime import datetime, timezone
from typing import Any

_RESERVED = frozenset(
    logging.LogRecord("", 0, "", 0, "", (), None).__dict__.keys()
) | {"message", "asctime", "taskName"}


class JsonFormatter(logging.Formatter):
    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "msg": record.getMessage(),
        }
        for key, value in record.__dict__.items():
            if key not in _RESERVED and not key.startswith("_"):
                payload[key] = value
        if record.exc_info:
            payload["exc"] = self.formatException(record.exc_info)
        return json.dumps(payload, ensure_ascii=False, default=str)


def configure_logging(level: str = "INFO") -> None:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(JsonFormatter())
    root = logging.getLogger()
    root.handlers.clear()
    root.addHandler(handler)
    root.setLevel(level)
    # uvicorn 기본 핸들러가 중복 출력하지 않도록 정리한다.
    for name in ("uvicorn", "uvicorn.error", "uvicorn.access"):
        logger = logging.getLogger(name)
        logger.handlers.clear()
        logger.propagate = True


def fingerprint(secret: str | bytes | None, length: int = 12) -> str | None:
    """비밀값의 짧은 SHA-256 지문. 로그 상관관계 추적용이며 역산 불가.

    원문 토큰을 로그에 남기지 않기 위한 유일한 허용 표현이다.
    """
    if secret is None:
        return None
    if isinstance(secret, str):
        secret = secret.encode("utf-8")
    return hashlib.sha256(secret).hexdigest()[:length]
