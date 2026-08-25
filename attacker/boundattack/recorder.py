"""Attack result recording.

각 공격 시도는 하나의 `AttackOutcome` 이다. 결과는 JSONL raw 로 append 되고,
집계는 별도 단계(experiments/runners)에서 수행한다. 수치를 미리 만들지 않는다.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass
class AttackOutcome:
    attack: str
    arm: str
    #: 공격자 관점에서 성공했는가 (= 보호 리소스에 접근/실행 성공).
    attack_succeeded: bool
    #: 서버 HTTP 상태.
    status_code: int
    #: 서버가 남긴 error code (detailed_errors=True 일 때).
    error_code: str | None = None
    #: 이 결과가 기대와 일치하는가 (설계상 예상 결과).
    matched_expectation: bool | None = None
    note: str = ""
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_json(self) -> str:
        return json.dumps(asdict(self), ensure_ascii=False)


class ResultWriter:
    def __init__(self, path: Path) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._outcomes: list[AttackOutcome] = []

    def add(self, outcome: AttackOutcome) -> AttackOutcome:
        self._outcomes.append(outcome)
        with self.path.open("a", encoding="utf-8") as handle:
            handle.write(outcome.to_json() + "\n")
        return outcome

    @property
    def outcomes(self) -> list[AttackOutcome]:
        return list(self._outcomes)

    def summary(self) -> dict[str, Any]:
        total = len(self._outcomes)
        succeeded = sum(1 for o in self._outcomes if o.attack_succeeded)
        return {
            "total": total,
            "attack_succeeded": succeeded,
            "blocked": total - succeeded,
            "success_rate": (succeeded / total) if total else None,
        }
