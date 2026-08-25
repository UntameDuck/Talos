"""Attack matrix runner.

(attack, arm) 조합을 `runs` 회 반복 실행한다. 각 반복은 **새 격리 서버**를 쓴다.
서버 상태(replay cache 등)가 반복 간에 새는 것을 막아 각 run 이 독립 시행이 되게 한다.
"""

from __future__ import annotations

from typing import Callable

from .attacks import ATTACK_FUNCS, EXPECTATION
from .harness import build_harness
from .recorder import AttackOutcome, ResultWriter
from .scenario import establish_legit_session


def run_single(attack: str, arm: str) -> AttackOutcome:
    """하나의 (attack, arm) 을 1회 실행한다. 격리 서버를 만들고 정리한다."""
    if EXPECTATION[attack][arm] is None:
        # 적용 불가한 조합. 실행하지 않고 표시만 한다.
        return AttackOutcome(
            attack=attack,
            arm=arm,
            attack_succeeded=False,
            status_code=0,
            error_code="N/A",
            matched_expectation=None,
            note="not applicable to this arm",
        )
    from .boundkey_sim import SignError

    harness, username, password = build_harness()
    try:
        ctx = establish_legit_session(harness, username, password, arm)
        try:
            outcome = ATTACK_FUNCS[attack](harness, ctx)
        except SignError as exc:
            # BoundKey(S3)가 서명을 거부해 공격이 서버에 도달조차 못한 경우.
            # 이것은 정상 방어다: proof 를 만들 수 없으면 공격은 실패한 것이다.
            expected = EXPECTATION[attack][arm]
            outcome = AttackOutcome(
                attack=attack,
                arm=arm,
                attack_succeeded=False,
                status_code=0,
                error_code=f"BOUNDKEY_{exc.reason}",
                matched_expectation=None if expected is None else (expected is False),
                note="BoundKey refused to produce a proof for this request",
            )
        ctx.client.close()
        return outcome
    finally:
        harness.cleanup()


def run_matrix(
    *,
    attacks: list[str],
    arms: list[str],
    runs: int,
    writer: ResultWriter | None = None,
    on_outcome: Callable[[AttackOutcome], None] | None = None,
) -> list[AttackOutcome]:
    results: list[AttackOutcome] = []
    for attack in attacks:
        for arm in arms:
            for _ in range(runs):
                outcome = run_single(attack, arm)
                if writer is not None:
                    writer.add(outcome)
                if on_outcome is not None:
                    on_outcome(outcome)
                results.append(outcome)
    return results
