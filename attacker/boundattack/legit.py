"""Legitimate request driver — 정상 요청 성공률/지연 측정용.

BoundAttack 은 공격을 재현하지만, 실험에는 "정상 요청이 각 arm 에서 잘 되는가"
(정상 요청 성공률, end-to-end latency, §9)도 필요하다. 그 정상 경로를 여기서 돈다.

S3 의 HIGH 요청(/api/transfer)은 실제 승인을 모사하기 위해 시뮬레이터 버튼을
프로그램적으로 누른다(= 사용자가 실제로 승인한 상황). 이는 공격이 아니라 정상
사용자 행동의 재현이다.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from .boundkey_sim import SimulatorSigner
from .scenario import LegitContext

#: (method, path, body) 정상 요청 시나리오.
LEGIT_REQUESTS = [
    ("GET", "/api/profile", None),
    ("GET", "/api/history", None),
    ("POST", "/api/settings", {"display_name": "demo"}),
    ("POST", "/api/transfer", {"to_account": "ACC-DEMO", "amount": 100}),
]


@dataclass
class LatencySample:
    arm: str
    method: str
    path: str
    risk_high: bool
    status_code: int
    ok: bool
    #: end-to-end 요청 지연(ms). 정상 클라이언트가 인증 헤더 구성 + HTTP 왕복.
    e2e_ms: float


def _press_if_high(ctx: LegitContext, method: str, path: str) -> None:
    """S3 에서 HIGH 요청이면 다음 서명에 대해 승인 버튼을 누른다.

    시뮬레이터는 request_id 단위로 승인을 소비하지만, SimulatorSigner 는 매 호출마다
    새 request_id 를 만든다. 정상 승인을 모사하기 위해 시뮬레이터를 auto_approve_high
    로 일시 전환하는 대신, 여기서는 '이번 한 번' 승인 의사를 표시한다.
    """
    if ctx.arm != "S3":
        return
    signer = ctx.signer
    if isinstance(signer, SimulatorSigner):
        # 정상 사용자 승인: 다음 HIGH 서명을 1회 허용한다.
        signer.sim.auto_approve_high = True  # 정상 요청 구간에서만 True


def run_legit_once(ctx: LegitContext) -> list[LatencySample]:
    samples: list[LatencySample] = []
    for method, path, body in LEGIT_REQUESTS:
        is_high = (method, path) == ("POST", "/api/transfer")
        if is_high and ctx.arm == "S3":
            _press_if_high(ctx, method, path)
        start = time.perf_counter()
        response = ctx.client.request(method, path, ctx.session, json_body=body)
        elapsed_ms = (time.perf_counter() - start) * 1000.0
        if is_high and ctx.arm == "S3" and isinstance(ctx.signer, SimulatorSigner):
            ctx.signer.sim.auto_approve_high = False  # 다시 보안 기본값으로
        samples.append(
            LatencySample(
                arm=ctx.arm,
                method=method,
                path=path,
                risk_high=is_high,
                status_code=response.status_code,
                ok=200 <= response.status_code < 300,
                e2e_ms=elapsed_ms,
            )
        )
    return samples
