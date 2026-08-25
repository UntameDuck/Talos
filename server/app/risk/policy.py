"""Endpoint risk classification (지시서 §1 Phase 1, §5.5).

이 테이블은 **BoundKey 펌웨어의 정책 테이블과 의미가 같아야 한다.**
서버와 BoundKey 가 서로 다른 risk 를 매기면 "서버는 허용했는데 서명이 없다" 또는
그 반대의 불일치가 생긴다. 변경 시 다음 세 곳을 함께 고쳐야 한다.

1. `server/app/risk/policy.py`            (본 파일)
2. `embedded/firmware/security/policy.c`  (펌웨어)
3. `attacker/boundattack/boundkey_sim.py` (시뮬레이터)
"""

from __future__ import annotations

import enum


class RiskLevel(str, enum.Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    UNKNOWN = "UNKNOWN"


#: (METHOD, path) -> RiskLevel. 경로는 정규화된 절대 경로(쿼리 제외)로 매칭한다.
POLICY_TABLE: dict[tuple[str, str], RiskLevel] = {
    ("GET", "/api/profile"): RiskLevel.LOW,
    ("GET", "/api/history"): RiskLevel.LOW,
    ("POST", "/api/settings"): RiskLevel.MEDIUM,
    ("POST", "/api/transfer"): RiskLevel.HIGH,
}


def classify(method: str, path: str) -> RiskLevel:
    """알 수 없는 (method, path) 는 UNKNOWN 이다.

    BoundKey 는 UNKNOWN 을 **DEFAULT DENY** 로 처리한다 (지시서 §5.5).
    서버는 라우팅되지 않는 경로를 404 로 돌려주므로 별도 거부가 필요 없지만,
    분류 자체는 동일하게 유지해 로그/실험에서 비교 가능하게 한다.
    """
    if not isinstance(method, str) or not isinstance(path, str):
        return RiskLevel.UNKNOWN
    return POLICY_TABLE.get((method.upper(), path), RiskLevel.UNKNOWN)


def requires_user_presence(level: RiskLevel) -> bool:
    """HIGH 만 물리 승인 필수 (지시서 §5.5)."""
    return level is RiskLevel.HIGH
