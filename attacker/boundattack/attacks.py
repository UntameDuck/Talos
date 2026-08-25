"""The eight BoundAttack attack implementations (지시서 §6 A~H).

각 공격은 `run(ctx) -> AttackOutcome` 를 제공한다. `ctx` 는 정상 세션이 확립된
`LegitContext` 다. 공격자는 **별도의 클라이언트**(다른 기기)에서 탈취물을 사용한다.

`attack_succeeded=True` 의 정의: 공격자가 보호 리소스 응답 2xx 를 받았다
(= 무단 접근/실행에 성공). 서버가 4xx 로 막으면 False.

`EXPECTATION[attack][arm]` 은 **설계상 예상**이다. 실측값이 아니다. 실측은
recorder 가 남긴 raw 에서만 집계한다. 예상과 실측의 불일치는 리포트에서
`matched_expectation=False` 로 드러난다.
"""

from __future__ import annotations

import time
from typing import Callable

import httpx

from .client import SoftwareSigner
from .crypto import ClientKey, ath, build_dpop_proof
from .recorder import AttackOutcome
from .scenario import LegitContext

ALL_ATTACKS = [
    "token-replay",
    "cross-key",
    "proof-replay",
    "uri-substitution",
    "method-substitution",
    "token-substitution",
    "stale-proof",
    "high-risk-abuse",
]

#: 설계상 예상 결과. True = 공격 성공 예상(방어 없음), False = 차단 예상.
#: None = 해당 arm 에 적용 불가.
EXPECTATION: dict[str, dict[str, bool | None]] = {
    "token-replay":       {"S0": True,  "S1": False, "S2": False, "S3": False},
    "cross-key":          {"S0": None,  "S1": False, "S2": False, "S3": False},
    "proof-replay":       {"S0": None,  "S1": False, "S2": False, "S3": False},
    "uri-substitution":   {"S0": None,  "S1": False, "S2": False, "S3": False},
    "method-substitution":{"S0": None,  "S1": False, "S2": False, "S3": False},
    "token-substitution": {"S0": None,  "S1": False, "S2": False, "S3": False},
    "stale-proof":        {"S0": None,  "S1": False, "S2": False, "S3": False},
    # 침해된 클라이언트의 고위험 남용. S0~S2 는 물리 방어가 없어 성공 예상, S3 만 차단.
    "high-risk-abuse":    {"S0": True,  "S1": True,  "S2": True,  "S3": False},
}


def _htu(base_url: str, path: str) -> str:
    return f"{base_url.rstrip('/')}{path}"


def _succeeded(response: httpx.Response) -> bool:
    return 200 <= response.status_code < 300


def _error_code(response: httpx.Response) -> str | None:
    try:
        return response.json().get("error")
    except Exception:
        return None


def _outcome(attack: str, ctx: LegitContext, response: httpx.Response, note: str = "") -> AttackOutcome:
    succeeded = _succeeded(response)
    expected = EXPECTATION[attack][ctx.arm]
    matched = None if expected is None else (succeeded == expected)
    return AttackOutcome(
        attack=attack,
        arm=ctx.arm,
        attack_succeeded=succeeded,
        status_code=response.status_code,
        error_code=_error_code(response),
        matched_expectation=matched,
        note=note,
    )


def _blocked_outcome(attack: str, ctx: LegitContext, *, status: int, code: str, note: str) -> AttackOutcome:
    """서버에 도달하기 전(클라이언트/BoundKey 단계)에서 막힌 경우."""
    expected = EXPECTATION[attack][ctx.arm]
    matched = None if expected is None else (False == expected)
    return AttackOutcome(
        attack=attack,
        arm=ctx.arm,
        attack_succeeded=False,
        status_code=status,
        error_code=code,
        matched_expectation=matched,
        note=note,
    )


# --------------------------------------------------------------------------
# 각 공격은 harness 와 legit ctx 를 받는다. base_url 은 harness 에서 얻는다.
# --------------------------------------------------------------------------


def attack_token_replay(harness, ctx: LegitContext) -> AttackOutcome:
    """A — 탈취한 access token 을 다른 기기(새 클라이언트)에서 그대로 사용."""
    stolen = ctx.session.access_token
    with harness.client(signer=None) as attacker:
        # 공격자는 proof 생성 능력이 없다. Bearer 로 시도한다.
        response = attacker.raw().get(
            "/api/profile", headers={"Authorization": f"Bearer {stolen}"}
        )
    return _outcome("token-replay", ctx, response, note="bearer replay from fresh client")


def attack_cross_key(harness, ctx: LegitContext) -> AttackOutcome:
    """B — 탈취 token + 공격자 자신의 key 로 proof 생성 → jkt mismatch 기대."""
    if EXPECTATION["cross-key"][ctx.arm] is None:
        return _blocked_outcome("cross-key", ctx, status=0, code="N/A", note="arm not applicable")
    stolen = ctx.session.access_token
    attacker_key = ClientKey.generate()
    base = harness.base_url
    proof = build_dpop_proof(
        attacker_key, htm="GET", htu=_htu(base, "/api/profile"), access_token=stolen
    )
    with harness.client(signer=None) as attacker:
        response = attacker.raw().get(
            "/api/profile",
            headers={"Authorization": f"DPoP {stolen}", "DPoP": proof},
        )
    return _outcome("cross-key", ctx, response, note="attacker key proof")


def attack_proof_replay(harness, ctx: LegitContext) -> AttackOutcome:
    """C — 정상 proof 전체를 캡처해 재전송 → jti replay 차단 기대."""
    if EXPECTATION["proof-replay"][ctx.arm] is None:
        return _blocked_outcome("proof-replay", ctx, status=0, code="N/A", note="arm not applicable")
    base = harness.base_url
    signer = ctx.signer
    proof = signer.proof(
        htm="GET", htu=_htu(base, "/api/profile"), access_token=ctx.session.access_token, nonce=None
    )
    token = ctx.session.access_token
    # 1차 사용(정상 클라이언트가 쓴 것처럼) — jti 를 소비시킨다.
    ctx.client.raw().get("/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof})
    # 공격자가 동일 proof 를 재전송.
    with harness.client(signer=None) as attacker:
        response = attacker.raw().get(
            "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )
    return _outcome("proof-replay", ctx, response, note="identical proof resent")


def attack_uri_substitution(harness, ctx: LegitContext) -> AttackOutcome:
    """D — GET /api/profile 용 proof 를 다른 URI 요청에 사용 → htu mismatch 기대."""
    if EXPECTATION["uri-substitution"][ctx.arm] is None:
        return _blocked_outcome("uri-substitution", ctx, status=0, code="N/A", note="arm not applicable")
    base = harness.base_url
    token = ctx.session.access_token
    proof = ctx.signer.proof(
        htm="GET", htu=_htu(base, "/api/profile"), access_token=token, nonce=None
    )
    # proof 는 /api/profile 용인데 /api/history 로 보낸다.
    with harness.client(signer=None) as attacker:
        response = attacker.raw().get(
            "/api/history", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )
    return _outcome("uri-substitution", ctx, response, note="profile proof on history")


def attack_method_substitution(harness, ctx: LegitContext) -> AttackOutcome:
    """E — GET proof 를 POST 요청에 사용 → htm mismatch 기대."""
    if EXPECTATION["method-substitution"][ctx.arm] is None:
        return _blocked_outcome("method-substitution", ctx, status=0, code="N/A", note="arm not applicable")
    base = harness.base_url
    token = ctx.session.access_token
    proof = ctx.signer.proof(
        htm="GET", htu=_htu(base, "/api/settings"), access_token=token, nonce=None
    )
    with harness.client(signer=None) as attacker:
        response = attacker.raw().post(
            "/api/settings",
            headers={"Authorization": f"DPoP {token}", "DPoP": proof},
            json={},
        )
    return _outcome("method-substitution", ctx, response, note="GET proof on POST")


def attack_token_substitution(harness, ctx: LegitContext) -> AttackOutcome:
    """F — token A 용 ath proof 를 token B 와 결합 → ath mismatch 기대.

    공격자는 자기 계정으로 두 번째 유효 세션(token B)을 갖고 있고, 피해자 token A 의
    proof(ath=hash(A))를 token B 요청에 붙인다.
    """
    if EXPECTATION["token-substitution"][ctx.arm] is None:
        return _blocked_outcome("token-substitution", ctx, status=0, code="N/A", note="arm not applicable")
    base = harness.base_url
    token_a = ctx.session.access_token
    if ctx.arm == "S3":
        # S3 에서는 BoundKey 가 ath 를 클라이언트가 준 token_hash 로 설정하되,
        # 서버는 실제 요청 토큰의 해시와 대조한다. 공격자가 임의 ath 를 강제하려면
        # BoundKey 에게 거짓 token_hash 를 주어야 하는데, 그러면 요청에 실제 쓰는
        # 토큰과 어긋나 서버가 ath mismatch 로 막는다. 아래에서 그 경로를 직접 만든다.
        forged = ctx.signer.proof(
            htm="GET",
            htu=_htu(base, "/api/profile"),
            access_token=token_a + "-different",  # 잘못된 토큰의 해시가 ath 로 들어감
            nonce=None,
        )
        with harness.client(signer=None) as attacker:
            response = attacker.raw().get(
                "/api/profile", headers={"Authorization": f"DPoP {token_a}", "DPoP": forged}
            )
        return _outcome("token-substitution", ctx, response, note="ath for other token (S3)")

    # S1/S2: 침해된 클라이언트가 키를 갖고 임의 ath 를 넣은 proof 를 만든다.
    other_hash = ath(token_a + "-different")
    proof = build_dpop_proof(
        _signer_key(ctx),
        htm="GET",
        htu=_htu(base, "/api/profile"),
        access_token=None,
        include_ath=False,
        override_claims={"ath": other_hash},
    )
    with harness.client(signer=None) as attacker:
        response = attacker.raw().get(
            "/api/profile", headers={"Authorization": f"DPoP {token_a}", "DPoP": proof}
        )
    return _outcome("token-substitution", ctx, response, note="mismatched ath")


def attack_stale_proof(harness, ctx: LegitContext) -> AttackOutcome:
    """G — iat 허용범위를 초과한 오래된 proof 사용 → expired 기대."""
    if EXPECTATION["stale-proof"][ctx.arm] is None:
        return _blocked_outcome("stale-proof", ctx, status=0, code="N/A", note="arm not applicable")
    base = harness.base_url
    token = ctx.session.access_token
    stale_iat = int(time.time()) - 3600  # 1시간 전
    if ctx.arm == "S3":
        # BoundKey 가 iat 를 스스로(현재시각) 설정하므로, 공격자는 stale iat 를
        # 강제할 수 없다. 유일한 stale-proof 경로는 예전에 캡처해 둔 proof 의 재사용인데
        # 그것은 proof-replay(jti)로 이미 막힌다. 즉 S3 에서 이 공격은 구성 불가.
        return _blocked_outcome(
            "stale-proof",
            ctx,
            status=0,
            code="BOUNDKEY_CONTROLS_IAT",
            note="BoundKey sets iat itself; attacker cannot forge a stale proof",
        )
    proof = build_dpop_proof(
        _signer_key(ctx),
        htm="GET",
        htu=_htu(base, "/api/profile"),
        access_token=token,
        iat=stale_iat,
    )
    with harness.client(signer=None) as attacker:
        response = attacker.raw().get(
            "/api/profile", headers={"Authorization": f"DPoP {token}", "DPoP": proof}
        )
    return _outcome("stale-proof", ctx, response, note="iat 1h in the past")


def attack_high_risk_abuse(harness, ctx: LegitContext) -> AttackOutcome:
    """H — 침해된 클라이언트가 물리 승인 없이 고위험 API 실행 시도 (지시서 §6 H).

    이 연구의 핵심. S3 에서는 BoundKey 가 승인 없이 서명하지 않으므로 실패해야 한다.
    S0~S2 는 물리 방어가 없어 성공 예상.
    """
    base = harness.base_url
    token = ctx.session.access_token
    transfer_body = {"to_account": "ATTACKER-1", "amount": 999999}

    if ctx.arm == "S0":
        with harness.client(signer=None) as attacker:
            response = attacker.raw().post(
                "/api/transfer",
                headers={"Authorization": f"Bearer {token}"},
                json=transfer_body,
            )
        return _outcome("high-risk-abuse", ctx, response, note="bearer transfer")

    if ctx.arm in ("S1", "S2"):
        # 침해된 앱은 서명 키/키스토어에 자유 접근할 수 있다. 유효 proof 를 만든다.
        proof = ctx.signer.proof(
            htm="POST", htu=_htu(base, "/api/transfer"), access_token=token, nonce=None
        )
        with harness.client(signer=None) as attacker:
            response = attacker.raw().post(
                "/api/transfer",
                headers={"Authorization": f"DPoP {token}", "DPoP": proof},
                json=transfer_body,
            )
        return _outcome("high-risk-abuse", ctx, response, note="app-signed transfer, no user consent")

    if ctx.arm == "S3":
        # 침해된 앱은 BoundKey 에 SIGN_REQUEST 를 보낼 수 있으나 버튼을 누를 수 없다.
        from .boundkey_sim import SignError

        try:
            proof = ctx.signer.proof(
                htm="POST", htu=_htu(base, "/api/transfer"), access_token=token, nonce=None
            )
        except SignError as exc:
            # BoundKey 가 서명을 거부 = 서버에 요청조차 못 간다. 공격 실패.
            return _blocked_outcome(
                "high-risk-abuse",
                ctx,
                status=0,
                code=f"BOUNDKEY_{exc.reason}",
                note="BoundKey refused to sign without physical approval",
            )
        # 만약 서명이 나왔다면(=방어 실패) 실제로 서버에 실행되는지까지 확인한다.
        with harness.client(signer=None) as attacker:
            response = attacker.raw().post(
                "/api/transfer",
                headers={"Authorization": f"DPoP {token}", "DPoP": proof},
                json=transfer_body,
            )
        return _outcome("high-risk-abuse", ctx, response, note="UNEXPECTED: BoundKey signed high-risk")

    raise ValueError(ctx.arm)


# --- helpers --------------------------------------------------------------


def _signer_key(ctx: LegitContext) -> ClientKey:
    """정상 signer 의 내부 키를 얻는다 (S1/S2 만; 공격이 유효 jkt proof 를 만들 때).

    S3 는 키를 노출하지 않으므로 이 경로를 쓰지 않는다 (해당 공격은 S3 에서 signer 를
    통해 proof 를 만든다).
    """
    signer = ctx.signer
    if isinstance(signer, SoftwareSigner):
        return signer.key
    # S3: 시뮬레이터는 키를 안 준다. build_dpop_proof 가 필요하면 signer.proof 를 써야 한다.
    raise RuntimeError("signer key not exportable for this arm")




ATTACK_FUNCS: dict[str, Callable] = {
    "token-replay": attack_token_replay,
    "cross-key": attack_cross_key,
    "proof-replay": attack_proof_replay,
    "uri-substitution": attack_uri_substitution,
    "method-substitution": attack_method_substitution,
    "token-substitution": attack_token_substitution,
    "stale-proof": attack_stale_proof,
    "high-risk-abuse": attack_high_risk_abuse,
}
