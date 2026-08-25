"""Legitimate-session setup per arm, shared by all attacks.

각 공격은 "정상 사용자가 arm X 로 로그인해 정상 요청을 한 번 성공시킨" 상태에서
출발한다. 그 상태를 만드는 코드를 여기 모은다.
"""

from __future__ import annotations

from dataclasses import dataclass

from .client import BoundAuthClient, Session, SoftwareSigner
from .crypto import ClientKey
from .harness import Harness

#: arm -> 서버에 등록할 디바이스 kind
_ARM_DEVICE_KIND = {"S1": "S1", "S2": "S2", "S3": "S3"}


@dataclass
class LegitContext:
    client: BoundAuthClient
    session: Session
    signer: object | None
    arm: str


def establish_legit_session(
    harness: Harness, username: str, password: str, arm: str
) -> LegitContext:
    """정상 클라이언트로 arm 에 맞게 로그인한다.

    S3 는 BoundKeySimulator 를 서명자로 쓴다. 시뮬레이터는 정상 요청(LOW)에는 자동
    승인, HIGH 에는 승인이 필요하다. 정상 세션 확립 단계에서는 등록/로그인만 한다.
    """
    if arm == "S0":
        client = harness.client(signer=None)
        session = client.login(username, password, arm="S0")
        return LegitContext(client=client, session=session, signer=None, arm=arm)

    if arm in ("S1", "S2"):
        signer = SoftwareSigner(ClientKey.generate())
        client = harness.client(signer=signer)
        device = client.register_device(
            username, password, kind=_ARM_DEVICE_KIND[arm], firmware_version=None
        )
        session = client.login(username, password, arm=arm, device_id=device["id"])
        return LegitContext(client=client, session=session, signer=signer, arm=arm)

    if arm == "S3":
        from .boundkey_sim import BoundKeySimulator, SimulatorSigner

        # 보안 기본값: HIGH 는 실제 버튼 승인 없이는 서명하지 않는다.
        # 정상 HIGH 요청(데모/legit 실험)은 명시적으로 press_button 한다.
        sim = BoundKeySimulator(base_url=harness.base_url, auto_approve_high=False)
        signer = SimulatorSigner(sim)
        client = harness.client(signer=signer)
        device = client.register_device(
            username, password, kind="S3", firmware_version=sim.firmware_version
        )
        session = client.login(username, password, arm="S3", device_id=device["id"])
        return LegitContext(client=client, session=session, signer=signer, arm=arm)

    raise ValueError(f"unknown arm {arm!r}")


