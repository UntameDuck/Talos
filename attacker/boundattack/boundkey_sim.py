"""BoundKey simulator — S3 authenticator reference model (지시서 §23).

이 시뮬레이터는 **실제 펌웨어와 동일한 정책·승인·DPoP 조립 로직**을 Python 으로
구현한 것이다. 목적:

* 하드웨어가 없는 동안 S3 프로토콜/보안 속성을 end-to-end 로 검증한다.
* firmware host test 의 기대값(golden)을 제공한다.

**성능 수치 산출에는 쓰지 않는다** (지시서 §34). BLE RTT, SE signing latency 등은
반드시 실제 하드웨어에서 측정한다.

핵심 보안 속성 (지시서 §4.3, §5.4~§5.8):

1. Android(=클라이언트)는 "서명할 bytes" 를 보내지 못한다. 구조화된 SIGN_REQUEST 만
   보낸다: {method, uri, token_hash, nonce, timestamp}.
2. BoundKey 가 jti/htm/htu/iat/ath/nonce/header/JWK 를 **직접** 구성한다.
3. htu 의 origin 은 provisioning 시 고정된 trusted base URL 로 강제한다. 클라이언트가
   보낸 uri 의 path 만 사용한다.
4. HIGH 요청은 물리 승인(present_and_press) 없이는 서명하지 않는다. UNKNOWN 은 DENY.
5. private key 는 시뮬레이터 밖으로 반환하는 경로가 없다 (raw export 함수 부재).
"""

from __future__ import annotations

import hashlib
import json
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum

from .crypto import ClientKey, ath, b64u

# 서버 정책과 **동일해야 한다** (server/app/risk/policy.py, firmware policy.c).
_POLICY = {
    ("GET", "/api/profile"): "LOW",
    ("GET", "/api/history"): "LOW",
    ("POST", "/api/settings"): "MEDIUM",
    ("POST", "/api/transfer"): "HIGH",
}


class SignError(Exception):
    """서명 거부. reason 은 로그/실험 집계용."""

    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


class LedState(str, Enum):
    OFF = "OFF"
    BLUE = "BLUE"
    GREEN = "GREEN"
    RED = "RED"
    BLINKING = "BLINKING"


@dataclass
class SignRequest:
    request_id: str
    method: str
    uri: str  # path only, 예: "/api/transfer"
    token_hash: str  # base64url(sha256(access_token))
    nonce: str | None
    timestamp: int


@dataclass
class BoundKeySimulator:
    """단일 디바이스를 모사한다."""

    base_url: str
    #: 실험 편의: HIGH 요청을 자동 승인할지. 침해-클라이언트 공격 시나리오에서는 False.
    auto_approve_high: bool = False
    approval_timeout_s: float = 30.0
    firmware_version: str = "sim-0.1.0"
    #: SE 내부 개인키. 외부로 내보내는 함수는 제공하지 않는다.
    _key: ClientKey = field(default_factory=ClientKey.generate, repr=False)
    led: LedState = LedState.OFF
    #: 마지막으로 승인된 request_id. 이전 승인 재사용을 막기 위해 1회용으로 소비된다.
    _approved_request_id: str | None = field(default=None, repr=False)
    #: 처리한 request_id 집합 (중복/재사용 방지, 지시서 §21).
    _seen_request_ids: set[str] = field(default_factory=set, repr=False)

    # -- enrollment (지시서 §5.2) ------------------------------------
    @property
    def public_jwk(self) -> dict[str, str]:
        """공개키만 내보낸다."""
        return self._key.public_jwk

    @property
    def thumbprint(self) -> str:
        return self._key.thumbprint

    # -- policy engine (지시서 §5.5) ---------------------------------
    def classify(self, method: str, path: str) -> str:
        return _POLICY.get((method.upper(), path), "UNKNOWN")

    # -- physical presence (지시서 §5.6) -----------------------------
    def press_button(self, request_id: str) -> None:
        """사용자가 특정 request_id 에 대해 버튼을 눌렀다.

        승인은 해당 request_id 에만 바인딩된다. 이전 이벤트 재사용은 불가하다.
        """
        self._approved_request_id = request_id

    def _consume_approval(self, request_id: str) -> bool:
        if self._approved_request_id == request_id:
            self._approved_request_id = None  # 1회용 소비
            return True
        return False

    # -- sign (지시서 §5.4, §5.7, §5.8) ------------------------------
    def sign(self, req: SignRequest) -> str:
        """구조화된 SIGN_REQUEST 를 받아 완성된 DPoP proof JWT 를 돌려준다.

        raw bytes 를 받지 않는다. BoundKey 가 proof 를 처음부터 조립한다.
        """
        # 1. request_id 유일성 (재사용/중복 거부).
        if req.request_id in self._seen_request_ids:
            self.led = LedState.RED
            raise SignError("DUPLICATE_REQUEST_ID")
        self._seen_request_ids.add(req.request_id)

        # 2. 정책 분류. UNKNOWN 은 DEFAULT DENY.
        level = self.classify(req.method, req.uri)
        if level == "UNKNOWN":
            self.led = LedState.RED
            raise SignError("POLICY_DENY_UNKNOWN")

        # 3. 물리 승인 (HIGH 필수).
        if level == "HIGH":
            self.led = LedState.BLINKING
            approved = self._consume_approval(req.request_id)
            if not approved and self.auto_approve_high:
                # 실험 편의 경로: 데모/정상 시나리오에서 버튼 대신 자동 승인.
                approved = True
            if not approved:
                self.led = LedState.RED
                # 승인 없이는 서명하지 않는다. software fallback 없음 (지시서 §19).
                raise SignError("APPROVAL_REQUIRED")

        # 4. DPoP proof 를 **BoundKey 가** 조립한다.
        htu = f"{self.base_url.rstrip('/')}{req.uri}"
        header = {"typ": "dpop+jwt", "alg": "ES256", "jwk": self._key.public_jwk}
        payload = {
            "jti": secrets.token_urlsafe(16),  # BoundKey 가 생성 (Android 조작 불가)
            "htm": req.method.upper(),
            "htu": htu,
            "iat": int(time.time()),
            "ath": req.token_hash,  # 클라이언트가 준 token_hash 를 그대로 ath 로
        }
        if req.nonce is not None:
            payload["nonce"] = req.nonce

        signing_input = (
            b64u(json.dumps(header, separators=(",", ":")).encode())
            + "."
            + b64u(json.dumps(payload, separators=(",", ":")).encode())
        )
        signature = self._key.sign(signing_input.encode("ascii"))
        self.led = LedState.GREEN
        return signing_input + "." + b64u(signature)


class SimulatorSigner:
    """`client.Signer` 인터페이스를 BoundKeySimulator 로 구현한다.

    클라이언트(SDK 역할)는 access_token 을 SE 밖으로 보내지 않기 위해 **token_hash**
    만 전달한다 (실제로는 이미 access_token 을 갖고 있지만, 프로토콜상 hash 만 넘기는
    경계를 지킨다).
    """

    def __init__(self, sim: BoundKeySimulator) -> None:
        self.sim = sim

    @property
    def public_jwk(self) -> dict[str, str]:
        return self.sim.public_jwk

    @property
    def thumbprint(self) -> str:
        return self.sim.thumbprint

    def proof(self, *, htm: str, htu: str, access_token: str, nonce: str | None) -> str:
        from urllib.parse import urlsplit

        path = urlsplit(htu).path or "/"
        token_hash = ath(access_token)
        req = SignRequest(
            request_id=secrets.token_urlsafe(12),
            method=htm.upper(),
            uri=path,
            token_hash=token_hash,
            nonce=nonce,
            timestamp=int(time.time()),
        )
        return self.sim.sign(req)
