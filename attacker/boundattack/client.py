"""BoundAuth client — 정상 사용자 흐름의 참조 구현.

이 클라이언트는 4개 arm 을 모두 다룬다. S3(BOUNDKEY)에서는 proof 를 직접 만들지
않고 `BoundKeySimulator`(또는 실제 하드웨어)에 위임한다.

httpx 를 쓰며 서버 URL 은 주입받는다. 실험 하네스는 in-process ASGI transport 로,
실제 배포에서는 네트워크 URL 로 붙는다.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from .crypto import ClientKey, build_dpop_proof

ARM_TO_SERVER_MODE = {"S0": "S0", "S1": "S1", "S2": "S2", "S3": "S3"}


@dataclass
class Session:
    access_token: str
    refresh_token: str
    token_type: str
    jkt: str | None
    device_id: str | None
    session_id: str
    scope: str
    mode: str


class Signer:
    """arm 별 proof 생성 전략의 공통 인터페이스."""

    @property
    def public_jwk(self) -> dict[str, str]:
        raise NotImplementedError

    @property
    def thumbprint(self) -> str:
        raise NotImplementedError

    def proof(self, *, htm: str, htu: str, access_token: str, nonce: str | None) -> str:
        raise NotImplementedError


class SoftwareSigner(Signer):
    """S1/S2 참조 구현.

    S1(소프트웨어)과 S2(하드웨어 백드)는 **클라이언트 관점의 proof 구성이 동일**하다.
    차이는 키가 어디 저장되는가일 뿐이며, 서버가 보는 proof 는 같은 형식이다.
    S2 의 하드웨어 격리/latency 는 Android(Phase 4)에서만 실측 가능하므로 여기서는
    프로토콜 동등성만 재현한다.
    """

    def __init__(self, key: ClientKey | None = None) -> None:
        self.key = key or ClientKey.generate()

    @property
    def public_jwk(self) -> dict[str, str]:
        return self.key.public_jwk

    @property
    def thumbprint(self) -> str:
        return self.key.thumbprint

    def proof(self, *, htm: str, htu: str, access_token: str, nonce: str | None) -> str:
        return build_dpop_proof(
            self.key, htm=htm, htu=htu, access_token=access_token, nonce=nonce
        )


@dataclass
class BoundAuthClient:
    base_url: str
    transport: httpx.BaseTransport | None = None
    signer: Signer | None = None
    _http: httpx.Client = field(init=False)

    def __post_init__(self) -> None:
        self._http = httpx.Client(
            base_url=self.base_url, transport=self.transport, timeout=30.0
        )
        self._nonce: str | None = None

    def close(self) -> None:
        self._http.close()

    def __enter__(self) -> "BoundAuthClient":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # -- registration / login ----------------------------------------
    def register_device(
        self, username: str, password: str, *, kind: str, firmware_version: str | None = None
    ) -> dict[str, Any]:
        assert self.signer is not None, "device registration requires a signer"
        response = self._http.post(
            "/devices/register",
            json={
                "username": username,
                "password": password,
                "public_key_jwk": self.signer.public_jwk,
                "kind": kind,
                "firmware_version": firmware_version,
            },
        )
        response.raise_for_status()
        return response.json()

    def login(self, username: str, password: str, *, arm: str, device_id: str | None = None) -> Session:
        payload: dict[str, Any] = {
            "username": username,
            "password": password,
            "mode": ARM_TO_SERVER_MODE[arm],
        }
        if device_id:
            payload["device_id"] = device_id
        response = self._http.post("/auth/login", json=payload)
        response.raise_for_status()
        body = response.json()
        return Session(
            access_token=body["access_token"],
            refresh_token=body["refresh_token"],
            token_type=body["token_type"],
            jkt=body.get("jkt"),
            device_id=body.get("device_id"),
            session_id=body["session_id"],
            scope=body["scope"],
            mode=body["mode"],
        )

    # -- authenticated requests --------------------------------------
    def request(
        self, method: str, path: str, session: Session, *, json_body: Any = None
    ) -> httpx.Response:
        """정상 요청. arm 에 맞는 인증 헤더를 자동으로 붙인다.

        nonce 챌린지(첫 401 + DPoP-Nonce)를 한 번 처리한다.
        """
        if session.jkt is None:
            headers = {"Authorization": f"Bearer {session.access_token}"}
            return self._http.request(method, path, headers=headers, json=json_body)

        assert self.signer is not None
        htu = self._htu(path)
        response = self._signed_request(method, path, session, htu, json_body)
        if response.status_code == 401 and "dpop-nonce" in {
            k.lower() for k in response.headers
        }:
            self._nonce = response.headers.get("DPoP-Nonce")
            response = self._signed_request(method, path, session, htu, json_body)
        return response

    def _signed_request(
        self, method: str, path: str, session: Session, htu: str, json_body: Any
    ) -> httpx.Response:
        assert self.signer is not None
        proof = self.signer.proof(
            htm=method.upper(),
            htu=htu,
            access_token=session.access_token,
            nonce=self._nonce,
        )
        headers = {
            "Authorization": f"DPoP {session.access_token}",
            "DPoP": proof,
        }
        return self._http.request(method, path, headers=headers, json=json_body)

    def _htu(self, path: str) -> str:
        base = str(self._http.base_url).rstrip("/")
        return f"{base}{path}"

    # -- raw escape hatch for attacks --------------------------------
    def raw(self) -> httpx.Client:
        return self._http
