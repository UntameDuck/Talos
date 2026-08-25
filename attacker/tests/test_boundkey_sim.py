"""BoundKey simulator unit tests (지시서 §22 Firmware Unit/Host Test).

이 테스트는 **펌웨어 host test 의 golden 명세** 역할을 한다. 실제 펌웨어의
정책 엔진/승인 상태머신은 여기 기술된 것과 동일하게 동작해야 한다.
"""

from __future__ import annotations

import sys
import time
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from boundattack.boundkey_sim import BoundKeySimulator, SignError, SignRequest

BASE = "http://127.0.0.1:9"


def make_req(method="GET", uri="/api/profile", rid="r1", nonce=None):
    return SignRequest(
        request_id=rid,
        method=method,
        uri=uri,
        token_hash="dummyhash",
        nonce=nonce,
        timestamp=int(time.time()),
    )


def test_public_key_exported_but_not_private():
    sim = BoundKeySimulator(base_url=BASE)
    jwk = sim.public_jwk
    assert jwk["kty"] == "EC" and "d" not in jwk
    # 개인키 raw 를 반환하는 공개 메서드가 없어야 한다 (지시서 §5.7).
    assert not hasattr(sim, "export_private_key")
    assert not any("private" in name and "bytes" in name for name in dir(sim))


def test_policy_classification():
    sim = BoundKeySimulator(base_url=BASE)
    assert sim.classify("GET", "/api/profile") == "LOW"
    assert sim.classify("GET", "/api/history") == "LOW"
    assert sim.classify("POST", "/api/settings") == "MEDIUM"
    assert sim.classify("POST", "/api/transfer") == "HIGH"


def test_unknown_endpoint_is_default_deny():
    sim = BoundKeySimulator(base_url=BASE)
    assert sim.classify("DELETE", "/api/profile") == "UNKNOWN"
    with pytest.raises(SignError) as exc:
        sim.sign(make_req(method="DELETE", uri="/api/profile"))
    assert exc.value.reason == "POLICY_DENY_UNKNOWN"


def test_low_endpoint_signs_without_approval():
    sim = BoundKeySimulator(base_url=BASE)
    proof = sim.sign(make_req(method="GET", uri="/api/profile"))
    assert proof.count(".") == 2  # 완성된 JWS


def test_high_endpoint_requires_approval():
    sim = BoundKeySimulator(base_url=BASE, auto_approve_high=False)
    with pytest.raises(SignError) as exc:
        sim.sign(make_req(method="POST", uri="/api/transfer", rid="h1"))
    assert exc.value.reason == "APPROVAL_REQUIRED"


def test_high_endpoint_signs_after_button_press():
    sim = BoundKeySimulator(base_url=BASE, auto_approve_high=False)
    sim.press_button("h2")
    proof = sim.sign(make_req(method="POST", uri="/api/transfer", rid="h2"))
    assert proof.count(".") == 2


def test_approval_is_bound_to_request_id():
    """다른 request_id 에 대한 승인은 재사용되지 않는다 (지시서 §5.6)."""
    sim = BoundKeySimulator(base_url=BASE, auto_approve_high=False)
    sim.press_button("h3")  # h3 를 승인
    with pytest.raises(SignError) as exc:
        sim.sign(make_req(method="POST", uri="/api/transfer", rid="h4"))  # 다른 rid
    assert exc.value.reason == "APPROVAL_REQUIRED"


def test_approval_is_single_use():
    """승인은 1회용. 같은 request_id 로 두 번 서명할 수 없다."""
    sim = BoundKeySimulator(base_url=BASE, auto_approve_high=False)
    sim.press_button("h5")
    sim.sign(make_req(method="POST", uri="/api/transfer", rid="h5"))
    with pytest.raises(SignError) as exc:
        # 같은 rid 재사용: 중복 request_id 로 먼저 걸린다.
        sim.sign(make_req(method="POST", uri="/api/transfer", rid="h5"))
    assert exc.value.reason == "DUPLICATE_REQUEST_ID"


def test_duplicate_request_id_rejected():
    sim = BoundKeySimulator(base_url=BASE)
    sim.sign(make_req(uri="/api/profile", rid="dup"))
    with pytest.raises(SignError) as exc:
        sim.sign(make_req(uri="/api/profile", rid="dup"))
    assert exc.value.reason == "DUPLICATE_REQUEST_ID"


def test_boundkey_constructs_own_claims():
    """BoundKey 가 jti/htm/htu/iat 를 스스로 만든다 (Android 조작 불가, §5.8)."""
    import base64
    import json

    sim = BoundKeySimulator(base_url=BASE)
    proof = sim.sign(make_req(method="GET", uri="/api/profile", rid="c1", nonce="N"))
    payload = json.loads(base64.urlsafe_b64decode(proof.split(".")[1] + "=="))
    assert payload["htm"] == "GET"
    assert payload["htu"] == f"{BASE}/api/profile"  # origin 은 provisioning 고정값
    assert payload["ath"] == "dummyhash"
    assert payload["nonce"] == "N"
    assert isinstance(payload["jti"], str) and len(payload["jti"]) > 0
    assert isinstance(payload["iat"], int)
