"""DPoP proof verification (RFC 9449 §4.3, 지시서 §2, §4.4).

`docs/dpop-mapping.md` 가 각 검사 ↔ 코드 위치를 매핑한다.

검사 순서 (실패 시 첫 위반에서 구체적 error code 로 거부):

  1. proof 크기 제한, strict JWS 파싱
  2. header: typ=dpop+jwt, alg=ES256, jwk(공개 P-256, 개인성분 없음)
  3. jwk 로 서명 검증
  4. jkt(=thumbprint(jwk)) == access token 의 cnf.jkt   → DPOP_JKT_MISMATCH
  5. payload 필수 클레임 존재
  6. htm == 요청 method                                  → DPOP_HTM_MISMATCH
  7. normalize(htu) == 요청 htu                           → DPOP_HTU_MISMATCH
  8. iat 가 skew 창 안                                    → DPOP_EXPIRED
  9. ath == base64url(sha256(access_token))              → DPOP_ATH_MISMATCH
 10. nonce (요구되거나 존재하면) 유효                      → DPOP_NONCE_*
 11. jti 미사용(원자적 소비)                               → DPOP_REPLAY

**Fail closed.** 알 수 없는 상황은 거부한다. software fallback 없음 (지시서 §19).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from sqlalchemy.orm import Session

from ..core import jose
from ..core.config import get_settings
from ..core.errors import ApiError, ErrorCode
from ..core.http import normalize_htu
from ..replay import cache
from ..tokens.service import access_token_hash
from .nonce import verify_nonce


@dataclass(frozen=True)
class DpopVerification:
    jti: str
    jkt: str


def _require(condition: bool, status: int, code: str, detail: str) -> None:
    if not condition:
        raise ApiError(status, code, detail)


def verify_dpop_proof(
    db: Session,
    *,
    proof: str,
    expected_htm: str,
    expected_htu: str,
    access_token: str,
    bound_jkt: str,
) -> DpopVerification:
    settings = get_settings()

    # 1. 크기 제한 (지시서 §20 strict parser).
    if not isinstance(proof, str) or len(proof.encode("utf-8")) > settings.dpop_max_proof_bytes:
        raise ApiError(400, ErrorCode.DPOP_MALFORMED, "proof missing or too large")

    # 2. header 검사. (검증 전에 header 를 읽어 jwk 를 꺼낸다.)
    try:
        header = jose.decode_unverified_header(proof)
    except jose.JoseError as exc:
        raise ApiError(400, ErrorCode.DPOP_MALFORMED, f"malformed proof: {exc}") from exc

    _require(header.get("typ") == "dpop+jwt", 400, ErrorCode.DPOP_TYP_INVALID, "typ must be dpop+jwt")
    _require(header.get("alg") == "ES256", 400, ErrorCode.DPOP_ALG_INVALID, "alg must be ES256")

    jwk = header.get("jwk")
    if not isinstance(jwk, dict):
        raise ApiError(400, ErrorCode.DPOP_JWK_INVALID, "header jwk missing")
    try:
        public_key = jose.public_key_from_jwk(jwk)
        canonical_jwk = {k: jwk[k] for k in ("crv", "kty", "x", "y")}
        jkt = jose.jwk_thumbprint(canonical_jwk)
    except jose.JoseError as exc:
        raise ApiError(400, ErrorCode.DPOP_JWK_INVALID, f"invalid jwk: {exc}") from exc

    # 3. 서명 검증 (반드시 proof 안의 jwk 로).
    try:
        _, payload = jose.verify_es256(proof, public_key)
    except jose.JoseError as exc:
        raise ApiError(401, ErrorCode.DPOP_SIGNATURE_INVALID, f"bad signature: {exc}") from exc

    # 4. 토큰 바인딩. proof 키가 access token 이 묶인 키와 같은가.
    if not _consteq(jkt, bound_jkt):
        raise ApiError(401, ErrorCode.DPOP_JKT_MISMATCH, "proof key does not match cnf.jkt")

    # 5. 필수 클레임.
    jti = payload.get("jti")
    if not isinstance(jti, str) or not (1 <= len(jti) <= 128):
        raise ApiError(400, ErrorCode.DPOP_JTI_INVALID, "jti missing or invalid")
    for field in ("htm", "htu", "iat"):
        if field not in payload:
            raise ApiError(400, ErrorCode.DPOP_MALFORMED, f"missing claim {field}")

    # 6. htm.
    htm = payload.get("htm")
    if not isinstance(htm, str) or htm.upper() != expected_htm.upper():
        raise ApiError(401, ErrorCode.DPOP_HTM_MISMATCH, "htm mismatch")

    # 7. htu (정규화 후 비교).
    htu = payload.get("htu")
    if not isinstance(htu, str):
        raise ApiError(400, ErrorCode.DPOP_MALFORMED, "htu must be a string")
    try:
        if normalize_htu(htu) != normalize_htu(expected_htu):
            raise ApiError(401, ErrorCode.DPOP_HTU_MISMATCH, "htu mismatch")
    except ValueError as exc:
        raise ApiError(400, ErrorCode.DPOP_MALFORMED, f"htu not absolute: {exc}") from exc

    # 8. iat freshness.
    iat = payload.get("iat")
    if not isinstance(iat, int):
        raise ApiError(400, ErrorCode.DPOP_MALFORMED, "iat must be an integer")
    now = int(time.time())
    skew = settings.dpop_iat_skew_seconds
    if iat > now + skew:
        raise ApiError(401, ErrorCode.DPOP_EXPIRED, "iat in the future")
    if iat < now - skew:
        raise ApiError(401, ErrorCode.DPOP_EXPIRED, "proof too old")

    # 9. ath.
    ath = payload.get("ath")
    expected_ath = access_token_hash(access_token)
    if not isinstance(ath, str) or not _consteq(ath, expected_ath):
        raise ApiError(401, ErrorCode.DPOP_ATH_MISMATCH, "ath mismatch")

    # 10. nonce.
    nonce = payload.get("nonce")
    if settings.dpop_require_nonce:
        if not isinstance(nonce, str) or not nonce:
            raise ApiError(
                401,
                ErrorCode.DPOP_NONCE_REQUIRED,
                "nonce required",
                headers={"DPoP-Nonce": _fresh_nonce()},
            )
    if nonce is not None:
        if not isinstance(nonce, str) or not verify_nonce(nonce):
            raise ApiError(
                401,
                ErrorCode.DPOP_NONCE_INVALID,
                "nonce invalid or expired",
                headers={"DPoP-Nonce": _fresh_nonce()},
            )

    # 11. jti replay (마지막에, 원자적으로 소비). 앞 검사를 다 통과한 proof 만 캐시를
    #     오염시키도록 순서를 맨 뒤에 둔다.
    if not cache.check_and_store(db, jti=jti, jkt=jkt, ttl_seconds=settings.dpop_replay_ttl_seconds):
        raise ApiError(401, ErrorCode.DPOP_REPLAY, "jti already used")

    return DpopVerification(jti=jti, jkt=jkt)


def _fresh_nonce() -> str:
    from .nonce import issue_nonce

    return issue_nonce()


def _consteq(a: str, b: str) -> bool:
    import hmac

    return hmac.compare_digest(a, b)
