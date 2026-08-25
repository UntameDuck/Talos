# RFC 9449 (DPoP) ↔ 구현 매핑

이 문서는 RFC 9449 개념과 본 구현 코드 위치를 매핑한다 (지시서 §24).

## 1. 토큰 바인딩 (RFC 9449 §6, RFC 7800)

| 개념 | 위치 |
|------|------|
| Access token `cnf.jkt` 발급 | `server/app/tokens/service.py` `issue_access_token` |
| JWK Thumbprint (RFC 7638) | `server/app/core/jose.py` `jwk_thumbprint` / `attacker/boundattack/crypto.py` `ClientKey.thumbprint` |
| 바인딩 여부 판정 (cnf 유무) | `server/app/api/deps.py` `authenticate` (`jkt is None` 분기) |

## 2. DPoP Proof JWT (RFC 9449 §4.2)

| 필드 | 생성(client/BoundKey) | 검증(server) |
|------|----------------------|--------------|
| `typ=dpop+jwt` | crypto.build_dpop_proof / boundkey_sim.sign | verifier `DPOP_TYP_INVALID` |
| `alg=ES256` | 동일 | verifier `DPOP_ALG_INVALID`, jose 화이트리스트 |
| `jwk` (공개키) | 동일 | verifier `public_key_from_jwk` (개인성분 거부) |
| `jti` | 동일 (BoundKey가 생성) | verifier `DPOP_JTI_INVALID` + replay cache |
| `htm` | 동일 | verifier `DPOP_HTM_MISMATCH` |
| `htu` | 동일 | verifier `DPOP_HTU_MISMATCH` (normalize 비교) |
| `iat` | 동일 (BoundKey가 생성) | verifier `DPOP_EXPIRED` (skew 창) |
| `ath` | 동일 (sha256 access token) | verifier `DPOP_ATH_MISMATCH` |
| `nonce` | 서버 챌린지 시 삽입 | verifier `DPOP_NONCE_*` |

서명 검증: `server/app/core/jose.py` `verify_es256` — **반드시 proof 안의 jwk 로**
검증하고, `alg` 를 호출자가 강제한 ES256 로만 처리한다 (algorithm confusion 불가).

## 3. htu 정규화 규칙 (RFC 9449 §4.2 / RFC 3986 §6.2.2)

구현: `server/app/core/http.py` `normalize_htu`.
서버·SDK·BoundKey·공격도구가 **동일 규칙**을 써야 한다.

1. scheme, host 소문자
2. 기본 포트(80/443) 생략
3. query/fragment 제거
4. 빈 path 는 `/`

## 4. Replay 방지 (RFC 9449 §11.1, 지시서 §4.4)

| 항목 | 위치 |
|------|------|
| `jti` 원자적 소비 | `server/app/replay/cache.py` `check_and_store` |
| TTL 만료 | 동일 (iat skew 창보다 길게) |
| 응답 전 커밋 (race 방지) | `server/app/api/deps.py` `authenticate` 말미 `db.commit()` |

## 5. 서버 제공 nonce (RFC 9449 §8, §9)

구현: `server/app/dpop/nonce.py` — 서버 서명키에서 파생한 HMAC 로 상태 없이 검증.
`BOUNDAUTH_DPOP_REQUIRE_NONCE=true` 이면 nonce 없는 proof 를 401 + `DPoP-Nonce` 로 거부.

## 6. 검증 순서

`server/app/dpop/verifier.py` `verify_dpop_proof` 상단 docstring 에 11단계로 명시.
각 단계는 지시서 §2 의 error code 로 실패한다.

## 7. 본 프로젝트 확장 (표준을 넘어서는 부분)

RFC 9449 표준이 **아닌** 제안 요소 (지시서 §31-6 "표준과 제안 구분"):

- Proof key 를 **별도 하드웨어**(BoundKey/ATECC608B)에 둠 → 보안 경계 분리
- BoundKey 가 **request-aware policy enforcement** 수행 (blind signer 아님)
- 고위험 endpoint 에 **physical user presence** 요구

이 요소들은 `docs/embedded-security.md` 와 `docs/architecture.md` §2 에 기술한다.
