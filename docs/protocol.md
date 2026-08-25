# BoundAuth Protocol — Android ↔ BoundKey ↔ Server

지시서 §5.3, §24. 전체 메시지 흐름을 정의한다.

---

## 1. Server HTTP API

| Method | Path | 설명 | Risk |
|--------|------|------|------|
| POST | `/auth/login` | 로그인, 토큰 발급 | - |
| POST | `/auth/refresh` | 토큰 회전 | - |
| POST | `/devices/register` | 공개키 등록 | - |
| GET | `/devices` | 내 디바이스 목록 | - |
| POST | `/devices/{id}/revoke` | 디바이스 폐기 | - |
| GET | `/api/profile` | 프로필 조회 | LOW |
| GET | `/api/history` | 이력 조회 | LOW |
| POST | `/api/settings` | 설정 변경 | MEDIUM |
| POST | `/api/transfer` | (모의) 이체 | HIGH |
| GET | `/api/security-events` | 보안 이벤트(데모용) | LOW |
| GET | `/.well-known/boundauth-config` | 서버 공개키/파라미터 | - |

### 인증 헤더

- S0: `Authorization: Bearer <access_token>`
- S1/S2/S3: `Authorization: DPoP <access_token>` + `DPoP: <proof_jwt>`

nonce 챌린지: 서버가 `401` + `DPoP-Nonce: <n>` 를 주면, 클라이언트는 proof 에
`nonce` 를 넣어 재시도한다.

---

## 2. BLE Protocol (Android ↔ BoundKey)

MVP 인코딩은 JSON. `protocol/` 에 인코딩 추상화를 두어 CBOR/deterministic binary 로
교체 가능하게 한다 (지시서 §5.3). BLE-level 독자 암호는 설계하지 않는다 (§21, §30).

### 메시지 타입

```
HELLO
DEVICE_INFO_REQUEST
DEVICE_INFO_RESPONSE
SIGN_REQUEST
SIGN_RESPONSE
APPROVAL_REQUIRED
APPROVAL_RESULT
ERROR
```

모든 메시지는 `request_id`(correlation id)를 갖는다.

### SIGN_REQUEST (Android → BoundKey)

Android 는 "서명할 bytes" 를 보내지 않는다. 구조화 데이터만 보낸다 (지시서 §4.3, §5.4).

```json
{
  "type": "SIGN_REQUEST",
  "request_id": "…",
  "method": "POST",
  "uri": "/api/transfer",
  "token_hash": "<base64url sha256(access_token)>",
  "nonce": "…",
  "timestamp": 0
}
```

### BoundKey 내부 처리

```
parse & size check
  → request_id uniqueness (중복 거부)
  → policy.classify(method, uri)
      UNKNOWN → ERROR(POLICY_DENY_UNKNOWN)
      HIGH    → APPROVAL_REQUIRED → (버튼) → APPROVAL_RESULT
  → BoundKey가 jti/htm/htu/iat/ath/nonce/header/jwk 구성
  → Secure Element ECDSA P-256 sign
  → SIGN_RESPONSE { proof: <jwt> }
```

htu 의 origin 은 provisioning 시 고정된 trusted base URL 을 쓰고, SIGN_REQUEST 의
`uri`(path)만 결합한다. 참조 구현: `attacker/boundattack/boundkey_sim.py`.

### SIGN_RESPONSE (BoundKey → Android)

```json
{ "type": "SIGN_RESPONSE", "request_id": "…", "proof": "<dpop jwt>" }
```

### ERROR

```json
{ "type": "ERROR", "request_id": "…", "reason": "APPROVAL_REQUIRED" }
```

reason 값: `POLICY_DENY_UNKNOWN`, `APPROVAL_REQUIRED`, `APPROVAL_TIMEOUT`,
`DUPLICATE_REQUEST_ID`, `SECURE_ELEMENT_ERROR`, `MALFORMED_FRAME`.

---

## 3. Enrollment 흐름

```
BoundKey: Secure Element 에서 P-256 키쌍 생성 (개인키 내부 유지)
  → 공개키 export → Android
Android → Server POST /devices/register { username, password, public_key_jwk, kind }
Server: thumbprint 계산, Device(status=TRUSTED) 저장
```

이후 로그인 시 서버는 `cnf.jkt = thumbprint` 로 토큰을 바인딩한다.

---

## 4. End-to-End (S3) 요청 시퀀스

`docs/architecture.md` §6 시퀀스 다이어그램 참조.
