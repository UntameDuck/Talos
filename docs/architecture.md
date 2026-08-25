# BoundAuth — Architecture

> 상태: 초안 (Phase 0 작성, 이후 Phase 진행에 따라 갱신)
> 이 문서에는 **측정 수치를 쓰지 않는다.** 수치는 `experiments/results/`에서만 나온다.

---

## 1. 문제 정의

기존 OAuth/OIDC Bearer Access Token은 **소지 = 인증**이다.
토큰이 앱 저장소, 로그, 프록시, 백업, 메모리 덤프 중 어디에서든 유출되면
공격자는 **다른 기기에서 그대로 재사용**할 수 있다.

RFC 9449 DPoP는 토큰을 클라이언트가 보유한 키에 결합(sender-constrained)해 이 문제를 완화한다.
그러나 DPoP proof key가 **토큰과 같은 보안 경계**(= 같은 스마트폰, 같은 앱 프로세스) 안에 있으면,
앱 계층이 침해된 순간 공격자는 토큰과 서명 능력을 **동시에** 얻는다.

BoundAuth의 제안은 두 가지다.

1. **보안 경계 분리** — Access Token은 스마트폰에, Proof Key는 물리적으로 독립된
   Embedded Secure Element에 둔다.
2. **Request-aware Authenticator** — BoundKey는 임의 바이트를 서명하는 oracle이 아니라,
   요청의 *의미*(method/URI/token binding/freshness)를 검증하고 고위험 요청에는
   **물리 버튼 승인**을 요구하는 정책 시행점(policy enforcement point)이다.

---

## 2. 비교 대상 4개 구조

| Arm | 이름 | Token 위치 | Proof Key 위치 | 요청 의미 검증 | 물리 승인 |
|-----|------|-----------|----------------|----------------|-----------|
| S0 | Bearer | Android | 없음 | 없음 | 없음 |
| S1 | Software DPoP | Android | Android 프로세스 메모리/저장소 | 없음(앱이 자유 생성) | 없음 |
| S2 | Android Hardware DPoP | Android | Android Keystore / TEE / StrongBox | 없음(앱이 자유 요청) | 없음 |
| S3 | **BoundAuth (제안)** | Android | **별도 기기의 ATECC608B** | **BoundKey 내부 정책 엔진** | **HIGH 요청 필수** |

S2와 S3의 결정적 차이:

- S2에서 키는 추출 불가능하지만 **서명 요청은 앱이 무제한 호출**할 수 있다.
  앱이 침해되면 공격자는 `POST /api/transfer` 용 proof를 원하는 만큼 만들 수 있다.
- S3에서는 키가 다른 기기에 있고, **BoundKey가 무엇에 서명하는지 스스로 안다.**
  고위험 요청은 사람이 버튼을 누르지 않으면 서명 자체가 생성되지 않는다.

이것이 RQ3 / RQ4가 겨냥하는 지점이다.

---

## 3. 시스템 구성도

```text
                    +------------------------+
                    |    BoundAuth Server    |
                    |  Token Issuer          |
                    |  DPoP Verifier         |
                    |  Replay Detector       |
                    |  Device Registry       |
                    |  Security Event Log    |
                    +-----------^------------+
                                | HTTPS
                       Authorization: DPoP <token>
                       DPoP: <proof JWT>
                                |
                    +-----------+------------+
                    |   Android Demo App     |
                    |   -- BoundAuth SDK --  |
                    |   TokenManager         |
                    |   AuthenticatorBridge  |
                    +-----------+------------+
                                | BLE GATT
                     SIGN_REQUEST (structured)
                     {method, uri, token_hash, nonce, ts}
                                |
                    +-----------v------------+
                    |       BoundKey         |
                    |  ESP32-S3              |
                    |   - Frame parser       |
                    |   - Policy engine      |
                    |   - Approval FSM       |
                    |   - DPoP builder       |
                    |  ATECC608B             |
                    |   - P-256 private key  |
                    |     (non-exportable)   |
                    +------------------------+
```

---

## 4. 신뢰 경계 (Trust Boundaries)

```text
[ TB-1 ] Android application process
   - Access Token (평문 보유)
   - Refresh Token
   - 요청 파라미터
   => 위협 모델상 "부분 침해 가능"으로 가정
        |
        |  BLE (신뢰하지 않음, TB-2)
        v
[ TB-3 ] BoundKey MCU (ESP32-S3)
   - 정책 테이블, 승인 상태머신, DPoP 조립
   => 소프트웨어적으로 격리, 물리 접근은 사용자만
     [ TB-4 ] ATECC608B Secure Element
        - P-256 private key (추출 불가)
        => 침해 불가로 가정 (docs/limitations.md)
        |
        |  TLS (TB-5)
        v
[ TB-6 ] BoundAuth Server
   - 서명키, 사용자 DB, replay cache
   => 침해되지 않는다고 가정
```

**핵심 주장:** TB-1이 침해되어도 TB-3/TB-4가 온전하면, 고위험 API는
사람의 물리 행위 없이 실행될 수 없다.

---

## 5. 컴포넌트 책임

### 5.1 BoundAuth Server (`server/`)

| 모듈 | 책임 |
|------|------|
| `app/auth/` | 로그인, 비밀번호 검증(argon2), refresh |
| `app/tokens/` | Access/Refresh JWT 발급·검증, `cnf.jkt` 바인딩 |
| `app/dpop/` | RFC 9449 proof 파싱·검증, nonce 발급 |
| `app/replay/` | `jti` replay cache (TTL) |
| `app/devices/` | 디바이스 등록/조회/폐기(revoke) |
| `app/risk/` | endpoint → risk level 분류 |
| `app/api/` | 보호 리소스 엔드포인트 |
| `app/core/` | 설정, DB, 로깅, 오류코드, 키 로딩 |

서버는 **하나의 인스턴스로 S0~S3 모두를 처리한다.**
분기 기준은 서버 설정이 아니라 **토큰 자체**다:

- 토큰에 `cnf.jkt` 가 없음 → Bearer 규칙 (S0)
- 토큰에 `cnf.jkt` 가 있음 → DPoP proof 필수 (S1/S2/S3)

이렇게 하면 동일 서버·동일 공격 도구로 4개 arm을 공정 비교할 수 있다(RQ1/RQ2).
`mode` 클레임은 **실험 라벨링 용도로만** 기록하며, 검증 강도를 낮추는 데 쓰지 않는다.

### 5.2 BoundAuth Android SDK (`android/boundauth-sdk/`)

앱 개발자가 보는 표면은 `BoundAuth.Builder()` 하나다.
SDK 내부에서 mode에 따라 서명 주체를 바꾼다:

```text
BEARER                 -> 서명 없음
SOFTWARE_DPOP          -> SoftwareKeyManager (앱 내 P-256)
ANDROID_HARDWARE_DPOP  -> KeystoreKeyManager (TEE/StrongBox)
BOUNDKEY_DPOP          -> AuthenticatorBridge -> BLE -> BoundKey
```

`BOUNDKEY_DPOP`에서 SDK는 **proof를 만들지 않는다.** 구조화된 요청 정보만 넘기고
완성된 proof JWT를 돌려받는다.

### 5.3 BoundKey Firmware (`embedded/firmware/`)

```text
communication/  BLE GATT, MTU/fragmentation
protocol/       프레임 인코딩 추상화 (JSON MVP -> CBOR 교체 가능), 메시지 타입
security/       request_id 유일성, stale 요청 거부, 크기 제한
approval/       LED, 버튼 디바운스, 타임아웃, request_id 바인딩
dpop/           protected header / payload 조립, signing input 생성
crypto/         CryptoAuthLib 래퍼 (SHA-256, ECDSA sign, public key read)
main/           상태머신
```

### 5.4 BoundKey Simulator (`attacker/boundattack/boundkey_sim.py`)

실제 하드웨어가 없는 동안 **동일한 정책·승인 로직**을 Python으로 구현한 참조 모델.
프로토콜 정합성과 S3 보안 속성 검증에 사용한다.
**성능 수치 산출에는 사용하지 않는다** (지시서 §34).

### 5.5 BoundAttack (`attacker/`)

8종 공격을 S0~S3 각 arm에 대해 반복 수행하고 raw JSONL로 기록한다.

---

## 6. 요청 흐름 (S3)

```text
App          SDK              BoundKey              Server
 |            |                  |                    |
 | get()      |                  |                    |
 |----------->|                  |                    |
 |            | (nonce 필요 시 최초 401로 획득)         |
 |            | SIGN_REQUEST     |                    |
 |            | {method,uri,     |                    |
 |            |  token_hash,     |                    |
 |            |  nonce,ts}       |                    |
 |            |----------------->|                    |
 |            |                  | policy(uri,method) |
 |            |                  |  LOW  -> 자동       |
 |            |                  |  HIGH -> LED+버튼   |
 |            |  APPROVAL_REQUIRED                    |
 |            |<-----------------|                    |
 |            |                  | [사용자 버튼]        |
 |            |                  | SE ECDSA sign      |
 |            |  SIGN_RESPONSE   |                    |
 |            |  {proof JWT}     |                    |
 |            |<-----------------|                    |
 |            | Authorization: DPoP <at>              |
 |            | DPoP: <proof>                         |
 |            |-------------------------------------->|
 |            |                       verify chain    |
 |            |<--------------------------------------|
```

서버 검증 체인은 `docs/dpop-mapping.md` 참조.

---

## 7. 데이터 모델 요약

`User` / `Device` / `SessionToken` / `ReplayEntry` / `SecurityEvent` — 지시서 §17 참조.
`SecurityEvent`에는 토큰 원문이나 개인키 재료를 저장하지 않는다.
토큰은 SHA-256 앞부분 축약(fingerprint)만 기록한다.

---

## 8. 설계 결정 기록 (ADR 요약)

| # | 결정 | 이유 |
|---|------|------|
| 1 | 서버가 토큰의 `cnf` 유무로 검증 모드를 결정 | 동일 서버로 4-arm 공정 비교, RFC 9449 정합 |
| 2 | Access Token은 ES256(P-256)으로 서버 서명 | 임베디드와 동일 곡선, 라이브러리 일관성 |
| 3 | replay cache를 DB 테이블로 (Redis 선택) | MVP 단순성, 재현 가능성. 지시서 §6 허용 |
| 4 | BLE MVP는 JSON, 인코딩 계층 추상화 | 지시서 §5.3. CBOR 전환 시 상위 로직 불변 |
| 5 | BoundKey가 `jti`/`iat`를 생성 | Android가 freshness를 조작하지 못하게 함 (§5.8) |
| 6 | trusted base URL은 provisioning 시 고정 | BoundKey가 절대 URI(`htu`)를 검증 가능해야 함 |
| 7 | 하드웨어 실패 시 소프트웨어 fallback 없음 | 지시서 §19, §34 |
