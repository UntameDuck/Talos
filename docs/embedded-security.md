# Embedded Security — BoundKey

지시서 §24, §4.2, §4.3, §5.7, §5.8, §19.

> 상태: 설계 문서 + 시뮬레이터 참조 구현. **실제 ESP32-S3 + ATECC608B 펌웨어는
> 이 저장소의 `embedded/firmware/` 에 스켈레톤으로 존재하며, 이 개발 환경에는
> ESP-IDF 툴체인이 없어 빌드/플래시가 검증되지 않았다 (`NOT VERIFIED ON HARDWARE`).**

---

## 1. Key Lifecycle

```
provisioning: ATECC608B slot 에 P-256 키쌍 생성
              → 개인키는 slot 내부에만 존재
read:         공개키만 읽어 export
sign:         signing digest 입력 → slot 내부 ECDSA → signature 출력
```

**금지 (지시서 §4.2):** 개인키 raw bytes 를 반환하는 함수는 코드베이스에 존재하지
않는다. `crypto/` 래퍼는 다음만 노출한다:

```
atecc_read_public_key()
atecc_sign_digest(slot, digest, out_sig)   // 개인키는 인자/반환에 없음
```

시뮬레이터(`attacker/boundattack/boundkey_sim.py`)도 동일 제약을 지킨다:
`export_private_key` 류 메서드가 없음 (테스트 `test_public_key_exported_but_not_private`).

---

## 2. Blind-Signing 방지 (지시서 §4.3)

BoundKey 는 Android 가 준 임의 바이트/해시를 그대로 서명하지 않는다.
구조화된 `SIGN_REQUEST`(method/uri/token_hash/nonce/timestamp)를 받아:

1. `request_id` 유일성 검사
2. `policy.classify(method, uri)` — UNKNOWN 은 DEFAULT DENY
3. HIGH 는 물리 승인 필수
4. **jti/htm/htu/iat/ath/nonce/header/jwk 를 BoundKey 가 직접 구성**
5. signing input 을 만들고 SHA-256 → ECDSA

이로써 Android 는 `htm`/`htu`/`iat`/`jti` 를 조작할 수 없다. 이것이 stale-proof/
uri-substitution/method-substitution 이 S3 에서 **생성 단계에서** 막히는 이유다.

---

## 3. Physical User Presence (지시서 §5.6)

```
HIGH SIGN_REQUEST
  → LED BLINKING
  → 승인 창(approval_timeout) 시작
  → 버튼 이벤트(디바운스) 는 해당 request_id 에만 바인딩
  → 승인: ECDSA sign, LED GREEN
  → 타임아웃/거부: signature 없음, LED RED
```

규칙:
- 승인은 **1회용**으로 소비된다.
- 이전 request_id 의 승인을 다른 request_id 에 재사용할 수 없다.
- 연결이 끊긴 클라이언트의 이전 승인은 무효화한다 (지시서 §20, §21).

시뮬레이터 대응 테스트: `test_approval_is_bound_to_request_id`,
`test_approval_is_single_use`, `test_high_endpoint_requires_approval`.

---

## 4. 프로토콜 보안 (지시서 §21)

BLE 링크 자체를 신뢰하지 않는다. BoundKey 가 고려하는 것:

- `request_id` uniqueness / duplicate 거부
- stale request 거부
- approval ↔ request_id 바인딩
- 프레임 size limit / malformed frame 거부
- connection reset 처리
- timeout
- monotonic/session counter (검토 대상)

C/C++ 파싱에서 길이 검증, buffer overflow 방지, BLE fragmentation 경계 검증,
malformed packet fuzz 테스트를 둔다 (host test).

---

## 5. Fail-Closed (지시서 §19, §34)

Secure Element 서명 실패 시 **소프트웨어 키로 fallback 하지 않는다.**
S3 모드에서 하드웨어가 실패하면 요청을 거부한다. 명시적 mode 전환만 허용한다.

---

## 6. 시뮬레이터와 하드웨어의 경계 (지시서 §23, §34)

| 검증 항목 | 시뮬레이터로 검증 | 하드웨어 필요 |
|-----------|-------------------|---------------|
| 정책 분류 / 승인 상태머신 | O | (재확인) |
| DPoP proof 구성 정합성 | O | (재확인) |
| blind-signing 방지 | O | (재확인) |
| Secure Element signing latency | X | **필수** |
| BLE round-trip latency | X | **필수** |
| firmware RAM/Flash footprint | X | **필수** |
| 전력 소비 | X | 장비 있을 때만 (§9.3) |

**성능 수치(§28의 7·8·9·10)는 반드시 실제 하드웨어에서 재측정한다.**
