# BoundKey Firmware (ESP32-S3 + ATECC608B)

> **빌드 상태: 미검증.** 이 개발 환경에는 ESP-IDF 툴체인과 C 컴파일러가 없어
> 빌드/플래시가 검증되지 않았다. 하드웨어(ESP32-S3 + ATECC608B) 부재로 HIL 미검증.
> `NOT VERIFIED ON HARDWARE`.

## 모듈 (지시서 §7)
- `communication/` — BLE GATT, MTU/fragmentation
- `protocol/` — 프레임 인코딩 추상화(JSON MVP -> CBOR), 메시지 타입
- `security/` — policy 엔진(`policy.c`), request_id/stale/size 검사
- `approval/` — 물리 승인 상태머신(`approval.c`)
- `dpop/` — protected header/payload 조립, signing input
- `crypto/` — CryptoAuthLib 래퍼 (SHA-256, ECDSA, public key read)
- `main/` — app_main 상태머신
- `host_test/` — 순수 C 모듈 host 단위 테스트

## 검증된 로직 (host-testable, 현재 컴파일러 부재)
- `security/policy.c` — 서버/시뮬레이터와 동일한 위험도 분류표
- `approval/approval.c` — request_id 바인딩 1회용 승인 + 타임아웃

golden 동작: `attacker/tests/test_boundkey_sim.py` (Python, 이 환경에서 검증됨).

## 빌드 (툴체인 확보 후)
```bash
# ESP-IDF
idf.py set-target esp32s3 && idf.py build flash monitor
# host tests
cd host_test && cmake -S . -B build && cmake --build build && ctest --test-dir build
```
