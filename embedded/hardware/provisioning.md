# BoundKey — Provisioning

지시서 §5.2, §5.7. Secure Element 키 프로비저닝 및 디바이스 등록.

## 1. ATECC608B 슬롯 구성

- P-256 개인키 슬롯을 **private, non-exportable** 로 설정한다.
- 슬롯 잠금(lock) 후에는 개인키 read 가 불가능해야 한다.
- CryptoAuthLib 로 `genkey` 수행 → 개인키는 슬롯 내부에만 존재.

> **개인키 raw bytes 를 읽는 명령/코드 경로를 두지 않는다** (지시서 §4.2, §5.7).

## 2. 최초 등록 흐름

```
1. BoundKey 부팅, ATECC608B 초기화
2. (미프로비저닝 시) 슬롯에 P-256 키쌍 생성
3. 공개키 read → JWK 로 변환
4. BLE 로 Android 에 공개키 전달 (DEVICE_INFO_RESPONSE)
5. Android → Server POST /devices/register { public_key_jwk, kind:"S3", firmware_version }
6. Server: thumbprint 계산, Device(status=TRUSTED) 저장
```

## 3. Trusted Base URL 고정

BoundKey 가 `htu` 의 origin 을 검증할 수 있도록, provisioning 시 서버 base URL 을
장치에 저장하거나 펌웨어 정책으로 고정한다 (지시서 §5.8).
SIGN_REQUEST 의 `uri` 는 path 만 받고 origin 은 이 고정값을 쓴다.

## 4. Device Status 전이

```
PENDING → (등록/승인) → TRUSTED → (폐기) → REVOKED
```

MVP 서버는 인증된 사용자의 등록을 즉시 TRUSTED 로 둔다. 실제 배포에서는 OOB 승인
단계를 두는 것을 권장한다 (`server/app/devices/service.py` 주석 참조).

## 5. 검증 항목 (하드웨어 확보 후)

- 슬롯 잠금 후 개인키 read 시도 실패 확인
- 재부팅 후 동일 공개키 유지 확인
- 서명 결과가 서버에서 검증됨 확인

> **NOT VERIFIED ON HARDWARE.**
