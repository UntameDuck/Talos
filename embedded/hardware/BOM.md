# BoundKey — Bill of Materials

지시서 §5.1. 최소 구성. 실제 부품 확정 시 정확한 MPN/수량으로 갱신한다.

| # | 부품 | 예시 사양 | 수량 | 비고 |
|---|------|-----------|------|------|
| 1 | MCU 보드 | ESP32-S3 (DevKitC-1 등) | 1 | BLE, USB, 충분한 GPIO |
| 2 | Secure Element | ATECC608B (MOD/SOIC 또는 브레이크아웃) | 1 | I2C, ECDSA P-256 |
| 3 | Push Button | 택트 스위치 | 1 | 물리 승인 |
| 4 | Status LED | RGB 또는 단색 x3 | 1 | 상태 표시(§16) |
| 5 | 저항 | 10kΩ(버튼 풀업), LED 직렬 220–330Ω | 수개 | |
| 6 | 배선/브레드보드 | 점퍼선 | - | 프로토타입 |
| 7 | 전원 | USB 5V | 1 | 개발용 |

> 단색 LED 만 있으면 색 대신 blink pattern 으로 상태를 구분한다 (§16).
