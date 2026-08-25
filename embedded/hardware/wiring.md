# BoundKey — Wiring

지시서 §5.1. I2C 연결 및 전원 조건. 실제 배선 확정 시 핀맵을 확정한다.

## I2C (ESP32-S3 ↔ ATECC608B)

| 신호 | ESP32-S3 (예시) | ATECC608B | 비고 |
|------|-----------------|-----------|------|
| SDA | GPIO8 | SDA | 4.7kΩ 풀업 to 3V3 |
| SCL | GPIO9 | SCL | 4.7kΩ 풀업 to 3V3 |
| VCC | 3V3 | VCC | 3.3V |
| GND | GND | GND | 공통 접지 |

I2C 주소는 ATECC608B 프로비저닝 설정에 따른다(기본 0x60 계열; 부품/설정 확인 필요).

## Button

| 신호 | ESP32-S3 | 비고 |
|------|----------|------|
| BTN | GPIO4 | 내부/외부 풀업, 눌림 = LOW. 디바운스 펌웨어 처리 |

## LED

| 신호 | ESP32-S3 | 비고 |
|------|----------|------|
| LED_R | GPIO5 | 직렬저항 |
| LED_G | GPIO6 | |
| LED_B | GPIO7 | 단색이면 하나만 사용, blink pattern |

## 전원

- 개발: USB 5V → 온보드 3V3 레귤레이터
- ATECC608B, 버튼 풀업, LED 모두 3V3 도메인

> 이 핀맵은 초안이다. 실제 보드 revision 에 맞춰 `main/` 의 pin 정의와 함께 확정한다.
> **NOT VERIFIED ON HARDWARE.**
