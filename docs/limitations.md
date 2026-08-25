# Limitations — 정직한 한계 명시

지시서 §3, §24, §30, §34. 본 프로젝트가 **해결하지 않는** 문제를 명시한다.

---

## 1. 위협 모델상 가정 (깨지면 주장 무효)

- Secure Element 내부 개인키 추출 불가 (N1)
- 서버 signing key 안전 (N2)
- TLS 안전 (N3)
- MCU invasive physical attack 없음 (N4)
- 사용자 물리 버튼 원격 조작 불가 (N5)

---

## 2. 명시적 비목표 (지시서 §3)

BoundAuth 는 다음을 완전히 해결한다고 **주장하지 않는다**:

- Secure Element 물리 침해
- 서버 전체 장악
- 사용자가 직접 공격자 요청을 승인하는 사회공학
- 모든 malware / 모든 OAuth 공격 / 모든 session hijacking

특히 앱 계층이 침해되면 LOW/MEDIUM API 는 여전히 호출될 수 있다. BoundAuth 의 추가
방어는 **HIGH(고위험) API 의 물리 승인**에 집중된다.

---

## 3. 구현 범위 밖 (지시서 §30)

자체 암호 알고리즘, 자체 OAuth 대체 표준, blockchain, AI anomaly detection,
face recognition, iOS, 실제 금융 API, 복잡한 클라우드 마이크로서비스, Kubernetes,
과도한 관리자 대시보드, BLE 독자 암호 프로토콜, SE 물리공격 대응, 범용 password
manager — 모두 제외한다.

---

## 4. 이 개발 환경의 검증 한계 (실측 2026-08-21)

| 구성요소 | 상태 |
|----------|------|
| Server (S0~S3 검증 로직) | 이 환경에서 실행·테스트 검증됨 |
| BoundAttack 8종 공격 | 이 환경에서 실행 검증됨 |
| BoundKey **시뮬레이터** | 이 환경에서 실행·테스트 검증됨 |
| Android SDK / Demo App | **빌드 미검증** — JDK17+/Android SDK 부재 |
| ESP32-S3 펌웨어 | **빌드 미검증** — ESP-IDF/컴파일러 부재 |
| 실제 BoundKey 하드웨어 (HIL) | **미검증** — 하드웨어 부재 |

따라서 다음 수치는 **아직 실제 하드웨어에서 측정되지 않았다** (`NOT VERIFIED ON HARDWARE`):

- Secure Element ECDSA signing latency
- BLE round-trip latency
- BoundKey firmware RAM / Flash usage
- 전력 소비

현재 `experiments/results/` 의 S3 latency 는 **시뮬레이터 기반**이며 위 항목을
포함하지 않는다. 이를 하드웨어 성능으로 보고하는 것은 지시서 §34 위반이다.

---

## 5. 목표치(TARGET)와 결과의 구분 (지시서 §10, §11)

README/문서의 `TARGET` 표기는 engineering target 이며 **결과가 아니다.**
실제 결과는 오직 `experiments/results/` CSV 와 `experiments/plots/` 에서 나온다.

---

## 6. 알려진 단순화

- S1 과 S2 는 클라이언트 관점 proof 형식이 동일하다. S2 의 하드웨어 키 격리/latency
  차이는 실제 Android 단말(Phase 4)에서만 드러나며, 현재 실험 하네스에서는
  프로토콜 동등성만 재현한다.
- replay cache 는 단일 서버 SQLite 기반이다. 다중 인스턴스 배포에서는 공유 저장소
  (Redis 등)가 필요하다 (지시서 §6).
- nonce 는 stateless HMAC 방식이다. 강한 one-time nonce 가 필요하면 저장소 기반으로
  교체해야 한다.
