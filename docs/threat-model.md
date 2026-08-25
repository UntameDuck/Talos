# BoundAuth — Threat Model

> 상태: 초안 (Phase 0). Phase 진행에 따라 "검증됨/미검증" 열을 갱신한다.

---

## 1. 보호 대상 (Assets)

| ID | 자산 | 손상 시 영향 |
|----|------|-------------|
| A1 | Access Token | 세션 탈취, 사용자 사칭 |
| A2 | Refresh Token | 장기 세션 탈취 |
| A3 | DPoP Private Key | 토큰 바인딩 무력화 |
| A4 | 고위험 API 실행 권한 (`POST /api/transfer`) | 직접적 피해 |
| A5 | 서버 서명키 | 임의 토큰 위조 (범위 밖 가정) |
| A6 | 사용자 자격증명 (password) | 계정 탈취 |

---

## 2. 공격자 모델

### 2.1 A-NET — 네트워크/로그 관찰자

정상 요청의 HTTP 헤더(토큰, DPoP proof)를 획득할 수 있다.
TLS는 깨지 않지만 프록시 로그, 디버그 로그, 크래시 리포트 등에서 값을 얻는다고 가정.

### 2.2 A-EXFIL — 토큰 유출 공격자

Android 앱 저장소/메모리에서 Access Token을 꺼내 **자신의 기기**에서 사용한다.
이것이 RQ1의 주 대상이다.

### 2.3 A-APP — 부분 침해된 Android 클라이언트

앱 프로세스 내부에서 임의 코드 실행이 가능하다. 따라서:

- 토큰을 읽을 수 있다
- SDK가 서명자에게 보내는 요청을 **자유롭게 조작**할 수 있다
- S1: 소프트웨어 키를 직접 꺼내 쓸 수 있다
- S2: 키는 못 꺼내지만 **Keystore에 무제한 서명 요청**을 할 수 있다
- S3: BLE로 SIGN_REQUEST를 보낼 수 있으나, **BoundKey의 정책과 버튼을 통과해야 한다**

이것이 RQ3/RQ4의 주 대상이다.

### 2.4 공격자가 할 수 있는 것 (지시서 §3)

| ID | 능력 |
|----|------|
| C1 | Android 앱에서 Access Token 탈취 |
| C2 | Refresh Token 탈취 시도 |
| C3 | HTTP 요청/로그에서 DPoP proof 획득 |
| C4 | 정상 요청 전체 replay |
| C5 | 자신의 key pair 생성 |
| C6 | 탈취 token + 공격자 key 조합 |
| C7 | 기존 proof의 URI/method 변경 |
| C8 | token A의 proof와 token B 조합 |
| C9 | 오래된 proof 재사용 |
| C10 | (A-APP) 임의 API 호출 시도 |
| C11 | (A-APP) 사용자 의도 없이 high-risk API 호출 시도 |

### 2.5 공격자가 할 수 없다고 가정하는 것

| ID | 가정 |
|----|------|
| N1 | Secure Element 내부 Private Key 직접 추출 |
| N2 | 서버 signing key 탈취 |
| N3 | TLS 암호학적 파괴 |
| N4 | MCU에 대한 invasive physical extraction |
| N5 | 사용자의 물리 버튼을 원격으로 누름 |

N1/N4/N5가 깨지면 BoundAuth의 핵심 주장은 성립하지 않는다.
이는 `docs/limitations.md`에 명시한다.

---

## 3. 공격 → 방어 매핑

각 arm에서 **설계상 기대되는 결과**를 적는다.
`실측` 열은 실험 후 `experiments/results/security_summary.csv`가 채운다.
**여기에 예상 수치를 미리 쓰지 않는다.**

| # | 공격 | 능력 | S0 기대 | S1 기대 | S2 기대 | S3 기대 | 방어 메커니즘 |
|---|------|------|---------|---------|---------|---------|--------------|
| A | Token Replay (다른 기기) | C1 | **성공** | 차단 | 차단 | 차단 | proof 부재 → `DPOP_MISSING` |
| B | Cross-Key | C1+C5+C6 | 해당없음 | 차단 | 차단 | 차단 | `cnf.jkt` ≠ proof jkt → `DPOP_JKT_MISMATCH` |
| C | Proof Replay | C3+C4 | 해당없음 | 차단 | 차단 | 차단 | `jti` replay cache → `DPOP_REPLAY` |
| D | URI Substitution | C3+C7 | 해당없음 | 차단 | 차단 | 차단 | `htu` 검증 → `DPOP_HTU_MISMATCH` |
| E | Method Substitution | C3+C7 | 해당없음 | 차단 | 차단 | 차단 | `htm` 검증 → `DPOP_HTM_MISMATCH` |
| F | Token Substitution | C3+C8 | 해당없음 | 차단 | 차단 | 차단 | `ath` 검증 → `DPOP_ATH_MISMATCH` |
| G | Stale Proof | C3+C9 | 해당없음 | 차단 | 차단 | 차단 | `iat` skew → `DPOP_EXPIRED` |
| H | High-Risk Abuse (침해 클라이언트) | C10+C11 | **성공** | **성공** | **성공** | 차단 | BoundKey 정책 + 물리 승인 |

> 공격 H가 이 연구의 핵심이다. S1/S2에서 H가 성공한다는 것은 결함이 아니라
> **측정 대상**이다. 하드웨어 키(S2)만으로는 침해된 클라이언트의 고위험 요청을
> 막을 수 없음을 정량적으로 보이는 것이 RQ3이다.

---

## 4. 신뢰 경계별 잔여 위험

| 경계 | 잔여 위험 | 대응 |
|------|-----------|------|
| TB-1 Android | 앱 침해 시 LOW/MEDIUM API는 여전히 호출 가능 | MEDIUM 정책 상향 설정 가능. 범위 밖은 문서화 |
| TB-2 BLE | MITM/재전송 | request_id 유일성, 서버 nonce, iat freshness. BLE 자체 암호는 신뢰하지 않음 |
| TB-3 MCU | 펌웨어 취약점(파서 오버플로) | 길이 검증, 프레임 크기 제한, fuzz 테스트 |
| TB-4 SE | 물리 공격 | **범위 밖** (지시서 §30) |
| TB-6 Server | 서버 장악 | **범위 밖** |
| 사용자 | 사회공학으로 버튼 승인 | **범위 밖**. 단 LED/표시로 완화 시도 |

---

## 5. 검증 방법

| 위협 | 검증 수단 | 위치 |
|------|-----------|------|
| A~G | BoundAttack 자동 반복 실행 | `attacker/boundattack/attacks/` |
| H | 침해 클라이언트 시뮬레이터 | `attacker/boundattack/attacks/high_risk_abuse.py` |
| 서버 검증 로직 | pytest 단위 테스트 | `server/tests/` |
| 펌웨어 파서/정책 | host unit test | `embedded/firmware/host_test/` |
| 물리 승인 | HIL 수동 시나리오 | `docs/experiment-design.md` |

---

## 6. 명시적 비목표 (지시서 §3)

BoundAuth는 다음을 해결한다고 주장하지 않는다.

- Secure Element 자체의 물리적 침해
- 서버 전체 장악
- 사용자가 직접 공격자의 요청을 승인하는 사회공학
- 모든 종류의 malware
- 모든 OAuth 공격
- 모든 session hijacking 공격
