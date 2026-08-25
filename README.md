# BoundAuth / BoundKey

**Device-Bound Session Security Framework** — 모바일 세션 토큰의 탈취·재사용
(session/token replay)을 막기 위해, Access Token 사용권한을 **독립 임베디드 장치의
하드웨어 보호 개인키**에 암호학적으로 결합하고, 고위험 요청에는 **물리적 사용자 승인**을
요구하는 연구 프로토타입.

- 프레임워크: **BoundAuth**
- 외부 임베디드 인증기: **BoundKey**
- 공격/평가 도구: **BoundAttack**

> ⚠️ 이 README 에는 성능·보안 **수치를 하드코딩하지 않는다** (지시서 §10, §34).
> 모든 결과 수치는 `experiments/results/` 의 CSV 와 `experiments/plots/` 에서 나온다.

---

## 1. 문제 정의

기존 OAuth Bearer 토큰은 "소지 = 인증"이라 유출 시 다른 기기에서 그대로 재사용된다.
RFC 9449 DPoP 는 토큰을 클라이언트 키에 결합하지만, 그 키가 토큰과 **같은 보안 경계**
(스마트폰/앱)에 있으면 앱 침해 시 토큰과 서명 능력을 동시에 잃는다.

**BoundAuth 의 제안:** ① Access Token(스마트폰)과 Proof Key(독립 Secure Element)의
보안 경계 분리, ② BoundKey 를 blind signer 가 아닌 **request-aware 정책 시행점**으로
만들어 고위험 요청에 물리 승인 강제.

---

## 2. 4개 비교 구조

| Arm | Token | Proof Key | 요청 의미 검증 | 물리 승인 |
|-----|-------|-----------|----------------|-----------|
| S0 Bearer | 폰 | 없음 | 없음 | 없음 |
| S1 Software DPoP | 폰 | 앱 내부 | 없음 | 없음 |
| S2 Android HW DPoP | 폰 | Keystore/TEE/StrongBox | 없음 | 없음 |
| **S3 BoundAuth** | 폰 | **ATECC608B (별도 기기)** | **BoundKey 정책** | **HIGH 필수** |

---

## 3. 아키텍처

```
BoundAuth Server  ── Token+DPoP ──  Android Demo App (BoundAuth SDK)
  Token Issuer                          │ BLE (structured SIGN_REQUEST)
  DPoP Verifier                         │
  Replay Detector                 BoundKey (ESP32-S3)
  Device Registry                   Policy Engine / DPoP Builder / User Presence
                                    ATECC608B (non-exportable P-256)
```

자세한 내용: [docs/architecture.md](docs/architecture.md),
[docs/threat-model.md](docs/threat-model.md), [docs/protocol.md](docs/protocol.md),
[docs/dpop-mapping.md](docs/dpop-mapping.md),
[docs/embedded-security.md](docs/embedded-security.md).

---

## 4. 빠른 실행 (server + attacker + experiments)

이 세 구성요소는 Python 만 있으면 이 환경에서 바로 동작한다.

```bash
python -m venv .venv
.venv/Scripts/pip install -r requirements.txt   # Windows
# source .venv/bin/activate && pip install -r requirements.txt  # *nix
```

### 서버 부팅

```bash
cp .env.example .env    # BOUNDAUTH_SEED_PASSWORD 등 설정
.venv/Scripts/python -m uvicorn app.main:app --app-dir server --port 8000
# GET http://127.0.0.1:8000/health  →  {"status":"ok"}
```

### 공격 재현

```bash
cd attacker
python -m boundattack list
python -m boundattack attack token-replay --arm S0     # baseline: 성공
python -m boundattack attack high-risk-abuse --arm all # S0~S2 성공, S3 차단
python -m boundattack attack all --arm all --runs 100
```

### 실험 + 그래프

```bash
python experiments/runners/run_security.py --mode all --runs 1000
python experiments/runners/run_latency.py  --mode all --runs 1000
python experiments/runners/make_plots.py
```

### 테스트

```bash
python -m pytest server/tests attacker/tests -q
```

---

## 5. Android / Embedded

- `android/` — BoundAuth SDK + Demo App (Kotlin/Compose). **이 개발 환경에는
  JDK17+/Android SDK 가 없어 빌드가 검증되지 않았다.** 스켈레톤/설계 참조.
- `embedded/` — ESP32-S3 + ATECC608B 펌웨어 (ESP-IDF). **ESP-IDF 툴체인 부재로
  빌드 미검증.** 하드웨어 부재로 HIL 미검증 (`NOT VERIFIED ON HARDWARE`).

하드웨어가 없는 동안 개발이 멈추지 않도록 **BoundKey 시뮬레이터**
(`attacker/boundattack/boundkey_sim.py`)가 펌웨어와 동일한 정책·승인·DPoP 로직을
구현한다. 단, **최종 성능 수치는 실제 하드웨어에서 재측정한다** (지시서 §23, §34).

---

## 6. 데모 시나리오 (지시서 §26)

| # | 시나리오 | 재현 |
|---|----------|------|
| 1 | Bearer 취약성 | `boundattack attack token-replay --arm S0` → 성공 |
| 2 | Device-Bound (proof 없음) | `--arm S1` token-replay → 401 |
| 3 | Attacker Key | `attack cross-key` → `DPOP_JKT_MISMATCH` |
| 4 | Proof Replay | `attack proof-replay` → `DPOP_REPLAY` |
| 5 | URI/Method 치환 | `attack uri-substitution` / `method-substitution` |
| 6 | BoundKey 물리 승인 | 시뮬레이터: HIGH 는 버튼 없이는 서명 불가 |
| 7 | 침해 클라이언트 | `attack high-risk-abuse --arm S3` → 차단 |

---

## 7. 결과

`experiments/runners/run_security.py` / `run_latency.py` 실행 후:

- `experiments/results/security_summary.csv` — 공격 성공률(arm x attack)
- `experiments/results/legit_summary.csv` — 정상 요청 성공률
- `experiments/results/latency_summary.csv` — end-to-end latency
- `experiments/plots/*.png` — 그래프 A/B/D

핵심 관찰(지시서 §29 템플릿, 값은 CSV 에서):

> N회의 token replay / cross-device replay 에서 Bearer(S0)는 성공률 **X%**,
> BoundAuth(S3)는 **Y%**. 정상 요청 성공률 **Z%**. 침해 클라이언트의 고위험 요청
> 성공률은 S0~S2 에서 **높게**, S3 에서 **낮게** 측정된다.
> (구체 수치는 실행 CSV 로만 보고한다.)

---

## 8. 목표 (TARGET, 결과 아님 — 지시서 §11)

- 정상 요청 성공률: TARGET ≥ 99%
- token/cross-key/proof replay: 설계상 차단
- 물리 승인 없는 고위험 실행: 설계상 차단 (S3)
- 추가 latency: 사용자 체감 최소화 (특정 ms 하드코딩 금지)

---

## 9. 한계

[docs/limitations.md](docs/limitations.md) 참조. 요약: Secure Element 물리 침해,
서버 장악, 사회공학, 범용 malware 는 범위 밖. S3 성능 수치는 하드웨어 재측정 필요.

---

## 10. 진행 상태

전체 체크리스트: [IMPLEMENTATION_CHECKLIST.md](IMPLEMENTATION_CHECKLIST.md).

| Phase | 상태 |
|-------|------|
| 0 초기화 | 서버/공격/실험 검증됨; Android/펌웨어 빌드는 툴체인 확보 후 |
| 1 Bearer baseline | ✅ 검증 |
| 2 Software DPoP | ✅ 검증 |
| 3 Android SDK | 스켈레톤 (빌드 미검증) |
| 4 Android HW DPoP | 스켈레톤 (하드웨어 필요) |
| 5 BoundKey | 시뮬레이터 검증; 실제 펌웨어/HIL 미검증 |
| 6 BoundAttack | ✅ 8종 검증 |
| 7 Experiments | ✅ CSV/그래프 생성 검증 |

---

## License

See [LICENSE](LICENSE).
