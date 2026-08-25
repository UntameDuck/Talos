# Experiment Design

지시서 §7, §9, §22, §24.

---

## 1. 대조군 (Arms)

| Arm | 설명 |
|-----|------|
| S0 | Bearer token (baseline, 의도적 취약) |
| S1 | Software DPoP |
| S2 | Android Hardware-backed DPoP (프로토콜 동등; 하드웨어 격리는 Android 단계에서 실측) |
| S3 | BoundAuth (BoundKey + Secure Element + 물리 승인) |

동일 서버·동일 공격 도구로 4개 arm 을 비교한다. 서버는 토큰의 `cnf.jkt` 유무로만
검증 모드를 결정하므로 arm 간 공정성이 보장된다 (`docs/architecture.md` ADR-1).

---

## 2. 공격 시나리오 (8종, 지시서 §6)

| 코드 | 공격 | 대상 arm |
|------|------|----------|
| A | token-replay | S0~S3 |
| B | cross-key | S1~S3 |
| C | proof-replay | S1~S3 |
| D | uri-substitution | S1~S3 |
| E | method-substitution | S1~S3 |
| F | token-substitution | S1~S3 |
| G | stale-proof | S1~S3 |
| H | high-risk-abuse | S0~S3 |

각 (attack, arm) 은 격리된 서버 인스턴스에서 독립 시행된다 (replay cache 오염 방지).

---

## 3. 지표 (지시서 §9)

### Security (§9.1)
- Token/Cross-Device Replay Success Rate
- Proof Replay / Cross-Key / URI / Method / Token Substitution Success Rate
- Unauthorized High-Risk API Success Rate  ← 핵심 (RQ3)
- Legitimate Request Success Rate

### Performance (§9.2)
- End-to-End API Latency (mean/median/p95/p99/std)
- (하드웨어) DPoP proof generation, ECDSA signing, server verify, BLE RTT

### Embedded (§9.3) — **하드웨어 필요**
- Firmware Flash/RAM, Secure Element signing latency, BLE latency
- 전력: 장비 있을 때만

---

## 4. 실행

```bash
python experiments/runners/run_security.py --mode all --runs 1000
python experiments/runners/run_latency.py  --mode all --runs 1000
python experiments/runners/make_plots.py
```

산출물:
```
experiments/raw/security_raw.jsonl        # 원자료 (모든 시행)
experiments/raw/latency_raw.jsonl
experiments/results/security_summary.csv
experiments/results/legit_summary.csv
experiments/results/latency_summary.csv
experiments/results/run_metadata.json     # 재현 조건
experiments/plots/graph_a_security.png
experiments/plots/graph_b_latency.png
experiments/plots/graph_d_high_risk.png
```

---

## 5. 반복 횟수

기본 시연은 소규모(runs=10~20)로 빠르게, 보고용 결과는 `--runs 1000` 으로 생성한다.
반복 횟수는 `run_metadata.json` 에 기록된다.

---

## 6. 재현성 원칙 (지시서 §10, §34)

- 모든 수치는 **실행 결과에서만** 생성한다. 사전에 채워진 값은 없다.
- 목표치는 `TARGET` 으로만 표기한다 (`docs/limitations.md`, README).
- S3 의 성능 수치는 **시뮬레이터 기반**이며, BLE/SE latency 와 firmware footprint 는
  실제 하드웨어에서 재측정해야 한다. CSV/metadata 에 `NOT VERIFIED ON HARDWARE` 명시.

---

## 7. Hardware-in-the-loop (지시서 §22)

실제 ESP32-S3 + ATECC608B 확보 후 검증할 항목:
enrollment / sign / approval / timeout / disconnect / repeated request.
이 결과로 §28 의 7·8·9·10번 수치를 채우고 그래프 C(S3 latency breakdown)를 생성한다.
