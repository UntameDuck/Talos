# BoundAuth — Implementation Checklist

이 문서는 `BoundAuth_complete_development_prompt.md`의 요구사항을 추적 가능한 작업 단위로
분해한 마스터 체크리스트다. **모든 체크는 실제 실행/검증 후에만 표시한다.**

상태 표기:

| 표기 | 의미 |
|------|------|
| `[ ]` | 미착수 |
| `[~]` | 구현됨, 미검증 |
| `[x]` | 구현 + 이 환경에서 실행 검증 완료 |
| `[H]` | 구현됨, **실제 하드웨어 검증 필요** (`NOT VERIFIED ON HARDWARE`) |
| `[B]` | 구현됨, **이 개발 환경에 툴체인 없음 → 빌드 미검증** |

---

## 개발 환경 제약 (2026-08-21 실측)

| 툴체인 | 상태 | 영향 |
|--------|------|------|
| Python 3.14.3 + pip | 있음 | server / attacker / experiments 전부 실행·검증 가능 |
| git 2.55 | 있음 | monorepo 관리 가능 |
| Docker 29.2.1 | 있음 | compose 검증 가능 |
| JDK | **JRE 1.8 뿐** (JDK 17+ 없음) | Android **빌드 불가** → `[B]` |
| Android SDK | **없음** | Android 빌드/실행 불가 → `[B]` |
| ESP-IDF | **없음** | firmware 빌드 불가 → `[B]` |
| gcc / cmake / make | **없음** | firmware host unit test 컴파일 불가 → `[B]` |
| ESP32-S3 + ATECC608B | **없음** | HIL 검증 불가 → `[H]` |

> 이 제약 때문에 §23의 `MockAuthenticator`(Python BoundKey 시뮬레이터)를 **1급 구성요소**로 만든다.
> 시뮬레이터는 firmware와 **동일한 프로토콜/정책 로직**을 구현하여 S3 프로토콜 정합성을 검증하되,
> **최종 성능 수치(§9.3, §28의 7·8·9·10번)는 반드시 실제 하드웨어에서 재측정한다.**
> mock 수치를 하드웨어 수치로 보고하는 것은 §34에 의해 금지된다.

---

## Phase 0 — 프로젝트 초기화

- [x] P0-1 monorepo 디렉터리 구조 생성 (§7)
- [x] P0-2 `.gitignore` (secrets/키/실험 raw 제외)
- [x] P0-3 `IMPLEMENTATION_CHECKLIST.md`
- [x] P0-4 `docs/architecture.md`
- [x] P0-5 `docs/threat-model.md`
- [x] P0-6 `README.md` 기본 작성 (수치 없음 — §10)
- [x] P0-7 `.env.example`
- [x] P0-8 server boot 확인
- [x] P0-9 attacker CLI `--help` 동작
- [~] P0-10 Android demo/SDK shell 생성 (코드 스켈레톤 O), [B] build (SDK/JDK 없음)
- [~] P0-11 firmware shell 생성 (policy/approval C + host test O), [B] build (IDF/gcc 없음)
- [x] P0-12 docker-compose / Dockerfile
- [x] P0-13 GitHub Actions lint/test skeleton

**Phase 0 완료 조건:** `server boot` / `attacker help` 동작 (이 환경에서 검증),
`android build` / `firmware build` 는 툴체인 확보 후 검증 필요.

---

## Phase 1 — Bearer Token Baseline (S0, 의도적 취약)

- [x] P1-1 SQLAlchemy 모델: User / Device / SessionToken / ReplayEntry / SecurityEvent (§17)
- [x] P1-2 argon2 password hashing (§20)
- [x] P1-3 서버 서명키: 파일/ENV 로드, **하드코딩 금지**, 없으면 dev 한정 자동 생성
- [x] P1-4 JWT 발급 (ES256), `alg=none` 및 algorithm confusion 방어 (§20)
- [x] P1-5 `POST /auth/login`
- [x] P1-6 `POST /auth/refresh`
- [x] P1-7 `POST /devices/register`
- [x] P1-8 `GET /api/profile`, `GET /api/history`
- [x] P1-9 `POST /api/settings`, `POST /api/transfer`
- [x] P1-10 risk classification LOW/LOW/MEDIUM/HIGH (§주1)
- [x] P1-11 structured logging + SecurityEvent 기록 (§14), 토큰/키 원문 미기록
- [x] P1-12 server unit test (pytest)
- [x] P1-13 BoundAttack CLI skeleton + `attack token-replay`
- [x] P1-14 공격 결과 자동 기록 (JSONL raw + CSV summary)
- [x] P1-15 **baseline에서 token replay 실제 성공 재현** ← 첫 milestone (§36)

**Phase 1 완료 조건:** 정상 호출 성공 / 탈취 token 재사용 성공 / 결과 자동 기록. ✅ 달성

---

## Phase 2 — Software DPoP (S1) — RFC 9449

- [x] P2-1 DPoP proof 생성기 (참조 구현, attacker/시뮬레이터 공용): typ/alg/jwk + jti/htm/htu/iat/ath/nonce
- [x] P2-2 JWK thumbprint (RFC 7638) 계산
- [x] P2-3 access token `cnf.jkt` 바인딩 (§4.1)
- [x] P2-4 서버 DPoP 검증 파이프라인 (§4.4 전 항목)
- [x] P2-5 replay cache (`jti`) — SQLite 기반, TTL 만료
- [x] P2-6 nonce 발급/검증 (`DPoP-Nonce` 헤더, 401 challenge)
- [x] P2-7 error code 체계 + 환경별 상세도 조정 (§2 실패사유)
- [x] P2-8 strict parser (alg 화이트리스트, `none` 거부, 크기 제한)
- [x] P2-9 clock skew 허용범위 설정화
- [x] P2-10 htu normalization 규칙 문서화 + 일관 적용
- [x] P2-11 server unit test: 8종 실패 케이스 전부
- [x] P2-12 BoundAttack: cross-key / proof-replay / uri-sub / method-sub / token-sub / stale-proof
- [x] P2-13 S1에서 공격 차단 실측 재현

**Phase 2 완료 조건:** 정상 DPoP 성공 / token-only 실패 / jkt mismatch / replay 차단 / method·URI 치환 차단. ✅ 달성

---

## Phase 3 — BoundAuth Android SDK

- [B] P3-1 Gradle multi-module (`boundauth-sdk`, `demo-app`)
- [B] P3-2 `AuthClient` / `TokenManager` / `KeyManager`
- [B] P3-3 `DpopProofBuilder` / `NonceManager`
- [B] P3-4 `BoundAuthInterceptor` (OkHttp)
- [B] P3-5 `AuthenticatorBridge` (BLE / Mock)
- [B] P3-6 `RiskClassifier` / `SecurityEventListener`
- [B] P3-7 테스트용 Clock / NonceSource 추상화
- [B] P3-8 `BoundAuth.Builder()` 공개 API (§3 예시와 동일 형태)
- [B] P3-9 Android unit test (DPoP 구성/nonce/interceptor/token manager)
- [B] P3-10 Demo App이 보안 코드를 직접 갖지 않음

---

## Phase 4 — Android Hardware-Backed DPoP (S2)

- [B] P4-1 Android Keystore P-256 키 생성
- [B] P4-2 hardware-backed / StrongBox 감지
- [B] P4-3 key export 금지 확인
- [B] P4-4 unsupported 환경 명시적 fallback 보고 (§19: 조용한 fallback 금지)
- [B] P4-5 keygen/sign/proof latency 계측
- [H] P4-6 실제 단말에서 S1 vs S2 비교

---

## Phase 5 — BoundKey Embedded Authenticator (S3)

### 5.0 시뮬레이터 (하드웨어 부재 시 개발 지속용, §23)
- [x] P5-0a Python BoundKey 시뮬레이터: 프로토콜·정책·승인 상태머신
- [x] P5-0b 시뮬레이터 기반 S3 end-to-end 검증
- [x] P5-0c high-risk 물리 승인 미승인 시 서명 거부 검증

### 5.1 하드웨어
- [x] P5-1 `hardware/BOM.md`
- [x] P5-2 `hardware/wiring.md` (I2C/전원)
- [x] P5-3 `hardware/provisioning.md`

### 5.2~5.8 펌웨어
- [ ] P5-4 Device enrollment (SE 키 생성 → 공개키만 export)
- [ ] P5-5 BLE GATT + 프레이밍 추상화 (JSON→CBOR 교체 가능)
- [ ] P5-6 메시지 타입 8종 + correlation id
- [ ] P5-7 `SIGN_REQUEST` 구조화 파싱 (raw bytes 서명 금지 — §4.3)
- [~] P5-8 policy engine C (`security/policy.c`) — [B] 빌드 미검증, golden=Python
- [~] P5-9 approval FSM C (`approval/approval.c`) — [B] 빌드 미검증, golden=Python
- [ ] P5-10 CryptoAuthLib ATECC608B 연동 (private key export 함수 부재 보장)
- [ ] P5-11 BoundKey 내부 DPoP proof 구성 + 서명
- [~] P5-12 host unit test C (`host_test/`) 작성 — [B] 컴파일러 부재로 미실행
- [ ] P5-13 malformed frame fuzz test (§20)
- [H] P5-14 HIL: enrollment/sign/approval/timeout/disconnect/repeat

---

## Phase 6 — BoundAttack (8종)

- [x] P6-A token-replay
- [x] P6-B cross-key
- [x] P6-C proof-replay
- [x] P6-D uri-substitution
- [x] P6-E method-substitution
- [x] P6-F token-substitution
- [x] P6-G stale-proof
- [x] P6-H high-risk-abuse
- [x] P6-1 `boundattack attack <name>` CLI
- [x] P6-2 S0/S1/S2/S3 모드별 반복 실행
- [x] P6-3 raw 결과 JSONL 저장

---

## Phase 7 — Experiment Framework

- [x] P7-1 `run_security.py --mode all --runs N`
- [x] P7-2 `run_latency.py --mode all --runs N`
- [ ] P7-3 `run_embedded.py` (flash/RAM/SE latency) — 하드웨어 필요
- [x] P7-4 `security_summary.csv` / `latency_summary.csv` / `run_metadata.json`
- [x] P7-5 그래프 A/B/D 자동 생성
- [ ] P7-6 그래프 C (S3 latency breakdown) — 실제 BLE/SE 측정 필요
- [ ] P7-7 실제 하드웨어 기반 최종 재측정 (§23)

---

## 문서

- [x] D-1 `README.md`
- [x] D-2 `docs/architecture.md`
- [x] D-3 `docs/threat-model.md`
- [x] D-4 `docs/protocol.md`
- [x] D-5 `docs/dpop-mapping.md`
- [x] D-6 `docs/embedded-security.md`
- [x] D-7 `docs/experiment-design.md`
- [x] D-8 `docs/limitations.md`

---

## 상시 준수 규칙 (§10 / §34)

- [x] R-1 실험 전 성능/보안 **수치를 문서에 미리 쓰지 않음**
- [x] R-2 목표치는 `TARGET`으로만 표기
- [x] R-3 키·토큰 하드코딩 없음
- [x] R-4 실행하지 않은 테스트를 실행했다고 하지 않음
- [x] R-5 하드웨어 미검증 항목에 `NOT VERIFIED ON HARDWARE` 명시
- [x] R-6 보안 실패 시 silent fallback 없음
- [x] R-7 mock 수치를 하드웨어 수치로 제시하지 않음 (CSV/metadata에 SIMULATOR 명시)
