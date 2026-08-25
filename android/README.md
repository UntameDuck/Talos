# BoundAuth Android (SDK + Demo)

> **빌드 상태: 미검증.** 이 개발 환경에는 JDK17+ 와 Android SDK 가 없어
> `./gradlew assembleDebug` 를 실행/검증하지 못했다. 아래 코드는 설계 스켈레톤이며,
> 서버/공격/실험 구성요소(Python)는 별도로 실행 검증되었다.

## 모듈
- `boundauth-sdk/` — 앱 개발자가 쓰는 Device-Bound Session 라이브러리 (deliverable ①)
- `demo-app/` — SDK 를 사용하는 데모 앱 (deliverable ②)

## 공개 API (목표 형태, 지시서 §3)
```kotlin
val boundAuth = BoundAuth.Builder()
    .baseUrl(BASE_URL)
    .mode(AuthMode.BOUNDKEY_DPOP)
    .build()

boundAuth.login(username, password)
boundAuth.get("/api/profile")
boundAuth.post("/api/transfer", body = transferRequest)
```

## SDK 내부 모듈 (지시서 §3)
`AuthClient` / `TokenManager` / `KeyManager` / `DpopProofBuilder` / `NonceManager` /
`BoundAuthInterceptor` / `AuthenticatorBridge` / `RiskClassifier` / `SecurityEventListener`.

## Mock 전략 (지시서 §23)
`MockAuthenticator` 로 하드웨어 없이 개발한다. 서버·프로토콜은 Python
`boundattack.boundkey_sim` 시뮬레이터로 이미 검증되어 있으며, 최종 성능 수치는
실제 BoundKey 하드웨어에서 재측정한다.
