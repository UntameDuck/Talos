package io.boundauth.sdk.embedded

import io.boundauth.sdk.Authenticator
import io.boundauth.sdk.DeviceInfo
import io.boundauth.sdk.SignRequest

/**
 * MockAuthenticator (지시서 §23) — 하드웨어 없이 BOUNDKEY_DPOP 흐름을 개발/테스트.
 *
 * 실제 BoundKey 와 **동일한 정책/승인 규칙**을 재현해야 한다. 정합성의 권위 있는
 * 참조 구현은 Python `attacker/boundattack/boundkey_sim.py` 이며, 이 Mock 은 그것과
 * 동일하게 동작하도록 구현한다.
 *
 * > 최종 결과는 반드시 실제 BoundKey 하드웨어에서 재검증한다 (§23, §34).
 * > 이 Mock 으로 성능 수치를 산출하지 않는다.
 */
class MockAuthenticator : Authenticator {
    // 실제 구현 시: P-256 키쌍(소프트웨어), 정책 테이블, 승인 상태머신.
    // 정책: GET /api/profile,history=LOW; POST /api/settings=MEDIUM; POST /api/transfer=HIGH;
    //       그 외 UNKNOWN=DEFAULT DENY.
    override suspend fun deviceInfo(): DeviceInfo =
        TODO("소프트웨어 P-256 공개키 JWK 반환")

    override suspend fun sign(request: SignRequest): String =
        TODO("정책 분류 -> HIGH면 승인 대기 -> jti/htm/htu/iat/ath 구성 -> 서명")

    override fun isConnected(): Boolean = true
}
