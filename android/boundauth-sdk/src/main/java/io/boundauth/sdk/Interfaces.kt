package io.boundauth.sdk

/**
 * SDK 내부 모듈의 인터페이스 골격 (지시서 §3 SDK 내부 주요 모듈).
 *
 * 이 파일은 계약(interface)만 정의한다. 구현체는 툴체인 확보 후 채운다.
 * 서버·프로토콜 정합성은 Python 참조 구현(`server/`, `attacker/boundattack/`)에서
 * 이미 검증되었으므로, Android 구현은 그 동작을 재현해야 한다.
 */

// --- 데이터 ----------------------------------------------------------------

data class SessionState(
    val loggedIn: Boolean,
    val mode: AuthMode,
    val jkt: String?,
    val deviceId: String?,
    val hardwareBacked: Boolean?,
    val strongBox: Boolean?,
    val boundKeyConnected: Boolean,
    val lastProofJti: String?,
    val replayBlocks: Int,
)

data class ApiResponse(val statusCode: Int, val body: String, val errorCode: String?)

/** 구조화된 서명 요청. Android 는 "서명할 bytes" 를 보내지 않는다 (지시서 §4.3, §5.4). */
data class SignRequest(
    val requestId: String,
    val method: String,
    val uri: String,       // path only
    val tokenHash: String, // base64url(sha256(access_token))
    val nonce: String?,
    val timestamp: Long,
)

data class DeviceInfo(val publicKeyJwk: Map<String, String>, val firmwareVersion: String?)

// --- 서명 주체 -------------------------------------------------------------

/** BoundKey(실제 또는 Mock). BLE 뒤의 인증기. */
interface Authenticator {
    suspend fun deviceInfo(): DeviceInfo
    /** 구조화된 요청을 받아 완성된 DPoP proof JWT 를 돌려준다. */
    suspend fun sign(request: SignRequest): String
    fun isConnected(): Boolean
}

/** arm 별 키/서명 전략. */
interface KeyManager {
    fun publicJwk(): Map<String, String>?
    fun thumbprint(): String?
    suspend fun proof(method: String, htu: String, accessToken: String, nonce: String?): String?
    val hardwareBacked: Boolean?
    val strongBox: Boolean?

    companion object {
        fun forMode(mode: AuthMode, authenticator: Authenticator?): KeyManager =
            TODO("구현 예정: mode 에 따라 Software/Keystore/BoundKey KeyManager 반환")
    }
}

// --- 지원 모듈 -------------------------------------------------------------

interface TokenManager {
    fun store(access: String, refresh: String)
    fun accessToken(): String?
    fun refreshToken(): String?
    fun clear()
}

interface NonceManager {
    fun current(): String?
    fun update(nonce: String)
}

interface RiskClassifier {
    // 서버/BoundKey 정책 테이블과 동일해야 한다 (server/app/risk/policy.py).
    fun classify(method: String, path: String): RiskLevel
}

enum class RiskLevel { LOW, MEDIUM, HIGH, UNKNOWN }

fun interface SecurityEventListener {
    // AUTH_LOGIN_SUCCESS, TOKEN_RECEIVED, DPoP_REQUESTED, BOUNDKEY_CONNECTED,
    // APPROVAL_REQUIRED, APPROVAL_GRANTED, REQUEST_SUCCESS, REQUEST_REJECTED ... (§14)
    fun onEvent(type: String, metadata: Map<String, Any?>)
}

/** 테스트 가능한 시계 추상화 (지시서 §3 clock skew, §22). */
interface Clock {
    fun nowEpochSeconds(): Long
    object System : Clock {
        override fun nowEpochSeconds(): Long = java.time.Instant.now().epochSecond
    }
}
