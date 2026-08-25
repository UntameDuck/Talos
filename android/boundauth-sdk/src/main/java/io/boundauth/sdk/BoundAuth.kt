package io.boundauth.sdk

/**
 * BoundAuth SDK 공개 진입점 (지시서 §3, deliverable ①).
 *
 * 앱 개발자는 이 클래스만 다룬다. mode 에 따라 내부 서명 주체가 바뀐다:
 *
 * ```
 * BEARER                 -> 서명 없음
 * SOFTWARE_DPOP          -> SoftwareKeyManager (앱 내 P-256)
 * ANDROID_HARDWARE_DPOP  -> KeystoreKeyManager (TEE/StrongBox)
 * BOUNDKEY_DPOP          -> AuthenticatorBridge -> BLE -> BoundKey
 * ```
 *
 * BOUNDKEY_DPOP 에서 SDK 는 proof 를 직접 만들지 않는다. 구조화된 요청 정보만
 * BoundKey 로 넘기고 완성된 proof 를 돌려받는다 (지시서 §4.3).
 *
 * > 빌드 상태: 이 개발 환경에는 Android 툴체인이 없어 미검증. 서버/프로토콜은
 * > Python 시뮬레이터로 검증됨. 최종 검증은 실제 하드웨어에서 수행한다 (§23, §34).
 */
class BoundAuth private constructor(
    private val config: BoundAuthConfig,
    internal val authClient: AuthClient,
) {
    /** 로그인 후 arm 에 맞는 세션을 확립한다. */
    suspend fun login(username: String, password: String): SessionState =
        authClient.login(username, password)

    suspend fun get(path: String): ApiResponse = authClient.request("GET", path, null)

    suspend fun post(path: String, body: Any? = null): ApiResponse =
        authClient.request("POST", path, body)

    /** 현재 세션/보안 상태 (지시서 §15 Session Security 화면용). */
    fun sessionState(): SessionState = authClient.sessionState()

    /** 보안 이벤트 리스너 등록 (지시서 §14 Android 로그). */
    fun addSecurityEventListener(listener: SecurityEventListener) =
        authClient.addSecurityEventListener(listener)

    class Builder {
        private var baseUrl: String? = null
        private var mode: AuthMode = AuthMode.BEARER
        private var authenticator: Authenticator? = null
        private var clock: Clock = Clock.System
        private var clockSkewSeconds: Long = 60

        fun baseUrl(url: String) = apply { this.baseUrl = url }
        fun mode(mode: AuthMode) = apply { this.mode = mode }

        /** BOUNDKEY_DPOP 에서 실제/Mock BoundKey 를 주입한다 (지시서 §23). */
        fun authenticator(a: Authenticator) = apply { this.authenticator = a }
        fun clock(c: Clock) = apply { this.clock = c }
        fun clockSkewSeconds(s: Long) = apply { this.clockSkewSeconds = s }

        fun build(): BoundAuth {
            val url = requireNotNull(baseUrl) { "baseUrl is required" }
            val config = BoundAuthConfig(url, mode, clockSkewSeconds)
            val keyManager = KeyManager.forMode(mode, authenticator)
            val client = AuthClient(config, keyManager, clock)
            return BoundAuth(config, client)
        }
    }
}

/** 실험 arm / 서명 주체 (지시서 §23 Modes). */
enum class AuthMode { BEARER, SOFTWARE_DPOP, ANDROID_HARDWARE_DPOP, BOUNDKEY_DPOP }

data class BoundAuthConfig(
    val baseUrl: String,
    val mode: AuthMode,
    val clockSkewSeconds: Long,
)
