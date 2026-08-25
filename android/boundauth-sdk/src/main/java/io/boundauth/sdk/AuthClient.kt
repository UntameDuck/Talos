package io.boundauth.sdk

/**
 * AuthClient — 로그인/요청 오케스트레이션 (지시서 §3).
 *
 * 스켈레톤: 시그니처와 흐름 주석만 있고 실제 OkHttp 호출은 툴체인 확보 후 채운다.
 * 흐름은 Python 참조 클라이언트(`attacker/boundattack/client.py`)와 동일해야 한다.
 */
class AuthClient(
    private val config: BoundAuthConfig,
    private val keyManager: KeyManager,
    private val clock: Clock,
) {
    private val listeners = mutableListOf<SecurityEventListener>()
    // private val tokenManager: TokenManager = ...
    // private val nonceManager: NonceManager = ...
    // private val http: OkHttpClient = OkHttpClient.Builder()
    //     .addInterceptor(BoundAuthInterceptor(...)).build()

    suspend fun login(username: String, password: String): SessionState {
        // 1. mode != BEARER 이면 keyManager.publicJwk() 로 /devices/register (최초 1회)
        // 2. POST /auth/login { username, password, mode, device_id }
        // 3. 응답의 access/refresh 저장, jkt/device_id 기록
        // 4. emit(AUTH_LOGIN_SUCCESS), emit(TOKEN_RECEIVED)
        TODO("툴체인 확보 후 구현 - 흐름은 client.py 와 동일")
    }

    suspend fun request(method: String, path: String, body: Any?): ApiResponse {
        // BEARER: Authorization: Bearer <at>
        // DPoP arms:
        //   htu = config.baseUrl + path
        //   proof = keyManager.proof(method, htu, accessToken, nonce)   // BoundKey면 BLE
        //   Authorization: DPoP <at> ; DPoP: <proof>
        //   401 + DPoP-Nonce 면 nonce 갱신 후 1회 재시도
        //   emit(DPoP_REQUESTED / APPROVAL_REQUIRED / REQUEST_SUCCESS / REQUEST_REJECTED)
        TODO("툴체인 확보 후 구현")
    }

    fun sessionState(): SessionState = TODO("현재 세션/BoundKey 상태 반환")

    fun addSecurityEventListener(listener: SecurityEventListener) {
        listeners += listener
    }

    private fun emit(type: String, metadata: Map<String, Any?> = emptyMap()) {
        listeners.forEach { it.onEvent(type, metadata) }
    }
}
