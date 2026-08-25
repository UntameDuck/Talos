package io.boundauth.demo

/**
 * BoundAuth Demo App (지시서 §15, deliverable ②).
 *
 * 화면(설계):
 *  - Login: username / password / login
 *  - Session Security: 로그인/토큰 상태, DPoP mode, BoundKey 연결, Device ID,
 *    Hardware Key 상태, Last Proof, Replay Blocks
 *  - API Demo: GET Profile / GET History / POST Settings / POST Transfer
 *  - Attack / Security Events: 최근 차단/승인 이벤트 (읽기 전용)
 *
 * **데모 앱은 공격 기능을 구현하지 않는다** (지시서 §15). 공격은 BoundAttack 에만 둔다.
 * 데모 앱은 자체 보안 코드를 갖지 않고 BoundAuth SDK 를 통해서만 인증 요청을 한다
 * (지시서 §3 완료 조건).
 *
 * > 빌드 상태: 이 개발 환경에는 Android 툴체인이 없어 미검증 (skeleton).
 */
// import android.app.Activity 등은 툴체인 확보 후.
class MainActivity {
    // val boundAuth = BoundAuth.Builder()
    //     .baseUrl(BuildConfig.BASE_URL)
    //     .mode(AuthMode.BOUNDKEY_DPOP)
    //     .authenticator(bleAuthenticator)   // 또는 MockAuthenticator
    //     .build()
    //
    // Compose UI 로 위 4개 화면을 구성한다. 모든 네트워크/서명은 boundAuth 를 통해서만.
}
