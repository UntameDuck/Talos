/* BoundKey firmware entry point (skeleton, 지시서 §5).
 *
 * 실제 구현은 ESP-IDF app_main() 에서 BLE GATT, ATECC608B(CryptoAuthLib),
 * 버튼/LED GPIO, 프로토콜 파서, 정책 엔진, 승인 상태머신, DPoP 조립을 초기화한다.
 *
 * 상태머신 개요:
 *   BOOT -> BLE_ADVERTISE -> BLE_CONNECTED
 *     on SIGN_REQUEST:
 *       parse & validate (size, request_id uniqueness, stale check)
 *       level = policy_classify(method, uri)
 *       if level == RISK_UNKNOWN: send ERROR(POLICY_DENY_UNKNOWN)
 *       if policy_requires_user_presence(level):
 *           approval_begin(...); LED blink; wait button or timeout
 *           if !approval_consume(...): send ERROR(APPROVAL_REQUIRED/TIMEOUT)
 *       build DPoP proof (jti/htm/htu/iat/ath/nonce/header/jwk) internally
 *       digest = sha256(signing_input)
 *       atecc_sign_digest(slot, digest, sig)   // 개인키는 슬롯 내부에만
 *       send SIGN_RESPONSE { proof }
 *
 * Fail-closed: ATECC 서명 실패 시 소프트웨어 fallback 하지 않는다 (지시서 §19).
 *
 * > 빌드 상태: ESP-IDF 툴체인 부재로 미검증. NOT VERIFIED ON HARDWARE.
 */
#include "security/policy.h"
#include "approval/approval.h"

/* void app_main(void) { ... }  // ESP-IDF 진입점 (툴체인 확보 후) */
