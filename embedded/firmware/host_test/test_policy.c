/* Host unit test — policy engine (지시서 §22 Firmware Unit/Host Test).
 * ESP-IDF 불필요. gcc/clang 로 컴파일. (이 개발 환경에는 C 컴파일러가 없어 아직
 * 빌드/실행되지 않음.) */
#include "../security/policy.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    assert(policy_classify("GET", "/api/profile") == RISK_LOW);
    assert(policy_classify("GET", "/api/history") == RISK_LOW);
    assert(policy_classify("POST", "/api/settings") == RISK_MEDIUM);
    assert(policy_classify("POST", "/api/transfer") == RISK_HIGH);

    /* DEFAULT DENY */
    assert(policy_classify("DELETE", "/api/profile") == RISK_UNKNOWN);
    assert(policy_classify("GET", "/api/settings") == RISK_UNKNOWN);
    assert(policy_classify("POST", "/unknown") == RISK_UNKNOWN);
    assert(policy_classify(NULL, NULL) == RISK_UNKNOWN);

    /* user presence: HIGH 만 */
    assert(policy_requires_user_presence(RISK_HIGH) == 1);
    assert(policy_requires_user_presence(RISK_LOW) == 0);
    assert(policy_requires_user_presence(RISK_MEDIUM) == 0);
    assert(policy_requires_user_presence(RISK_UNKNOWN) == 0);

    printf("policy tests passed\n");
    return 0;
}
