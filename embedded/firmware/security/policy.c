/* BoundKey policy engine — shared table (지시서 §5.5).
 *
 * server/app/risk/policy.py 및 boundkey_sim.py 와 동일한 분류를 구현한다.
 * 변경 시 세 곳을 함께 수정한다.
 *
 * 순수 C: ESP-IDF 없이도 host_test 에서 컴파일 가능하다. (이 개발 환경에는 컴파일러가
 * 없어 아직 빌드 검증되지 않았다 — NOT VERIFIED ON HARDWARE / host build pending.)
 */
#include "policy.h"
#include <string.h>

typedef struct {
    const char *method;
    const char *uri;
    risk_level_t level;
} policy_entry_t;

static const policy_entry_t POLICY_TABLE[] = {
    {"GET",  "/api/profile",  RISK_LOW},
    {"GET",  "/api/history",  RISK_LOW},
    {"POST", "/api/settings", RISK_MEDIUM},
    {"POST", "/api/transfer", RISK_HIGH},
};

static const unsigned POLICY_TABLE_LEN =
    sizeof(POLICY_TABLE) / sizeof(POLICY_TABLE[0]);

risk_level_t policy_classify(const char *method, const char *uri)
{
    if (method == NULL || uri == NULL) {
        return RISK_UNKNOWN;
    }
    for (unsigned i = 0; i < POLICY_TABLE_LEN; ++i) {
        if (strcmp(method, POLICY_TABLE[i].method) == 0 &&
            strcmp(uri, POLICY_TABLE[i].uri) == 0) {
            return POLICY_TABLE[i].level;
        }
    }
    return RISK_UNKNOWN; /* DEFAULT DENY (지시서 §5.5) */
}

int policy_requires_user_presence(risk_level_t level)
{
    return level == RISK_HIGH ? 1 : 0;
}
