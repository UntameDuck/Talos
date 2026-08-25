/* BoundKey policy engine (지시서 §5.5).
 *
 * 이 테이블은 server/app/risk/policy.py, attacker/boundattack/boundkey_sim.py 와
 * **의미가 동일해야 한다.** 세 곳을 함께 유지한다.
 */
#ifndef BOUNDKEY_POLICY_H
#define BOUNDKEY_POLICY_H

typedef enum {
    RISK_LOW = 0,
    RISK_MEDIUM = 1,
    RISK_HIGH = 2,
    RISK_UNKNOWN = 3 /* DEFAULT DENY */
} risk_level_t;

/* method/uri 로 위험도를 분류한다. 알 수 없는 조합은 RISK_UNKNOWN.
 * uri 는 쿼리를 제외한 정규화된 절대 경로여야 한다. */
risk_level_t policy_classify(const char *method, const char *uri);

/* RISK_HIGH 만 물리 승인 필수 (지시서 §5.5). */
int policy_requires_user_presence(risk_level_t level);

#endif /* BOUNDKEY_POLICY_H */
