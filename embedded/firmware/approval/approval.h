/* BoundKey physical approval state machine (지시서 §5.6, §21).
 *
 * 규칙:
 *  - 승인은 특정 request_id 에만 바인딩된다.
 *  - 승인은 1회용으로 소비된다.
 *  - 정해진 timeout 후 자동 거부.
 *  - 이전 버튼 이벤트 재사용 금지.
 *  - disconnect 시 대기 중 승인 무효화.
 *
 * 참조 동작(golden): attacker/boundattack/boundkey_sim.py 의 승인 로직 및
 * attacker/tests/test_boundkey_sim.py.
 */
#ifndef BOUNDKEY_APPROVAL_H
#define BOUNDKEY_APPROVAL_H

#include <stdint.h>

typedef enum {
    APPROVAL_IDLE = 0,
    APPROVAL_WAITING = 1,
    APPROVAL_GRANTED = 2,
    APPROVAL_TIMEOUT = 3,
    APPROVAL_REJECTED = 4
} approval_state_t;

#define APPROVAL_REQUEST_ID_MAX 32

typedef struct {
    approval_state_t state;
    char request_id[APPROVAL_REQUEST_ID_MAX];
    uint64_t deadline_ms;
} approval_ctx_t;

/* HIGH 요청에 대해 승인 창을 연다. */
void approval_begin(approval_ctx_t *ctx, const char *request_id, uint64_t now_ms,
                    uint32_t timeout_ms);

/* 디바운스된 버튼 이벤트. 현재 대기 중인 request_id 와 일치할 때만 승인. */
void approval_on_button(approval_ctx_t *ctx, uint64_t now_ms);

/* 주기적 tick. 데드라인 초과 시 TIMEOUT 전이. */
void approval_tick(approval_ctx_t *ctx, uint64_t now_ms);

/* request_id 에 대해 승인이 확정되었는지 확인하고 **소비**한다(1회용). */
int approval_consume(approval_ctx_t *ctx, const char *request_id);

/* 연결 종료 시 대기 승인 무효화 (지시서 §20, §21). */
void approval_reset(approval_ctx_t *ctx);

#endif /* BOUNDKEY_APPROVAL_H */
