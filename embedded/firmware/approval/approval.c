/* BoundKey approval state machine (지시서 §5.6). 순수 C, host-testable. */
#include "approval.h"
#include <string.h>

static void copy_request_id(approval_ctx_t *ctx, const char *request_id)
{
    strncpy(ctx->request_id, request_id, APPROVAL_REQUEST_ID_MAX - 1);
    ctx->request_id[APPROVAL_REQUEST_ID_MAX - 1] = '\0';
}

void approval_begin(approval_ctx_t *ctx, const char *request_id, uint64_t now_ms,
                    uint32_t timeout_ms)
{
    ctx->state = APPROVAL_WAITING;
    copy_request_id(ctx, request_id);
    ctx->deadline_ms = now_ms + (uint64_t)timeout_ms;
}

void approval_on_button(approval_ctx_t *ctx, uint64_t now_ms)
{
    /* 대기 중이고 아직 데드라인 전일 때만 승인으로 전이한다.
     * IDLE 상태의 버튼(이전 이벤트)은 무시한다 = 재사용 금지. */
    if (ctx->state == APPROVAL_WAITING && now_ms <= ctx->deadline_ms) {
        ctx->state = APPROVAL_GRANTED;
    }
}

void approval_tick(approval_ctx_t *ctx, uint64_t now_ms)
{
    if (ctx->state == APPROVAL_WAITING && now_ms > ctx->deadline_ms) {
        ctx->state = APPROVAL_TIMEOUT;
    }
}

int approval_consume(approval_ctx_t *ctx, const char *request_id)
{
    if (ctx->state == APPROVAL_GRANTED &&
        strncmp(ctx->request_id, request_id, APPROVAL_REQUEST_ID_MAX) == 0) {
        approval_reset(ctx); /* 1회용 소비 */
        return 1;
    }
    return 0;
}

void approval_reset(approval_ctx_t *ctx)
{
    ctx->state = APPROVAL_IDLE;
    ctx->request_id[0] = '\0';
    ctx->deadline_ms = 0;
}
