/* Host unit test — approval state machine (지시서 §5.6, §22). */
#include "../approval/approval.h"
#include <assert.h>
#include <stdio.h>

int main(void)
{
    approval_ctx_t ctx;
    approval_reset(&ctx);

    /* HIGH 요청 승인 창 */
    approval_begin(&ctx, "req-A", 1000, 30000);
    assert(ctx.state == APPROVAL_WAITING);

    /* 다른 request_id 는 소비 불가 */
    assert(approval_consume(&ctx, "req-B") == 0);

    /* 버튼 누름 -> 승인 */
    approval_on_button(&ctx, 2000);
    assert(ctx.state == APPROVAL_GRANTED);

    /* 해당 request_id 로 1회 소비 */
    assert(approval_consume(&ctx, "req-A") == 1);
    /* 재소비 불가 (1회용) */
    assert(approval_consume(&ctx, "req-A") == 0);

    /* 타임아웃 경로 */
    approval_reset(&ctx);
    approval_begin(&ctx, "req-C", 0, 1000);
    approval_tick(&ctx, 2000); /* 데드라인 초과 */
    assert(ctx.state == APPROVAL_TIMEOUT);
    approval_on_button(&ctx, 2500); /* 타임아웃 후 버튼은 무시 */
    assert(ctx.state == APPROVAL_TIMEOUT);
    assert(approval_consume(&ctx, "req-C") == 0);

    /* 이전(IDLE) 버튼 이벤트 재사용 금지 */
    approval_reset(&ctx);
    approval_on_button(&ctx, 100); /* IDLE 상태의 버튼 */
    approval_begin(&ctx, "req-D", 200, 30000);
    assert(ctx.state == APPROVAL_WAITING);
    assert(approval_consume(&ctx, "req-D") == 0); /* 자동 승인되지 않음 */

    printf("approval tests passed\n");
    return 0;
}
