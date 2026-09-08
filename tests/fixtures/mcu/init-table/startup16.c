/* Scatter-load style init: 16-byte records {src, dst, size, fn_ptr} */
#include <stdint.h>
typedef struct { uint32_t src, dst, size, fn; } InitRec;
extern InitRec __init_table_start__[], __init_table_end__[];
extern uint32_t __StackTop;
extern int main(void);
void Default_Handler(void) { while (1) {} }

__attribute__((noinline)) void copy_fn(uint32_t s, uint32_t d, uint32_t n) {
    const uint32_t *sp=(const uint32_t*)s; uint32_t *dp=(uint32_t*)d;
    for (uint32_t i=0;i<n/4;i++) dp[i]=sp[i];
}
__attribute__((noinline)) void zero_fn(uint32_t s, uint32_t d, uint32_t n) {
    (void)s; uint32_t *dp=(uint32_t*)d;
    for (uint32_t i=0;i<n/4;i++) dp[i]=0u;
}
void RuntimeInit(void) {
    for (InitRec *r = __init_table_start__; r < __init_table_end__; r++) {
        ((void(*)(uint32_t,uint32_t,uint32_t))(r->fn | 1u))(r->src, r->dst, r->size);
    }
}
void SystemInit(void) {
    *(volatile uint32_t*)0xE000ED88u |= (0xFu<<20);   /* FPU  */
    *(volatile uint32_t*)0x52002000u  = 0x4u;         /* flash latency */
}
void Reset_Handler(void) { SystemInit(); RuntimeInit(); main(); while(1){} }
__attribute__((section(".vectors"), used))
void *const __vector_table[8] = {
    (void*)&__StackTop, (void*)Reset_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler,
};
