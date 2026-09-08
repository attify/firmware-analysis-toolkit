/* Scatter-load startup whose third record decompresses rather than copies.
 *
 * unpack_fn is an LZSS decoder in the shape real packed-.data runtimes use: a
 * control byte splits into a 3-bit literal count and a 4-bit match count, each
 * with a byte-extend fallback when the field reads zero, followed by a literal
 * run and a back-reference copy. That is the shape the handler classifier
 * recognises; the record's payload really is in that format (see packed_blob).
 */
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
/* A plain byte-wise memcpy: the same byte granularity as the decoder but none
 * of the codec machinery. It must NOT be mistaken for a decompressor. */
__attribute__((noinline)) void bytecopy_fn(uint32_t s, uint32_t d, uint32_t n) {
    const uint8_t *sp = (const uint8_t *)s; uint8_t *dp = (uint8_t *)d;
    while (n--) *dp++ = *sp++;
}
__attribute__((noinline)) void unpack_fn(uint32_t s, uint32_t d, uint32_t n) {
    const uint8_t *src = (const uint8_t *)s;
    uint8_t *dst = (uint8_t *)d;
    uint8_t *end = dst + n;
    while (dst < end) {
        uint32_t ctl = *src++;          /* control byte                     */
        uint32_t lit = ctl & 7u;        /* low 3 bits  -> literal count     */
        if (lit == 0u) lit = *src++;    /* ... extended by the next byte    */
        uint32_t mat = ctl >> 4;        /* high 4 bits -> match count       */
        if (mat == 0u) mat = *src++;    /* ... extended by the next byte    */
        while (lit--) *dst++ = *src++;  /* literal run                      */
        const uint8_t *back = dst - *src++; /* 1-byte back-reference offset */
        while (mat--) *dst++ = *back++; /* back-reference copy              */
    }
}

/* 9 packed bytes that expand to the 16 bytes of __unpacked_start__:
 *   0x44           lit=4, mat=4
 *   'A' 'B' 'C' 'D'   literals            -> "ABCD"
 *   0x04           back-reference offset 4 -> "ABCD"          (8 bytes so far)
 *   0x71           lit=1, mat=7
 *   'E'            literal                 -> "E"             (9 bytes)
 *   0x09           back-reference offset 9 -> "ABCDABC"       (16 bytes)
 */
__attribute__((section(".packed"), used))
const uint8_t packed_blob[] = { 0x44, 'A', 'B', 'C', 'D', 0x04, 0x71, 'E', 0x09 };

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
