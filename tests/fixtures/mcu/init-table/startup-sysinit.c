/* Scatter-load startup with a full-fat STM32H7-shaped SystemInit.
 *
 * The plain scatter-load fixture only enables the FPU and sets flash latency.
 * This one adds every side effect the SystemInit analysis classifies — VTOR
 * relocation sentinel check, ART accelerator, RCC clock bring-up, I/D cache
 * enable, MPU region programming, VTOR write — plus one write to a peripheral
 * the analysis does not model, which must survive as an unclassified write
 * rather than being dropped.
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
void RuntimeInit(void) {
    for (InitRec *r = __init_table_start__; r < __init_table_end__; r++) {
        ((void(*)(uint32_t,uint32_t,uint32_t))(r->fn | 1u))(r->src, r->dst, r->size);
    }
}

extern void *const __vector_table[8];

#define REG(a)      (*(volatile uint32_t *)(uint32_t)(a))
#define SCB_VTOR    REG(0xE000ED08u)
#define SCB_CCR     REG(0xE000ED14u)
#define SCB_CPACR   REG(0xE000ED88u)
#define MPU_RBAR    REG(0xE000ED9Cu)
#define MPU_RASR    REG(0xE000EDA0u)
#define ART_CTR     REG(0x51008000u)   /* STM32H7 ART accelerator */
#define FLASH_ACR   REG(0x52002000u)   /* STM32H7 flash controller */
#define RCC_CR      REG(0x58024400u)   /* STM32H7 RCC             */
#define RCC_CFGR    REG(0x58024410u)
#define CRC_INIT    REG(0x58024C0Cu)   /* not a modelled category    */

void SystemInit(void) {
    SCB_CPACR |= (0xFu << 20);              /* FPU: CP10/CP11 full access */

    uint32_t acr = FLASH_ACR;
    acr &= ~0xFu;
    acr |= 7u;
    FLASH_ACR = acr;                        /* flash latency = 7 wait states */

    RCC_CR |= 1u;                           /* HSION                       */
    RCC_CR &= ~(1u << 18);                  /* HSEBYP clear                */
    RCC_CFGR = 3u;                          /* sysclk switch               */

    SCB_CCR |= (1u << 16) | (1u << 17);     /* D-cache + I-cache enable    */

    MPU_RBAR = 0x24000000u;                 /* MPU region base             */
    MPU_RASR = 0x0300001Bu;                 /* MPU region attributes       */

    CRC_INIT = 2u;                          /* not a modelled category     */

    /* Bootloader sentinel: only touch the ART accelerator when we were not
     * started from RAM by something that already relocated the table. */
    if ((uint32_t)(uintptr_t)__vector_table < 0x20000000u) {
        ART_CTR = 1u;
    }
    SCB_VTOR = (uint32_t)(uintptr_t)__vector_table;
}

void Reset_Handler(void) { SystemInit(); RuntimeInit(); main(); while(1){} }
__attribute__((section(".vectors"), used))
void *const __vector_table[8] = {
    (void*)&__StackTop, (void*)Reset_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler, Default_Handler,
};
