/* CMSIS-style startup: vector table -> Reset_Handler -> SystemInit -> copy/zero table walk */
#include <stdint.h>

extern uint32_t __copy_table_start__, __copy_table_end__;
extern uint32_t __zero_table_start__, __zero_table_end__;
extern uint32_t __StackTop;

void Reset_Handler(void);
void Default_Handler(void) { while (1) {} }
void SystemInit(void);
extern int main(void);

/* Real CMSIS copy/zero table walk, same shape as ARM's startup_ARMCMx.c */
void Reset_Handler(void) {
    uint32_t *pTable = &__copy_table_start__;
    for (; pTable < &__copy_table_end__; pTable += 3) {
        uint32_t *src = (uint32_t *)pTable[0];
        uint32_t *dst = (uint32_t *)pTable[1];
        for (uint32_t i = 0; i < pTable[2] / 4; i++) dst[i] = src[i];
    }
    pTable = &__zero_table_start__;
    for (; pTable < &__zero_table_end__; pTable += 2) {
        uint32_t *dst = (uint32_t *)pTable[0];
        for (uint32_t i = 0; i < pTable[1] / 4; i++) dst[i] = 0u;
    }
    SystemInit();
    main();
    while (1) {}
}

extern void *const __vector_table[16];
/* SystemInit-shaped: VTOR set + FPU enable + flash latency */
#define SCB_VTOR (*(volatile uint32_t *)0xE000ED08u)
#define SCB_CPACR (*(volatile uint32_t *)0xE000ED88u)
#define FLASH_ACR (*(volatile uint32_t *)0x40023C00u)

void SystemInit(void) {
    SCB_VTOR = (uint32_t)__vector_table;
    SCB_CPACR |= (0xFu << 20);
    FLASH_ACR = 0x5u;
}

__attribute__((section(".vectors"), used))
void *const __vector_table[16] = {
    (void *)&__StackTop, (void *)Reset_Handler,
    Default_Handler, Default_Handler, Default_Handler, Default_Handler,
    Default_Handler, 0, 0, 0, 0, Default_Handler,
    Default_Handler, 0, Default_Handler, Default_Handler,
};
