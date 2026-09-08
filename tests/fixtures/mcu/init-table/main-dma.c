/* An H7-shaped app that parks DMA pools above the linker-managed cap and
 * drives the Ethernet MAC, so the SRAM partition has real pool literals and a
 * real DMA master to find. Same .data/.bss shape as main.c, so the init
 * descriptor table and the initial SP are unchanged. */
#include <stdint.h>
volatile uint32_t initialized_data = 0xDEADBEEF;  /* -> .data, needs copy */
volatile uint32_t zeroed_bss[64];                 /* -> .bss,  needs zero */

#define ETH_MACCR      (*(volatile uint32_t *)0x40028000u) /* STM32H7 ETH_MAC */
#define RX_DESCRIPTORS ((volatile uint32_t *)0x24020000u)  /* AXI SRAM pool   */
#define TX_POOL        ((volatile uint32_t *)0x24040000u)  /* AXI SRAM pool   */

int main(void) {
    zeroed_bss[0] = initialized_data;
    RX_DESCRIPTORS[0] = (uint32_t)(uintptr_t)TX_POOL;
    TX_POOL[0] = 0u;
    ETH_MACCR = 1u;
    return 0;
}
