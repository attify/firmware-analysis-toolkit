#include <stdint.h>
volatile uint32_t initialized_data = 0xDEADBEEF;  /* -> .data,     needs copy   */
volatile uint32_t zeroed_bss[64];                 /* -> .bss,      needs zero   */
__attribute__((section(".unpacked")))
volatile uint8_t unpacked_area[16];               /* -> .unpacked, needs unpack */
__attribute__((section(".bytewise")))
volatile uint8_t bytewise_area[16];               /* -> .bytewise, byte-wise copy */
int main(void) {
    zeroed_bss[0] = initialized_data + unpacked_area[0] + bytewise_area[0];
    return 0;
}
