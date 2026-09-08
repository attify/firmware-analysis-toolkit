#include <stdint.h>
volatile uint32_t initialized_data = 0xDEADBEEF;  /* -> .data, needs copy */
volatile uint32_t zeroed_bss[64];                 /* -> .bss,  needs zero */
int main(void) { zeroed_bss[0] = initialized_data; return 0; }
