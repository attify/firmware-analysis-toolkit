MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2M
  SRAM  (rwx) : ORIGIN = 0x24000000, LENGTH = 512K
}
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
  .init.table : ALIGN(4) {
    __init_table_start__ = .;
    LONG(LOADADDR(.data)) LONG(ADDR(.data)) LONG(SIZEOF(.data)) LONG(copy_fn)
    LONG(0)              LONG(ADDR(.bss))  LONG(SIZEOF(.bss))  LONG(zero_fn)
    __init_table_end__ = .;
  } > FLASH
  .data : ALIGN(4) { *(.data*) . = ALIGN(4); } > SRAM AT > FLASH
  .bss  : ALIGN(4) { *(.bss*) *(COMMON) . = ALIGN(4); } > SRAM
  __StackTop = ADDR(.bss) + SIZEOF(.bss);
}
