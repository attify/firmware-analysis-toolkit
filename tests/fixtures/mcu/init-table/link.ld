MEMORY {
  FLASH (rx) : ORIGIN = 0x08000000, LENGTH = 256K
  SRAM (rwx) : ORIGIN = 0x20000000, LENGTH = 64K
}
ENTRY(Reset_Handler)
SECTIONS {
  .text : {
    KEEP(*(.vectors))
    *(.text*) *(.rodata*)
  } > FLASH

  /* CMSIS copy/zero descriptor tables: the real ARM EABI startup shape */
  .copy.table : ALIGN(4) {
    __copy_table_start__ = .;
    LONG (LOADADDR(.data)) LONG (ADDR(.data)) LONG (SIZEOF(.data))
    __copy_table_end__ = .;
  } > FLASH

  .zero.table : ALIGN(4) {
    __zero_table_start__ = .;
    LONG (ADDR(.bss)) LONG (SIZEOF(.bss))
    __zero_table_end__ = .;
  } > FLASH

  .data : ALIGN(4) { *(.data*) . = ALIGN(4); } > SRAM AT > FLASH
  .bss  : ALIGN(4) { *(.bss*) *(COMMON) . = ALIGN(4); } > SRAM
  __StackTop = ORIGIN(SRAM) + LENGTH(SRAM);
}
