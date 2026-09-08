MEMORY {
  FLASH (rx)  : ORIGIN = 0x08000000, LENGTH = 2M
  SRAM  (rwx) : ORIGIN = 0x24000000, LENGTH = 512K
}
ENTRY(Reset_Handler)
SECTIONS {
  .text : { KEEP(*(.vectors)) *(.text*) *(.rodata*) } > FLASH
  .packed : ALIGN(4) {
    __packed_start__ = .;
    KEEP(*(.packed))
    . = ALIGN(4);
    __packed_end__ = .;
  } > FLASH
  .init.table : ALIGN(4) {
    __init_table_start__ = .;
    LONG(LOADADDR(.data))  LONG(ADDR(.data))     LONG(SIZEOF(.data))     LONG(copy_fn)
    LONG(0)                LONG(ADDR(.bss))      LONG(SIZEOF(.bss))      LONG(zero_fn)
    LONG(__packed_start__) LONG(ADDR(.unpacked)) LONG(SIZEOF(.unpacked)) LONG(unpack_fn)
    LONG(__packed_start__) LONG(ADDR(.bytewise)) LONG(SIZEOF(.bytewise)) LONG(bytecopy_fn)
    __init_table_end__ = .;
  } > FLASH
  .data : ALIGN(4) { *(.data*) . = ALIGN(4); } > SRAM AT > FLASH
  .bss  : ALIGN(4) { *(.bss*) *(COMMON) . = ALIGN(4); } > SRAM
  .unpacked (NOLOAD) : ALIGN(4) { *(.unpacked) . = ALIGN(4); } > SRAM
  .bytewise (NOLOAD) : ALIGN(4) { *(.bytewise) . = ALIGN(4); } > SRAM
  __StackTop = ADDR(.bytewise) + SIZEOF(.bytewise);
}
