# Golden fixtures for the startup init-descriptor table parser.
#
# The point of building these with a real toolchain is that the descriptor
# table layout, the literal-pool ordering and the copy/zero loop shapes come
# from GCC + ld, not from hand-assembled bytes. The parser is therefore
# validated against the shape real firmware actually has.
#
# Committed .bin files were produced with:
#
#   arm-none-eabi-gcc (GCC) 16.2.0
#   GNU ld (GNU Binutils) 2.47.20260726
#
# `make verify` re-builds and diffs against the committed binaries. A newer
# toolchain may legitimately produce different code; if `verify` fails, check
# the disassembly before re-recording the goldens with `make record`.
#
# Two formats are covered, which are genuinely different layouts:
#
#   cmsis-*.bin        CMSIS `startup_ARMCMx.c` style: a 12-byte-stride
#                      __copy_table of {src, dst, size} triples plus a
#                      separate 8-byte-stride __zero_table of {dst, size}
#                      pairs.
#   scatter-load.bin   scatter-load style: one 16-byte-stride table of
#                      {src, dst, size, handler} records, handler dispatched
#                      per record with the Thumb bit OR-ed in by the caller.
#   scatter-load-dma.bin
#                      same startup and linker script as scatter-load.bin, with
#                      an application that parks two DMA pools above the linker
#                      cap and drives the Ethernet MAC. Exercises the SRAM
#                      partition's runtime-literal scan and its DMA-master
#                      threat-model hint.
#   scatter-load-lz-*.bin
#                      four-record scatter-load table whose handlers are a word
#                      copy, a zero fill, an LZSS decompressor with a 3/4
#                      control-byte split, and a plain byte-wise memcpy. The
#                      memcpy is the false positive the handler classifier has
#                      to avoid; the -os/-o0 pair pins that the codec shape
#                      survives optimisation level.
#   system-init-rich.bin
#                      scatter-load startup whose SystemInit performs every
#                      side effect the SystemInit analysis classifies — FPU
#                      enable, flash wait states via a bic/orr read-modify-
#                      write, RCC bring-up, I/D cache enable, MPU programming,
#                      a bootloader sentinel check and the ART accelerator —
#                      plus one write to a peripheral it does not model, which
#                      must survive as an unclassified write.
#
# The -O0/-O2/-Os/cortex-m0 variants exist because the table *address* moves
# with optimisation level while the descriptor *contents* do not; the parser
# must not depend on either the address or the literal-pool ordering (GCC
# emits the bounds as `end, start, start, end` at -Os and
# `start, end, start, end` at -O0).

CC      := arm-none-eabi-gcc
OBJCOPY := arm-none-eabi-objcopy
CFLAGS  := -mthumb -nostdlib -nostartfiles -ffreestanding -Wall -Wextra

CMSIS_SRC   := startup.c main.c
SCATTER_SRC := startup16.c main.c
DMA_SRC     := startup16.c main-dma.c
LZ_SRC      := startup-lz.c main-lz.c
SYSINIT_SRC := startup-sysinit.c main.c

GOLDEN := cmsis-copy-zero-os.bin cmsis-copy-zero-o0.bin cmsis-copy-zero-o2.bin \
          cmsis-copy-zero-m0.bin scatter-load.bin scatter-load-dma.bin \
          scatter-load-lz-os.bin scatter-load-lz-o0.bin system-init-rich.bin

.PHONY: all verify record clean
all: $(GOLDEN)

cmsis-copy-zero-os.elf: $(CMSIS_SRC) link.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m4 -Os -T link.ld $(CMSIS_SRC) -o $@

cmsis-copy-zero-o0.elf: $(CMSIS_SRC) link.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m4 -O0 -T link.ld $(CMSIS_SRC) -o $@

cmsis-copy-zero-o2.elf: $(CMSIS_SRC) link.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m4 -O2 -T link.ld $(CMSIS_SRC) -o $@

cmsis-copy-zero-m0.elf: $(CMSIS_SRC) link.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m0 -Os -T link.ld $(CMSIS_SRC) -o $@

scatter-load.elf: $(SCATTER_SRC) link16.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m7 -Os -T link16.ld $(SCATTER_SRC) -o $@

scatter-load-dma.elf: $(DMA_SRC) link16.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m7 -Os -T link16.ld $(DMA_SRC) -o $@

scatter-load-lz-os.elf: $(LZ_SRC) link-lz.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m7 -Os -T link-lz.ld $(LZ_SRC) -o $@

scatter-load-lz-o0.elf: $(LZ_SRC) link-lz.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m7 -O0 -T link-lz.ld $(LZ_SRC) -o $@

system-init-rich.elf: $(SYSINIT_SRC) link16.ld
	$(CC) $(CFLAGS) -mcpu=cortex-m7 -Os -T link16.ld $(SYSINIT_SRC) -o $@

# objcopy inherits the ELF's exec bit; the goldens are data, so normalise the
# mode or every re-record shows up as a spurious 100644 -> 100755 diff.
%.bin: %.elf
	$(OBJCOPY) -O binary $< $@
	@chmod 644 $@

verify:
	@tmp=$$(mktemp -d); \
	for f in $(GOLDEN); do cp $$f $$tmp/$$f.golden; done; \
	$(MAKE) --no-print-directory all >/dev/null; \
	status=0; \
	for f in $(GOLDEN); do \
	  if cmp -s $$f $$tmp/$$f.golden; then echo "ok   $$f"; \
	  else echo "DIFF $$f"; status=1; fi; \
	done; \
	rm -rf $$tmp; exit $$status

record: all

clean:
	rm -f *.elf
