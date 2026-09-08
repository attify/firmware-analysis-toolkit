## Experimental U-Boot Backend Scaffold

This experimental backend provides QEMU/U-Boot launch scaffolding for
bootloader labs. FAT does not redistribute a U-Boot binary. Supply an
authorized image through `FAT_UBOOT_ASSET`, a compatible project bootloader,
or a host QEMU installation that provides one.

What FAT does today:
- prepares `bootloader/qemu/launch.json`
- records a serial log path at `bootloader/qemu/serial.log`
- prefers a compatible project or explicitly supplied asset, then falls back
  to host-discovered assets
- discovers host QEMU binaries such as `qemu-system-ppc`, `qemu-system-arm`
- exposes `fat bootloader emulate` and `fat bootloader console`
- runs QEMU inside a tmux session and captures UART output with `tmux pipe-pane`

Current limitations:
- no public release bundle includes a generic or device U-Boot image
- target-family realism is still driven mostly by the imported environment and
  workspace artifacts, not by a family-matched bundled bootloader binary
- `fat bootloader emulate` still reports a clear error when no runnable
  QEMU/U-Boot pairing is available on the host

Expected future direction:
- publish pinned acquisition/build documentation for a supported ARM U-Boot
  asset when its redistribution boundary is approved
- support the real autoboot interrupt and `printenv` / `setenv` workflow
