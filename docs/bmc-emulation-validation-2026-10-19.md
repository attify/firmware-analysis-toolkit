# BMC emulation validation — 2026-10-19

FAT's native runtime was exercised with four real firmware images on macOS using QEMU 11.0.2. Each image went through a fresh `fat new`, native extraction, analysis, profile selection, launch, status probes and cleanup. Extraction projects used case-sensitive APFS storage. Firmware and extracted filesystems remain outside this repository.

## Service results

The HTTP columns are actual unauthenticated HTTPS requests through FAT's allocated loopback forwarding. ServiceRoot success requires a JSON Redfish ServiceRoot, not merely HTTP 200. Self-signed certificates were accepted; certificate trust was not validated.

| Image | Mode / profile | ServiceRoot | Managers | Result |
|---|---|---|---|---|
| OpenBMC Romulus | Full flash / `bmc-romulus` | 200, valid JSON | 401 | Service reachable |
| OpenBMC Romulus | Original FIT kernel, DTB and initramfs / `bmc-romulus-vendor-kernel` | 200, valid JSON | 401 | Service reachable; U-Boot bypassed, DTB unchanged |
| ASUS ESC8000-E12 BHS 1.20.02 | Vendor kernel / `bmc-asus-bhs-1.20.02` | 200, valid JSON | 401 | Service reachable with HACE disabled |
| ASUS ESC8000-E12 BHS 1.20.02 | Unadapted full-flash control | No response | No response | Boot/service compatibility failure; not a supported full-flash profile |
| OpenBMC TiogaPass | Full flash / `bmc-tiogapass` | 200, valid JSON | 401 | Service reachable |
| ASPEED v11.04 AST2500, Linux 6.12 | Full flash / `bmc-aspeed-ast2500-v11.04` | 200, valid JSON | 401 | Service reachable |

Input hashes and the official ASPEED download are listed in [BMC emulation](bmc-emulation.md#profiles-and-input-identities). The ASPEED archive SHA-256 matched its GitHub release asset digest before selecting the static MTD member. These results apply to those exact images and QEMU version.

## ASUS adaptations and control

The source HPM SHA-256 is `20954d5d143552ba68be44902d3de17828d88d8f2eb5e86cd2a6584fd75f3a81`. The flash region starts at byte 165 and spans 64 MiB. Its SHA-256 is `b11136a051e0f91497d565f7f36869cea715559e567688fdc4d8316dd4c0732e`.

The vendor-kernel profile extracts `kernel@1` and `fdt@Z14PN.dtb` from the FIT at flash-relative `0x27d0040`, verifies their declared SHA-256 hashes, and records:

- Original kernel: `9f9a887b9800aad5bdfced358654d6db5dec7d304c18230395a049d2112ddd91`.
- Original DTB: `a36c6aa6dffbd3d8b92dbb0ad556fb0fd45c197224a200ec99c6d6b309915bca`.
- Adapted DTB: `5b625c6ad311608949118b184dbd4167017c97d9d404513e3dba734558a44a91`.
- One property change: `/ahb/apb/hace@1e6d0000/status`, `okay` to `disabled`.
- Explicit boot arguments: `root=/dev/mtdblock2 ro ip=none console=ttyS4,115200 rootfstype=squashfs imagebooted=1`.

The original kernel and filesystem bytes are retained. Direct boot bypasses SPL/U-Boot. Four NICs use distinct restricted subnets; management HTTPS is forwarded only on loopback. This prevents the duplicate DHCP addressing observed when all NICs used the same user-network subnet.

The full-flash control retains the original bootloader and DTB. Its serial log shows an initial root-mount panic (`unknown-block(0,0)`) followed by a watchdog restart. QEMU reports `aspeed_hace_write: Crypt commands not implemented`. The restarted guest logs `UDSIfcTask` blocked for more than 122 seconds, with a backtrace through `wait_for_completion`, `crypto_helper_dev_cipher_encrypt` and `crypto_helper_dev_ioctl`, followed by a hung-task panic at guest uptime 244 seconds. Redfish did not answer the recorded probes. This agrees with the missing cipher implementation in [QEMU's ASPEED HACE model](https://github.com/qemu/qemu/blob/v11.0.2/hw/misc/aspeed_hace.c). The root-mount failure and HACE limitation are separate observations; disabling HACE is not a fix for full-flash boot selection.

## Debugging and readiness checks

FAT's recorded QEMU monitor returned `VM status: running` for all four images. GDB register reads worked on Romulus, ASUS and TiogaPass, and instruction disassembly worked on ASUS and ASPEED. The ASUS serial attach displayed a login prompt without supplying credentials. These are whole-system debug surfaces; userspace daemon symbols and authenticated management operations were not tested.

Pausing Romulus with `fat debug monitor --command stop` kept QEMU alive while FAT's next status probe changed Redfish to not ready. Resuming with `cont` restored the 200/401 observations. This checks that readiness tracks current guest responses rather than a cached successful probe or a listening host port.

All validation sessions were stopped through FAT. Source and staged asset hashes were checked after execution, allocated TCP listeners closed, and stopped sessions exposed no current debug surfaces. Per-run manifests, serial/device logs, HTTP bodies/headers, debug transcripts and cleanup records were retained outside Git.

## Automated verification and limits

- Workspace tests: 2,072 passed, one ignored, zero failed.
- Formatting, strict workspace Clippy, kernel-profile consistency and runtime-data validation passed.
- Installer tests: 39 passed.
- Synthetic regression tests cover malformed profiles/FDTs, FIT digest failures, exact DTB changes, staging failures, canonical validators, non-JSON 401 responses, Unix monitor exchange and inactive debug surfaces.

This validates emulated service reachability and debug access. Sensor readings, host interfaces, authenticated management operations, firmware updates and hardware boot enforcement remain unvalidated. ASUS still logs missing sensor/I2C/host-device behavior. A 401 on Managers establishes denial for that request only. See [adding another BMC image](bmc-emulation.md#add-another-bmc-image) for the supported profile contract and its FIT limitations.
