# Emulating BMC firmware

FAT can boot supported ASPEED images using an explicit, hash-pinned rehosting profile. The native runtime provides private flash staging, loopback HTTPS forwarding, serial capture, a QEMU monitor, GDB, and stop/status handling. These features were added after v2.0.1 and require a build that includes BMC emulation profiles.

See the [real-image validation report](bmc-emulation-validation-2026-10-19.md) for the tested images, service responses, debugger checks and remaining compatibility limits.

## Boot modes

| Mode | Executed firmware | Adaptations |
|---|---|---|
| Full flash | Original bootloader, kernel and filesystems on a QEMU board | Private flash copy and ephemeral QEMU snapshot writes |
| Vendor kernel | Original SHA-256-checked FIT kernel, DTB and optional initramfs; original flash filesystems | Bypasses SPL/U-Boot; explicit boot arguments and optional DTB node disabling |

Both modes require an exact input SHA-256 and explicit board/flash geometry. Neither imports raw bootloader string hints. FIT payload hashes check integrity; they do not authenticate firmware or demonstrate hardware boot enforcement.

## Start a session

Install `qemu-system-arm` with ASPEED board support and `curl`. QEMU 11.0.2 was used for the recorded runs. GDB is optional for debugging; interactive console/monitor attach requires netcat with Unix socket support. Use case-sensitive storage for extraction on macOS.

```bash
fat new ./obmc-phosphor-image-romulus.static.mtd --name romulus
fat extract .fat-projects/romulus --extractor native
fat analyze .fat-projects/romulus
fat rehost profiles list
fat rehost profiles show bmc-romulus --json
fat emulate --project .fat-projects/romulus --pack bmc-romulus
fat emulate --project .fat-projects/romulus --status
```

FAT prints the allocated HTTPS, GDB and Unix socket endpoints. `--status` performs a fresh, bounded HTTPS probe of `/redfish/v1/`, requiring HTTP 200 and a JSON ServiceRoot. Once that succeeds, it also records the unauthenticated `/redfish/v1/Managers` status. Plain-text 401 bodies are supported. A running QEMU process or an open forwarded socket alone does not validate Redfish readiness. Startup can take several minutes.

The probe ignores curl configuration, credentials and proxies, does not follow redirects, and accepts the firmware's self-signed TLS certificate only at the recorded loopback endpoint. Certificate verification is explicitly reported as false. A 401 records denial for this request, not a complete authentication audit.

For the supported ASUS HPM image, use the same project workflow with `--pack bmc-asus-bhs-1.20.02`. It selects the original Z14PN kernel/DTB and disables `/ahb/apb/hace@1e6d0000`: the tested QEMU HACE implementation lacks the cipher operation needed by this firmware. This change is recorded in the boot manifest. Sensor, I2C and host-device errors remain visible.

BMC profiles select the native `qemu-direct` system runtime. Do not pass `--port`, `--kernel-class`, generic partition repairs, or another backend. Each emulated MAC uses a distinct restricted user-network subnet; only the profile's management MAC forwards HTTPS to loopback. No guest outbound network access is enabled.

## Profiles and input identities

Embedded profiles require explicit `--pack` selection. `fat rehost match` continues to search operator-supplied directories; it does not automatically apply embedded BMC adaptations.

| Profile | Image | Mode | Input SHA-256 |
|---|---|---|---|
| `bmc-romulus` | OpenBMC Romulus static MTD, 32 MiB | Full flash | `7d4f776b5e1728abc1624fb698149b50425dd4efd8e2df8b711046f8649c0461` |
| `bmc-romulus-vendor-kernel` | Same Romulus image | Vendor kernel + original initramfs | Same hash as above |
| `bmc-tiogapass` | OpenBMC TiogaPass static MTD, 32 MiB | Full flash | `36395de059fcd98f316c3d4399b3110befaa176406afa00d1f84292f3933393e` |
| `bmc-asus-bhs-1.20.02` | ASUS ESC8000-E12 `BHS_Gen_1.20.02.hpm` | Vendor kernel; HACE disabled | `20954d5d143552ba68be44902d3de17828d88d8f2eb5e86cd2a6584fd75f3a81` |
| `bmc-aspeed-ast2500-v11.04` | ASPEED v11.04 AST2500 default Linux 6.12 static MTD, 32 MiB | Full flash | `a6befbd5b957a7662516b2795b05c3d9176a18eb4caeeb6e059c6efdeaef4e69` |

The ASPEED image comes from the official [v11.04 release](https://github.com/AspeedTech-BMC/openbmc/releases/tag/v11.04), asset `ast2500-default-612-obmc.tar.gz` (archive SHA-256 `29986e9ecfa7527f00db78f3bf2f7385964cda106a1b68db5295bdc7bb6397b0`). Select its `obmc-phosphor-image-ast2500-default-612.static.mtd` member, not the compressed archive, as the project input. Firmware binaries and extracted filesystems are not distributed with FAT.

## Debug and stop

```bash
fat debug surfaces --project .fat-projects/romulus --json
fat debug monitor --project .fat-projects/romulus --command 'info status'
fat debug gdb --project .fat-projects/romulus --command 'info registers'
fat debug gdb --project .fat-projects/romulus --command 'x/8i $pc'
fat debug shell --project .fat-projects/romulus
fat emulate --project .fat-projects/romulus --stop
```

The shell command attaches to the serial console for interactive login; it does not supply credentials or execute `--command` over an unauthenticated console. GDB connects to the whole-system QEMU stub. Register and instruction inspection work without symbols; source debugging requires a matching symbol-bearing ELF. This is separate from attaching a userspace gdbserver to a particular daemon.

For a controlled readiness check, `fat debug monitor --command stop` pauses the guest; `--status` should then report Redfish not ready. Resume with `fat debug monitor --command cont` and check again. The QEMU process remains running during this test. Stopped/failed runs retain historical observations but no longer advertise current attachable debug surfaces.

Per-run staging under `work/rehosting/` contains:

- `bmc-boot-manifest.json`: source hash, profile, runtime version, command, asset hashes, boot-chain bypass and DTB changes.
- `flash.bin`: the private flash region; QEMU snapshot changes are discarded on stop.
- `kernel.bin`, `original.dtb`, `boot.dtb`, and optional `initrd.bin` for vendor-kernel mode.
- `serial.log`, `qemu-devices.log`, stdout and stderr logs.

Runtime outputs also contain `bmc-service-state.json` with the latest timestamped HTTP observation and debug command transcripts. Keep these with the source image identity when comparing runs.

## Add another BMC image

Copy a profile from [`crates/fat_cli/assets/bmc`](../crates/fat_cli/assets/bmc), or export `fat rehost profiles show <id> --json` and use its `pack` object as a local YAML/JSON profile. Set its own ID, exact source digest, flash offset/size and a compatible [QEMU ASPEED board](https://www.qemu.org/docs/master/system/arm/aspeed.html). Machine names and versions alone do not establish compatibility.

Start with full flash. If a direct boot experiment is needed, specify FIT-relative kernel, DTB and optional initrd node names plus explicit boot arguments in `vendor_kernel`. `fit_offset` is relative to the carved flash, while `flash_offset` is relative to the original input. This version supports inline, uncompressed FIT payload declarations with SHA-256 hashes, not external FIT data or automatic decompression. Declare `modified_fixture: true` for vendor-kernel boot, including when its original DTB is unchanged. Missing nodes, corrupt hashes and out-of-range regions fail before QEMU starts.

BMC readiness currently supports exactly the `redfish-service` HTTP validator on port 443 at `/redfish/v1/`. Other custom validators are rejected rather than silently ignored. Use the serial and debugger evidence to investigate images without Redfish support.

```bash
fat rehost profiles validate ./my-bmc.yaml
fat emulate --project .fat-projects/my-bmc --pack ./my-bmc.yaml
```

Keep an unadapted control when changing device-tree properties. Recovery of web/Redfish services does not establish physical sensor fidelity, host management behavior, update-signature enforcement, or secure boot on hardware.
