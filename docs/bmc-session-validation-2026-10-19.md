# Romulus and ASUS session/role validation — 2026-10-19

Fresh projects were created, natively extracted, analyzed and booted from the two images below. The final FAT commands then ran a complete Redfish session/role experiment while a separate FAT process-debugging command captured an authentication entry breakpoint and detached. Both completed successfully with unchanged daemon identity. Commands and fixture format are in [BMC session and process debugging](bmc-session-debugging.md).

## Inputs and lab changes

| Target | Input SHA-256 | Boot profile |
|---|---|---|
| OpenBMC Romulus static MTD | `7d4f776b5e1728abc1624fb698149b50425dd4efd8e2df8b711046f8649c0461` | `bmc-romulus`: full flash |
| ASUS ESC8000-E12 `BHS_Gen_1.20.02.hpm` | `20954d5d143552ba68be44902d3de17828d88d8f2eb5e86cd2a6584fd75f3a81` | `bmc-asus-bhs-1.20.02`: vendor kernel, U-Boot bypass, HACE disabled |

The host was macOS with case-sensitive APFS extraction storage and QEMU 11.0.2. A static ARM EABI5 soft-float gdbserver was built from [GNU GDB 13.2 source](https://ftp.gnu.org/gnu/gdb/gdb-13.2.tar.xz) and copied into each guest's `/tmp`. GDB used matching extracted executables/libraries. Neither image supplied full daemon debug symbols.

Lab setup used authenticated console/Redfish access and ephemeral QEMU snapshot writes. It provisioned an SSH key and disposable `fatreader`/`fattarget` ReadOnly accounts. ASUS required the administrator's first-login password change and the reader's password-change completion. Its non-console `defshell` refused SSH commands; the lab explicitly changed the `sysadmin` shell to `/bin/sh` in `/conf/passwd`. These changes were not added to FAT's boot profiles and do not establish that an unmodified ASUS image exposes a usable SSH shell.

## Final HTTP observations

The target account started enabled. A fresh administrator GET checked state after each attempted mutation.

| Check | Romulus | ASUS |
|---|---:|---:|
| Administrator / reader session creation | 201 / 201 | 201 / 201 |
| Anonymous Managers GET | 401 | 401 |
| ReadOnly Managers GET | 200 | 200 |
| ReadOnly PATCH of other account `Enabled: false` | 403 | 403 |
| Target still enabled after denied PATCH | true | true |
| Administrator performs same PATCH | 200 | 204 |
| Target disabled after administrator PATCH | false | false |
| Reader session DELETE | 200 | 204 |
| Deleted token reused on Managers | 401 | 401 |
| Target restoration and fresh GET | 200; enabled | 204; enabled |
| Administrator session DELETE / token reuse | 200 / 401 | 204 / 401 |

All 17 checks per target passed, including cleanup. An earlier ASUS attempt encountered its password-change gate; it was retained as a setup failure and was not counted as authorization evidence. The final test completed that setup and exercised a usable ReadOnly session before the denied PATCH.

## Process observations and controls

| Target | Daemon | Authentication breakpoint | Final outcome |
|---|---|---|---|
| Romulus | `bmcweb`, PID 161 | `pam_authenticate` in `libpam.so.0` | Breakpoint hit; 8-frame native trace; detached; login 201; same process resumed |
| ASUS | LuaJIT Redfish server, PID 13065 | `PKCS5_PBKDF2_HMAC` in `libcrypto.so.3`, caller in `redfishinterface.so` | Breakpoint hit; partial native trace; detached; login 201; same process resumed |

The reported PID, start time, executable path and executable SHA-256 matched before and after each attachment. Both PIDs remained unchanged after the complete HTTP experiment. Each temporary SSH forward was confirmed removed. The ASUS native unwind stopped after three frames with GDB's identical-frame warning; Lua source-level tracing was not established.

Two controls delimit the debugger result:

- On Romulus, an intentionally stalled GDB command exceeded a two-second deadline. FAT returned exit 1 and `timed_out: true`; the same guest process resumed and the temporary forward was removed. This establishes recovery for that observed timeout, not every possible guest/debugger failure.
- On ASUS, exploratory `finish` commands after the password-derivation breakpoint produced HTTP 501 and process replacement. The entry-breakpoint/backtrace/detach sequence subsequently returned 201 without replacement. The cause of the step-out disruption remains unresolved; this report does not infer a watchdog trigger or a firmware vulnerability from it.

These observations cover one ReadOnly cross-account mutation, usable authenticated reads, session revocation and native authentication-entry tracing in the adapted emulated guests. They do not establish all role mappings, concurrent-session behavior, password-reset invalidation, Lua-level authorization flow, physical device behavior or hardware boot enforcement.

## Evidence

The local evidence archive `bmc-session-debug-20261019` contains input identities, fresh extraction/boot logs, build records, final session and process JSON reports, the timeout control and the failed exploratory ASUS traces. The final artifacts are `<target>/final-session.json`, `<target>/final-process.json`, `romulus/timeout-process.json` and `final-runtime-summary.json`. Reports are also registered with the corresponding FAT runs. Credentials, SSH keys, vendor firmware and extracted filesystems are kept outside Git.

After validation, both disposable accounts were deleted and GET returned 404 on each image. Both QEMU sessions were stopped and their HTTPS, GDB and setup SSH ports were confirmed closed. Original inputs, staged inputs and every staged boot asset retained their recorded SHA-256 digests.

Regression coverage includes unauthorized mutation, stale-token acceptance, password-change gates, lost responses after mutation, unknown session handles, unsafe resource paths, PID reuse, forward ownership, debugger deadlines, oversized transcripts and GDB sysroot handling. The documented commands require explicit lab credentials and account-mutation opt-in; no credentials or debugger payloads are bundled with FAT.

Validation passed: 2,085 workspace tests (one ignored), strict workspace Clippy, formatting, four kernel-profile consistency tests, runtime-data verification and 39 installer tests. Documentation links and the two command help pages were checked. A separate read-only code review found no remaining correctness blockers after cleanup and transcript-limit fixes.
