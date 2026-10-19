# BMC session and process debugging

These commands work with an already running native BMC session. Start with the [BMC emulation workflow](bmc-emulation.md). They were added after v2.0.1; build a revision containing them. The [Romulus/ASUS validation report](bmc-session-validation-2026-10-19.md) records the tested firmware and adaptations.

## A controlled Redfish role test

Provision three distinct lab principals in the emulated snapshot: an administrator, an enabled ReadOnly reader, and an enabled ReadOnly target account. Finish any first-login password change for the reader before testing. Use a disposable target: the positive control temporarily sets its `Enabled` property to false, then restores it to true. FAT does not create accounts or change their passwords.

Store a private fixture outside the repository, with permissions such as `chmod 600 credentials.json`:

```json
{
  "admin": {"username": "labadmin", "password": "ADMIN_PASSWORD"},
  "reader": {"username": "fatreader", "password": "READER_PASSWORD"},
  "reader_account": "/redfish/v1/AccountService/Accounts/fatreader",
  "target_account": "/redfish/v1/AccountService/Accounts/fattarget",
  "target_username": "fattarget"
}
```

Replace account paths with the actual resource IDs. ASUS uses numeric IDs (5 and 6 in the recorded run); names and IDs need not match. The fixture accepts simple usernames and direct account paths, without URLs, query strings or escaped path components.

```bash
fat debug redfish-session --project .fat-projects/romulus \
  --fixture ./credentials.json --allow-account-mutation --json
```

The experiment checks these observations in order:

1. Administrator and reader session creation return 201 with usable session handles. The reader is enabled, ReadOnly, unlocked and not awaiting a password change.
2. Anonymous access to `/redfish/v1/Managers` returns 401; the reader receives a valid collection with 200.
3. The reader's PATCH of the other account's `Enabled` property returns 403, and the administrator observes unchanged account identity, role and state.
4. The administrator performs the same PATCH successfully, and a fresh GET confirms `Enabled: false`. PATCH uses the current ETag, or `If-Match: *` when none was returned.
5. Reader logout succeeds and reuse of its token returns 401.
6. Cleanup restores and verifies the target, deletes created sessions and verifies revocation. Restoration is attempted even when a mutation request loses its response.

A 403 from a password-change gate does not pass this test. The administrator positive control demonstrates that the tested mutation is supported. This covers one cross-account authorization operation and session lifecycle, not every Redfish role or endpoint.

The command returns nonzero if a check or cleanup fails. A lost login response can leave an unknown session handle, so it cannot report cleanup success. Inspect the guest after a cleanup failure; stopping a snapshot session discards its lab changes. Cleanup covers ordinary request failures, not a killed FAT process or host failure.

Requests go only to the selected runtime's loopback HTTPS endpoint. Self-signed TLS is accepted and reported explicitly; redirects, proxies and curl configuration are excluded. Passwords and tokens use private temporary files rather than command arguments. The saved report contains statuses and selected account-state observations, without credentials, tokens or raw response bodies.

## Attach to a userspace daemon

Requirements: a Unix host with `ssh` and GDB, a compatible guest `gdbserver`, an explicitly provisioned SSH key, and a guest account with ptrace permission. FAT does not install the debugger, discover passwords, or enable a guest shell. Use the guest PID, not QEMU's host PID.

```bash
fat debug process --project .fat-projects/romulus \
  --pid 161 --user root --identity-file ./lab-key \
  --gdbserver /tmp/fat-gdbserver \
  --sysroot .fat-projects/romulus/extracted --json
```

Replace PID 161 with the current daemon PID. A matching extracted rootfs avoids transferring executable/library files while the service is stopped. Without `--sysroot`, GDB reads files from the guest. Stripped binaries still provide registers, process maps and any exported dynamic symbols; source lines require matching debug symbols.

FAT creates a temporary SSH forward on `127.0.0.1` for the selected profile's management NIC. SSH verifies a newly learned guest host key in an isolated temporary known-hosts file, using only the supplied identity. GDB communicates with `gdbserver --once --attach - PID` over SSH; there is no guest GDB TCP listener. GDB startup scripts, auto-loading and debuginfod are disabled.

Default commands record inferiors, threads and a bounded backtrace, then detach. Repeat `--command` to insert commands before detach. For example, start this command and trigger a Redfish login from another terminal while it waits:

```bash
fat debug process --project .fat-projects/romulus \
  --pid 161 --user root --identity-file ./lab-key \
  --gdbserver /tmp/fat-gdbserver --sysroot .fat-projects/romulus/extracted \
  --command 'tbreak pam_authenticate' --command continue --command 'bt 8'
```

For the tested ASUS image, the login breakpoint is `PKCS5_PBKDF2_HMAC` in `libcrypto.so.3`, reached from `redfishinterface.so` in the LuaJIT Redfish daemon. Use entry-breakpoint capture and detach: stepping out with `finish` disrupted the recorded ASUS request and caused a process replacement. The short entry capture completed login with the same daemon. Symbol names alone do not identify every authentication path.

`--timeout` bounds the GDB phase, including symbol loading and breakpoint waits (default 120 seconds, maximum 600). Pre/post SSH identity probes have separate 15-second deadlines. Each helper transcript is capped at 8 MiB; overflow fails the command rather than reporting a complete transcript. A timeout kills the local debugger/SSH process group, then checks whether the same guest process resumed and removes the forward. Recovery is reported even though the timed-out command exits nonzero. If resume cannot be confirmed, inspect the serial console or stop the emulated session.

The report compares `/proc/PID/stat` start time, executable path and SHA-256 before and after attachment. It separately records detach, resumed state and forwarding cleanup. A replacement process does not count as success. The SHA-256 probe supports guest `sha256sum` or `openssl dgst -sha256`.

Both commands register uniquely named JSON artifacts with FAT's selected run. Process transcripts include output from your GDB commands: avoid credential or memory dumps in evidence intended for publication. Keep firmware, keys and private fixtures outside Git. `fat debug gdb` remains the separate whole-system QEMU debugger.
