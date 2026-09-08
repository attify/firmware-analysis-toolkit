# Example bootloader profiles

`consumer-iot-camera.json` and `consumer-iot-plug.json` are example templates
for FAT bootloader workspaces. Their names describe example device categories;
they do not identify supported products or verified vendor boot chains.

FAT loads the selected profile when creating a bootloader workspace. The
profile supplies default environment values and QEMU settings. Workspace
creation also requires boot artifacts discovered in the project; a profile
alone cannot make a firmware image boot.

Review the following values against your firmware before using a template:

- Load address, boot command, console, and root filesystem arguments.
- QEMU executable and machine, which must match the intended boot setup.
- Signature-check flags, recovery settings, and rollback counters. These are
  example environment values, not observations of the device's security state
  or an implementation of signature verification.

For a custom profile, copy a template to
`profiles/bootloader/<name>.json` under your own data root, change its `name`
field to match the filename, and adapt its values. Set `FAT_DATA_DIR` to that
data root when selecting the profile. Keep customizations outside an installed
versioned data bundle so its manifest checksums remain valid.
