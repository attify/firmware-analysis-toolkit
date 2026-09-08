# Third-Party Notices

FAT source code is distributed under the repository license. Rust and Python
dependencies remain subject to the licenses declared by their respective
projects. The locked Rust dependency graph is checked against `about.toml` by
`scripts/generate-third-party-licenses.sh`. Every binary release bundle must
include the generated `third-party-licenses.json`, which contains the detected
license expressions, copyright notices, and license texts.

The public source tree intentionally does **not** redistribute firmware images,
Linux kernel binaries, U-Boot binaries, proprietary model files, or extracted
device filesystems. Configuration records may identify external tools or asset
classes, but they do not grant a right to obtain or redistribute those assets.

Users are responsible for acquiring external analysis targets and emulation
assets lawfully and for complying with their licenses. SHA-256 verification
establishes file identity only; it does not establish publisher authenticity or
legal permission.

The optional external-asset verifier recognizes two Linux kernel files observed
in a local FirmAE installation by SHA-256. FirmAE ignores its `binaries/`
directory, so FAT has not established their source revision, license, build
configuration, or corresponding-source completeness. They are never included
in FAT source, data bundles, crates, or release archives. Redistribution must
remain disabled until those obligations are independently resolved.

## Optional QEMU hook

`scripts/fat-hook-plugin.c` is separately licensed GPL-2.0-or-later; see `LICENSES/GPL-2.0-or-later.txt`.
QEMU plugin API headers must be checked at the exact supported QEMU revision.
Do not assume a permissive header exception.
Build and redistribution review must include QEMU/GLib terms, source, notices and any combined-work obligations.
No compiled QEMU hook or QEMU executable belongs in an ordinary FAT release bundle.

Historical FAT 1.x QEMU downloads are a separate distribution record.
Replacing the source tree does not remove release-body attachments or resolve obligations from earlier binary distribution.
A written source offer is one GPLv2 compliance route, not an automatic requirement for every distribution.
Attify must review what was actually distributed and which source/offer route applied.
