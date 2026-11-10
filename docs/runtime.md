# Runtime Data

FAT keeps architecture-independent profiles, schemas, and helper resources in a versioned data tree. Release bundles place it at `share/fat` beside the executable prefix. 

Cargo and `cargo binstall` installations place only the executable, so they install the data explicitly:

```bash
fat data install --release
fat data status
fat data verify
fat data list
```

`--release` fetches `fat-data-<version>.zip` and its `.sha256` from the GitHub release for the running executable, verifies the digest and every manifest entry, and activates the version.
`--archive <path>` installs a local data directory or ZIP instead, for offline or pinned setups.

`fat data status` reports which origin supplied the active tree: an explicit path, `FAT_DATA_DIR` (`environment`), executable-relative bundled `share/fat`, the managed user root, or a marked development checkout. `FAT_DATA_DIR` may point directly at an unversioned reviewed data tree. 

The managed user-data root instead uses `active.json`; FAT verifies that referenced version and its manifest before it is considered ready.
An empty managed root with no active record is reported as `missing`.
A present malformed active record, or one that points to missing, incompatible, or unverifiable data, is reported as structured `broken` status (including origin/path fields in JSON), never as ready.

Release maintainers build the downloadable ZIP from the reviewed source files:

```bash
python3 scripts/build-runtime-data-bundle.py --check
release_version="$(awk -F'\"' '/^version = / { print $2; exit }' Cargo.toml)"
python3 scripts/build-runtime-data-bundle.py \
  --output "dist/fat-data-$release_version.zip"
```

The bundle contains example bootloader profiles, kernel metadata and configuration files, Android runtime helpers, setup READMEs, and license notices.
Its manifest pins every file by SHA-256 and declares compatibility with the accompanying FAT version.
Linux kernels, U-Boot images, the kernel builder image, APKs, and Android instrumentation runners are separate prerequisites.

The packaged READMEs explain each group's purpose and setup:

- `profiles/bootloader/README.md`: adapting example environment and QEMU values; the templates do not establish support for specific products.
- `profiles/kernels/README.md`: kernel selection and build resources, including how to build and check a candidate local builder from a source checkout.
- `scripts/discovery/android/README.md`: Python, ADB, device, APK, and instrumentation-runner prerequisites and execution effects.

The kernel builder record's `localhost/...` reference names a local image, not a download. The exact pinned image must be present before the offline kernel build can run. Container rebuilds require a digest comparison; a clean source checkout by itself does not supply a verified builder.

Download the data ZIP for your executable version from [FAT Releases](https://github.com/attify/firmware-analysis-toolkit/releases).
Asset URLs use this pattern, with `VERSION` replaced by the release version:

```text
https://github.com/attify/firmware-analysis-toolkit/releases/download/vVERSION/fat-data-VERSION.zip
https://github.com/attify/firmware-analysis-toolkit/releases/download/vVERSION/fat-data-VERSION.zip.sha256
```

`fat data install --release` verifies the adjacent `.sha256` asset before installing; when installing an archive by hand, verify it first. Installation preflights the ZIP and rejects oversized archives or central directories, path traversal, symlinks, duplicate or undeclared payloads, more than 1,024 entries, manifests over 1 MiB, and expanded output over 32 MiB. Streamed bytes are bounded independently of declared sizes, and no partially verified version is activated.

Resolution order is: command-level path, `FAT_DATA_DIR`, executable-relative `<exe_dir>/share/fat`, executable-relative `<exe_dir>/../share/fat`, platform user data, then a marked development checkout (debug builds only).
Within a managed root, a verified active version takes precedence over stale direct files.

Normal commands do not access the network. SHA-256 verification detects file changes but does not by itself authenticate a publisher; release signing is a separate launch gate.
