# Runtime Data

FAT keeps architecture-independent profiles, schemas, and helper resources in a versioned data tree. Release bundles place it at `share/fat` beside the executable prefix. 

Cargo installations use an explicit local installation:

```bash
fat data install --archive ./fat-data-VERSION.zip
fat data status
fat data verify
fat data list
```

`fat data status` reports which origin supplied the active tree: an explicit path, `FAT_DATA_DIR` (`environment`), executable-relative bundled `share/fat`, the managed user root, or a marked development checkout. `FAT_DATA_DIR` may point directly at an unversioned reviewed data tree. 

The managed user-data root
instead uses `active.json`; FAT verifies that referenced version and its manifest before it is considered ready. An empty managed root with no active record is reported as `missing`. A present malformed active record, or one that points to missing, incompatible, or unverifiable data, is reported as structured `broken` status (including origin/path fields in JSON), never as ready.

Release maintainers build the downloadable ZIP from the reviewed source files:

```bash
python3 scripts/build-runtime-data-bundle.py --check
python3 scripts/build-runtime-data-bundle.py \
  --output dist/fat-data-2.0.0-alpha.1.zip
```

The bundle contains two example bootloader profiles, 21 kernel metadata and configuration files, three Android runtime helpers, and a README for each group. Its manifest pins every file by SHA-256 and declares compatibility with FAT 2.0.0 alpha releases. Linux kernels, U-Boot images, the kernel builder image, APKs, and Android instrumentation runners are separate prerequisites.

The packaged READMEs explain each group's purpose and setup:

- `profiles/bootloader/README.md`: adapting example environment and QEMU values; the templates do not establish support for specific products.
- `profiles/kernels/README.md`: kernel selection and build resources, including how to build and check a candidate local builder from a source checkout.
- `scripts/discovery/android/README.md`: Python, ADB, device, APK, and instrumentation-runner prerequisites and execution effects.

The kernel builder record's `localhost/...` reference names a local image, not a download. The exact pinned image must be present before the offline kernel build can run. Container rebuilds require a digest comparison; a clean source checkout by itself does not supply a verified builder.

Official data assets use the exact URL pattern:

```text
https://github.com/attify/firmware-analysis-toolkit/releases/download/v2.0.0-alpha.1/fat-data-2.0.0-alpha.1.zip
https://github.com/attify/firmware-analysis-toolkit/releases/download/v2.0.0-alpha.1/fat-data-2.0.0-alpha.1.zip.sha256
```

Verify the adjacent `.sha256` file before `fat data install`. Installation preflights the ZIP and rejects oversized archives or central directories, path traversal, symlinks, duplicate or undeclared payloads, more than 1,024 entries, manifests over 1 MiB, and expanded output over 32 MiB. Streamed bytes are bounded independently of declared sizes, and no partially verified version is activated.

Resolution order is: command-level path, `FAT_DATA_DIR`, executable-relative `../share/fat`, platform user data, then a marked development checkout. Within a managed root, a verified active version takes precedence over stale direct
files.

Normal commands do not access the network. SHA-256 verification detects file changes but does not by itself authenticate a publisher; release signing is a separate launch gate.
