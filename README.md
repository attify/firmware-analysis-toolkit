# FAT — Firmware Analysis Toolkit

**Firmware Analysis Toolkit** is a security research toolkit for investigating firmware security for IoT, Physical AI, Mobile Devices & Robotics. It is primarily built for the ["Offensive IoT Exploitation"](https://www.attify.com/training) training conducted by [Attify](https://attify.com).

It has been built based on actual hands-on field experience of what really matters when it comes to real firmware security investigations that matter.

FAT's goal is not just to build an exceptional world-class cutting-edge toolkit for Firmware Security Research, but also forge professionals and practitioners who operate at their peak, where the tool becomes a cognitive superpower if used in certain ways, while being easy enough to be used by those who are new to the field.

Some of the features include classifying unknown firmware, extracts filesystems, maps trust-relevant code, traces taint, and coordinating QEMU emulation.

## What FAT can analyze

- **Unknown blobs and directories:** containers, compressed members, high-entropy regions, MCU signals, and candidate firmware files
- **Firmware images:** headers, update envelopes, partitions, bootloaders, and image-to-image differences
- **Extracted Linux filesystems:** inventory, startup intent, trust-bearing binaries, crypto material, and string evidence
- **ELF binaries:** imports, exports, handler tables, stripped-code sinks, decompilation, and source-to-sink taint
- **Bare-metal and MCU images:** vector tables, memory maps, peripheral hints, flash-write authority, and boot handoff evidence
- **Edge AI artifacts:** MAGIK/JZDL, TFLite, ONNX, and Qualcomm DLC files plus visible inference runtimes
- **Android applications:** APK inventory, discovery leads, locality, capability chains, and handoff boundaries
- **Source repositories:** invariant queries, patch guidance, and nearby variant searches

## Quick start

Clone the repository, build with Rust 1.90 or newer, and install:

```bash
git clone https://github.com/attify/firmware-analysis-toolkit.git
cd firmware-analysis-toolkit
cargo build --release --locked
cargo install --path crates/fat_cli --locked
fat doctor
```

One-Shot Installer:

```bash
./scripts/install.sh --install-system-deps
```

Refer [INSTALL.md](INSTALL.md) for more customization in the installation process.

## Quick Command Ref. 

- Help : `fat -h`
- Identify a firmware: `fat $firmware` or `fat identify --file $firmware`
- New Project : `fat new $firmware`
- Extract file system : `fat extract $firmware`
- Analyze : `fat analyze $firmware`
- Emulation : `fat emulate --project $firmware`


### First contact with an unknown file

```bash
fat ./firmware.bin
fat inspect update --file ./firmware.bin --rootfs ./rootfs --reference ./older.bin
```

### Image to Runtime

The pipeline from Quick start, end to end:

```bash
fat new ./firmware.bin
fat extract .fat-projects/firmware
fat analyze .fat-projects/firmware
fat preflight .fat-projects/firmware
fat emulate --project .fat-projects/firmware
```

### Binary triage and data flow

```bash
fat r2-triage --file ./usr/sbin/httpd --json
fat taint --file ./www/cgi-bin/diag.cgi --summary
fat taint-query --file ./www/cgi-bin/diag.cgi
fat taint-cross --rootfs ./rootfs
fat taint-cross --rootfs ./rootfs --source-profile ./my-target-models.yaml --state-profile ./my-target-state.yaml
```

### Shell script data flow

```bash
fat taint --lang shell --file ./app/init/wifi.sh --summary
fat taint --lang shell --rootfs ./extracted-rootfs --json
fat taint --lang shell --rootfs ./extracted-rootfs --source-profile ./my-target-shell.yaml --severity high
```

### Stripped binaries

Find sinks statically, then prepare runtime hooks for the same addresses:

```bash
fat r2-triage --file ./usr/sbin/httpd --json
fat sink-discovery --file ./usr/sbin/httpd --json > sinks.json
fat handler-table --file ./usr/sbin/httpd --json > handlers.json
fat taint --file ./usr/sbin/httpd --sink-candidates sinks.json --json > taint.json
fat instrument-hooks --from-sinks sinks.json --output hooks.yaml
fat emulate --project .fat-projects/firmware --instrument hooks.yaml
```

### Filesystem-wide evidence sweep

```bash
fat tree --rootfs ./rootfs --profile inventory --summary --json
fat search --rootfs ./rootfs --profile credentials -I --context 2
fat startup-map --rootfs ./rootfs --profile cloud-tls
fat crypto-census --rootfs ./rootfs
fat trust-map --rootfs ./rootfs
```

### Source-backed invariant query

```bash
fat invariant query \
  --fixture tests/fixtures/query/source/invariant-permission \
  --rule 'Every privileged override method must call enforcePermission()'
fat patch check --help
fat verify --help
```


## Security

- Emulation executes untrusted vendor code.
- Review [SECURITY.md](SECURITY.md) before processing untrusted images or exposing an emulated service to a network.
- It is your responsibility to have authorisation for the targets you work on.

## Detailed Guides

| Document | What is in it? |
| --- | --- |
| [INSTALL.md](INSTALL.md) | External tools and optional component setup |
| [docs/commands.md](docs/commands.md) | Full command reference, grouped by task |
| [docs/capabilities.md](docs/capabilities.md) | Graph export, string search, crypto, Edge AI, startup intent, rehosting packs |
| [docs/epistemics.md](docs/epistemics.md) | How to read FAT output: what results do and do not prove |
| [docs/architecture.md](docs/architecture.md) | Workspace crates and extension points |
| [DEVELOPMENT.md](DEVELOPMENT.md) | Build and test workflow |
| [CONTRIBUTING.md](CONTRIBUTING.md) | Setup, PR checklist, and contribution guide |

## Citation

If you use FAT in research, publications, or technical reports, please cite it using the **Cite this repository** option on GitHub. Include the FAT version or commit used so readers can identify the implementation behind your results. See [CITATION.cff](CITATION.cff) for citation metadata.

## Maintainers

FAT was authored by [adi0x90](https://github.com/adi0x90), who is also its current maintainer and principal contributor. The project is maintained under [Attify](https://www.attify.com/).

## License

FAT 2.0 is source available under [FSL-1.1-ALv2](LICENSE). See [LICENSING.md](LICENSING.md) and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for more details.
