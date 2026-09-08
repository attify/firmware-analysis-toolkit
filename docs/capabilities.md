# Capabilities in depth

Usage details for selected capabilities. What each output does and does not prove is covered in [How to read FAT output](epistemics.md).

## Graph export

`inventory` is the neutral graph profile. It emits directories, files, file kinds, SHA-256 hashes, and rabin2 import and export edges without adding research-specific labels.

```bash
fat graph export --rootfs ./rootfs --profile inventory --format json > inventory.json
fat ls --rootfs ./rootfs --profile inventory --json
fat tree --rootfs ./rootfs --profile inventory --summary --json
```

`update-authority` is an optional lens for update-trust research. It adds label assignments, rollups, update and decrypt path evidence, bounded assessment nodes, negative evidence, and symbol metadata.

```bash
fat graph export --rootfs ./rootfs --profile update-authority --output update-graph.json
fat label scan --rootfs ./rootfs --profile update-authority --emit json > update-graph.json
fat labels explain --rootfs ./rootfs --profile update-authority --path /sbin/updater --json
```

## String search

`fat search` scans printable firmware strings. By default it inspects ELF binaries under discovered filesystem candidates. Use `--all-files` for scripts and configuration, `-I` for case-insensitive matching, `--context N` for nearby strings, and `--profile credentials|urls|crypto|sinks|debug` for common security searches. JSON output uses `search-report/v2`.

## Crypto artifacts

`fat crypto-census` finds reused crypto artifacts across a filesystem and shows whether they appear on a governing update path. `fat crypto-extract` reports embedded artifacts with offsets, confidence, validation state, and trust-path context. Confirm runtime use through disassembly or instrumentation.

## Edge AI artifacts

`fat edge-ai scan` discovers four model families and reports library filename hints:

Use `fat edge-ai --help` or `fat edge-ai scan --help` for the full command reference.

| Format | Evidence collected |
| --- | --- |
| MAGIK/JZDL | MAGIK headers, input shapes, layer counts, and variants |
| TFLite | FlatBuffer files, embedded arrays, and ELF data |
| ONNX | ModelProto files |
| Qualcomm DLC | DLC candidates and metadata strings |

```bash
fat edge-ai scan --rootfs ./rootfs
fat edge-ai scan --rootfs ./rootfs --format magik,tflite --json
fat edge-ai scan --rootfs ./rootfs --format dlc --json > edge-ai-report.json
```

JSON output uses `schema_version: edge-ai-scan/v1` and stores format-specific details under `findings[].metadata`.

## Startup intent

`fat startup-map` resolves startup metadata to concrete binaries and attaches profile evidence such as strings, imports, and linked libraries.

## Rehosting packs

A rehosting pack is a YAML file containing device-specific knowledge needed to emulate a firmware image: the QEMU machine, init repairs, paths to materialize, network mode, and readiness validators.

FAT ships no packs. Device-specific knowledge is yours to supply, and a pack affects a run only after you point FAT at the directory holding it. Packs are discovered from:

1. any `--packs-dir <dir>` passed to `fat rehost match`, in the order given; then
2. directories in the colon-separated `FAT_REHOSTING_PACKS` environment variable.

With neither set, nothing is discovered and no pack is applied. `fat rehost match` reports which of your packs match an extracted firmware image.

```bash
fat rehost profiles validate ./my-packs/example-camera.yaml
fat rehost match .fat-projects/firmware --packs-dir ./my-packs
fat emulate --project .fat-projects/firmware --pack example/camera
fat emulate --project .fat-projects/firmware --experimental-rehosting
```

Unsupported partition roles and init repairs fail closed in the pack capability report. Network declarations remain degraded when the selected backend cannot prove their fidelity.
