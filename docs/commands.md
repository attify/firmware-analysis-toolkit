# Command reference

`fat -h` lists every command grouped by task, starting with `identify` and `doctor`. `fat --help` adds common workflows and examples. Every subcommand also has its own `--help` output and examples. Help uses color in a terminal and stays plain when piped; `FAT_COLOR=always` forces color and `FAT_COLOR=never` disables it.

## Projects and extraction

| Command | Purpose |
| --- | --- |
| `new`, `list`, `info`, `delete` | Manage project workspaces under `.fat-projects/` |
| `identify` | Classify evidence in an unknown file or directory |
| `extract` | Recursively unpack firmware and record filesystem recovery and per-artifact outcomes |
| `extract-payload`, `carve` | Extract a known byte range or format-sized object |
| `analyze` | Derive project signals, findings, and the bootloader snapshot |
| `doctor` | Report external-tool and backend readiness |
| `data`, `kernel` | Install and verify runtime data and maintained kernels |

`fat extract firmware.zip --extractor native --json` uses the built-in container and filesystem decoders. The default `auto` selection retains fallback extraction when native recovery is incomplete. `recovery_status` is `rootfs_recovered`, `files_only`, or `partial`; the `artifacts` array explains each recognized branch. `work/native-artifacts.json` also preserves native outcomes when the command cannot produce a final manifest.

For firmware with case-distinct names, create the project on a case-sensitive volume: `fat new firmware.zip --projects-dir /path/to/case-sensitive/projects`, then extract that project. On macOS, use a case-sensitive APFS volume or disk image. Existing project and extractor-selection arguments remain available.

## Firmware structure and classification

| Command | Purpose |
| --- | --- |
| `inspect` | Inspect headers, layout, carved artifacts, or bare-metal metadata |
| `inspect update`, `inspect envelope` | Build update-envelope and trust-path evidence |
| `detect-encryption`, `compare` | Measure opaque wrappers and compare envelope boundaries |
| `diff role`, `diff firmware` | Compare binaries by role or projects across filesystem, configuration, and binary layers |
| `bootloader` | Inspect bootloader images, environments, handoff, and sessions |

## Filesystem evidence

| Command | Purpose |
| --- | --- |
| `ls`, `tree` | Inventory-oriented filesystem views with optional evidence-backed labels |
| `search`, `xref-search` | Search printable strings and resolve pointer or code references |
| `source-map`, `startup-map` | Map inputs to consumers and startup metadata to binaries |
| `trust-map`, `trust-boundary` | Identify governing update paths and trust boundaries |
| `crypto-census`, `crypto`, `crypto-extract` | Locate reused crypto material and embedded keys, certificates, or blobs |
| `edge-ai` | Discover Edge AI models and library filename hints |
| `android` | Analyze APK inventory, discovery leads, locality, and capability chains |

## Binary analysis

| Command | Purpose |
| --- | --- |
| `r2-triage` | Profile a binary with radare2 and rank audit targets |
| `sink-discovery`, `handler-table` | Find sink candidates and URL or command dispatch tables |
| `identify-launcher`, `inspect-handoff` | Detect thin launchers and inspect downstream implementation artifacts |
| `decompile` | Decompile one function mechanically with r2ghidra |
| `taint`, `taint-query`, `taint-cross` | Trace data flow, ask precise path questions, and stitch cross-binary state |
| `taint --lang shell` | Trace source-to-sink flows through shell scripts with a tree-sitter-bash AST |
| `sdk-trace`, `bundle-reality`, `runtime-plane` | Inspect dependencies and compare runtime metadata with filesystem reality |

## Invariants, chains, and verification

| Command | Purpose |
| --- | --- |
| `invariant query` | Query security invariants against source repositories |
| `patch check` | Derive patch guidance and search for nearby variants |
| `chain query` | Assemble multi-step propagation paths from evidence |
| `verify` | Attach runtime confirmation to a derived finding |
| `signature-fit` | Test whether a byte window fits a public-key signature relation |

## Emulation and runtime

| Command | Purpose |
| --- | --- |
| `preflight` | Rank emulator backends and host readiness |
| `emulate` | Start, inspect, or stop a firmware runtime |
| `rehost`, `experiment`, `rehosting-trace` | Match, validate, and explain rehosting recipes and experiments |
| `debug`, `observe` | Inspect runtime processes, services, networking, shells, maps, monitors, and GDB surfaces |
| `instrument-hooks`, `trace-ingest`, `probe` | Configure QEMU hooks, ingest traces, and compare runtime events with static findings |
| `discover`, `hsm` | Produce family-scoped leads and query derived state-machine models |
| `benchmark` | Score and report analysis and emulation benchmarks |

## Graph and label views

| Command | Purpose |
| --- | --- |
| `graph export` | Export analysis facts as reusable JSON graph data |
| `label scan`, `labels explain` | Build label evidence and explain why a path carries a label |
