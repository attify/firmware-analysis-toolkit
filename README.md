# FAT — Firmware Analysis Toolkit

`fat` is a Rust-first firmware analysis platform for IoT security research. It
classifies unknown firmware, extracts filesystems, maps trust-relevant code, and
coordinates emulation so static evidence can be checked against a runtime.

FAT wraps established tools such as binwalk, unblob, radare2, Ghidra, Joern,
and QEMU behind one project model and evidence vocabulary. Commands report
measurements, classifications, confidence, and provenance. Machine-readable
surfaces use JSON so results remain useful in scripts and investigation
notebooks.

FAT accelerates evidence collection. The researcher decides what the evidence
proves.

> **Status: `2.0.0-alpha.1`, a public alpha candidate.** Interfaces may change
> before a stable release. Emulation findings describe one run on one backend;
> they are not physical-device fidelity claims.
> Public release remains blocked on removal or explicit externalization of
> bundled vendor behavior and target data, followed by consumer-package validation.
> Live-QEMU acceptance and a supported downloadable kernel supply chain also
> remain unfinished; the version label does not establish release readiness.

## What FAT can analyze

- **Unknown blobs and directories:** containers, compressed members,
  high-entropy regions, MCU signals, and candidate firmware files
- **Firmware images:** headers, update envelopes, partitions, bootloaders, and
  image-to-image differences
- **Extracted Linux filesystems:** inventory, startup intent, trust-bearing
  binaries, crypto material, and string evidence
- **ELF binaries:** imports, exports, handler tables, stripped-code sinks,
  decompilation, and source-to-sink taint
- **Bare-metal and MCU images:** vector tables, memory maps, peripheral hints,
  flash-write authority, and boot handoff evidence
- **Edge AI artifacts:** MAGIK/JZDL, TFLite, ONNX, and Qualcomm DLC files plus
  visible inference runtimes
- **Android applications:** APK inventory, discovery leads, locality,
  capability chains, and handoff boundaries
- **Source repositories:** invariant queries, patch guidance, and nearby
  variant searches

## Quick start

From the root of an obtained source checkout or unpacked source archive, build
with Rust 1.90 or newer:

```bash
cargo build --release --locked
cargo install --path crates/fat_cli --locked
fat doctor
```

The release binary is written to `target/release/fat`. The installed command is
`fat`.

That path installs the executable only. `./scripts/install.sh` is the supported
one-shot alternative from a source checkout: it installs `fat`, the matching
runtime data, and a pinned Binwalk under `~/.local`, then proves the result with
`fat doctor --strict` and a real synthetic extraction. Add `--install-system-deps`
to let it install host packages, or `--dry-run` to print every mutating command
first. See [Installer options](#installer-options) below or run
`./scripts/install.sh --help` for the full option list.

Point it at anything you have not identified:

```bash
fat ./firmware.bin
```

This is shorthand for `fat identify --file ./firmware.bin`. It reports the
strongest visible evidence without turning that evidence into an unsupported
conclusion.

Then move through the project pipeline:

```bash
fat new ./firmware.bin
fat extract .fat-projects/firmware
fat analyze .fat-projects/firmware
fat preflight .fat-projects/firmware
fat emulate --project .fat-projects/firmware
```

`fat -h` lists every command grouped by task, starting with `identify` and
`doctor`. `fat --help` adds common workflows and examples. Every subcommand
also has its own `--help` output and examples. Help uses color in a terminal
and stays plain when piped; `FAT_COLOR=always` forces color and
`FAT_COLOR=never` disables it.

## Command map

### Projects and extraction

| Command | Purpose |
| --- | --- |
| `new`, `list`, `info`, `delete` | Manage project workspaces under `.fat-projects/` |
| `identify` | Classify evidence in an unknown file or directory |
| `extract` | Run binwalk or unblob and record carved files and filesystem candidates |
| `extract-payload`, `carve` | Extract a known byte range or format-sized object |
| `analyze` | Derive project signals, findings, and the bootloader snapshot |
| `doctor` | Report external-tool and backend readiness |
| `data`, `kernel` | Install and verify runtime data and maintained kernels |

### Firmware structure and classification

| Command | Purpose |
| --- | --- |
| `inspect` | Inspect headers, layout, carved artifacts, or bare-metal metadata |
| `inspect update`, `inspect envelope` | Build update-envelope and trust-path evidence |
| `detect-encryption`, `compare` | Measure opaque wrappers and compare envelope boundaries |
| `diff role`, `diff firmware` | Compare binaries by role or projects across filesystem, configuration, and binary layers |
| `bootloader` | Inspect bootloader images, environments, handoff, and sessions |

### Filesystem evidence

| Command | Purpose |
| --- | --- |
| `ls`, `tree` | Inventory-oriented filesystem views with optional evidence-backed labels |
| `search`, `xref-search` | Search printable strings and resolve pointer or code references |
| `source-map`, `startup-map` | Map inputs to consumers and startup metadata to binaries |
| `trust-map`, `trust-boundary` | Identify governing update paths and trust boundaries |
| `crypto-census`, `crypto`, `crypto-extract` | Locate reused crypto material and embedded keys, certificates, or blobs |
| `edge-ai` | Discover Edge AI models and library filename hints |
| `android` | Analyze APK inventory, discovery leads, locality, and capability chains |

### Binary analysis

| Command | Purpose |
| --- | --- |
| `r2-triage` | Profile a binary with radare2 and rank audit targets |
| `sink-discovery`, `handler-table` | Find sink candidates and URL or command dispatch tables |
| `identify-launcher`, `inspect-handoff` | Detect thin launchers and inspect downstream implementation artifacts |
| `decompile` | Decompile one function mechanically with r2ghidra |
| `taint`, `taint-query`, `taint-cross` | Trace data flow, ask precise path questions, and stitch cross-binary state |
| `taint --lang shell` | Trace source-to-sink flows through shell scripts with a tree-sitter-bash AST |
| `sdk-trace`, `bundle-reality`, `runtime-plane` | Inspect dependencies and compare runtime metadata with filesystem reality |

### Invariants, chains, and verification

| Command | Purpose |
| --- | --- |
| `invariant query` | Query security invariants against source repositories |
| `patch check` | Derive patch guidance and search for nearby variants |
| `chain query` | Assemble multi-step propagation paths from evidence |
| `verify` | Attach runtime confirmation to a derived finding |
| `signature-fit` | Test whether a byte window fits a public-key signature relation |

### Emulation and runtime

| Command | Purpose |
| --- | --- |
| `preflight` | Rank emulator backends and host readiness |
| `emulate` | Start, inspect, or stop a firmware runtime |
| `rehost`, `experiment`, `rehosting-trace` | Match, validate, and explain rehosting recipes and experiments |
| `debug`, `observe` | Inspect runtime processes, services, networking, shells, maps, monitors, and GDB surfaces |
| `instrument-hooks`, `trace-ingest`, `probe` | Configure QEMU hooks, ingest traces, and compare runtime events with static findings |
| `discover`, `hsm` | Produce family-scoped leads and query derived state-machine models |
| `benchmark` | Score and report analysis and emulation benchmarks |

### Graph and label views

| Command | Purpose |
| --- | --- |
| `graph export` | Export analysis facts as reusable JSON graph data |
| `label scan`, `labels explain` | Build label evidence and explain why a path carries a label |

## Common workflows

### First contact with an unknown file

```bash
fat ./firmware.bin
fat inspect update --file ./firmware.bin --rootfs ./rootfs --reference ./older.bin
```

### Image to runtime

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

Which function writes a device's shared state and which reads it is a claim
about that platform's config API, so FAT ships no such catalog. Without
`--state-profile`, `taint-cross` assigns no function a read or write role and
produces no cross-binary findings. JSON output is an empty array; the command
does not emit a raw symbol inventory.

The two profiles serve different purposes: `--source-profile` supplies binary
source/sink models to the analyzer, merged with the core models;
`--state-profile` maps read, write, and flush names into shared-state families.
A state profile alone does not teach the binary analyzer how an unfamiliar
function carries data. Both flags take file paths; an invalid selected file is
an error. See `fat taint-cross --help` for the state-profile schema.

Both `--json` and `--as-taint-json` preserve the binary models' identity in
`model_provenance` and the state mappings' identity in `state_model_provenance`.
External identities include the declared name, selected path, and SHA-256 of
the loaded file. Output remains an array of findings, or `[]` when none exist.

`fat source-map --source-profile` likewise adds operator-supplied hints to the
ISO C core hints. Its JSON report records `model_provenance` even when no
backend candidates match. Source hints describe observed names, not proven
flows.

### Shell script data flow

Shell is the firmware layer where source-to-sink reachability is cheapest to
show. `--lang shell` parses scripts with `tree-sitter-bash` and walks
assignments forward, so `$(cat /configs/...)` → `$var` → `sed -i "s/.../$var/g"`
comes back as one chain instead of an isolated grep hit. Findings serialize to
the same `TaintFinding` JSON as `fat taint --json`, so anything that already
reads taint findings deserializes them unchanged.

```bash
fat taint --lang shell --file ./app/init/wifi.sh --summary
fat taint --lang shell --rootfs ./extracted-rootfs --json
fat taint --lang shell --rootfs ./extracted-rootfs --source-profile ./my-target-shell.yaml --severity high
```

The always-loaded shell profile only carries constructs that hold for any POSIX
script: positional parameters, `read`, `cat`/`head`/`tail`, the RFC 3875 CGI
meta-variables, and the documented `uci get`, `fw_printenv` and `getprop`
reads. It asserts nothing about any device's filesystem, so a read of
`/configs/...` is `Secondary` on the strength of the read alone — the path's
name is not evidence that an attacker can write the file. `--source-profile`
takes a YAML overlay you write; a `path-prefix` source in it declares a mount
attacker-writable, which promotes reads under that mount to `Primary` and makes
the finding cite the mount by name.

Shell taint is deliberately unsound — shell is too dynamic to prove
reachability — so every finding lands as a `Candidate` at `WEAK` strength and
only flows with a named source are reported. For sink hits without provenance,
use `fat sink-discovery --rootfs`.

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

## How to read FAT output

FAT reports hits, evidence, categories, counts, offsets, confidence, validation
state, provenance, and next probes. These terms describe what FAT observed.

Some graph-schema names sound more conclusive than they are.
`UpdateCandidate`, `AuthorityVerdict`, and `update-authority` are compatibility
names for evidence groups and bounded static assessments. They do not represent
a final analytical judgment.

- Startup intent does not prove runtime reachability or exploitability.
- Edge AI findings identify artifacts and likely inference stacks; they do not
  prove that a model executes.
- A structurally valid key length says something about the bytes, not whether
  the firmware uses those bytes at runtime.
- An emulation validator proves only what that validator checked during that
  run on that backend.

`fat inspect update --json` is the aggregate surface for envelope, trust, and
crypto evidence. It embeds the underlying submodels so downstream tools do not
need to reconstruct their relationships from prose.

## Selected capabilities

### Graph export

`inventory` is the neutral graph profile. It emits directories, files, file
kinds, SHA-256 hashes, and rabin2 import and export edges without adding
research-specific labels.

```bash
fat graph export --rootfs ./rootfs --profile inventory --format json > inventory.json
fat ls --rootfs ./rootfs --profile inventory --json
fat tree --rootfs ./rootfs --profile inventory --summary --json
```

`update-authority` is an optional lens for update-trust research. It adds label
assignments, rollups, update and decrypt path evidence, bounded assessment
nodes, negative evidence, and symbol metadata.

```bash
fat graph export --rootfs ./rootfs --profile update-authority --output update-graph.json
fat label scan --rootfs ./rootfs --profile update-authority --emit json > update-graph.json
fat labels explain --rootfs ./rootfs --profile update-authority --path /sbin/updater --json
```

### String search

`fat search` scans printable firmware strings. By default it inspects ELF
binaries under discovered filesystem candidates. Use `--all-files` for scripts
and configuration, `-I` for case-insensitive matching, `--context N` for nearby
strings, and `--profile credentials|urls|crypto|sinks|debug` for common
security searches. JSON output uses `search-report/v2`.

### Crypto artifacts

`fat crypto-census` finds reused crypto artifacts across a filesystem and shows
whether they appear on a governing update path. `fat crypto-extract` reports
embedded artifacts with offsets, confidence, validation state, and trust-path
context. Confirm runtime use through disassembly or instrumentation.

### Edge AI artifacts

`fat edge-ai scan` discovers four model families and reports library filename hints:

Use `fat edge-ai --help` or `fat edge-ai scan --help` for the full command
reference.

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

JSON output uses `schema_version: edge-ai-scan/v1` and stores format-specific details under
`findings[].metadata`. Library filename hints require the four-byte ELF magic
and use `artifact_kind: filename-match`, `matched_pattern`, and `evidence`.
They do not establish a runtime identity or model format; their metadata omits
`runtime` and `format`. The repository contains deterministic synthetic fixtures;
it does not redistribute private model corpora.

### Startup intent

`fat startup-map` resolves startup metadata to concrete binaries and attaches
profile evidence such as strings, imports, and linked libraries. Use it to
choose the next target to inspect, not as runtime proof.

## Rehosting packs

A rehosting pack is a YAML file containing device-specific knowledge needed to
emulate a firmware image: the QEMU machine, init repairs, paths to materialize,
network mode, and readiness validators.

FAT ships no packs. Device-specific knowledge is yours to supply, and a pack
affects a run only after you point FAT at the directory holding it. Packs are
discovered from:

1. any `--packs-dir <dir>` passed to `fat rehost match`, in the order given;
   then
2. directories in the colon-separated `FAT_REHOSTING_PACKS` environment
   variable.

With neither set, nothing is discovered and no pack is applied. `fat rehost
match` reports which of your packs match an extracted firmware image.

```bash
fat rehost profiles validate ./my-packs/example-camera.yaml
fat rehost match .fat-projects/firmware --packs-dir ./my-packs
fat emulate --project .fat-projects/firmware --pack example/camera
fat emulate --project .fat-projects/firmware --experimental-rehosting
```

Unsupported partition roles and init repairs fail closed in the pack capability
report. Network declarations remain degraded when the selected backend cannot
prove their fidelity.

## Installation requirements

### Installer options

The source installer requires Rust 1.90+, Python 3, and a C compiler. The default
extraction profile also needs Binwalk's native build dependencies; use
`--install-system-deps` to install the supported host packages.

```bash
./scripts/install.sh --install-system-deps
# CLI and runtime data only, with paths containing spaces:
./scripts/install.sh --profile core --prefix "$HOME/FAT tools" \
  --data-dir "$HOME/FAT data"
```

| Option | Effect |
| --- | --- |
| `--profile core\|extraction` | CLI plus runtime data, optionally with Binwalk (default: extraction) |
| `--prefix PATH` | Install under PATH (default: `~/.local`); add its `bin` directory to your shell's PATH |
| `--data-dir PATH` | Store data there and link `PREFIX/share/fat` for automatic discovery; refuse an existing conflicting path |
| `--jobs N`, `--native` | Choose Cargo concurrency or optimize for this CPU |
| `--test` | Run locked workspace tests before installation |
| `--dry-run` | Print mutating commands without executing them or deleting temporary files |
| `--skip-extraction-smoke` | Explicitly skip the synthetic extraction check |

No `FAT_DATA_DIR` export is needed for installer-managed custom data. An existing
`FAT_DATA_DIR` environment override still takes precedence; unset it to use the
installation's data. Keep the linked custom directory in place when using FAT.

### External tools

FAT orchestrates external tools. Install only those needed for your workflow;
`fat doctor` reports what it finds. For binwalk and unblob, strict mode requires
a bounded version probe to succeed, not merely a matching executable name.

| Tool | Needed for | Typical installation |
| --- | --- | --- |
| binwalk | Firmware extraction | `./scripts/install.sh --profile extraction` installs pinned Rust Binwalk 3.1.0 |
| unblob | Alternative extraction | `pipx install unblob` |
| debugfs | ext filesystem extraction and ext2 repair | `brew install e2fsprogs` or `apt install e2fsprogs` |
| radare2 | Binary triage and symbol resolution | `brew install radare2` or `apt install radare2` |
| Ghidra | Decompilation and taint normalization | Install from [ghidra-sre.org](https://ghidra-sre.org/) and set `GHIDRA_HOME` |
| Joern | CPG proof stage | Install from [joern.io](https://joern.io/) |
| QEMU | System-mode emulation | `brew install qemu` or `apt install qemu-system` |
| Docker | Containerized emulation backends | Follow the [Docker installation guide](https://docs.docker.com/get-docker/) |
| Python 3 | Discovery runners | `apt install python3` |
| Python 3.10+ and angr | Optional binary taint engine | Isolated environment described below |

### Optional angr setup

Python alone does not install angr. Following the
[upstream installation guidance](https://docs.angr.io/en/latest/getting-started/installing.html),
create an isolated environment with Python 3.10 or newer:

```bash
python3 -m venv "$HOME/.local/share/fat-angr-venv"
"$HOME/.local/share/fat-angr-venv/bin/python" -m pip install angr pyyaml
export FAT_PYTHON="$HOME/.local/share/fat-angr-venv/bin/python"
"$FAT_PYTHON" -c 'import angr, yaml; print(angr.__version__)'
```

Keep `FAT_PYTHON` set in shells running FAT. On Debian/Ubuntu, install
`python3-venv` if environment creation is unavailable. `fat doctor --strict`
checks extraction-engine readiness; it does not validate the optional angr
environment. The import command above checks that environment without running
firmware analysis.

On macOS, `FAT_EXT2_BUILDER_IMAGE` may point to an operator-provided image
pinned by digest. FAT does not pull that image or install packages at runtime.
The builder disables networking, mounts firmware source read-only, enables
`no-new-privileges`, and uses five narrow capabilities.

## Security

Emulation executes untrusted vendor code. Run it in a disposable VM. Docker is
not a security boundary for hostile firmware.

FAT fails closed when required extraction, filesystem, or backend conditions
are unavailable. Review [SECURITY.md](SECURITY.md) before processing untrusted
images or exposing an emulated service to a network.

## Architecture

The workspace contains thirteen crates. `fat_cli` is the only binary crate;
the others are libraries.

```text
fat_cli
├── fat_core         shared models and SQLite persistence
├── fat_extract      binwalk and unblob extraction wrapper
├── fat_analyze      analyzer engine and registry
├── fat_emulate      emulation planning and session orchestration
│   ├── fat_backend  backend abstraction and registry
│   └── fat_family   signal-based device-family classification
├── fat_bootloader   bootloader profiles and runtime operations
├── fat_query        typed evidence graph and query adapters
├── fat_taint        firmware-wide taint analysis
├── fat_package      release and runtime-data packaging
├── fat_plugin_api   plugin contracts
└── fat_plugin_host  plugin discovery and dispatch
```

The main extension points are:

- `Analyzer` in `fat_analyze`, registered with `AnalysisEngine`;
- `Backend` in `fat_backend`, ranked by architecture and family affinity;
- family traits in `fat_family`, scored from observed firmware signals; and
- the evidence IR in `fat_query`, shared by static, runtime, and source
  adapters.

## Development

```bash
cargo build
cargo test --workspace --locked
cargo test -p fat-toolkit-core
cargo test -p firmware-analysis-toolkit --test test_cli_bootstrap
```

Integration tests live in `tests/integration/` and use temporary directories for
filesystem isolation. See [CONTRIBUTING.md](CONTRIBUTING.md) and
[CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting a change.

## Maintainers

FAT was authored by [adi0x90](https://github.com/adi0x90), who is also its
current maintainer and principal contributor. The project is maintained under
[Attify](https://www.attify.com/); reach us at
[attify.com/contact](https://www.attify.com/contact) for anything that is not a
security report or a code of conduct concern.

## License

FAT 2.0 is source available under [FSL-1.1-ALv2](LICENSE).
Each version also becomes available under Apache-2.0 on the second anniversary of the date Attify first makes that version available.
A public commit can start that clock; it is not reset by a later release tag.

You may use FAT internally, make permitted forks and modifications, and submit pull requests.
Competing commercial use, as defined in the license, requires separate permission from Attify during that two-year period.
Commercial terms, including any fees or revenue share, require a separate agreement.
Contact [Attify](https://www.attify.com/) for licensing enquiries.

FAT 2.0 is a rewrite with different terms from FAT 1.x.
Previously released FAT 1.x code retains its MIT license; this change does not revoke those rights.
See [LICENSING.md](LICENSING.md) for the transition and component exceptions, and [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency obligations.
FSL-covered versions are not OSI-approved open source before conversion.
