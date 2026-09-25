# Architecture

The workspace contains thirteen crates. `fat_cli` is the only binary crate; the others are libraries.

```text
fat_cli
├── fat_core         shared models and SQLite persistence
├── fat_extract      recursive native extraction and fallback orchestration
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
- the evidence IR in `fat_query`, shared by static, runtime, and source adapters.

For build, test, and contribution workflow, see [DEVELOPMENT.md](../DEVELOPMENT.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).

## Extraction

`fat_extract::pipeline` runs a deterministic queue of container members and embedded regions. Archive handlers unwrap ZIP, TAR, and gzip; filesystem handlers produce terminal trees. Extracted filesystem contents retain their original layout rather than gaining analysis-generated files. A single signature scanner skips successfully decoded spans.

`output::OutputTree` owns path validation, cumulative output accounting, private staging, mode preservation, and deferred symlinks. Publication happens only after the decoder finishes. SquashFS header, inode, compression, and cached metadata readers are separate modules. CramFS reuses its bounded decoder. New formats can reuse the writer and return child paths for further inspection or a terminal tree.

Artifact records retain their source, parent, source-relative offset, decoder, output, counts, timing, and failure reason. Failed children preserve successful siblings. Rootfs content evidence and unresolved branches determine whether fallback extraction continues. The manifest adds `artifacts` and `recovery_status` without removing earlier fields.

Default native limits are 512 MiB per input, 256 MiB per file, 1 GiB cumulative output including symlink targets, 262,144 output entries, 4,096 artifacts, eight container levels, and 64 path components. Metadata and fragment caches share a 16 MiB cap. Filesystem decoders never execute recovered programs.

Supported SquashFS codecs are zlib, LZMA, and XZ. Other codecs produce explicit unsupported outcomes. Special device entries are counted and omitted; ownership, timestamps, and extended attributes are not restored. TAR hard links and sparse entries are currently unsupported. Case-distinct filenames require case-sensitive output storage; collisions fail the tree instead of overwriting a file.
