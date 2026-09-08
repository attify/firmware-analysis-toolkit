# Architecture

The workspace contains thirteen crates. `fat_cli` is the only binary crate; the others are libraries.

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
- the evidence IR in `fat_query`, shared by static, runtime, and source adapters.

For build, test, and contribution workflow, see [DEVELOPMENT.md](../DEVELOPMENT.md) and [CONTRIBUTING.md](../CONTRIBUTING.md).
