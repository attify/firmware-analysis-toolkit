# Development

```bash
cargo build
cargo test --workspace --locked
cargo test -p fat-toolkit-core
cargo test -p firmware-analysis-toolkit --test test_cli_bootstrap
```

Integration tests live in `tests/integration/` and use temporary directories for filesystem isolation.

Toolchain requirements, the PR checklist, and the acceptance-gate commands are in [CONTRIBUTING.md](CONTRIBUTING.md). See [docs/architecture.md](docs/architecture.md) for the crate layout and extension points, and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) before submitting a change.
