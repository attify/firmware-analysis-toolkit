# Contributing to FAT

Thanks for taking a look. Firmware analysis is fiddly and under-tooled, so if you have a device FAT handles badly, a profile that's wrong, or a rough edge that annoyed you, we'd like to hear about it.

## About the license, up front

FAT 2.0 is under the [Functional Source License](https://fsl.software/), a non-compete license that becomes Apache-2.0 two years after each version ships. So it isn't open source today, but it will be.

What that means day to day: use FAT however you like, including at work and on paid engagements. Fork it, modify it, publish what you find with it. The one thing you can't do is build a competing product or service out of it while the restriction is still live — if that's what you have in mind, [talk to us](https://www.attify.com/) and we'll work something out.

We went this way because Attify is a small company and FAT is a real product rather than a side project. It felt better than keeping it closed.

## Getting set up

FAT is a Rust workspace. You need Rust **1.90** or newer via [rustup](https://rustup.rs); `rust-toolchain.toml` pins the channel and the `rustfmt`/`clippy` components. The [external tools list](INSTALL.md#external-tools) shows what FAT can orchestrate, and `fat doctor` tells you what's actually installed on your machine.

All workspace crates use the Rust 2024 edition and Cargo resolver 3.
The formatter retains the existing style independently of the language edition.
Tests that need environment variables or a different working directory should configure an isolated child process with `tests/support/subprocess.rs`.

```bash
cargo build                     # build everything
cargo test                      # run the full test suite
cargo test -p fat-toolkit-core  # test a single crate
cargo test --test test_preflight -- test_preflight_from_signals
```

Some integration tests spawn the `fat` binary and use host tools like `mke2fs` (e2fsprogs) and `timeout` (coreutils). On macOS, install GNU coreutils if you want those to run locally.

Most suites under `tests/integration/` are hermetic. Anything needing a live emulation backend, an external target, or a proprietary artifact is individually ignored or gated, so `cargo test --workspace` should pass on a normal machine.

## Before you open a PR

Run the same checks the acceptance gate does:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets    # must be clean; warnings are errors
cargo test --workspace
cargo test -p firmware-analysis-toolkit --test test_kernel_profile_consistency
python3 scripts/build-runtime-data-bundle.py --check
```

Documentation is published as Markdown in this repository.
When changing it, check relative links and preview tables and code blocks in GitHub's rendered view.

The clippy policy lives in the root `Cargo.toml` under `[workspace.lints]`. A handful of design-level lints are allowed there; everything else has to pass.

## What's most useful to work on

The highest-value contributions are usually data rather than code:

- **Bootloader profiles** (`profiles/bootloader/*.json`) — if you've torn down a device and know its U-Boot quirks, that's exactly the thing.
- **Family signals** — the heuristics in `fat_family` that map firmware traits onto device families.
- **Backend adapter documentation** (`backends/`) — how a given emulation backend behaves in practice, including where it fails.
- **Plugin interfaces** — `fat_plugin_api` is the surface for building on FAT without touching the core.

For profile changes, include a small example or a validation result so we can check it against something real.

Two asks. Don't upload vendor firmware images, extracted filesystems, or anything else you don't have the right to redistribute — point at where you got it instead. And if a change includes code you didn't write, or your employer owns your work, mention it in the PR; it's much easier to sort out before review than after.

## Pull requests

Keep them focused and reference the issue they close (`Closes #NN`). Match the style of the code around you, and add or update tests when behavior changes.
If it changes user-facing behavior, add a line under `Unreleased` in `CHANGELOG.md`.
Use Conventional Commit PR titles: `feat:` for compatible additions, `fix:` for fixes, and `!` for breaking changes, such as `feat(cli)!: rename an option`.
These feed release-note drafts; maintainers review the version and user-facing wording before publication.
See [RELEASING.md](RELEASING.md) for the release workflow.
If it changes the workspace layout, a key abstraction, or the CLI surface, update `AGENTS.md` — it's the shared instruction file for coding agents, and `CLAUDE.md` is just a one-line import of it.

If you're planning something large, open an issue first so we can talk it through before you spend the time on it.

## Security issues

Please don't open a public issue for a vulnerability. [SECURITY.md](SECURITY.md) has the disclosure process.

Participation in this project is governed by our [Code of Conduct](CODE_OF_CONDUCT.md).
