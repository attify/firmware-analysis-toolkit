# Releasing FAT

FAT releases are created on request from tested commits on `master`.
Use `cargo-release` for shared version updates, `git-cliff` for release-note drafts, `cargo-dist` for platform archives and release automation, and GitHub CLI for maintainer actions.
The GitHub release is the download page; the README badge and latest-release link follow it automatically.

## Version and timing

| Kind | Example | Use |
| --- | --- | --- |
| Major | `2.4.3` → `3.0.0` | Breaking changes to documented commands, JSON, configuration, or plugin interfaces |
| Minor | `2.4.3` → `2.5.0` | Compatible features |
| Patch | `2.4.3` → `2.4.4` | Compatible fixes |
| Preview | `2.5.0-alpha.1`, `2.5.0-rc.1` | Testing before a regular release |

Use one product tag, `vMAJOR.MINOR.PATCH`, and the release title `FAT MAJOR.MINOR.PATCH`.
All workspace crates and the accompanying runtime data use that version.
Runtime-data bundles declare compatibility with the exact executable version they accompany.
Review accumulated changes roughly every two weeks; release when there is a useful tested update, and ship urgent fixes as needed.
Regular releases are marked Latest; previews are prereleases.

"Prepare the next FAT release" means a reviewed version update and draft release.
"Publish the next FAT minor release from master" includes publishing after the checks below pass.

## Tools

Install the tested maintainer tools, or use their official prebuilt binaries:

```bash
cargo install cargo-release --version 1.1.6 --locked
cargo install git-cliff --version 2.14.2 --locked
cargo install cargo-about --version 0.8.2 --locked
cargo install cargo-dist --version 0.33.0 --locked
gh auth status
```

GitHub CLI (`gh`) is installed separately through its [installation guide](https://cli.github.com/manual/installation).
The workspace remains `publish = false`; this workflow distributes FAT through GitHub.

## Prepare a version

Start in a clean, dedicated worktree based on current `origin/master`.
For the first regular release use `release_version=2.0.0`; subsequently choose the next SemVer version.

```bash
release_version=2.0.0
release_tag="v$release_version"
cargo release version "$release_version" --workspace
cargo release version "$release_version" --workspace --execute --no-confirm
cargo release replace --workspace --execute --no-confirm
python3 scripts/build-runtime-data-bundle.py --check
```

The first command previews the changes.
The execute steps update Cargo manifests, dependency requirements, the lockfile, runtime-data metadata, citation metadata, runtime-data asset names in `dist-workspace.toml`, and the README's pinned source-install command.
README source-install instructions stay on the regular release when preparing a preview.
Review the diff before committing it.

## Release notes

The first regular release uses the curated introduction in [release-notes/v2.0.0.md](release-notes/v2.0.0.md).
It describes the product, highlights, installation, and migration from FAT 1.x.
It is the baseline for subsequent release notes.

```bash
release_notes=release-notes/v2.0.0.md
```

For later releases, generate a draft from the previous published FAT tag:

```bash
previous_tag=v2.0.0
mkdir -p .tmp
release_notes=.tmp/release-notes.md
git cliff "$previous_tag..HEAD" --tag "$release_tag" --output "$release_notes"
```

`cliff.toml` groups features, fixes, performance improvements, and other changes.
It recognizes FAT SemVer tags and excludes historical QEMU tags.
Nonconventional commits remain visible for review; routine documentation, test, CI, style, and release-maintenance commits are omitted unless breaking.
Review the generated notes, preserve useful entries already under `Unreleased`, and add the finalized release section to `CHANGELOG.md` while retaining its history.
Keep the notes focused on user-visible changes, including migration instructions for breaking changes.
Include an absolute link to the tagged installation guide so the notes can also serve as the binary bundle's README.
Commit the version, notes, and changelog through a release PR.

## Validate the release PR

Run the checks from [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
python3 -m unittest discover -s tests/release -p 'test_*.py'
python3 scripts/build-runtime-data-bundle.py --check
dist generate --check
dist plan
```

The Release workflow builds portable archives on native GitHub runners for macOS Apple Silicon and Intel, Linux x86-64 and ARM64, and Windows x86-64.
Linux x86-64 uses Ubuntu 22.04 (glibc 2.35); ARM64 uses Ubuntu 24.04 (glibc 2.39).
Both Linux archives are also tested on Fedora 42.
Each archive contains the executable, matching `share/fat` runtime data, release notes, and dependency license notices.
Compression libraries are built from their bundled sources to avoid dependencies on runner-specific Homebrew or Linux packages.

Pull requests build and test the archives without publishing them.
The smoke checks extract each archive into a fresh directory, verify its checksum, run the executable, verify the bundled data, and exercise identification and MCU inspection with a synthetic input.
They also inspect native shared-library dependencies on macOS and Linux.
The workflow stops before publication if any build or smoke check fails.

`dist-workspace.toml` is the source of truth for the generated `.github/workflows/release.yml`.
Change the configuration or reusable setup/smoke workflow, then run `dist generate`; do not hand-edit the generated workflow.
Release builds use the compiler pinned in `rust-toolchain.toml`; the minimum supported source-build compiler remains Rust 1.90.

For a local archive build:

```bash
python3 scripts/prepare-release-resources.py
bash scripts/generate-third-party-licenses.sh target/release-resources/third-party-licenses.json
LZMA_API_STATIC=1 BZIP2_NO_PKG_CONFIG=1 dist build --artifacts=local --target TARGET
python3 scripts/smoke-release.py target/distrib/firmware-analysis-toolkit-TARGET.tar.gz --version "$release_version"
```

Replace `TARGET` with the host's Rust target triple and use `.zip` on Windows.
The archive contains `fat` or `fat.exe` alongside `share`, so keep them together after extraction.
Archives use the package name and target triple; the enclosing GitHub release tag identifies their version.
The separately installable runtime-data archive retains the name `fat-data-VERSION.zip`.

## Merge, tag, and publish

Merge the release PR after its validation and platform checks pass.
Use a clean checkout of the exact merged commit on `origin/master`, and verify the workspace version matches the intended tag.
Create the product tag on that commit:

```bash
release_tag="v$release_version"
cargo release tag -p firmware-analysis-toolkit
cargo release tag -p firmware-analysis-toolkit --execute --no-confirm
git push origin "refs/tags/$release_tag"
```

Create a draft with the reviewed release notes:

```bash
gh release create "$release_tag" --verify-tag --draft \
  --title "FAT $release_version" --notes-file "$release_notes"
```

If a draft already exists, update its notes and target commit instead of creating another.
Remove obsolete assets from that draft before the first cargo-dist run.
Never replace assets or move tags belonging to a published version.

Publication is an explicit workflow dispatch; pushing a tag alone does not publish:

```bash
gh workflow run release.yml --ref "$release_tag" -f tag="$release_tag"
```

The workflow rebuilds and tests the tagged code, uploads the archives and checksums to the draft, and publishes it only after every platform passes.
A dry run uses `-f tag=dry-run` and leaves releases untouched.
For a regular release, confirm it is marked Latest:

```bash
gh release edit "$release_tag" --prerelease=false --latest
```

For a preview, use `--prerelease=true --latest=false` instead.
Verify the published tag, release notes, asset list, and checksums by downloading the release assets.
The GitHub sidebar and README badge follow the latest regular release.
