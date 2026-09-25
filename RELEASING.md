# Releasing FAT

FAT releases are created on request from tested commits on `master`.
Use `cargo-release` for shared version updates, `git-cliff` for release-note drafts, and GitHub CLI for GitHub releases.
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
The execute steps update Cargo manifests, dependency requirements, the lockfile, runtime-data metadata, citation metadata, and the README's pinned source-install command.
README source-install instructions stay on the regular release when preparing a preview.
Review the diff before committing it.

## Release notes

The first regular release uses the curated introduction in [release-notes/v2.0.0.md](release-notes/v2.0.0.md).
It describes the product, highlights, installation, and migration from FAT 1.x.
It is the baseline for subsequent release notes.

For later releases, generate a draft from the previous published FAT tag:

```bash
previous_tag=v2.0.0
mkdir -p .tmp
git cliff "$previous_tag..HEAD" --tag "$release_tag" --output .tmp/release-notes.md
```

`cliff.toml` groups features, fixes, performance improvements, and other changes.
It recognizes FAT SemVer tags and excludes historical QEMU tags.
Nonconventional commits remain visible for review; routine documentation, test, CI, style, and release-maintenance commits are omitted unless breaking.
Review the generated notes, preserve useful entries already under `Unreleased`, and add the finalized release section to `CHANGELOG.md` while retaining its history.
Keep the notes focused on user-visible changes, including migration instructions for breaking changes.
Commit the version, notes, and changelog through a release PR.

## Validate and build

After the release PR is merged, use a clean checkout of the exact release commit on `origin/master`.
Re-read `release_version` from `Cargo.toml` and check it matches the intended tag.
Run the checks from [CONTRIBUTING.md](CONTRIBUTING.md):

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets --locked -- -D warnings
cargo test --workspace --locked -- --test-threads=1
cargo test -p firmware-analysis-toolkit --locked --test test_kernel_profile_consistency
python3 scripts/build-runtime-data-bundle.py --check
cargo build --release --locked -p firmware-analysis-toolkit
```

Build and smoke-test each binary on its intended operating system and CPU.
Use the Rust target triple in asset names, such as `aarch64-apple-darwin`.
Publish only the targets built and tested for this release; the tagged source is also available for source installation.
Check native shared-library dependencies with `otool -L` on macOS or `ldd` on Linux and document any non-system requirements.

## Package a host build

Run from the tested checkout, with `release_version` set to its version:

```bash
release_target="$(rustc -vV | sed -n 's/^host: //p')"
release_bundle="fat-$release_version-$release_target"
release_assets="$PWD/dist/$release_version"
release_stage="$PWD/target/release-stage/$release_bundle"
release_binary="${CARGO_TARGET_DIR:-target}/release/fat"
mkdir -p "$release_assets" "$release_stage/bin" "$release_stage/share/fat"
cp "$release_binary" "$release_stage/bin/fat"
python3 scripts/build-runtime-data-bundle.py \
  --output "$release_assets/fat-data-$release_version.zip"
unzip -q "$release_assets/fat-data-$release_version.zip" -d "$release_stage/share/fat"
cp LICENSE LICENSING.md THIRD_PARTY_NOTICES.md INSTALL.md "$release_stage/"
cp -R LICENSES "$release_stage/"
./scripts/generate-third-party-licenses.sh "$release_stage/third-party-licenses.json"
"$release_stage/bin/fat" --version
"$release_stage/bin/fat" data verify
tar -czf "$release_assets/$release_bundle.tar.gz" \
  -C "$PWD/target/release-stage" "$release_bundle"
```

Use a fresh staging directory for each build.
Extract the finished archive into a fresh temporary directory, run `bin/fat --version` and `bin/fat data verify` there, and exercise identification with a synthetic input.
`data verify --json` must report the bundled runtime-data path and the expected version.
Repeat the installed smoke test on a clean machine for each platform listed in the release.
Include the generated third-party license report in every binary archive.

Collect all tested archives in the same release-assets directory, then generate checksums:

```bash
(cd "$release_assets" && shasum -a 256 ./*.tar.gz ./*.zip > SHA256SUMS)
(cd "$release_assets" && shasum -a 256 -c SHA256SUMS)
```

The runtime-data builder also writes the ZIP's adjacent `.sha256` digest.
Asset names include the version and target; never replace assets of a published version.

## Tag, draft, and publish

Create the tag on the validated release commit after it has landed on `master`:

```bash
release_tag="v$release_version"
cargo release tag -p firmware-analysis-toolkit
cargo release tag -p firmware-analysis-toolkit --execute --no-confirm
git push origin "refs/tags/$release_tag"
```

For the first release, set `release_notes=release-notes/v2.0.0.md`; use the reviewed notes file for later releases.
Create a draft and upload the tested artifacts:

```bash
gh release create "$release_tag" --verify-tag --draft \
  --title "FAT $release_version" --notes-file "$release_notes" \
  "$release_assets"/*.tar.gz "$release_assets"/*.zip \
  "$release_assets"/*.sha256 "$release_assets/SHA256SUMS"
gh release view "$release_tag" --web
```

Confirm the tag's commit, notes, asset names, checksums, and installation instructions.
Publish a regular release with:

```bash
gh release edit "$release_tag" --draft=false --prerelease=false --latest
```

For a preview, use `--draft=false --prerelease=true --latest=false` instead.
Verify the published release, download and check its assets, and check the README badge after its cache refreshes.

