# Offline BMC OEM validation — 2026-10-18

## Scope and result

The existing `fat inspect bmc` implementation was exercised against six local
OEM firmware artifacts. Three images have corroborating MegaRAC/SP-X evidence:
Gigabyte MZ32-AR0 12.61.39, ASRock B650D4U 7.02.00, and ASUS ESC8000-E12 1.20.02.
Their freshly extracted `usr/local/bin/flasher` executables contain
`MegaRAC Firmware Upgrade Utility`, and their filesystem trees contain
`spx_restservice` and associated SP-X libraries. Both executables were checked
byte for byte with independent extraction methods.

This closes the absence of representative MegaRAC artifact testing for the
implemented offline inspection and filesystem extraction features. It does not
establish complete support for every OEM container, proprietary signature
verification, device-selected boot paths, or hardware enforcement. No firmware
was executed or flashed, and no controller was contacted. Hardware testing was
explicitly excluded by the user for this run.

The initial baseline used unchanged FAT source. A follow-up investigation
identified missing JFFS2 reconstruction behind the three MegaRAC partial
results; the native extraction fix and fresh results are recorded below.
Supermicro X11 rootfs recovery remains unresolved.

## Initial baseline build identity

- Implementation commit: `3fe6b6922f40bee12f1d05343e3d2aa5e68d091b`.
- Implementation branch: `bmc/firmware-inspection`, based on FAT 2.0.1.
- Executed binary: the existing `fat-bmc-inspection/fat/target/debug/fat`.
- Binary SHA256: `8ebaf4dd176c772a76f6fe2e4d5b4e52929c0502947955f24fe92b60f383be75`.
- Validation worktree: `bmc-megarac-validation/fat`.
- Validation branch: `fix/bmc-megarac-validation`, based on that exact commit.
- Host: macOS. Extraction was repeated on a newly created case-sensitive APFS
  disk image when the host output filesystem could not represent the firmware
  filenames.

## Initial baseline results

Filesystem counts below are regular files inside recovered CramFS/SquashFS
trees, independently counted. They exclude symlinks, directories, and separately
decompressed gzip artifacts. `partial` is the actual aggregate extraction status,
even when both filesystem trees recovered.

| Artifact | FIT metadata | Recovered filesystem regions | Regular files | Aggregate extraction status | Warning-gate exit |
|---|---|---|---:|---|---:|
| Gigabyte MZ32-AR0 12.61.39 | No FIT detected | CramFS at `0x560000` and `0x2fd0000` | 3,853 | `partial`: six additional gzip candidates failed | 0 |
| ASRock B650D4U 7.02.00 | FIT at `0x26a0040`; two SHA256 image hashes; no signature nodes | SquashFS at `0x510000` and `0x2af0000` | 2,599 | `partial`: six additional gzip candidates failed | 1 |
| ASUS ESC8000-E12 1.20.02 HPM package | FIT at `0x27d00e5`; six SHA256 image hashes; no signature nodes | SquashFS at `0x4100a5` and `0x2c800a5` | 3,291 | `partial`: three additional gzip candidates failed | 1 |
| Supermicro X12SPW 01.07.22 | FIT at `0x1d00000`; four SHA256 image hashes; no signature nodes | SquashFS at `0x140000` and `0x2100000` | 1,254 | `rootfs_recovered` | 1 |
| Supermicro X11 01.74.13 | No FIT detected | No rootfs recovered; gzip/kernel artifacts only | — | `partial` | 0 |
| Lenovo SR630 XCC 10.40 comparison image | No FIT detected | SquashFS at `0x95be00` | 11,322 | `rootfs_recovered` | 0 |

All six images produced valid JSON and SARIF reports. The five Gigabyte,
ASRock, ASUS, and Supermicro images also completed both text modes. Lenovo was
checked in JSON, SARIF, and warning-gated SARIF. These are 28 inspection
invocations with the expected exit statuses. Each warning-gated SARIF document
was identical to its ordinary SARIF document and passed the SARIF 2.1.0 schema.

No CRC-valid U-Boot environment was found by the configured automatic search
in these six inputs. That search checks 4 KiB alignment and the documented
candidate sizes within the first 64 MiB. It does not establish the absence of
stored environments or report a live boot policy.

## Independent checks

1. Each tested input matched the corresponding member of its existing local ZIP
   or UXZ archive by SHA256. Archive acquisition URLs were preserved from prior
   local records where available; no fresh vendor download was made in this run.
   The ASRock acquisition URL and the X11 inner-archive URL are not recorded.
2. `fdtget` traversed each carved FIT independently: 9 nodes for ASRock, 25 for
   ASUS, and 13 for X12. All three contained zero signature-prefixed nodes.
3. The image `data` properties were read with `fdtget`; Python independently
   recomputed all 12 SHA256 digests. Each matched both the stored FIT value and
   FAT's metadata report. This validates component integrity for these files;
   it does not authenticate a signing identity. `fdtget -t r` appends one output
   newline, which the checker removes without stripping payload bytes.
4. Gigabyte's `flasher` and `spx_restservice` were independently recovered by
   traversing CramFS inodes and decompressing their blocks with Python zlib.
   Both matched FAT's output byte for byte. ASRock's and ASUS's equivalent
   files matched `unsquashfs -cat` output. Supermicro X12's `etc/os-release`
   and Lenovo's `bin/RF_Root` also matched independent `unsquashfs` output.
5. Every reported raw marker's bytes and offset were checked against the input.
   Input size/SHA256, SARIF result count, and warning-gate policy were checked
   against the JSON evidence.

## Input identities

| Artifact filename | Bytes | SHA256 |
|---|---:|---|
| `126139.bin` | 66,060,552 | `43817b0f37c7bf98922b8120dec3755e872f1cb4df0cdeede4ebbf9ab742f5a9` |
| `B650D4U_7.02.00.ima` | 67,109,128 | `db2b83bd106b9aa65255e242e64e89ddce65fe82f37ffda537c987f67a969083` |
| `BHS_Gen_1.20.02.hpm` | 67,109,115 | `20954d5d143552ba68be44902d3de17828d88d8f2eb5e86cd2a6584fd75f3a81` |
| `BMC_X12AST2600-ROT-5201MS_20260430_01.07.22_STDsph.bin` | 49,020,928 | `6cc0241424d15f39d68326eadce18e168eea7a74e382ca1a3c7d43cc1b2a8799` |
| `BMC_X11AST2500-4101MS_20230802_01.74.13_STDsp.bin` | 33,554,432 | `38bf1fd2ebd7bf0a384c0fa6ea668c8300ea5ff347590799fb8da13f7cdf2b7d` |
| `xcc_cdi3b8d-10.40.upd` | 144,410,624 | `173da196faf0fa516a4fae1b66ed9b53fd23378fa269d19531ed5909620fefea` |

## Interpretation and remaining limits

- The ASRock, ASUS, and X12 FIT findings describe embedded FITs. In particular,
  X12 includes `sigtable@1` and `optee@1` images; hashes and a `sig_table` marker
  do not interpret the proprietary table or establish outer authentication.
- ASUS offsets are relative to the complete HPM package. FAT found embedded
  structures through scanning; this run does not establish HPM record parsing,
  component selection, wrapper-checksum validation, or update acceptance.
- X12's raw `OpenBMC` evidence is the compiler string `openbmc-linux-gcc` at
  `0x72c9b`. Its extracted `os-release` identifies `Supermicro BMC`. Multiple
  ASPEED compatible strings also describe code support, not a measured SoC.
- An exit status of zero means inspection completed without a warning finding
  under the selected policy. X11 has no FIT finding and no recovered rootfs;
  its zero warning-gate exit is not a security verdict.
- The baseline preserved additional gzip failures. The follow-up independently
  reconstructed all 15 streams from JFFS2 nodes and identified them as valid
  fragmented files; see the native JFFS2 results below.
- Case-insensitive macOS output failed for real case-distinct filenames. The
  case-sensitive reruns recovered all listed filesystem regions. Gigabyte's
  CramFS collision originally surfaced as `File exists`; SquashFS reported the
  case-sensitive-volume requirement explicitly.
- ASRock stores `etc/defconfig/crontabs` with mode `0644`. Counting its child
  required temporarily adding the owner directory-search bit to the extracted
  copy; its original mode was restored. Original firmware bytes were untouched.
- Lenovo extraction skipped 210 special files, as recorded by FAT. No special
  devices were created and no extracted executable was run.
- Supermicro X11 rootfs recovery and its representation remain unresolved.
  This run does not attribute that failure to encryption without evidence.
- The baseline did not rerun Cargo tests because its FAT source and binary
  were unchanged. The implementation follow-up uses a new build and regression
  tests, recorded separately below.

## Native JFFS2 follow-up

The 15 failing gzip candidates were valid files fragmented across JFFS2 inode
nodes. Treating bytes after the first fragment as one contiguous gzip stream
fed filesystem metadata into the decompressor. Independent reconstruction
validated the JFFS2 header, inode, and payload CRCs and recovered all 15 complete
streams, including their gzip checksums.

The fix adds native JFFS2 reconstruction to the existing recursive pipeline.
It applies inode versions, truncations, and directory-entry deletions; supports
both byte orders and none/copy/zero/zlib fragments; and publishes through
`OutputTree`. Reconstructed files enter the recursive queue with their original
paths and filesystem parent IDs. Private temporary snapshots allow inspection
of files under restrictive firmware permissions without changing the published
modes. This also resolves ASRock's two unreadable `crontabs/sysadmin` paths.

The node layout is documented in the [Linux JFFS2 format header](https://github.com/torvalds/linux/blob/master/include/uapi/linux/jffs2.h).
The implementation retains bounded work and staged publication. Bad CRCs,
unsupported codecs or node types, missing fragment ranges, unreachable live
directory entries, and exceeded limits remain unresolved.

Fresh native-only extraction on the same case-sensitive volume produced:

| Image | JFFS2 region offsets | JFFS2 regular files | Previously failing gzip streams recovered | Aggregate status | Unresolved artifacts |
|---|---|---:|---:|---|---:|
| Gigabyte | `0x60000`, `0x260000`, `0x2f50000` | 184 | 6 | `rootfs_recovered` | 0 |
| ASRock | `0x110000`, `0x310000` | 194 | 6 | `rootfs_recovered` | 0 |
| ASUS HPM | `0x2100a5`, `0x30a00a5` | 100 | 3 | `rootfs_recovered` | 0 |

These counts cover seven JFFS2 regions and 478 regular files, including redundant
copies; the second ASUS region contains only directories. All 15 reconstructed
gzip files and their decompressed contents matched an independent Python
reassembly byte for byte. All 16,418 existing CramFS/SquashFS file-content and
symlink-target entries matched the baseline. Firmware inputs were unchanged.

The follow-up binary was built in `bmc-megarac-validation/fat` from commit
`3fe6b69` plus the local JFFS2 patch on `fix/bmc-megarac-validation`.
Its SHA256 is `47fcb69d6410dcd21456a7a2e7baeadc328292c19b84ff4364cc5d12e7802447`.
The saved source-patch SHA256 is
`0fdda769fd7a9febe7954bc1158a5d64bc62cdd82151e10a93495f801c77d2c5`.

Sixteen synthetic JFFS2 regression tests cover fragmented gzip, both byte orders,
versions and truncations, deletion, obsolete/duplicate nodes, erased gaps,
CRC failures, unsupported compression, decompression bounds, missing ranges,
path traversal, depth/size limits, symlinks, and restrictive permissions.

Fresh verification passed: 2,055 workspace tests, zero failures, one ignored;
Clippy with `-D warnings`; formatting; four kernel-profile consistency tests;
and the runtime-data bundle check (33 files). The focused extraction suite
passed 90 tests with one ignored, including the 16 new JFFS2 regressions.

The new private evidence directory is `.tmp/jffs2-fix/`: `source.patch`,
`source-sha256.json`, `FINAL-CHECKS.json`, `fragment-proof.json`, `real-image-results.json`,
`independent-checks.json`, command logs, and the reproducible `validate_real.py`
and `check_real.py` scripts. `fat-validated` preserves the exact executable
used for the real-image checks. The case-sensitive disk image retains both the
baseline projects and `jffs2-final-projects`. This follow-up reran the three
MegaRAC images; the other corpus rows above remain baseline observations.

## PR review and upstream integration

Review of the BMC parsers and CLI found no blocking correctness issue. Scoped
checks passed 36 parser/model tests and seven CLI tests. FIT and environment
probes rejected terminal-control payloads before text rendering.

The extraction review identified and fixed temporary snapshot retention after
failed JFFS2 attempts. A regression fixture reconstructs one file, then fails on
an unsupported codec; the test requires both the unpublished output and private
copies to be removed. A guard now retains copies only after successful staged
publication. The symlink fixture and assertions are Unix-specific; directory
and depth checks still run on other platforms.

The branch incorporates upstream `28c8a40` (installer migration and Rust 1.91
minimum). Merge `1506a11` preserves those changes and the BMC/JFFS2 changelog
entries. The three MegaRAC extraction and independent-comparison runs were
repeated at that merge: all three remain `rootfs_recovered`, with zero unresolved
artifacts, all 15 gzip streams recovered, and all 16,418 baseline entries
unchanged. The pinned rerun binary SHA256 is
`498b12597b3d00444b2b24c18f98727f07778e4fa1e7d181e582f0ce674ad6e6`.
Private review and rerun evidence is in `.tmp/pr-review/`, including command
logs, `REVIEW.md`, and the `real/` results. The disk image also retains
`pr-review-projects`.

Final preflight passed formatting, workspace Clippy with warnings denied,
2,056 Rust tests (one ignored), all four kernel-profile consistency tests,
runtime-data bundle verification, all 39 installer tests, and diff whitespace
checks. The final source also explicitly discards the retained temporary path
returned by `TempDir::keep`; this satisfies Clippy without changing the tested
snapshot lifetime.

## Reproduction and local evidence

Use the archived baseline binary to reproduce the initial results, or build
merged commit `d024d01` (PR #113) for the corrected extraction. Use
an input matching the hash table. The ordinary, detailed, and structured reports consume the same
analysis:

```sh
fat inspect bmc --file "$image"
fat inspect bmc --file "$image" --details
fat inspect bmc --file "$image" --json > inspection.json
fat inspect bmc --file "$image" --sarif > findings.sarif
fat inspect bmc --file "$image" --sarif --fail-on-warning > gated.sarif

# projects_dir must be on a case-sensitive filesystem for these OEM roots.
fat new "$image" --name "$name" --projects-dir "$projects_dir"
fat extract "$projects_dir/$name" --extractor native --json > extraction.json
```

The validation worktree was removed after merging. The maintainers retain the
original reports, pinned binaries, disk image, and Git history in a private
archive with a SHA256 manifest and verification script. Historical `.tmp/`
paths in this report describe the original runs, not files shipped with FAT.
Public reproduction uses the source commit and input hashes above; vendor
firmware and extracted filesystems are not included in the repository. The
archived evidence includes:

- `baseline-manifest.json`, `package-provenance.json`, `formats-manifest.json`.
- Per-image JSON, text, detailed, SARIF, stderr, command/exit records, and native
  extraction manifests, including the original case-insensitive failures.
- `independent-fit-checks.json` and `independent-extraction-checks.json`.
- `baseline.py`, `formats.py`, `extract.py`, `check_fit.py`, and
  `check_extraction.py`, with the exact local paths and commands used.
- `case-sensitive.asif`, preserving the additional extracted projects on a
  case-sensitive filesystem. Reattach with `diskutil image attach --readOnly` to inspect
  the `FAT-BMC-CaseSensitive` volume.

See [BMC inspection usage](bmc-inspection.md) for search bounds and finding
semantics.
