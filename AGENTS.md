# AGENTS.md

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup and verification.

## Rust workspace

Workspace crates use Rust 2024, Cargo resolver 3, and a minimum compiler version of Rust 1.91.
Keep dependency upgrades separate from edition changes.
`rustfmt.toml` retains the existing formatting style so edition changes do not reformat unrelated code.
Use `tests/support/subprocess.rs` for tests that need a custom environment or working directory; configure the child command instead of mutating the test process.

## Releases

Follow [RELEASING.md](RELEASING.md) for versioning, validation, packaging, and publication.
Use one `vMAJOR.MINOR.PATCH` product tag and one shared workspace version.
Keep runtime-data and citation versions synchronized through `cargo-release` replacements.
Release notes describe user-facing changes; the first regular release introduces the product and its migration path.
Use `cargo-dist` for native GitHub platform builds and archive smoke tests; publishing is an explicit maintainer workflow dispatch.

## Firmware extraction

`fat_extract::pipeline` owns the recursive container and embedded-region queue and per-artifact outcomes.
`output::OutputTree` owns staged publication, path validation, shared output limits, and deferred symlinks.
SquashFS header, inode, codec, and cached metadata readers remain separate; new formats reuse the output contract.
Carved images and directory names alone do not establish rootfs recovery; unresolved branches must leave fallback available.
Explicit native selection must not invoke external filesystem fallback.
JFFS2 reconstruction validates node and data CRCs, applies inode versions and dirent deletions, and queues reconstructed regular files for recursive inspection.
Do not treat gzip signatures inside fragmented filesystem data as contiguous streams or suppress unresolved artifacts to improve aggregate status. Gzip output directories identify the artifact and compression format, not a kernel role.

## MCU analysis and terminal reports

**Raw MCU identification** (`fat_analyze::mcu`): Structural vector candidates, family evidence, and code mapping are independent.
`identify_mcu` preserves unresolved mappings and rejected-candidate diagnostics; family-pack strings only corroborate compatible SRAM/executable ranges.
`ImageLayoutReport.vector_address` maps the selected vector table's file offset to memory.
`image_measurements` reports exact whole-image periods and uniform regions without attributing repetition to encryption.
Both `identify` and `inspect mcu` consume these models.

**MCU static evidence**: Fast and detailed inspection share `mcu::scan_vector_table`; counts describe populated pointers, not enabled IRQs or default-handler roles.
`mcu_code` follows supported Thumb control flow from mapped vector seeds with explicit budgets and reports candidate functions, literal/string references, and local constant-derived accesses.
`mcu_registers` attaches profile names to that evidence without promoting literal loads into accesses.
Declarative `fat_family::mcu_packs` data owns vendor ranges, identity markers, reserved slots, core attribution, and sourced register definitions; unknown profiles retain raw addresses.
Register aliases/part conditions remain unresolved unless supported.

**Terminal reports** (`fat_cli::report`): `identify` and `inspect mcu` share width-aware sections, labeled values, and wrapping tables.
`mcu_report` owns MCU text presentation.
`terminal_table::render` provides reusable table rendering without a `Report`; `terminal_text` shares width and wrapping helpers.
Borders and section dividers are independent of color settings.
Use `Palette` for semantic colors, keep evidence readable without color, and preserve all displayed values when tables stack on narrow terminals.
Rendering must not alter analysis models or JSON output; confidence labels must not be converted into invented numeric scores.
Default text reports show matched findings and useful measurements.
Omit empty sections, absent-feature rows, and diagnostic notes/limits footers.
Keep essential qualifications on the finding itself; full diagnostics remain in JSON.
`identify` gives a short identity/image overview.
`inspect mcu` groups findings by image mapping, startup, interrupts, and hardware.
`--details` expands the same groups with reference tables.
Summarize repeated relationships in the overview; keep raw pointers, instruction sites, and accounting in details.
Presentation flags do not change analysis or JSON.
Descriptions state concrete observations and applicability conditions directly.
Avoid generic proof disclaimers such as "presence is not established"; use precise labels and fields to distinguish static accesses, constants, and profile matches.

## BMC inspection

`fat_analyze::fit` interprets FIT metadata using the shared validated FDT reader in `firmware_formats`; `fat_core::fit` owns its serializable evidence. Image signatures, configuration signatures, and control-FDT key requirements remain distinct. A completely interpreted blob is required before emitting absence-based findings; signature metadata is not cryptographic verification or enforcement.

`fat_analyze::boot_env` owns bounded, CRC-validated raw environment discovery. Region sizes include their headers; preserve offsets, CRC byte order, and redundant flags without selecting an active environment. `fat_analyze::bmc` assembles layout, FIT, environment and located marker evidence. `fat_cli::bmc_cmd` renders text, JSON and SARIF from the same model; presentation flags never change analysis.

Raw bootloader text analysis stores assignments in `BootloaderSnapshot.raw_env_hints`; these are unvalidated strings, not boot-policy findings or emulation inputs. Keep imported/legacy `env_variables` separate from those hints and from `BootEnvScan` CRC-validated regions. Older snapshots must remain readable.

## BMC emulation

`fat_core::bmc_boot` owns the explicit, hash-pinned flash/vendor-kernel contract. `fat_emulate::bmc_runner` owns native launch arguments; `fat_cli::bmc_emulate` stages private inputs and performs bounded loopback Redfish observations. Reuse FAT native process ownership and lifecycle. FIT boot assets use the validated FDT reader and require SHA-256 integrity checks; never conflate this with signature verification. Record boot-chain bypass, exact asset hashes and each DTB adaptation. Never seed these modes from raw environment hints. Keep NIC subnets distinct and forwarding on loopback. Current BMC validators are the canonical Redfish ServiceRoot probe; reject unsupported validators. Current service readiness must be refreshed and kept separate from process state and historical observations. Vendor images and validation filesystems stay outside Git.

`fat_cli::bmc_session` owns the disposable-account Redfish experiment. Require distinct principals, a usable ReadOnly session, denied cross-account mutation with unchanged state, and an administrator positive control. Restore the target and verify token revocation; an unknown session handle or cleanup failure must prevent success. Credentials/tokens stay out of arguments and reports. `fat_cli::bmc_process` owns Unix userspace debugging through an owned temporary loopback SSH forward. Bound helper process groups and transcripts, compare guest PID start time and executable identity, and report resume/forward cleanup separately. Firmware account provisioning, SSH shell changes and gdbserver installation remain explicit lab setup, outside automatic FAT boot adaptations.
