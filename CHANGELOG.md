# Changelog

## [Unreleased]

- Native recursive ZIP, TAR, and gzip extraction with SquashFS 2/3/4 decoding, including both byte orders and legacy LZMA block layouts.
- Extraction manifests include per-artifact lineage, decoder outcomes, limits, and recovery status. Carved images and empty output directories no longer stop rootfs recovery attempts.

## [2.0.0]

First regular release of the Rust-based FAT CLI.
See the [release notes](release-notes/v2.0.0.md) for capabilities, installation, and migration from FAT 1.x.

### Added

- A shared Rust CLI for firmware identification, extraction, binary and filesystem analysis, and emulation workflows.
- Versioned runtime-data bundles with installation and integrity verification.
- Portable archives with bundled runtime data for macOS Apple Silicon and Intel, Linux x86-64 and ARM64, and Windows x86-64.
- A maintainer release workflow using `cargo-release`, `git-cliff`, `cargo-dist`, and GitHub CLI, with synchronized versions and release links in the README.
- `identify` and `inspect mcu` show compact overviews by default.
  `--details` expands related findings into grouped reference tables; JSON stays unchanged.
- `inspect mcu` reports bounded Thumb code and function candidates, referenced strings, recovered initialization descriptors, and decoded MMIO accesses.
  Literal address references remain separate from reads/writes.
  LPC13xx and Cortex-M3 register names carry documentation sources, alias conditions, and profile-selection provenance; unsupported control flow remains unresolved.

### Fixed

- Identification and MCU tables have outer borders and row separators.
  MCU hardware tables label register addresses and operations explicitly.
- Report tables use a shared renderer; Unicode borders and section dividers remain visible when ANSI colors are disabled.
- MCU terminal output omits the security-controls summary table.
- MCU register descriptions retain chip and DLAB conditions without repetitive proof disclaimers; register metadata uses direct descriptions of observations.
- Default identification and MCU inspection reports omit unmatched sections, absent-feature rows, and explanatory notes/limits footers, keeping matched findings and measurements prominent.
  JSON diagnostics are unchanged.
- `identify` and `inspect mcu` share readable terminal reports with semantic colors, grouped evidence, wrapping tables, and narrow-terminal layouts.
  Confidence labels no longer display invented percentages; identity rows group repeated text while retaining every offset.
  Plain text and JSON remain usable without color, and analysis results are unchanged.
- Fast and detailed MCU reports share vector bounds and populated-handler counts, distinguishing core exceptions, external IRQs, reserved slots, and unpopulated slots.
  Shared targets no longer imply default handlers or an interrupt-driven execution model.
  Vendor address/identity rules live in family profiles, and wide conditional Thumb branches use the correct encoding.
- MCU identification retains vector evidence independently of family and load address, recognizes LPC13xx boot ROM mappings, and reports ASCII/UTF-16LE identity evidence with offsets.
  `identify` and `inspect mcu` share this assessment; explicit bases participate in startup addressing.
- Repeated image copies and uniform fill are measured separately.
  Repeated blocks alone no longer imply ECB encryption or trigger encryption gates.
  Known containers are selected by format signatures rather than entropy; UTPK recognition requires its fixed-position TEA marker as well as its magic.
