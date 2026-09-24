# AGENTS.md

Follow [CONTRIBUTING.md](CONTRIBUTING.md) for setup and verification.

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
