use clap::Command;

pub fn apply(root: &mut Command) {
    configure(root, None, Some(ROOT_AFTER), true);

    if let Some(cmd) = root.find_subcommand_mut("android") {
        configure(
            cmd,
            Some("Analyze Android app packages (APKs): inventory, discovery leads, capability chains, and locality"),
            None,
            true,
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("rehosting-trace") {
        configure(
            cmd,
            Some("Trace how a rehosting recipe was selected and staged for a project session"),
            None,
            false,
        );
    }

    if let Some(cmd) = root.find_subcommand_mut("new") {
        configure(
            cmd,
            Some("Create a FAT project workspace from a firmware image"),
            Some(NEW_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("firmware", "Path to the firmware image that should seed the new FAT project"),
                ("name", "Optional project name override. Defaults to a slug derived from the firmware filename"),
                ("projects_dir", "Parent directory where FAT should create the new project workspace"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("extract") {
        configure(
            cmd,
            Some("Extract a project firmware image or raw firmware into carved files and rootfs candidates"),
            Some(EXTRACT_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("project", "Path to an existing FAT project directory, or a raw firmware image to auto-wrap in .fat-projects"),
                ("force", "Re-run extraction and overwrite existing extraction artifacts"),
                ("extract_timeout", "Seconds before a stalled binwalk/unblob run is killed (0 disables; defaults to FAT_EXTRACT_TIMEOUT or 1800)"),
                ("extractor", "Engines to use: auto (priority chain), all (run every engine), or one of native, binwalk, unblob"),
                ("unblob_processes", "Worker processes for unblob; forwarded only when set"),
                ("unblob_depth", "Recursion depth for unblob; forwarded only when set"),
                ("json", "Emit one machine-readable JSON object on stdout; progress goes to stderr"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("carve") {
        configure(
            cmd,
            Some("Carve a byte range or format-sized object from firmware"),
            Some(CARVE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "project",
                    "Optional FAT project directory to resolve the primary firmware image from",
                ),
                ("file", "Standalone firmware image to carve from"),
                ("offset", "Start offset to carve from, decimal or hex"),
                ("size", "Explicit byte count for generic carving"),
                (
                    "format",
                    "Optional format parser such as squashfs for size inference",
                ),
                (
                    "output",
                    "Optional output path; defaults under work/carves or .fat-carves",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("extract-payload") {
        configure(
            cmd,
            Some("Extract a payload fragment from a project or file at a specific offset"),
            Some(EXTRACT_PAYLOAD_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "project",
                    "Optional FAT project directory to resolve the primary firmware image from",
                ),
                (
                    "file",
                    "Standalone file to extract from when you are not using a FAT project",
                ),
                (
                    "offset",
                    "Payload offset inside the selected file or firmware image",
                ),
                (
                    "format",
                    "Expected payload format such as gzip, lzma, or other supported parser labels",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("analyze") {
        configure(
            cmd,
            Some("Analyze extracted firmware artifacts and derive project signals"),
            Some(ANALYZE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("project", "Path to an existing FAT project directory"),
                (
                    "json",
                    "Emit one machine-readable JSON object on stdout instead of the human summary",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("preflight") {
        configure(
            cmd,
            Some("Rank emulator backends and host readiness for a project or signal set"),
            Some(PREFLIGHT_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "project",
                    "Optional FAT project directory whose analysis signals should be used",
                ),
                (
                    "signals",
                    "Manual classification signals such as arch:mips or web:cgi",
                ),
                (
                    "json",
                    "Emit one machine-readable JSON object on stdout instead of the human report",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("info") {
        configure(
            cmd,
            Some("Show project metadata, status, and known artifact paths"),
            Some(INFO_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("project", "Path to an existing FAT project directory"),
                (
                    "json",
                    "Emit one machine-readable JSON object on stdout instead of the human summary",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("identify") {
        configure(
            cmd,
            Some("Classify evidence in an unknown file or directory"),
            Some(IDENTIFY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("path", "Path to the file or directory to identify"),
                ("file", "Path to the file or directory to identify"),
                (
                    "details",
                    "Expand the overview with detailed findings and measurements",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("doctor") {
        configure(
            cmd,
            Some("Check the local host environment for missing external dependencies"),
            Some(DOCTOR_AFTER),
            false,
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("debug") {
        configure(
            cmd,
            Some("Open runtime-oriented debugging views and control surfaces"),
            Some(DEBUG_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("surfaces") {
            configure(
                sub,
                Some("List debugger and runtime control surfaces for a session"),
                Some(DEBUG_SURFACES_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime session should be inspected",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("shell") {
            configure(
                sub,
                Some("Open or run a command in an interactive shell for a runtime session"),
                Some(DEBUG_SHELL_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime shell should be opened",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    (
                        "command",
                        "Single shell command to run instead of opening an interactive shell",
                    ),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("maps") {
            configure(
                sub,
                Some("Inspect process memory maps for a runtime target"),
                Some(DEBUG_MAPS_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime target should be inspected",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("target", "Target process or binary name to inspect"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("monitor") {
            configure(
                sub,
                Some("Send monitor commands to the underlying runtime backend"),
                Some(DEBUG_MONITOR_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose backend monitor should be contacted",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("command", "Monitor command to send to the backend"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("gdb") {
            configure(
                sub,
                Some("Connect to or script a GDB session against a runtime target"),
                Some(DEBUG_GDB_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime GDB endpoint should be used",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("target", "Optional target process or binary name"),
                    (
                        "command",
                        "Single GDB command to run instead of opening an interactive client",
                    ),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("suggest") {
            configure(
                sub,
                Some("Suggest the most relevant next debugging actions for a runtime session"),
                Some(DEBUG_SUGGEST_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime session should be evaluated",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("observe") {
        configure(
            cmd,
            Some("Inspect live runtime state such as processes, services, and network bindings"),
            Some(OBSERVE_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("ps") {
            configure(
                sub,
                Some("List running processes inside the runtime session"),
                Some(OBSERVE_PS_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime processes should be listed",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("services") {
            configure(
                sub,
                Some("List observed services and their reachability from the runtime session"),
                Some(OBSERVE_SERVICES_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose services should be listed",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("net") {
            configure(
                sub,
                Some("List observed listeners, ports, and network endpoints"),
                Some(OBSERVE_NET_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose network state should be listed",
                    ),
                    ("session_id", "Optional explicit runtime session identifier"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("benchmark") {
        configure(
            cmd,
            Some("Score, import, and report benchmark data for FAT analyses and emulation"),
            Some(BENCHMARK_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("taint") {
            configure(
                sub,
                Some("Summarize taint findings across a benchmark dataset manifest"),
                Some(BENCHMARK_TAINT_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("dataset", "Path to a benchmark dataset manifest JSON file"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("score") {
            configure(
                sub,
                Some("Score a persisted FAT-native runtime run into benchmark records"),
                Some(BENCHMARK_SCORE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose runtime records should be scored",
                    ),
                    ("session_id", "Optional runtime session identifier"),
                    ("run_id", "Optional explicit run record identifier"),
                    (
                        "comparator",
                        "Optional comparator label to pair the FAT-native result against",
                    ),
                    ("run_mode", "Optional benchmark run mode override"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("import") {
            configure(
                sub,
                Some("Import an external comparator benchmark report into the runtime store"),
                Some(BENCHMARK_IMPORT_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory that should receive the imported report",
                    ),
                    ("report", "Path to the external comparator report JSON file"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("report") {
            configure(
                sub,
                Some("Render stored benchmark comparisons for a project"),
                Some(BENCHMARK_REPORT_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory whose benchmark history should be rendered",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("discover") {
        configure(
            cmd,
            Some(
                "Emit family-scoped discovery leads and manage harness plans, attempts, and triage",
            ),
            None,
            true,
        );
        annotate_args(
            cmd,
            &[
                (
                    "fixture",
                    "Legacy lead-emission fixture root when not using subcommands",
                ),
                (
                    "repo",
                    "Legacy lead-emission source root when not using subcommands",
                ),
                (
                    "family",
                    "Optional family filter such as lifetime-reentrancy or size-stride-arithmetic",
                ),
                ("top_k", "Maximum number of ranked leads or plans to emit"),
                ("mode", "Execution mode budget such as triage or deep"),
                (
                    "debug_bundle_dir",
                    "Optional directory to persist source analysis debug bundles",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
        if let Some(sub) = cmd.find_subcommand_mut("leads") {
            configure(
                sub,
                Some("Emit discovery leads for a fixture or source tree"),
                None,
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "fixture",
                        "Fixture root containing source files and compile metadata",
                    ),
                    ("repo", "Source tree root to analyze for discovery leads"),
                    ("family", "Optional family filter"),
                    ("top_k", "Maximum number of leads to render"),
                    ("mode", "Execution mode budget such as triage or deep"),
                    (
                        "debug_bundle_dir",
                        "Optional directory to persist source analysis debug bundles",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("preflight") {
            configure(
                sub,
                Some("Validate a local discovery lane manifest without executing the loop"),
                None,
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "manifest",
                        "Path to a discovery target-lane manifest JSON file",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("harvest") {
            configure(
                sub,
                Some("Expand discovery siblings for a promoted family through the local lane manifest"),
                None,
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "manifest",
                        "Path to a discovery target-lane manifest JSON file",
                    ),
                    ("family", "Promoted family to harvest"),
                    (
                        "top_k",
                        "Maximum number of ranked leads to seed harvesting from",
                    ),
                    ("mode", "Execution mode budget such as triage or deep"),
                    (
                        "debug_bundle_dir",
                        "Optional directory to persist source analysis debug bundles",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("run") {
            configure(
                sub,
                Some("Generate harness plans, execute bounded attempts, and normalize triage"),
                None,
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "manifest",
                        "Path to a discovery target-lane manifest JSON file",
                    ),
                    ("family", "Promoted family to execute"),
                    ("top_k", "Maximum number of ranked leads to run"),
                    ("mode", "Execution mode budget such as triage or deep"),
                    (
                        "debug_bundle_dir",
                        "Optional directory to persist source analysis debug bundles",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("triage") {
            configure(
                sub,
                Some("Normalize a persisted harness attempt into a discovery triage record"),
                None,
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "attempt_record",
                        "Path to a persisted harness attempt JSON file",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("source-map") {
        configure(
            cmd,
            Some("Discover frontend input surfaces and rank likely backend consumers"),
            Some(SOURCE_MAP_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to an extracted firmware rootfs directory"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("startup-map") {
        configure(
            cmd,
            Some("Resolve startup metadata to concrete binaries and profile evidence"),
            Some(STARTUP_MAP_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to an extracted firmware rootfs directory"),
                (
                    "profile",
                    "Optional built-in profile: cloud-tls, curl, dns, web, or update",
                ),
                ("name", "Regex filter for startup entry paths or names"),
                ("binary", "Regex filter for resolved binary paths"),
                ("api", "Regex filter for import or string evidence"),
                ("library", "Regex filter for linked-library evidence"),
                ("max", "Maximum candidates to render or emit"),
                ("json", "Emit machine-readable startup-map/v1 JSON"),
                (
                    "explain",
                    "Add short teaching-oriented stage explanations to text output",
                ),
                (
                    "emit_actions",
                    "Print suggested follow-up FAT commands for top candidates",
                ),
                (
                    "all_scripts",
                    "Also scan init.d scripts that are not referenced by rc.d entries",
                ),
                (
                    "no_r2",
                    "Skip rabin2 import/library analysis and use script/string evidence only",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("search") {
        configure(
            cmd,
            Some("Search extracted firmware strings across binaries or all regular files"),
            Some(SEARCH_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to the extracted firmware rootfs directory"),
                ("include", "Regex that matching strings must satisfy"),
                (
                    "profiles",
                    "Built-in search profile; repeatable: credentials, urls, crypto, sinks, debug",
                ),
                (
                    "case_insensitive",
                    "Match include, exclude, and profile regexes case-insensitively",
                ),
                (
                    "exclude",
                    "Regex to suppress noisy matches; may be repeated",
                ),
                ("path", "Rootfs-relative subtree to scan"),
                ("max", "Maximum matches reported per file"),
                (
                    "all_files",
                    "Scan all regular files instead of only ELF binaries",
                ),
                ("min_len", "Minimum printable string length"),
                (
                    "context",
                    "Neighboring extracted strings to show around each match",
                ),
                (
                    "unique",
                    "Deduplicate repeated matching strings within each file",
                ),
                (
                    "no_discover_rootfs",
                    "Disable nested rootfs auto-discovery under --rootfs",
                ),
                ("show_empty", "List scanned files that produced no matches"),
                (
                    "min_strength",
                    "Only report hits at or above weak, medium, or strong",
                ),
                (
                    "context_filter",
                    "Context filtering policy: boilerplate or none",
                ),
                (
                    "verbose",
                    "Show full execution metadata instead of compact triage header",
                ),
                ("summary", "Print one ranked summary line per matching file"),
                ("format", "Output format for human modes: text or anchor"),
                (
                    "color",
                    "Color policy for highlighted matches: auto, always, or never",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("emulate") {
        configure(
            cmd,
            Some("Start, inspect, or stop a firmware runtime backend for a FAT project"),
            Some(EMULATE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("project", "Optional FAT project directory to emulate"),
                ("backend", "Optional backend override such as a specific emulator family"),
                ("ports", "Port mappings or requested exposed ports"),
                ("session_id", "Optional explicit runtime session identifier"),
                ("status", "Show status for the selected or inferred session instead of starting a new one"),
                ("stop", "Stop the selected or inferred session"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("diff") {
        configure(
            cmd,
            Some("Compare binaries or runtime-backed artifacts by semantic role"),
            Some(DIFF_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("role") {
            configure(
                sub,
                Some("Compare two binaries by launcher and runtime-plane role signals"),
                Some(DIFF_ROLE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("left", "Left-hand binary or shared library"),
                    ("right", "Right-hand binary or shared library"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("firmware") {
            configure(
                sub,
                Some("Compare two firmware projects across filesystem, config, and binary layers"),
                Some(DIFF_FIRMWARE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "base",
                        "Base (older) FAT project directory or direct rootfs directory",
                    ),
                    (
                        "head",
                        "Head (newer) FAT project directory or direct rootfs directory",
                    ),
                    (
                        "security",
                        "Show only security-tagged filesystem changes and recompute the summary after filtering",
                    ),
                    (
                        "layer",
                        "Layer to diff: filesystem, config, binary, or all. Binary mode compares changed ELF files with radare2/r2 when available",
                    ),
                    ("json", "Emit the full FirmwareDiffReport JSON payload"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("bootloader") {
        configure(
            cmd,
            Some("Manage and inspect bootloader-oriented projects and sessions"),
            Some(BOOTLOADER_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("new") {
            configure(
                sub,
                Some("Create a bootloader workspace profile for a project"),
                Some(BOOTLOADER_NEW_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory to attach the bootloader profile to",
                    ),
                    (
                        "profile",
                        "Bootloader profile identifier to use for workspace setup",
                    ),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("export-env") {
            configure(
                sub,
                Some("Export discovered bootloader environment variables"),
                Some(BOOTLOADER_EXPORT_ENV_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[(
                    "project",
                    "FAT project directory to export environment variables from",
                )],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("emulate") {
            configure(
                sub,
                Some("Prepare or launch a bootloader emulation workflow"),
                Some(BOOTLOADER_EMULATE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory containing the bootloader workspace",
                    ),
                    (
                        "assist",
                        "Print additional setup guidance while preparing emulation",
                    ),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("console") {
            configure(
                sub,
                Some("Open the bootloader console for a prepared workspace"),
                Some(BOOTLOADER_CONSOLE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[(
                    "project",
                    "FAT project directory containing the bootloader workspace",
                )],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("stop") {
            configure(
                sub,
                Some("Stop the running bootloader emulation session for a project"),
                Some(BOOTLOADER_STOP_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "project",
                        "FAT project directory containing the bootloader workspace",
                    ),
                    (
                        "all",
                        "Stop every FAT-managed bootloader session on this host",
                    ),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("status") {
            configure(
                sub,
                Some("Show current bootloader workspace and session state"),
                Some(BOOTLOADER_STATUS_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[(
                    "project",
                    "FAT project directory containing the bootloader workspace",
                )],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("inspect") {
            configure(
                sub,
                Some("Inspect bootloader artifacts, environment, and discovered launch hints"),
                Some(BOOTLOADER_INSPECT_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[(
                    "project",
                    "FAT project directory containing the bootloader workspace",
                )],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("inspect") {
        configure(
            cmd,
            Some("Inspect carved artifacts, binary layout, or bare-metal firmware metadata"),
            Some(INSPECT_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("headers") {
            configure(
                sub,
                Some("Inspect firmware headers or container metadata"),
                Some(INSPECT_HEADERS_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("project", "Optional FAT project directory to inspect"),
                    (
                        "file",
                        "Optional standalone file to inspect instead of a project",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("layout") {
            configure(
                sub,
                Some("Inspect binary layout, sections, and evidence-bearing regions"),
                Some(INSPECT_LAYOUT_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("project", "Optional FAT project directory to inspect"),
                    (
                        "file",
                        "Optional standalone file to inspect instead of a project",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("mcu") {
            configure(
                sub,
                Some("Detect and characterize bare-metal MCU firmware from raw bytes"),
                Some(INSPECT_MCU_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("file", "Path to a raw MCU firmware binary"),
                    ("base", "Optional base address override such as 0x08000000"),
                    ("family", "Optional family-pack hint such as STM32H7"),
                    (
                        "details",
                        "Expand image, startup, interrupt, and hardware details",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("peripheral-map") {
            configure(
                sub,
                Some("Inspect family-backed peripheral, register, and config surfaces"),
                Some(INSPECT_PERIPHERAL_MAP_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("file", "Path to a raw MCU firmware binary"),
                    ("base", "Optional base address override such as 0x08000000"),
                    ("family", "Optional family-pack hint such as STM32H7"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("isr-state") {
            configure(
                sub,
                Some("Inspect interrupt-boundary shared-state candidates"),
                Some(INSPECT_ISR_STATE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("file", "Path to a raw MCU firmware binary"),
                    ("base", "Optional base address override such as 0x08000000"),
                    ("family", "Optional family-pack hint such as STM32H7"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("envelope") {
            configure(
                sub,
                Some("Inspect opaque wrapper behavior and compare against a reference image"),
                Some(INSPECT_ENVELOPE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    ("file", "Path to the opaque firmware blob to analyze"),
                    (
                        "reference",
                        "Optional reference image used to compare shared header structure",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
        if let Some(sub) = cmd.find_subcommand_mut("update") {
            configure(
                sub,
                Some("Combine envelope triage, trust-path reconstruction, and governing-updater crypto context"),
                Some(INSPECT_UPDATE_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "file",
                        "Path to the firmware blob or wrapper under investigation",
                    ),
                    (
                        "rootfs",
                        "Path to the extracted rootfs used for updater-path reconstruction",
                    ),
                    (
                        "reference",
                        "Optional reference blob for shared-header and boundary comparison",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("detect-encryption") {
        configure(
            cmd,
            Some("Detect opaque wrapper characteristics for a firmware blob"),
            Some(DETECT_ENCRYPTION_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to the firmware blob to analyze"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("compare") {
        configure(
            cmd,
            Some("Compare an encrypted blob against a reference for envelope boundary clues"),
            Some(COMPARE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("encrypted", "Encrypted firmware blob under analysis"),
                (
                    "reference",
                    "Reference firmware blob for header/prefix comparison",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("crypto-census") {
        configure(
            cmd,
            Some("Census a rootfs for reused crypto artifacts and governing-path hits"),
            Some(CRYPTO_CENSUS_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to the extracted firmware rootfs directory"),
                (
                    "only",
                    "Comma-separated artifact filter such as rsa or blob",
                ),
                (
                    "group_by",
                    "Grouping mode for reuse clusters; initial support is fingerprint",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("inspect-handoff") {
        configure(
            cmd,
            Some("Inspect likely downstream implementation artifacts for a binary"),
            Some(INSPECT_HANDOFF_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a binary or shared library"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("bundle-reality") {
        configure(
            cmd,
            Some("Compare linked framework metadata with visible filesystem reality"),
            Some(BUNDLE_REALITY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a binary or shared library"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("runtime-plane") {
        configure(
            cmd,
            Some("Summarize the likely runtime-backed object plane around a binary"),
            Some(RUNTIME_PLANE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a binary or shared library"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("xref-search") {
        configure(
            cmd,
            Some("Find pointer and code references to addresses or strings"),
            Some(XREF_SEARCH_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to an ELF binary or raw firmware blob"),
                ("vaddr", "Virtual address or raw address to search for"),
                (
                    "string_pattern",
                    "String text to locate before searching for references",
                ),
                ("raw", "Treat the input as a raw firmware blob"),
                (
                    "arch",
                    "Architecture hint for raw blobs such as cortex-m or mips-pic",
                ),
                ("base", "Base address for raw firmware blobs"),
                (
                    "scan",
                    "ELF pointer scan filter; raw mode currently uses code-hit recovery",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("r2-triage") {
        configure(
            cmd,
            Some("Profile a binary quickly with radare2 and rank audit targets"),
            Some(R2_TRIAGE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to an ELF binary or raw firmware blob"),
                ("arch", "Architecture hint for raw blobs such as cortex-m"),
                ("base", "Base address for raw firmware blobs"),
                ("family", "Family hint for raw blobs such as STM32H7"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("sink-discovery") {
        configure(
            cmd,
            Some("Inspect sink candidates from profile-driven binary evidence"),
            Some(SINK_DISCOVERY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to an ELF binary to analyze"),
                (
                    "profile",
                    "One or more sink profile YAML files. Omit this to use the built-in linux-command-exec profile",
                ),
                (
                    "family",
                    "Restrict results to one sink family name from the loaded profile",
                ),
                (
                    "min_confidence",
                    "Minimum confidence threshold: weak, probable, strong, or confirmed",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
        if let Some(sub) = cmd.find_subcommand_mut("profiles") {
            configure(
                sub,
                Some("Inspect built-in sink profiles and validate community YAML"),
                Some(SINK_DISCOVERY_PROFILES_AFTER),
                true,
            );
            if let Some(list) = sub.find_subcommand_mut("list") {
                configure(
                    list,
                    Some("List built-in sink discovery profiles"),
                    Some(SINK_DISCOVERY_PROFILES_LIST_AFTER),
                    false,
                );
            }
            if let Some(show) = sub.find_subcommand_mut("show") {
                configure(
                    show,
                    Some("Show a built-in sink discovery profile"),
                    Some(SINK_DISCOVERY_PROFILES_SHOW_AFTER),
                    false,
                );
                annotate_args(
                    show,
                    &[(
                        "name",
                        "Built-in sink discovery profile name to display, such as linux-command-exec",
                    )],
                );
            }
            if let Some(validate) = sub.find_subcommand_mut("validate") {
                configure(
                    validate,
                    Some("Validate a community sink discovery profile YAML file"),
                    Some(SINK_DISCOVERY_PROFILES_VALIDATE_AFTER),
                    false,
                );
                annotate_args(
                    validate,
                    &[(
                        "path",
                        "Path to a community sink discovery profile YAML file",
                    )],
                );
            }
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("taint") {
        configure(
            cmd,
            Some("Trace data flow from attacker-controlled inputs to dangerous sinks"),
            Some(TAINT_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to an ELF binary or raw firmware blob"),
                (
                    "arch",
                    "Architecture for raw blobs when FAT cannot infer it from the file",
                ),
                ("base", "Base address for raw firmware blobs"),
                ("severity", "Minimum severity threshold to print"),
                ("summary", "Print one line per finding"),
                ("json", "Emit machine-readable JSON instead of text"),
                (
                    "decompile",
                    "Attach decompiled source context when available",
                ),
                (
                    "sink_candidates",
                    "Supplemental SinkDiscoveryReport candidate sinks for stripped or static binaries",
                ),
                (
                    "no_cache",
                    "Force a fresh analysis instead of reusing cached findings",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("identify-launcher") {
        configure(
            cmd,
            Some("Determine whether a binary is likely a thin launcher/bootstrapper"),
            Some(IDENTIFY_LAUNCHER_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a binary or shared library"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("taint-query") {
        configure(
            cmd,
            Some("Ask precise source-to-sink path questions over a queryable taint graph"),
            Some(TAINT_QUERY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "fixture",
                    "Fixture directory containing a prebuilt query graph",
                ),
                (
                    "file",
                    "Binary path for live angr-backed query graph construction",
                ),
                ("from", "Source selector expression"),
                ("to", "Sink selector expression"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("crypto") {
        configure(
            cmd,
            Some("Detect, classify, and extract security-relevant crypto artifacts"),
            Some(CRYPTO_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a firmware binary to analyze"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("crypto-extract") {
        configure(
            cmd,
            Some("Extraction-focused alias for embedded keys, certs, and crypto blobs"),
            Some(CRYPTO_EXTRACT_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("file", "Path to a firmware binary to analyze"),
                ("json", "Emit machine-readable JSON instead of text"),
                (
                    "output_dir",
                    "Write extracted PEM key artifacts and a JSON manifest to this directory",
                ),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("signature-fit") {
        configure(
            cmd,
            Some("Test whether a firmware byte window fits a public-key signature relation"),
            Some(SIGNATURE_FIT_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "firmware",
                    "Firmware/package file containing the suspected signature window",
                ),
                (
                    "key_blob",
                    "Raw Microsoft PUBLICKEYBLOB exported by `fat crypto-extract`",
                ),
                (
                    "signature_offset",
                    "Start offset of the suspected signature window, decimal or hex",
                ),
                (
                    "signature_size",
                    "Length of the suspected signature window, decimal or hex",
                ),
                (
                    "signature_byte_order",
                    "Interpret signature bytes as big-endian or little-endian integer order",
                ),
                (
                    "zero_range",
                    "Range to zero before hashing, as offset:length or start..end; repeatable",
                ),
                (
                    "output_dir",
                    "Directory for verified PSS salt, firmware hash, and manifest artifacts",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("taint-cross") {
        configure(
            cmd,
            Some("Stitch source-to-sink evidence across binaries connected by shared state"),
            Some(TAINT_CROSS_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("files", "One or more ELF binaries to analyze together"),
                (
                    "rootfs",
                    "Extracted rootfs directory to scan for candidate binaries",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("trust-boundary") {
        configure(
            cmd,
            Some("Map firmware update, auth, and crypto trust boundaries across a rootfs"),
            Some(TRUST_BOUNDARY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to the extracted firmware rootfs directory"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("trust-map") {
        configure(
            cmd,
            Some("Highlight the governing updater path and trust-bearing binaries across a rootfs"),
            Some(TRUST_MAP_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                ("rootfs", "Path to the extracted firmware rootfs directory"),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("sdk-trace") {
        configure(
            cmd,
            Some("Trace linked-library and import/export dependencies across an SDK directory"),
            Some(SDK_TRACE_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "dir",
                    "Directory to scan recursively for ELF binaries and shared libraries",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    if let Some(cmd) = root.find_subcommand_mut("invariant") {
        configure(
            cmd,
            Some("Check or query security invariants against source repositories"),
            Some(INVARIANT_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("query") {
            configure(
                sub,
                Some("Evaluate a structured invariant rule via the shared query graph"),
                Some(INVARIANT_QUERY_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "fixture",
                        "Fixture directory containing a prebuilt source query graph",
                    ),
                    (
                        "repo",
                        "Source repository path for future live query backends",
                    ),
                    ("rule", "Invariant rule to evaluate"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("patch") {
        configure(
            cmd,
            Some("Derive invariant-oriented patch guidance and search for nearby variants"),
            Some(PATCH_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("check") {
            configure(
                sub,
                Some("Check a patch fixture or repo for missing sibling fixes"),
                Some(PATCH_CHECK_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "fixture",
                        "Fixture directory containing patch and source graph inputs",
                    ),
                    (
                        "repo",
                        "Repository path for future live patch analysis backends",
                    ),
                    (
                        "find_variants",
                        "Search for sibling sites that may still be missing the fix",
                    ),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("chain") {
        configure(
            cmd,
            Some("Assemble multi-step exploit or propagation chains from evidence fixtures"),
            Some(CHAIN_AFTER),
            true,
        );
        if let Some(sub) = cmd.find_subcommand_mut("query") {
            configure(
                sub,
                Some("Query a chain goal against a fixture-backed evidence graph"),
                Some(CHAIN_QUERY_AFTER),
                false,
            );
            annotate_args(
                sub,
                &[
                    (
                        "fixture",
                        "Fixture directory containing a prebuilt chain graph",
                    ),
                    ("goal", "Chain goal label such as preauth-rce"),
                    ("json", "Emit machine-readable JSON instead of text"),
                ],
            );
        }
    }
    if let Some(cmd) = root.find_subcommand_mut("verify") {
        configure(
            cmd,
            Some("Attach runtime confirmation evidence to a previously derived finding"),
            Some(VERIFY_AFTER),
            false,
        );
        annotate_args(
            cmd,
            &[
                (
                    "fixture",
                    "Fixture directory containing runtime confirmation data",
                ),
                ("json", "Emit machine-readable JSON instead of text"),
            ],
        );
    }
    apply_root_banner(root);
}

// Presentation order only: parsing and per-command help remain clap's responsibility.
const ROOT_COMMAND_GROUPS: &[(&str, &[&str])] = &[
    ("Start here", &["identify", "doctor", "help"]),
    (
        "Projects & extraction",
        &[
            "new",
            "extract",
            "analyze",
            "list",
            "info",
            "delete",
            "carve",
            "extract-payload",
        ],
    ),
    (
        "Firmware structure",
        &[
            "inspect",
            "compare",
            "diff",
            "bootloader",
            "detect-encryption",
            "edge-ai",
            "android",
        ],
    ),
    (
        "Filesystem & code",
        &[
            "tree",
            "ls",
            "search",
            "xref-search",
            "startup-map",
            "source-map",
            "r2-triage",
            "decompile",
            "handler-table",
            "sink-discovery",
            "identify-launcher",
            "inspect-handoff",
            "sdk-trace",
            "bundle-reality",
            "runtime-plane",
        ],
    ),
    (
        "Security analysis",
        &[
            "taint",
            "taint-query",
            "taint-cross",
            "crypto",
            "crypto-extract",
            "crypto-census",
            "signature-fit",
            "trust-map",
            "trust-boundary",
        ],
    ),
    (
        "Emulation & runtime",
        &[
            "preflight",
            "emulate",
            "debug",
            "observe",
            "rehost",
            "experiment",
            "rehosting-trace",
            "instrument-hooks",
            "trace-ingest",
            "probe",
            "kernel",
            "data",
        ],
    ),
    (
        "Queries & evidence",
        &[
            "invariant",
            "patch",
            "chain",
            "verify",
            "graph",
            "label",
            "labels",
            "discover",
            "hsm",
            "benchmark",
        ],
    ),
];

fn apply_root_banner(root: &mut Command) {
    // Build first so clap's automatic `help` command participates in the same
    // metadata-driven rendering as all explicitly declared commands.
    root.build();
    let mut remaining: Vec<_> = root
        .get_subcommands()
        .filter(|command| !command.is_hide_set())
        .cloned()
        .collect();
    let mut sections = String::new();
    for (heading, names) in ROOT_COMMAND_GROUPS {
        let mut commands = Vec::new();
        for name in *names {
            if let Some(index) = remaining
                .iter()
                .position(|command| command.get_name() == *name)
            {
                commands.push(remaining.remove(index));
            }
        }
        sections.push_str(&render_command_group(root, heading, commands));
    }
    // Future commands must stay discoverable even before they are categorized.
    sections.push_str(&render_command_group(root, "Other commands", remaining));

    let heading = root.get_styles().get_header();
    let template = ROOT_HELP_TEMPLATE
        .replace("__FAT_VERSION__", env!("CARGO_PKG_VERSION"))
        .replace(
            "__OPTIONS_HEADING__",
            &format!("{heading}Options:{heading:#}"),
        );
    // Pass descriptions as content, not template syntax: a literal `{usage}`
    // in command metadata must not be expanded by the outer help renderer.
    let updated = std::mem::take(root)
        .before_help(sections.trim_end().to_owned())
        .help_template(template);
    *root = updated;
}

fn render_command_group(root: &Command, heading: &str, commands: Vec<Command>) -> String {
    if commands.is_empty() {
        return String::new();
    }
    // Reuse clap for names, descriptions, visible aliases, alignment and styling.
    // This is a display-only command; the real parser retains its original tree.
    let mut group = Command::new("help-group")
        .disable_help_flag(true)
        .disable_help_subcommand(true)
        .styles(root.get_styles().clone())
        .help_template("{subcommands}")
        .subcommands(
            commands
                .into_iter()
                .enumerate()
                .map(|(index, command)| command.display_order(index)),
        );
    let style = root.get_styles().get_header();
    let rendered = group.render_help();
    format!(
        "{style}{heading}:{style:#}\n{}\n\n",
        rendered.ansi().to_string().trim_end()
    )
}

fn configure(
    cmd: &mut Command,
    about: Option<&'static str>,
    after_long_help: Option<&'static str>,
    arg_required_else_help: bool,
) {
    let mut updated = std::mem::take(cmd);
    if let Some(about) = about {
        updated = updated.about(about);
    }
    if let Some(after_long_help) = after_long_help {
        updated = updated.after_long_help(after_long_help);
    }
    if arg_required_else_help {
        updated = updated.arg_required_else_help(true);
    }
    *cmd = updated;
}

fn annotate_args(cmd: &mut Command, specs: &[(&'static str, &'static str)]) {
    let mut updated = std::mem::take(cmd);
    for (name, help) in specs {
        updated = updated.mut_arg(*name, |arg| arg.help(*help).long_help(*help));
    }
    *cmd = updated;
}

const ROOT_HELP_TEMPLATE: &str = r#"
              ______   ___   ______                 v__FAT_VERSION__
             / ____/  /   | /_  __/
            / /_     / /| |  / /
           / __/    / ___ | / /
          /_/      /_/  |_|/_/

             Firmware Analysis Toolkit v__FAT_VERSION__ by Attify
        Offensive IoT Exploitation Training  https://www.attify.com/training
        ------------------------------------------------------------------------
{usage-heading} {usage}

{before-help}

__OPTIONS_HEADING__
{options}{after-help}
"#;

const ROOT_AFTER: &str = r#"Getting started:
  FAT is organized around project setup, extraction, analysis, runtime work, and
  higher-signal security queries. Start with a project, then extract and analyze
  it before moving to taint, trust-boundary, or runtime commands.

Examples:
  fat ./firmware.bin
  fat identify --file ./firmware.bin
  fat new ./firmware.bin
  fat extract ./.fat-projects/demo
  fat analyze ./.fat-projects/demo
  fat preflight ./.fat-projects/demo
  fat taint --file ./www/cgi-bin/diag.cgi --summary
  fat taint --lang shell --rootfs ./extracted-rootfs --summary
  fat sink-discovery --file ./usr/sbin/httpd --json
  fat source-map --rootfs ./extracted-rootfs --json
  fat invariant query --fixture tests/fixtures/query/source/invariant-permission --rule 'Every privileged override method must call enforcePermission()'

Common workflows:
  0. First-contact workflow:
     fat <firmware-or-directory> -> fat identify -> evidence and classification
  1. New project workflow:
     fat new -> fat extract -> fat analyze -> fat preflight -> fat emulate
  2. Binary triage workflow:
     fat inspect -> fat r2-triage -> fat taint -> fat taint-query -> fat taint-cross
  3. Stripped static sink workflow:
     fat r2-triage -> fat sink-discovery -> fat handler-table -> fat taint --sink-candidates -> fat instrument-hooks --from-sinks
  4. Source and invariant workflow:
     fat invariant query -> fat patch check -> fat verify

Stripped static sink workflow:
  fat r2-triage --file ./usr/sbin/httpd --json
  fat sink-discovery --file ./usr/sbin/httpd --json > sinks.json
  fat handler-table --file ./usr/sbin/httpd --json > handlers.json
  fat taint --file ./usr/sbin/httpd --sink-candidates sinks.json --json > taint.json
  fat instrument-hooks --from-sinks sinks.json --output hooks.yaml

Tips:
  - Use -h for a compact option list and --help for the full guide with examples.
  - Passing an existing path directly, such as `fat ./firmware.bin`, routes to identify.
  - Most analysis commands accept --json for automation-friendly output.
  - Runtime-oriented commands usually expect a FAT project directory, not just a raw file.
"#;

const NEW_AFTER: &str = r#"Syntax:
  fat new <firmware> [--name <project-name>] [--projects-dir <dir>]

What it does:
  Creates a FAT project directory, copies the firmware into input/, records the
  initial project metadata, and prepares the runtime store.

Examples:
  fat new ./downloads/router.bin
  fat new ./downloads/router.bin --name example-router
  fat new ./fw/image.bin --projects-dir ~/fat-projects

Tips:
  - Use a stable --name when you want reproducible project paths across runs.
  - The created project directory is what later commands like extract and analyze use.
"#;

const EXTRACT_AFTER: &str = r#"Syntax:
  fat extract <project-dir-or-firmware.bin> [--force] [--extract-timeout <secs>] [--extractor <engine>]
              [--unblob-processes <n>] [--unblob-depth <n>] [--json]

What it does:
  Runs extraction tooling, records the extraction manifest, and attempts to recover
  a rootfs and other carved artifacts for later analysis. If the argument is a raw
  firmware image, FAT first creates the default project under .fat-projects and
  then extracts that project. If that project already exists, FAT reuses it.

  When work/extraction-manifest.json already exists, FAT reports that the project
  is already extracted and leaves work/extractions untouched. Use --force when
  you intentionally want to re-run extraction and overwrite those artifacts.

  Each external extractor runs under a deadline. On timeout FAT kills that
  extractor's whole process group, records the timeout in work/<tool>.log, and
  continues down the chain instead of hanging.

  Extractor output streams into work/<tool>.log as it is produced, so a long run
  can be followed with tail -f while it happens. Runs that outlast a few seconds
  also report elapsed time on stdout.

  By default (--extractor auto) engines run in priority order and the first one
  that recovers enough stops the rest, with each skip recorded in that engine's
  log. Use --extractor all when an earlier engine carves something it cannot
  unpack and suppresses a later engine that could have.

  The manifest records the winning engine, the version it reported, and the exact
  arguments it ran with, so a result can be reproduced without reading logs.

  --json emits a single fat.extract.v1 object on stdout with the engine, engine
  version, per-engine outcomes, rootfs and kernel paths with sizes, and the file
  count. Progress moves to stderr so stdout stays parseable.

Examples:
  fat extract ./.fat-projects/demo
  fat extract ./firmware.bin
  fat extract ./firmware.bin --force
  fat extract ./firmware.bin --extract-timeout 300
  fat extract ./firmware.bin --extractor all
  fat extract ./firmware.bin --json | jq -r .rootfs.path

Tips:
  - Run fat doctor first if extraction tools such as binwalk or unblob are missing.
  - Re-running without --force is safe for hand-edited files under work/extractions.
  - The summary reports which engine won and why the others were skipped.
  - Follow a slow extraction with: tail -f <project>/work/binwalk.log
  - unblob tuning is forwarded only when set, so the default run is unblob's own.
  - Batch pipelines can set FAT_EXTRACT_TIMEOUT instead of passing the flag every run.
  - After extraction, run fat analyze to derive signals and inventory.
"#;

const CARVE_AFTER: &str = r#"Syntax:
  fat carve [<project-dir>] --offset <offset> (--size <bytes> | --format squashfs) [--file <path>] [--output <path>]

What it does:
  Materializes a byte-exact region from firmware. Generic carving uses --size.
  Format-aware carving can infer size when the format parser supports it.

Examples:
  fat carve --file ./firmware.bin --offset 0x0015CE00 --size 5955826 --output rootfs.sqsh
  fat carve --file ./firmware.bin --offset 0x0015CE00 --format squashfs --output rootfs.sqsh
  fat carve ./.fat-projects/demo --offset 0x0015CE00 --format squashfs

Tips:
  - Use --format squashfs when FAT identified a SquashFS region and you want FAT
    to infer the filesystem image size from the superblock.
  - Use --size for generic byte ranges and unknown formats.
"#;

const EXTRACT_PAYLOAD_AFTER: &str = r#"Syntax:
  fat extract-payload [<project-dir>] --offset <offset> --format <format> [--file <path>]

What it does:
  Extracts a specific payload fragment at a known offset from a project firmware
  image or an explicitly provided file.

Examples:
  fat extract-payload ./.fat-projects/demo --offset 0x1000 --format lzma
  fat extract-payload --file ./image.bin --offset 4096 --format gzip

Tips:
  - Use --file when you want to operate on a standalone artifact outside a FAT project.
  - Offset values can be decimal or hex when the downstream parser supports it.
"#;

const ANALYZE_AFTER: &str = r#"Syntax:
  fat analyze <project-dir> [--json]

What it does:
  Reads the extracted artifacts, derives project signals, inventories binaries,
  and persists analysis outputs used by preflight, trust-boundary, and runtime tooling.

  Signals are derived from the recovered tree and parsed headers, not from
  extractor logs, so the same firmware classifies the same way whichever engine
  extracted it. Each signal reports its provenance: measured, tree-name, or
  strings-fallback.

  --json emits a single fat.analyze.v1 object on stdout.

Examples:
  fat analyze ./.fat-projects/demo
  fat analyze ./.fat-projects/demo --json | jq -r '.signals[].signal'

Tips:
  - Run analyze after extraction finishes and before evaluating emulator backends.
  - analysis/signals.txt stays a bare signal list; provenance rides in the summary.
  - The resulting analysis artifacts drive backend ranking and expose runtime selection facts.
"#;

const PREFLIGHT_AFTER: &str = r#"Syntax:
  fat preflight [<project-dir>] [--signal <signal> ...] [--json]

What it does:
  Ranks backend families and host prerequisites using either a project's derived
  analysis signals or an explicit set of manual signals.

Examples:
  fat preflight ./.fat-projects/demo
  fat preflight --signal arch:mips --signal fs:squashfs --signal web:cgi
  fat preflight ./.fat-projects/demo --json | jq -r '.backends[] | select(.available)'

Tips:
  - Use manual --signal values when you want to evaluate a target before a full project exists.
  - The report is most useful after fat analyze has already derived project signals.
"#;

const INFO_AFTER: &str = r#"Syntax:
  fat info <project-dir> [--json]

What it does:
  Prints stored project metadata such as project status, tracked firmware, and
  the current known artifact layout.

Examples:
  fat info ./.fat-projects/demo
  fat info ./.fat-projects/demo --json

Tips:
  - Use info when you need the canonical project path and status before running runtime commands.
  - Use --json when another tool or UI needs the current FAT project/target/runtime summary.
"#;

const IDENTIFY_AFTER: &str = r#"Syntax:
  fat identify [<path> | --file <path>] [--details] [--json]

What it does:
  Identifies a file or directory, summarizes the strongest evidence that the
  target is structured firmware, executable code, or a simple directory tree.
  It can surface known top-level headers, high-entropy compression/encryption
  hints, ELF header facts, rootfs markers, and shallow firmware blob collections.
  The default view highlights identity, image structure, and address mapping.
  Use --details for supporting tables, or --json for the full analysis report.

Examples:
  fat identify --file ./firmware.bin
  fat identify ./firmware.bin --details
  fat identify ./firmware.bin --json

Tips:
  - Use this before choosing between inspect envelope, inspect layout, inspect mcu, or binary triage.
  - The command does not extract, create projects, or prescribe an investigation sequence.
"#;

const DOCTOR_AFTER: &str = r#"Syntax:
  fat doctor [--json] [--strict]

What it does:
  Checks host tooling and reports missing dependencies that block extraction,
  emulation, or analysis workflows. Also reports the FAT_SYSTEM_KERNEL_DIR
  system-kernel directory check, the FAT_DATA_DIR data-root discovery and
  writability check, and warns when the running binary was built from a
  different release than the git checkout it came from.

Examples:
  fat doctor
  fat doctor --json

Tips:
  - Run this first on a new machine before attempting extraction or emulation.
  - Use --json for machine-readable output in scripts and CI.
"#;

const DEBUG_AFTER: &str = r#"What it does:
  Groups session-oriented debugging commands for shells, memory maps, GDB,
  monitor access, and suggested next steps.

Examples:
  fat debug surfaces --project ./.fat-projects/demo
  fat debug shell --project ./.fat-projects/demo --session-id sess-123
  fat debug gdb --project ./.fat-projects/demo --target httpd

Tips:
  - Most debug subcommands accept an optional --session-id. If omitted, FAT uses
    its best available session resolution for the project.
"#;

const DEBUG_SURFACES_AFTER: &str = r#"Syntax:
  fat debug surfaces --project <project-dir> [--session-id <id>] [--json]

What it does:
  Lists the runtime control surfaces FAT knows about for a session, including
  shell, monitor, debug ports, or other backend-specific handles.

Examples:
  fat debug surfaces --project ./.fat-projects/demo
  fat debug surfaces --project ./.fat-projects/demo --session-id sess-123 --json
"#;

const DEBUG_SHELL_AFTER: &str = r#"Syntax:
  fat debug shell --project <project-dir> [--session-id <id>] [--command <cmd>]

What it does:
  Opens an interactive shell or runs a single command inside the selected
  runtime session.

Examples:
  fat debug shell --project ./.fat-projects/demo
  fat debug shell --project ./.fat-projects/demo --session-id sess-123 --command 'ps'

Tips:
  - Use --command for quick checks in scripts.
  - Omit --command when you want an interactive shell in the runtime environment.
"#;

const DEBUG_MAPS_AFTER: &str = r#"Syntax:
  fat debug maps --project <project-dir> --target <process-or-binary> [--session-id <id>]

What it does:
  Prints process memory maps for the selected target inside the runtime session.

Examples:
  fat debug maps --project ./.fat-projects/demo --target httpd
"#;

const DEBUG_MONITOR_AFTER: &str = r#"Syntax:
  fat debug monitor --project <project-dir> [--session-id <id>] [--command <cmd>]

What it does:
  Sends a backend monitor command, such as a QEMU monitor action, to the active session.

Examples:
  fat debug monitor --project ./.fat-projects/demo --command 'info registers'
"#;

const DEBUG_GDB_AFTER: &str = r#"Syntax:
  fat debug gdb --project <project-dir> [--session-id <id>] [--target <name>] [--command <cmd>]

What it does:
  Connects to the runtime's GDB endpoint or runs a single scripted GDB command.

Examples:
  fat debug gdb --project ./.fat-projects/demo --target httpd
  fat debug gdb --project ./.fat-projects/demo --command 'info threads'
"#;

const DEBUG_SUGGEST_AFTER: &str = r#"Syntax:
  fat debug suggest --project <project-dir> [--session-id <id>] [--json]

What it does:
  Suggests high-signal next debugging actions based on current session state.

Examples:
  fat debug suggest --project ./.fat-projects/demo --json
"#;

const OBSERVE_AFTER: &str = r#"What it does:
  Groups read-only runtime observations such as process listings, services, and
  network state snapshots.

Examples:
  fat observe ps --project ./.fat-projects/demo
  fat observe services --project ./.fat-projects/demo --json
  fat observe net --project ./.fat-projects/demo
"#;

const OBSERVE_PS_AFTER: &str = r#"Syntax:
  fat observe ps --project <project-dir> [--session-id <id>] [--json]

What it does:
  Lists the processes seen in the runtime session.
"#;

const OBSERVE_SERVICES_AFTER: &str = r#"Syntax:
  fat observe services --project <project-dir> [--session-id <id>] [--json]

What it does:
  Lists observed services, likely exposure, and related metadata in the runtime session.
"#;

const OBSERVE_NET_AFTER: &str = r#"Syntax:
  fat observe net --project <project-dir> [--session-id <id>] [--json]

What it does:
  Lists listeners, ports, and network endpoints visible in the runtime session.
"#;

const BENCHMARK_AFTER: &str = r#"What it does:
  Benchmark commands let FAT summarize taint datasets, score FAT-native runtime
  sessions, import comparator reports, and render stored benchmark views.

Examples:
  fat benchmark taint --dataset ./datasets/router-mini/manifest.json --json
  fat benchmark score --project ./.fat-projects/demo --session-id sess-123
  fat benchmark report --project ./.fat-projects/demo
"#;

const BENCHMARK_TAINT_AFTER: &str = r#"Syntax:
  fat benchmark taint --dataset <manifest.json> [--json]

What it does:
  Reads a dataset manifest, loads either fixture findings or live taint runs,
  and produces a summary grouped by severity and finding status.

Expected dataset manifest:
  {
    "dataset": "router-mini",
    "cases": [
      {
        "id": "router-httpd",
        "findings_fixture": "./findings/httpd.json",
        "duration_ms": 42
      }
    ]
  }

Notes:
  - findings_fixture lets you benchmark from checked-in results without rerunning analysis.
  - file/arch/base fields can be used for live binary analysis when you want fresh runs.

Examples:
  fat benchmark taint --dataset ./datasets/router-mini/manifest.json --json

Tips:
  - Use fixture-backed datasets for stable regression tests and documentation examples.
  - Use live file entries when measuring performance changes in the taint engine itself.
"#;

const BENCHMARK_SCORE_AFTER: &str = r#"Syntax:
  fat benchmark score --project <project-dir> [--session-id <id>] [--run-id <id>] [--comparator <name>] [--run-mode <mode>]

What it does:
  Converts a FAT-native runtime record into a scored benchmark outcome.
"#;

const BENCHMARK_IMPORT_AFTER: &str = r#"Syntax:
  fat benchmark import --project <project-dir> --report <report.json>

What it does:
  Imports an external comparator report into the runtime store so it can be
  compared with FAT-native benchmark outcomes.
"#;

const BENCHMARK_REPORT_AFTER: &str = r#"Syntax:
  fat benchmark report --project <project-dir> [--json]

What it does:
  Renders stored benchmark runs and comparator outcomes for a project.
"#;

const SOURCE_MAP_AFTER: &str = r#"Syntax:
  fat source-map --rootfs <extracted-rootfs> [--source-profile <file>] [--json]

What it does:
  Scans frontend assets such as HTML, JavaScript, and XML descriptors, then
  ranks likely backend binaries and source APIs that consume those parameters.

Source hints:
  A backend candidate's source_hints list names symbols observed in that
  binary's strings. FAT compiles in only the specified ones (getenv). Which
  platform symbol carries request data is a claim about one target, so pass
  --source-profile <file> to add your own; without it, no platform symbol is
  reported as a source hint. A hint is an observed name, never a proven flow.
  JSON reports include model_provenance (core, or the selected profile's name,
  path and SHA-256), including when no backend candidates match.

Examples:
  fat source-map --rootfs ./extracted-rootfs
  fat source-map --rootfs ./extracted-rootfs --json
  fat source-map --rootfs ./extracted-rootfs --source-profile ./my-target.yaml --json

Tips:
  - This works best on rootfs trees that still contain frontend assets under /www or similar paths.
  - Use the JSON output when feeding likely source functions into deeper taint analysis.
"#;

const STARTUP_MAP_AFTER: &str = r#"Syntax:
  fat startup-map --rootfs <extracted-rootfs> [--profile cloud-tls] [--json]

What it does:
  Reconstructs static startup intent from rc.d and init.d metadata, resolves
  referenced executables, and attaches binary evidence such as profile strings,
  imports, and linked libraries when rabin2 is available.

Examples:
  fat startup-map --rootfs ./rootfs --profile cloud-tls
  fat startup-map --rootfs ./rootfs --profile curl --emit-actions
  fat startup-map --rootfs ./rootfs --profile web --json

Tips:
  - This is a target-selection map, not runtime proof or exploitability proof.
  - Use --explain in notebooks when teaching the startup intent reasoning chain.
  - Follow strong candidates with fat r2-triage, fat trust-map, or fat taint.
"#;

const SEARCH_AFTER: &str = r#"What it does:
  Searches printable strings in extracted firmware. By default it scans ELF binaries under standard rootfs binary and library directories, and auto-discovers nested rootfs trees such as squashfs-root and rootfs under --rootfs.
  Text output is a compact triage view with offsets, strength labels, weighted ranking, and discriminating/common string summaries.
  JSON output uses search-report/v2 and includes offsets, line numbers, scoring weights, scores, files scanned without matches, ranked files, and shared-string summaries.

Examples:
  fat search --rootfs ./rootfs -i 'ota|update|upgrade'
  fat search --rootfs ./rootfs -i 'http|https' -e 'alsa|conf'
  fat search --rootfs ./rootfs -i 'password|secret' --path app/bin/
  fat search --rootfs . --profile credentials -I --context 2
  fat search --rootfs . -i '/configs/\.product_config|product_config_get_' --summary
  fat search --rootfs . -i '/configs/\.product_config|product_config_get_' --min-strength strong
  fat search --rootfs . -i 'password|secret' --all-files --format anchor
  fat search --rootfs . --profile urls --all-files --unique
  fat search --rootfs . --path firmware.bin -i 'ethernetif\.c' --all-files --json
  fat search --rootfs ./rootfs -i 'ota' --progress human | c++filt
  fat search --rootfs ./rootfs -i 'ota' --all-files --json

Tips:
  Start with the default ELF scope to keep noise low, then widen with --all-files when the firmware surface points at text assets.
  Valid Cortex-M images, or any explicit file selected with --path, are scanned as raw binaries with printable-string byte offsets.
  Use --summary for a one-line-per-file Observation draft.
  Use --format anchor when collecting pasteable notebook evidence.
  Use --no-discover-rootfs when you want --rootfs to be treated as the exact scan boundary.
  Use --progress human for realtime stderr scan updates while stdout remains pipe- and JSON-safe.
  Use --verbose when you need full scan metadata such as rootfs candidates, defaults, and skipped-file counts.
  Use --context-filter none if you need unfiltered string-table adjacency instead of boilerplate-filtered context.
"#;

const EMULATE_AFTER: &str = r#"Syntax:
  fat emulate [--project <project-dir>] [--backend <name>] [--substrate-policy <policy>] [--port <port> ...] [--session-id <id>] [--status] [--stop]

What it does:
  Starts or manages a runtime backend for a FAT project, or inspects/stops an existing session.

Examples:
  fat emulate --project ./.fat-projects/demo
  fat emulate --project ./.fat-projects/demo --substrate-policy system-first
  fat emulate --project ./.fat-projects/demo --status
  fat emulate --project ./.fat-projects/demo --stop --session-id sess-123

Tips:
  - Pair this with fat preflight first if you need backend candidate rankings and availability facts.
  - Valid substrate policies are auto, service-first, system-first, and reference-only.
  - Use --status and --stop when managing an existing session lifecycle.
"#;

const DIFF_AFTER: &str = r#"What it does:
  Diff commands compare targets by semantic role rather than only by bytes or paths.

Examples:
  fat diff role --left ./old-rootfs/usr/sbin/service --right ./new-rootfs/usr/sbin/service --json

Tips:
  - Start with diff role when two launchers or daemons may hand off into the same deeper implementation.
  - Use this before expensive byte-level diffing when the real question is “do these serve the same role?”
"#;

const DIFF_ROLE_AFTER: &str = r#"Syntax:
  fat diff role --left <binary> --right <binary> [--json]

What it does:
  Compares two binaries using launcher classification and runtime-plane signals
  to decide whether they appear to play the same semantic role.

Examples:
  fat diff role --left ./left.bin --right ./right.bin
  fat diff role --left ./old-rootfs/usr/sbin/service --right ./new-rootfs/usr/sbin/service --json

Tips:
  - This is a role diff, not a byte diff. Shared downstream handoff targets and runtime-plane IDs matter more than identical file contents.
  - Pair it with fat identify-launcher and fat runtime-plane when the result is inconclusive.
"#;

const DIFF_FIRMWARE_AFTER: &str = r#"Syntax:
  fat diff firmware --base <base-project-or-rootfs> --head <head-project-or-rootfs> [--layer <layer>] [--security] [--json]

Layers:
  filesystem  Walk both rootfs trees and report added, removed, changed, permission-changed, and symlink-changed paths.
  config      Compare extracted configuration signals such as NVRAM keys, web endpoints, and certificate metadata.
  binary      Compare changed ELF binaries that exist on both sides. Uses radare2 (`r2`) for function lists and strings.
  all         Run filesystem, config, and binary layers. This is the default.

Rootfs discovery:
  --base and --head can point at FAT project directories or direct rootfs directories.
  For project directories, FAT resolves the actual rootfs before diffing, including nested
  extraction layouts under extracted/ and work/extractions/.

Binary-layer notes:
  - Install radare2 and ensure `r2` is on PATH for binary diff support.
  - `--layer binary` discovers changed ELF pairs without requiring the filesystem layer in the output.
  - If no changed ELF pairs are found, or r2 is unavailable, the report includes a binary diagnostic.

Examples:
  fat diff firmware --base ./lab/v2.01 --head ./lab/v2.17
  fat diff firmware --base ./lab/v2.01 --head ./lab/v2.17 --security
  fat diff firmware --base ./lab/v2.01 --head ./lab/v2.17 --layer binary
  fat diff firmware --base ./lab/v2.01 --head ./lab/v2.17 --layer binary --json
"#;

const BOOTLOADER_AFTER: &str = r#"What it does:
  Groups bootloader-specific project setup, environment export, emulation, and inspection commands.

Examples:
  fat bootloader new ./.fat-projects/demo --profile u-boot-arm
  fat bootloader inspect ./.fat-projects/demo
  fat bootloader emulate ./.fat-projects/demo --assist
  fat bootloader stop ./.fat-projects/demo
"#;

const BOOTLOADER_NEW_AFTER: &str = r#"Syntax:
  fat bootloader new <project-dir> --profile <profile>

What it does:
  Creates or updates bootloader workspace metadata for the selected project.
"#;

const BOOTLOADER_EXPORT_ENV_AFTER: &str = r#"Syntax:
  fat bootloader export-env <project-dir>

What it does:
  Exports discovered bootloader environment variables for scripting or review.
"#;

const BOOTLOADER_EMULATE_AFTER: &str = r#"Syntax:
  fat bootloader emulate <project-dir> [--assist]

What it does:
  Launches or prepares the bootloader emulation workflow for the project.
"#;

const BOOTLOADER_CONSOLE_AFTER: &str = r#"Syntax:
  fat bootloader console <project-dir>

What it does:
  Opens the bootloader console for a prepared workspace.
"#;

const BOOTLOADER_STOP_AFTER: &str = r#"Syntax:
  fat bootloader stop <project-dir>
  fat bootloader stop --all

What it does:
  Terminates the tmux-hosted QEMU session started by `fat bootloader emulate`.
  Stopping is idempotent: if no session is running, the command reports that
  and exits successfully.

  --all sweeps every FAT-managed bootloader session on this host, including
  orphans whose project directory has been deleted. Only sessions named with
  the FAT prefix are touched, so your own tmux sessions are left alone.

Examples:
  fat bootloader stop ./.fat-projects/demo
  fat bootloader stop --all
"#;

const BOOTLOADER_STATUS_AFTER: &str = r#"Syntax:
  fat bootloader status <project-dir>

What it does:
  Shows current bootloader workspace state and readiness.
"#;

const BOOTLOADER_INSPECT_AFTER: &str = r#"Syntax:
  fat bootloader inspect <project-dir>

What it does:
  Inspects bootloader artifacts, flow hints, and discovered environment information.
"#;

const INSPECT_AFTER: &str = r#"What it does:
  Groups read-only inspection commands for headers, layout, opaque-wrapper triage,
  and MCU-oriented firmware characterization.

Examples:
  fat inspect headers --file ./firmware.bin
  fat inspect envelope --file ./opaque.bin --reference ./older.bin
  fat inspect layout --file ./router.cgi --json
  fat inspect mcu --file ./firmware.bin --json
  fat inspect peripheral-map --file ./firmware.bin --family STM32H7
  fat inspect isr-state --file ./firmware.bin --family STM32H7
"#;

const INSPECT_HANDOFF_AFTER: &str = r#"Syntax:
  fat inspect-handoff --file <binary> [--json]

What it does:
  Collects linked-library and entrypoint evidence, ranks likely downstream
  targets, and explains whether the visible binary is handing behavior off into
  deeper framework or runtime-backed logic.

Examples:
  fat inspect-handoff --file ./rootfs/usr/sbin/service-launcher
  fat inspect-handoff --file ./libfoo.dylib --json

Tips:
  - Use this after fat identify-launcher when a daemon looks too small or too shallow.
  - On Apple targets, this is a better first move than forcing the binary through taint.
"#;

const BUNDLE_REALITY_AFTER: &str = r#"Syntax:
  fat bundle-reality --file <binary> [--json]

What it does:
  Compares linked framework metadata with what is actually present as plain
  files on disk. This helps surface cases where a bundle declares an executable
  but the visible filesystem does not contain it, suggesting packaged or
  runtime-backed implementation reality.

Examples:
  fat bundle-reality --file ./rootfs/usr/sbin/service-launcher
  fat bundle-reality --file ./SomeFrameworkConsumer --json

Tips:
  - Use this to separate bundle declarations from true runtime reality.
  - Pair it with fat runtime-plane when you suspect dyld or shared-cache backed logic.
"#;

const RUNTIME_PLANE_AFTER: &str = r#"Syntax:
  fat runtime-plane --file <binary> [--json]

What it does:
  Builds a first-pass semantic view of the deeper object families that likely
  govern behavior beyond the visible binary. This is especially useful when the
  binary is just a launcher or a thin bridge into frameworks or runtime-backed
  objects.

Examples:
  fat runtime-plane --file ./rootfs/usr/sbin/service-launcher
  fat runtime-plane --file ./SomeFrameworkConsumer --json

Tips:
  - Treat this as a semantic pivot command, not a raw listing of linked libraries.
  - Use it before diffing or authority analysis when the visible executable is shallow.
"#;

const INSPECT_HEADERS_AFTER: &str = r#"Syntax:
  fat inspect headers [<project-dir>] [--file <path>] [--json]

What it does:
  Inspects known firmware container headers from a project or standalone file.
  When the input is an ELF binary or shared object, it falls back to ELF header
  metadata instead of firmware-container parsing.
"#;

const INSPECT_LAYOUT_AFTER: &str = r#"Syntax:
  fat inspect layout [<project-dir>] [--file <path>] [--json]

What it does:
  Reports binary layout information, region roles, nesting, and partition mappings.
  For ELF binaries and shared objects, this renders section-oriented ELF
  structure instead of firmware-container regions. When no plaintext regions
  are found but the blob looks like an opaque wrapper, FAT now says so directly
  and tells you to decrypt or unwrap first.
"#;

const INSPECT_MCU_AFTER: &str = r#"Syntax:
  fat inspect mcu --file <firmware.bin> [--base <hex>] [--family <name>] [--details] [--json]

What it does:
  Summarizes identity and image mapping, startup candidates, populated
  interrupts, and decoded hardware accesses from a raw MCU firmware image.
  Related findings appear together; empty sections are omitted.

  Use --details to expand these groups with vector entries, candidate functions,
  instruction locations, address constants, identity strings, and recovered
  initialization tables. Use --json for the full structured analysis report;
  --details does not change JSON output.

Examples:
  fat inspect mcu --file ./firmware.bin
  fat inspect mcu --file ./firmware.bin --details
"#;

const INSPECT_PERIPHERAL_MAP_AFTER: &str = r#"Syntax:
  fat inspect peripheral-map --file <firmware.bin> [--base <hex>] [--family <name>] [--json]

What it does:
  Builds a focused peripheral-oriented MCU report from a raw firmware blob,
  including family-backed register-block observations and bounded configuration
  recovery from exact register-address literals.
"#;

const INSPECT_ISR_STATE_AFTER: &str = r#"Syntax:
  fat inspect isr-state --file <firmware.bin> [--base <hex>] [--family <name>] [--json]

What it does:
  Builds a bounded interrupt-boundary shared-state report from a raw MCU blob,
  ranking likely IRQ-to-consumer edges using vector ownership, execution-model
  hints, peripheral roles, and conservative async-state signals.
"#;

const INSPECT_ENVELOPE_AFTER: &str = r#"Syntax:
  fat inspect envelope --file <blob> [--reference <blob>] [--json]

What it does:
  Characterizes whether a raw blob behaves like an opaque wrapper by reporting
  entropy, repeated-block evidence, likely plaintext header span, and optional
  shared-prefix comparison against a reference image. This is the preferred
  wrapper-side surface when `binwalk` and plaintext carving show nothing. JSON
  output also carries explicit confidence, ECB assessment, rationale, and
  supporting evidence.

Examples:
  fat inspect envelope --file ./camera-v3.bin
  fat inspect envelope --file ./camera-v3.bin --reference ./camera-v1.bin

Tips:
  - Treat this as an evidence-first wrapper triage command, not proof of a specific cipher.
  - FAT reports `ECB unlikely` when no repeated 16-byte blocks are observed; that is evidence, not proof.
  - Use it to measure wrapper evidence when `file`, `binwalk`, and `fat inspect layout` do not reveal plaintext structure.
"#;

const INSPECT_UPDATE_AFTER: &str = r#"Syntax:
  fat inspect update --file <blob> --rootfs <rootfs> [--reference <blob>] [--json]

What it does:
  Runs the full update-oriented investigation pivot in one report: wrapper or
  envelope triage for the outer blob, trust-path reconstruction for the
  extracted rootfs, a short rootfs-wide crypto-census summary, and crypto
  profiling for the governing updater binary when one is identified. This is
  the preferred one-shot workflow when `binwalk` shows nothing and the real
  question becomes “what governs updates here?” In JSON mode, treat this as
  the canonical aggregate report: it embeds the same envelope and trust-path
  submodels rather than re-expressing them.

Examples:
  fat inspect update --file ./camera-v3.bin --rootfs ./rootfs
  fat inspect update --file ./camera-v3.bin --rootfs ./rootfs --reference ./camera-v1.bin --json

Tips:
  - Use this when one report should preserve the envelope, trust-path, crypto-census, and governing-updater relationships.
  - The governing updater path is the decision anchor; helper libraries may still contain interesting key material without governing the update model.
  - The census summary is what tells you whether the same key material is only helper-local or also present on the governing updater path.
  - In `--json`, this is the canonical aggregate surface for Envelope/Trust/Crypto contract consumers.
"#;

const DETECT_ENCRYPTION_AFTER: &str = r#"Syntax:
  fat detect-encryption --file <blob> [--json]

What it does:
  Wrapper for `fat inspect envelope --file` used when the first question is:
  “does this blob look like an encrypted wrapper and where might payload start?”

Examples:
  fat detect-encryption --file ./camera-v3.bin
"#;

const COMPARE_AFTER: &str = r#"Syntax:
  fat compare --encrypted <blob> --reference <blob> [--json]

What it does:
  Wrapper for `fat inspect envelope --file ... --reference ...` to compare shared
  structure and infer likely header boundaries quickly. Use this as an oracle
  for shared wrapper structure, not as proof that the reference can decrypt the
  newer image.

Examples:
  fat compare --encrypted ./camera-v3.bin --reference ./camera-v1.bin
"#;

const CRYPTO_CENSUS_AFTER: &str = r#"Syntax:
  fat crypto-census --rootfs <rootfs> [--only <csv>] [--group-by fingerprint] [--json]

What it does:
  Aggregates crypto artifacts across an extracted rootfs into reuse clusters so
  you can see where the same key material, cert-like blob, or RSA artifact
  recurs and whether any occurrence sits on the governing updater path. The
  cluster summary also surfaces candidate classifications so helper-only versus
  updater-path-relevant copies stay separated.

Examples:
  fat crypto-census --rootfs ./rootfs
  fat crypto-census --rootfs ./rootfs --json

Tips:
  - Start here when a single binary-level crypto report is too narrow and you need rootfs-wide reuse context.
  - The initial grouping mode is fingerprint; if you ask for anything else, FAT will reject it for now.
  - `--only` currently filters a small set of artifact tokens such as `rsa` and `blob`.
  - Governing-path hits matter because they tell you which reuse cluster should be inspected first when helper libraries and updater binaries both contain the same material.
"#;

const R2_TRIAGE_AFTER: &str = r#"Syntax:
  fat r2-triage --file <binary-or-blob> [--arch <arch>] [--base <addr>] [--family <name>] [--json]

What it does:
  Uses radare2 tooling to extract metadata, strings, imports, exports, and
  complexity indicators for rapid binary triage. For raw firmware blobs, FAT
  can use loader hints and MCU inspection to synthesize a usable analysis context.

Examples:
  fat r2-triage --file ./www/cgi-bin/diag.cgi
  fat r2-triage --file ./www/cgi-bin/diag.cgi --json
  fat r2-triage --file ./firmware.bin --arch cortex-m --base 0x08000000 --json

Tips:
  - Start here when you need a quick survey before deeper taint or decompilation work.
  - For raw blobs, give `--arch` and `--base`; `cortex-m` is the most common MCU shorthand.
"#;

const XREF_SEARCH_AFTER: &str = r#"Syntax:
  fat xref-search --file <elf> (--vaddr <addr> | --string <text>) [--scan <mode>] [--json]
  fat xref-search --file <raw.bin> --raw --arch mips-pic --base <addr> --string <text> [--json]
  fat xref-search --file <raw.bin> --raw --arch cortex-m --base <addr> --string <text> [--json]

What it does:
  Finds where an address or matching string is referenced. For ELF binaries, FAT
  reports pointer hits and architecture-aware MIPS code hits. For raw MIPS-PIC
  bootloader blobs, FAT can recover low-16 string-reference hits and attribute
  them to the nearest preceding PIC prologue candidate. For raw Cortex-M blobs,
  FAT recovers 16-bit Thumb ADR references and the nearest PUSH prologue candidate.

Examples:
  fat xref-search --file ./usr/sbin/httpd --string /goform/ --json
  fat xref-search --file ./boot.bin --raw --arch mips-pic --base 0x0 --string "Starting kernel" --json
  fat xref-search --file ./firmware.bin --raw --arch cortex-m --base 0x08000000 --string ethernetif.c --json

Tips:
  - Raw MIPS-PIC and Cortex-M hits are candidate function evidence, not final proof of function boundaries.
  - Use the recovered candidate address with `fat decompile --raw --arch <arch> --base ... --function ...`.
"#;

const TAINT_AFTER: &str = r#"Syntax:
  fat taint --file <binary-or-blob> [--arch <arch>] [--base <addr>] [--severity <level>] [--summary] [--json] [--decompile] [--sink-candidates <json>] [--source-profile <file>] [--no-cache]
  fat taint --lang shell --file <script> [--severity <level>] [--summary] [--json] [--source-profile <file>]
  fat taint --lang shell --rootfs <dir> [--severity <level>] [--summary] [--json] [--source-profile <file>]

What it does:
  Runs the angr-backed taint engine to connect attacker-controlled sources to
  dangerous sinks such as system, popen, exec, copy APIs, or bare-metal write targets.

  With --lang shell it instead parses shell scripts with tree-sitter-bash and
  walks assignments forward, connecting $(cat ...), $1..$N, CGI environment
  variables, read, uci get, fw_printenv, and getprop to the sink families in
  the shared shell-command-exec profile (eval, sed -i with a variable,
  insmod $var, sh -c "$var", sh /tmp/...). Findings serialize to the same
  TaintFinding JSON as binary taint, so anything that already reads taint
  findings deserializes them unchanged.

  The always-loaded shell profile asserts nothing about any device: a path
  prefix never establishes attacker control on its own, so an unqualified read
  stays Secondary. To mark a mount attacker-writable, or to add a platform's
  own config helper, pass your own overlay with --source-profile.

Common flags:
  --lang       Analyze a source language instead of a compiled binary. Values: shell.
  --rootfs     Sweep every *.sh / shebang script under a directory (--lang shell only).
  --severity   Filter output to critical, high, medium, low, or info.
  --summary    Show one line per finding for quick triage.
  --json       Emit machine-readable findings.
  --source-profile   Path to a taint source profile you write, merged with the
                     core models. FAT ships no profiles and never selects one
                     on its own, and the value is always a filesystem path —
                     there are no built-in profile names to pass here. Without
                     this flag, analysis uses the core models alone. A profile
                     may add models but may not redefine one core already
                     defines — core entries are fixed by specification, and
                     restating one is an error rather than an override. With
                     --lang shell this selects a shell overlay file, which may
                     replace shell-base entries.
  --decompile  Attach decompiled source context when available.
  --no-cache   Force a fresh analysis instead of reusing cached results.
  --arch       Required for raw blobs that are not self-describing ELFs.
  --base       Base address for raw blobs, especially MCU flash dumps.

Examples:
  fat taint --file ./www/cgi-bin/diag.cgi --summary
  fat taint --file ./www/cgi-bin/diag.cgi --severity high --json
  fat taint --file ./firmware.bin --arch cortex-m --base 0x08000000
  fat taint --file ./usr/sbin/httpd --sink-candidates sinks.json --json
  fat taint --file ./usr/sbin/httpd --decompile --no-cache
  fat taint --lang shell --file ./app/init/wifi.sh --summary
  fat taint --lang shell --rootfs ./extracted-rootfs --json
  fat taint --lang shell --rootfs ./extracted-rootfs --source-profile ./my-target-shell.yaml --severity high

Tips:
  - Start with --summary, then re-run high-value binaries with --json or --decompile.
  - For raw blobs, give both --arch and --base so the analysis can resolve addresses correctly.
  - Use --sink-candidates when stripped or static binaries need supplemental candidate sinks from sink-discovery.
  - Use fat taint-query when you need an exact answer like “does source X reach sink slot Y?”
  - Shell taint is deliberately unsound: shell is too dynamic to prove reachability.
    Every shell finding is a Candidate at WEAK strength, and only flows with a named
    source are reported. For sink hits with no provenance, use fat sink-discovery --rootfs.
"#;

const SINK_DISCOVERY_AFTER: &str = r#"Syntax:
  fat sink-discovery --file <binary> [--profile <profile.yaml|builtin-name> ...] [--family <name>] [--min-confidence <weak|probable|strong|confirmed>] [--json]
  fat sink-discovery --rootfs <dir> [--profile <profile.yaml|builtin-name> ...] [--family <name>] [--json]

What it does:
  Emits candidate sink evidence. With --file it scans an ELF binary's strings,
  pointer xrefs, and code patterns; with --rootfs it line-scans shell scripts
  (*.sh or shebang) under a rootfs against a shell-target profile. The JSON
  report shows which rules fired, which profile produced them, and how the
  result was scored. It does not claim exploitability or reachability by itself.

Profiles:
  - Omit --profile to use the built-in linux-command-exec profile (ELF) or
    shell-command-exec when --rootfs is given.
  - Built-in profiles can also be referenced by name, e.g. --profile shell-command-exec.
  - Pass one or more local YAML profile paths with --profile to extend or replace the default bundle.
  - Shell-target profiles declare `target: shell` and carry a per-family regex
    `pattern`; --rootfs mode requires one and rejects ELF-only profile bundles.
  - Use fat sink-discovery profiles list/show to inspect built-in profiles.
  - Use fat sink-discovery profiles validate to vet community-contributed YAML before sharing it.

Function attribution:
  Profiles stay declarative; Rust providers interpret code-pattern IDs. The current
  MIPS provider can attribute direct string-address loads to a function and only
  assigns a candidate address when the evidence points to one function.

Examples:
  fat sink-discovery --file ./usr/sbin/httpd --json
  fat sink-discovery --file ./usr/sbin/httpd --profile ./profiles/vendor-foo.yaml --json
  fat sink-discovery --file ./usr/sbin/httpd --family command-exec --min-confidence probable --json
  fat sink-discovery --rootfs ./extracted-rootfs --profile shell-command-exec --json
  fat sink-discovery --rootfs ./extracted-rootfs --family tmpfs-staged-exec
  fat sink-discovery profiles validate ./profiles/vendor-foo.yaml

Tips:
  - Treat the JSON report as evidence, not proof of a reachable sink.
  - Keep profiles declarative and inspect the fired rules in the output before feeding candidates downstream.
  - Start with the built-in profile, then layer community profiles once they validate cleanly.
"#;

const SINK_DISCOVERY_PROFILES_AFTER: &str = r#"What it does:
  Inspect built-in sink discovery profiles and validate community YAML files.

Examples:
  fat sink-discovery profiles list
  fat sink-discovery profiles show linux-command-exec
  fat sink-discovery profiles validate ./profiles/vendor-foo.yaml

Tips:
  - Use list and show to learn the built-in profile vocabulary.
  - Use validate before publishing a community profile or wiring it into automation.
"#;

const SINK_DISCOVERY_PROFILES_LIST_AFTER: &str = r#"What it does:
  Prints the built-in sink discovery profiles available in this build, one per
  line as: name, target (elf or shell), and description.
"#;

const SINK_DISCOVERY_PROFILES_SHOW_AFTER: &str = r#"What it does:
  Prints the YAML for a built-in sink discovery profile so you can inspect its
  markers, family rules, weights, and confidence thresholds.
"#;

const SINK_DISCOVERY_PROFILES_VALIDATE_AFTER: &str = r#"What it does:
  Parses and validates a community sink discovery profile YAML file without running a scan.
"#;

const IDENTIFY_LAUNCHER_AFTER: &str = r#"Syntax:
  fat identify-launcher --file <binary> [--json]

What it does:
  Uses function count, complexity, linked-library evidence, and entrypoint clues
  to classify whether a binary is likely a thin launcher/bootstrapper or a
  substantive implementation artifact.

Examples:
  fat identify-launcher --file ./rootfs/usr/sbin/service-launcher
  fat identify-launcher --file ./daemon --json

Tips:
  - A launcher classification is a pivot, not a final answer. Follow with fat inspect-handoff.
  - This is especially useful on Apple and other packaged runtime targets where the visible daemon is shallow.
"#;

const TAINT_QUERY_AFTER: &str = r#"Syntax:
  fat taint-query [--fixture <fixture-dir> | --file <binary>] --from <selector> --to <selector> [--json]

What it does:
  Answers a precise graph query such as whether a particular source value reaches
  a particular sink slot, and classifies the result as direct flow, constant sink arg,
  control-only reachability, or no path.

Selector examples:
  call[name="getenv" and arg0="QUERY_STRING"].ret
  call[name="popen"].arg0
  call[name="system"].arg0

Examples:
  fat taint-query --fixture tests/fixtures/query/binary/genie-constant-arg --from 'call[name="getenv" and arg0="QUERY_STRING"].ret' --to 'call[name="popen"].arg0' --json
  fat taint-query --file ./www/cgi-bin/genie.cgi --from 'call[name="getenv" and arg0="QUERY_STRING"].ret' --to 'call[name="popen"].arg0' --json

Tips:
  - Use --fixture for deterministic regression tests and --file for live angr-backed binary queries.
  - Prefer exact sink slots like .arg0 or .ret instead of vague function-only selectors.
"#;

const CRYPTO_AFTER: &str = r#"Syntax:
  fat crypto --file <binary> [--json]

What it does:
  Profiles crypto-related functions, extracts likely key material, and flags
  suspicious usage patterns such as custom crypto, weak modes, weak PRNG use,
  and partial-encryption control surfaces. When the target binary sits inside
  an inferred rootfs, FAT also annotates the report with updater-path relevance.
  Exact-length ASCII-hex AES key literals are decoded and structurally
  validated when they map to legal AES key sizes.

Examples:
  fat crypto --file ./usr/lib/libdecrypt.so
  fat crypto --file ./usr/lib/libdecrypt.so --json

Tips:
  - Use this when you want both crypto role classification and embedded key extraction in one pass.
  - If the immediate question is just “what key material is embedded here?”, `fat crypto-extract` is the extraction-focused alias.
  - AES hex validation proves that the literal decodes to 16, 24, or 32 bytes; it does not prove the key is used at runtime.
"#;

const CRYPTO_EXTRACT_AFTER: &str = r#"Syntax:
  fat crypto-extract --file <binary> [--json] [--output-dir <dir>]

What it does:
  Extraction-focused alias for `fat crypto`. It surfaces embedded key material,
  cert-like blobs, confidence labels, offsets, and validation state without
  changing the underlying analysis pipeline. When FAT can infer the surrounding
  rootfs, it also annotates extracted keys with trust-path relevance such as
  whether the binary is on, linked from, or outside the governing updater path,
  whether the same key material also appears in sibling binaries, and the same
  trust fields used by `fat trust-map` such as candidate role, path confidence,
  score, and tiered evidence.

  FAT also scans printable constants for exact-length ASCII-hex AES key
  material:
    - 32 hex chars -> AES-128-hex, 16 decoded bytes
    - 48 hex chars -> AES-192-hex, 24 decoded bytes
    - 64 hex chars -> AES-256-hex, 32 decoded bytes

  When the hex decode succeeds and the decoded byte length matches the AES
  variant, JSON emits `validated: true`. If the binary also imports symmetric
  crypto such as AES_set_encrypt_key, the finding is reported as probable.
  This is structural validation of the key-shaped literal, not proof that the
  value is loaded into the cipher at runtime.

  RSA private/public Base64 DER material is converted to PEM, checked with
  OpenSSL, and reported with `validated: true` when it parses as a valid key.
  `--output-dir` writes those PEM artifacts plus `crypto_extract_manifest.json`
  so notebook workflows do not need a custom Python PEM extraction step.

Examples:
  fat crypto-extract --file ./usr/lib/libdecrypter.so
  fat crypto-extract --file ./usr/lib/libdecrypter.so --json
  fat crypto-extract --file ./usr/lib/libdecrypter.so --output-dir ./keys
  fat crypto-extract --file ./usr/bin/btgatt-server --json

Tips:
  - Use this after `fat trust-map` when a helper library still deserves forensic key extraction.
  - Key presence alone does not prove that the binary governs updates; pair this with `fat trust-map`.
  - If the same key material also appears in the governing updater path, FAT reports that explicitly as stronger relevance than a helper-only copy.
  - Use offsets such as 0x30C30 from the report to pivot into disassembly, xrefs, or a debugger.
"#;

const SIGNATURE_FIT_AFTER: &str = r#"Syntax:
  fat signature-fit --firmware <fw> --key-blob <publickeyblob> \
    --signature-offset <off> --signature-size <len> \
    [--signature-byte-order big|little] [--zero-range <off:len>] \
    [--output-dir <dir>] [--json]

What it does:
  Applies the RSA public operation to a suspected signature window, then checks
  whether the decoded block fits the RSA-PSS/SHA-256 shape:

    MaskedDB || H || 0xbc

  FAT unmasks MaskedDB with MGF1(SHA-256), looks for the PSS
  zero-padding || 0x01 || salt structure, and recomputes H from:

    8 zero bytes || SHA256(firmware with configured ranges zeroed) || salt

  If all three checks pass, the command reports `verdict: fit`.
  With `--output-dir`, FAT writes only verified signature evidence: the recovered
  PSS salt, the SHA-256 hash of the firmware after configured ranges are zeroed,
  and a JSON manifest. It does not interpret the salt as encryption key material.

Examples:
  fat signature-fit --firmware ./fw.bin --key-blob ./vendor_rsa_blob_5.publickeyblob \
    --signature-offset 0x20 --signature-size 0x100 --signature-byte-order little

  fat signature-fit --firmware ./fw.bin --key-blob ./vendor_rsa_blob_5.publickeyblob \
    --signature-offset 0x20 --signature-size 0x100 --zero-range 0x20:0x100 --json

  fat signature-fit --firmware ./fw.bin --key-blob ./vendor_rsa_blob_5.publickeyblob \
    --signature-offset 0x20 --signature-size 0x100 --signature-byte-order little \
    --output-dir ./signature-fit-artifacts

Tips:
  - If `--zero-range` is omitted, FAT zeros the signature window before hashing.
  - A fit shows that the bytes behave like an RSA-PSS/SHA-256 signature for the supplied public key.
  - A fit does not prove that the device accepts the package; pair this with updater reachability analysis.
"#;

const TAINT_CROSS_AFTER: &str = r#"Syntax:
  fat taint-cross [--file <binary> ...] [--rootfs <rootfs>] [--source-profile <file>] [--state-profile <file>] [--json]

What it does:
  Runs taint analysis across multiple binaries and stitches findings together
  using shared state: one binary writes a key that another reads and passes to
  a sink, so neither binary is vulnerable on its own.

Shared-state profile:
  Which function writes shared state and which reads it is a claim about one
  platform's config API, so FAT ships no such catalog. Pass --state-profile
  <file.yaml> to supply one:

    name: my-target-state
    families:
      - id: config-store
        write: [example_store_set]
        read:  [example_store_get]
        flush: [example_store_commit]

  Without it, no name is given a read or write role and no cross-binary findings
  are emitted. JSON mode returns an empty array, not a raw symbol inventory.

Binary source/sink models:
  Pass --source-profile <file.yaml> to model unfamiliar binary functions. The
  selected models are merged with the core models and delivered to the binary
  analyzer. A state profile groups operations; it does not define their argument
  or return-value semantics. Invalid selected profiles fail without fallback.

Saved provenance:
  Both --json and --as-taint-json include model_provenance for the binary models
  and state_model_provenance for the state mappings. Selected profiles record
  their name, path and SHA-256. Finding output remains an array (empty: []).

Examples:
  fat taint-cross --file ./usr/sbin/httpd --file ./sbin/rc
  fat taint-cross --rootfs ./extracted-rootfs --json
  fat taint-cross --rootfs ./extracted-rootfs --source-profile ./my-target-models.yaml --state-profile ./my-target-state.yaml --json

Tips:
  - Use --rootfs when you want FAT to scan and correlate all likely ELFs in an extracted filesystem.
  - Use explicit --file values when you are already focused on a small set of binaries.
  - `flush` entries commit state without accepting input, so they are never scored as writes.
"#;

const TRUST_BOUNDARY_AFTER: &str = r#"Syntax:
  fat trust-boundary --rootfs <rootfs> [--json]

What it does:
  Maps update, authentication, and crypto handling boundaries across binaries and init references.

Examples:
  fat trust-boundary --rootfs ./rootfs
  fat trust-boundary --rootfs ./rootfs --json
"#;

const TRUST_MAP_AFTER: &str = r#"Syntax:
  fat trust-map --rootfs <rootfs> [--json]
  fat update-path --rootfs <rootfs> [--json]

What it does:
  Reuses FAT's trust-boundary analysis but renders the result around the
  investigator question "which binary governs updates?" with a governing update
  path summary, scores, short evidence blocks, and tiered trust evidence. JSON
  output is trust-map-centric and includes candidate path confidence.

Examples:
  fat trust-map --rootfs ./rootfs
  fat trust-map --rootfs ./rootfs --json

Tips:
  - Use this after wrapper triage when you need the updater/decryptor path, not just crypto presence.
  - Helper libraries may still appear, but the goal is to separate them from the governing updater path.
"#;

const SDK_TRACE_AFTER: &str = r#"Syntax:
  fat sdk-trace --dir <dir> [--json]

What it does:
  Scans a local SDK directory for ELF binaries and shared libraries, then
  correlates linked-library names plus import/export symbol matches to reveal
  layered dependency chains across the SDK.

Examples:
  fat sdk-trace --dir ./Lib/Linux/x86
  fat sdk-trace --dir ./Lib/Linux/x86 --json

Tips:
  - Use this when one library appears to be a thin wrapper over deeper transport/session layers.
  - Treat symbol matches as evidence for dependency, not proof of runtime call paths.
"#;

const INVARIANT_AFTER: &str = r#"What it does:
  Invariant query evaluates recurring security rules against FAT's structured
  fixture or repository graph.

Examples:
  fat invariant query --fixture tests/fixtures/query/source/invariant-permission --rule 'Every privileged override method must call enforcePermission()' --json
"#;

const INVARIANT_QUERY_AFTER: &str = r#"Syntax:
  fat invariant query [--fixture <fixture-dir> | --repo <repo>] --rule <rule> [--json]

What it does:
  Evaluates a structured invariant rule against the shared query graph and reports
  satisfying, violating, and unknown sites.

Modes:
  --fixture   Use a lightweight fixture repo used in tests or local experiments.
  --repo      Analyze a real source repository when a live adapter is available.

Examples:
  fat invariant query --fixture tests/fixtures/query/source/invariant-permission --rule 'Every privileged override method must call enforcePermission()'
  fat invariant query --fixture tests/fixtures/query/source/invariant-permission --rule 'Every privileged override method must call enforcePermission()' --json

Tips:
  - Use fixture mode for reproducible regression tests and design iteration.
  - Keep rules specific and auditable rather than broad policy statements.
"#;

const PATCH_AFTER: &str = r#"What it does:
  Patch commands help derive fix patterns and search for nearby variant sites that may still be missing the guard.

Examples:
  fat patch check --fixture tests/fixtures/query/source/invariant-permission --find-variants --json
"#;

const PATCH_CHECK_AFTER: &str = r#"Syntax:
  fat patch check [--fixture <fixture-dir> | --repo <repo>] [--find-variants] [--json]

What it does:
  Imports a patch-oriented fixture or repository context, extracts the required fix pattern,
  and optionally searches for variant sites that still look unfixed.

Examples:
  fat patch check --fixture tests/fixtures/query/source/invariant-permission --find-variants --json

Tips:
  - Use --find-variants when the goal is variant hunting, not just patch summarization.
"#;

const CHAIN_AFTER: &str = r#"What it does:
  Chain commands assemble multi-step paths such as request -> shared state -> sink.

Examples:
  fat chain query --fixture tests/fixtures/query/binary/httpd-cross-channel --goal preauth-rce --json
"#;

const CHAIN_QUERY_AFTER: &str = r#"Syntax:
  fat chain query --fixture <fixture-dir> --goal <goal> [--json]

What it does:
  Runs a goal-oriented query over a chain fixture and reports the assembled steps.

Examples:
  fat chain query --fixture tests/fixtures/query/binary/httpd-cross-channel --goal preauth-rce --json
"#;

const VERIFY_AFTER: &str = r#"Syntax:
  fat verify [--fixture <fixture-dir>] [--json]

What it does:
  Attaches runtime evidence to a previously derived finding and returns a confirmation verdict.

Examples:
  fat verify --fixture tests/fixtures/query/runtime/verification --json

Tips:
  - Use verify after you already have a static finding or chain that you want to confirm dynamically.
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use clap::CommandFactory;
    use std::collections::BTreeSet;

    #[test]
    fn grouped_help_lists_every_visible_command_once() {
        // Constructing the existing large derived CLI exceeds libtest's small
        // default thread stack, before any help customization runs.
        std::thread::Builder::new()
            .stack_size(16 * 1024 * 1024)
            .spawn(|| {
                let mut root = crate::Cli::command().styles(crate::clap_help_styles());
                apply(&mut root);
                let expected: BTreeSet<_> = root
                    .get_subcommands()
                    .filter(|command| !command.is_hide_set())
                    .map(|command| command.get_name().to_owned())
                    .collect();
                for help in [root.render_help(), root.render_long_help()] {
                    let text = help.to_string();
                    assert!(
                        !text.contains("Other commands:"),
                        "assign every current command to a task group"
                    );
                    let reference = text
                        .split_once("Start here:\n")
                        .unwrap()
                        .1
                        .split_once("\nOptions:")
                        .unwrap()
                        .0;
                    let names: Vec<_> = reference
                        .lines()
                        .filter_map(|line| line.strip_prefix("  "))
                        .map(|line| {
                            let (name, description) =
                                line.split_once(' ').expect("command description");
                            assert!(!description.trim().is_empty(), "{name}");
                            name.to_owned()
                        })
                        .collect();
                    assert_eq!(
                        names.len(),
                        expected.len(),
                        "duplicate or missing commands: {names:?}"
                    );
                    assert_eq!(names.into_iter().collect::<BTreeSet<_>>(), expected);
                }
            })
            .unwrap()
            .join()
            .unwrap();
    }

    #[test]
    fn grouped_help_keeps_uncategorized_commands_and_aliases_but_hides_internal_commands() {
        let mut root = Command::new("fat")
            .subcommand(
                Command::new("future-command")
                    .visible_alias("future")
                    .about("A future command with a literal {usage} in its description"),
            )
            .subcommand(Command::new("internal-command").hide(true));
        apply_root_banner(&mut root);
        let help = root.render_help().to_string();
        assert!(help.contains("Other commands:"));
        assert!(help.contains("future-command"));
        assert!(help.contains("[alias: future]"), "{help}");
        assert!(help.contains("literal {usage} in its description"));
        assert!(!help.contains("internal-command"));
        assert!(root.clone().try_get_matches_from(["fat", "future"]).is_ok());
    }
}
