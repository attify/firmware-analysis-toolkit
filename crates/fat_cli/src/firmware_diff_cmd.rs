use std::error::Error;
use std::path::{Path, PathBuf};

use fat_core::firmware_diff::{
    diff_certificates, diff_config_scripts, diff_credentials, diff_filesystems, diff_nvram_keys,
    diff_summary, diff_web_endpoints, extract_nvram_keys_from_scripts, scan_persistent_weaknesses,
    ConfigDiff, DiffSummary, FilesystemDiff, FirmwareDiffReport, LibraryAbsorptionCandidate,
    PartitionDiff,
};

type DynResult<T> = Result<T, Box<dyn Error>>;

pub(crate) fn run(
    base: &Path,
    head: &Path,
    explicit_base_trees: &[PathBuf],
    explicit_head_trees: &[PathBuf],
    security: bool,
    layer: &str,
    json: bool,
) -> DynResult<()> {
    // Use explicit trees if provided, otherwise auto-discover
    let base_trees = if explicit_base_trees.is_empty() {
        resolve_project_trees(base)?
    } else {
        explicit_base_trees
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let label = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("tree-{i}"));
                (label, p.clone())
            })
            .collect()
    };
    let head_trees = if explicit_head_trees.is_empty() {
        resolve_project_trees(head)?
    } else {
        explicit_head_trees
            .iter()
            .enumerate()
            .map(|(i, p)| {
                let label = p
                    .file_name()
                    .map(|n| n.to_string_lossy().to_string())
                    .unwrap_or_else(|| format!("tree-{i}"));
                (label, p.clone())
            })
            .collect()
    };

    // Match trees once; reuse everywhere.
    let tree_pairs = match_tree_pairs(&base_trees, &head_trees);

    let include_filesystem = layer == "all" || layer == "filesystem";
    let include_config = layer == "all" || layer == "config";
    let include_binary = layer == "all" || layer == "binary";

    // Layer 1: Filesystem diff — across all matched partition pairs
    let mut filesystem: Option<FilesystemDiff> = None;
    let mut partitions: Vec<PartitionDiff> = Vec::new();

    if include_filesystem {
        let total_trees =
            tree_pairs.matched.len() + tree_pairs.head_only.len() + tree_pairs.base_only.len();

        if total_trees <= 1 && tree_pairs.head_only.is_empty() && tree_pairs.base_only.is_empty() {
            // Single tree: use the legacy top-level filesystem field
            if let Some((_, base_path, head_path)) = tree_pairs.matched.first() {
                filesystem = Some(diff_filesystems(base_path, head_path)?);
            }
        } else {
            // Multiple partitions: populate the partitions vec
            for (label, base_path, head_path) in &tree_pairs.matched {
                let diff = diff_filesystems(base_path, head_path)?;
                partitions.push(PartitionDiff {
                    label: label.clone(),
                    diff,
                });
            }
            // Head-only partitions: synthesize all-files-added diff
            for (label, head_path) in &tree_pairs.head_only {
                let empty_dir = tempfile::tempdir()?;
                let diff = diff_filesystems(empty_dir.path(), head_path)?;
                partitions.push(PartitionDiff {
                    label: format!("{label} (new)"),
                    diff,
                });
            }
            // Base-only partitions: synthesize all-files-removed diff
            for (label, base_path) in &tree_pairs.base_only {
                let empty_dir = tempfile::tempdir()?;
                let diff = diff_filesystems(base_path, empty_dir.path())?;
                partitions.push(PartitionDiff {
                    label: format!("{label} (removed)"),
                    diff,
                });
            }
        }
    }

    // Layer 2: Config diff — using label-matched pairs only
    let config = if include_config {
        // NVRAM keys are aggregated across all trees on each side (they're global names,
        // not partition-scoped), so collecting independently is correct.
        let mut all_base_nvram = Vec::new();
        let mut all_head_nvram = Vec::new();
        for (_, b, _) in &tree_pairs.matched {
            all_base_nvram.extend(extract_nvram_keys_from_scripts(b)?);
        }
        for (_, _, h) in &tree_pairs.matched {
            all_head_nvram.extend(extract_nvram_keys_from_scripts(h)?);
        }
        let nvram_changes = diff_nvram_keys(&all_base_nvram, &all_head_nvram);

        let mut cert_changes = Vec::new();
        let mut web_added = std::collections::BTreeSet::new();
        let mut web_removed = std::collections::BTreeSet::new();
        let mut credential_changes = Vec::new();
        let mut script_changes = Vec::new();

        // Pair-scoped config scans: certs, web endpoints, credentials
        for (_, base_root, head_root) in &tree_pairs.matched {
            cert_changes.extend(diff_cert_pairs(base_root, head_root)?);
            let web = diff_web_endpoints(base_root, head_root)?;
            web_added.extend(web.added_endpoints);
            web_removed.extend(web.removed_endpoints);
            credential_changes.extend(diff_credentials(base_root, head_root));
        }

        // Script diffing: collect changed scripts from the matching partitions,
        // then diff against the correct paired tree.
        let changed_scripts = collect_changed_scripts(&filesystem, &partitions);
        for (_, base_root, head_root) in &tree_pairs.matched {
            script_changes.extend(diff_config_scripts(base_root, head_root, &changed_scripts));
        }

        Some(ConfigDiff {
            certificate_changes: cert_changes,
            nvram_key_changes: nvram_changes,
            web_endpoint_changes: fat_core::firmware_diff::WebEndpointDiff {
                added_endpoints: web_added.into_iter().collect(),
                removed_endpoints: web_removed.into_iter().collect(),
                changed_handlers: Vec::new(),
            },
            credential_changes,
            script_changes,
        })
    } else {
        None
    };

    // Layer 3: Binary diff (requires r2 on PATH) — across matched pairs
    let (binaries, binary_diagnostic) = if include_binary {
        let mut all_results = Vec::new();

        if tree_pairs.matched.len() <= 1
            && tree_pairs.head_only.is_empty()
            && tree_pairs.base_only.is_empty()
        {
            // Single tree mode: can use the filesystem diff to scope binary candidates
            if let Some((_, ref bp, ref hp)) = tree_pairs.matched.first() {
                all_results = diff_changed_binaries(bp, hp, &filesystem)?;
            }
        } else {
            // Multi-tree: diff binaries in each matched partition pair
            for (_, base_path, head_path) in &tree_pairs.matched {
                let fs_opt: Option<FilesystemDiff> = None;
                let results = diff_changed_binaries(base_path, head_path, &fs_opt)?;
                all_results.extend(results);
            }
        }

        let diag = if all_results.is_empty() {
            let r2_available = std::process::Command::new("r2")
                .arg("-v")
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .map(|s| s.success())
                .unwrap_or(false);
            if !r2_available {
                Some("binary diff requested but radare2 (r2) is not on PATH".to_string())
            } else {
                Some(
                    "binary diff found no changed ELF binaries between the two projects"
                        .to_string(),
                )
            }
        } else {
            None
        };
        (all_results, diag)
    } else {
        (Vec::new(), None)
    };

    // Cross-layer correlation: library absorption and persistent weaknesses
    // only run in "all" mode — they depend on filesystem + binary + config data.
    let library_absorption = if layer == "all" {
        detect_library_absorption(&filesystem, &partitions, &base_trees, &head_trees)
    } else {
        Vec::new()
    };

    let mut persistent_weaknesses = Vec::new();
    if layer == "all" {
        for (_, base_root, head_root) in &tree_pairs.matched {
            persistent_weaknesses.extend(scan_persistent_weaknesses(base_root, head_root));
        }
        persistent_weaknesses.sort_by(|a, b| a.description.cmp(&b.description));
        persistent_weaknesses.dedup_by(|a, b| a.description == b.description);
    }

    // Apply security filter BEFORE computing summary so counts match payload
    if security {
        if let Some(ref mut fs_diff) = filesystem {
            fs_diff.added.retain(|f| !f.security_tags.is_empty());
            fs_diff.removed.retain(|f| !f.security_tags.is_empty());
            fs_diff.changed.retain(|f| !f.security_tags.is_empty());
        }
        for pd in &mut partitions {
            pd.diff.added.retain(|f| !f.security_tags.is_empty());
            pd.diff.removed.retain(|f| !f.security_tags.is_empty());
            pd.diff.changed.retain(|f| !f.security_tags.is_empty());
        }
    }

    // Compute summary AFTER filtering so counts are consistent
    let summary = compute_summary_multi(
        &filesystem,
        &partitions,
        &config,
        &binaries,
        &library_absorption,
        &persistent_weaknesses,
    );

    let report = FirmwareDiffReport {
        base_project: base.display().to_string(),
        head_project: head.display().to_string(),
        base_version: None,
        head_version: None,
        diff_timestamp: chrono_now(),
        filesystem,
        partitions,
        config,
        binaries,
        binary_diagnostic,
        library_absorption,
        persistent_weaknesses,
        summary,
    };

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text_report(&report);
    }

    Ok(())
}

/// Discover all extracted filesystem trees in a project directory.
///
/// Returns `Vec<(label, path)>` where label is "rootfs", "app", etc.
/// Falls back to the legacy single-rootfs discovery if multi-tree finds nothing.
fn resolve_project_trees(project_dir: &Path) -> DynResult<Vec<(String, PathBuf)>> {
    // 1. Try project/extracted with multi-tree discovery
    let extracted = project_dir.join("extracted");
    if extracted.exists() {
        let trees = fat_extract::rootfs::find_all_trees(&extracted);
        if !trees.is_empty() {
            return Ok(trees);
        }
        // If find_all_trees found nothing, check if extracted IS a rootfs
        if is_plausible_rootfs(&extracted) {
            return Ok(vec![("rootfs".to_string(), extracted)]);
        }
    }

    // 2. Try project/rootfs directory
    let rootfs = project_dir.join("rootfs");
    if rootfs.exists() {
        return Ok(vec![("rootfs".to_string(), rootfs)]);
    }

    // 3. Try work/extractions for nested trees
    let extractions = project_dir.join("work").join("extractions");
    if extractions.exists() {
        let trees = fat_extract::rootfs::find_all_trees(&extractions);
        if !trees.is_empty() {
            return Ok(trees);
        }
        // Fall back to single rootfs discovery
        if let Some(rootfs) = fat_extract::rootfs::find_rootfs(&extractions) {
            return Ok(vec![("rootfs".to_string(), rootfs)]);
        }
    }

    // 4. Treat the project dir itself as a rootfs (useful for direct paths)
    if project_dir.join("etc").exists() || project_dir.join("bin").exists() {
        return Ok(vec![("rootfs".to_string(), project_dir.to_path_buf())]);
    }

    Err(format!("no rootfs found in project: {}", project_dir.display()).into())
}

fn is_plausible_rootfs(dir: &Path) -> bool {
    let markers = ["bin", "etc", "lib", "sbin", "usr", "var"];
    let count = markers.iter().filter(|m| dir.join(m).is_dir()).count();
    count >= 3
}

/// Result of matching base and head tree lists by label.
struct TreePairResult {
    /// Trees present on both sides, matched by label.
    matched: Vec<(String, PathBuf, PathBuf)>,
    /// Trees only in head (new partitions).
    head_only: Vec<(String, PathBuf)>,
    /// Trees only in base (removed partitions).
    base_only: Vec<(String, PathBuf)>,
}

/// Match base and head tree pairs by label. Returns matched pairs plus
/// unmatched trees on each side.
///
/// Pass 1: match by identical label.
/// Pass 2: positionally pair any *remaining* unmatched trees (covers explicit
///          `--base-tree app-old --head-tree app-new` where names differ).
fn match_tree_pairs(
    base_trees: &[(String, PathBuf)],
    head_trees: &[(String, PathBuf)],
) -> TreePairResult {
    let mut matched = Vec::new();
    let mut matched_base_indices = std::collections::BTreeSet::new();
    let mut matched_head_indices = std::collections::BTreeSet::new();

    // Pass 1: label match
    for (hi, (h_label, h_path)) in head_trees.iter().enumerate() {
        for (bi, (b_label, b_path)) in base_trees.iter().enumerate() {
            if matched_base_indices.contains(&bi) {
                continue;
            }
            if b_label == h_label {
                matched.push((h_label.clone(), b_path.clone(), h_path.clone()));
                matched_base_indices.insert(bi);
                matched_head_indices.insert(hi);
                break;
            }
        }
    }

    // Pass 2: positionally pair remaining unmatched trees
    let remaining_base: Vec<(usize, &(String, PathBuf))> = base_trees
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_base_indices.contains(i))
        .collect();
    let remaining_head: Vec<(usize, &(String, PathBuf))> = head_trees
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_head_indices.contains(i))
        .collect();

    for (pos, ((bi, (_, b_path)), (hi, (h_label, h_path)))) in
        remaining_base.iter().zip(remaining_head.iter()).enumerate()
    {
        let _ = pos;
        matched.push((h_label.clone(), b_path.clone(), h_path.clone()));
        matched_base_indices.insert(*bi);
        matched_head_indices.insert(*hi);
    }

    let head_only: Vec<_> = head_trees
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_head_indices.contains(i))
        .map(|(_, t)| t.clone())
        .collect();

    let base_only: Vec<_> = base_trees
        .iter()
        .enumerate()
        .filter(|(i, _)| !matched_base_indices.contains(i))
        .map(|(_, t)| t.clone())
        .collect();

    TreePairResult {
        matched,
        head_only,
        base_only,
    }
}

fn diff_cert_pairs(
    base_rootfs: &Path,
    head_rootfs: &Path,
) -> DynResult<Vec<fat_core::firmware_diff::CertificateDiff>> {
    let mut changes = Vec::new();

    // Walk head rootfs for certificate files, find matching base files
    for entry in walkdir::WalkDir::new(head_rootfs).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path_str = entry.path().display().to_string();
        if !(path_str.ends_with(".pem") || path_str.ends_with(".crt")) {
            continue;
        }

        let rel_path = entry.path().strip_prefix(head_rootfs)?;
        let base_cert = base_rootfs.join(rel_path);

        if base_cert.exists() {
            // Both exist; diff them
            match diff_certificates(&base_cert, entry.path()) {
                Ok(diff) => changes.push(diff),
                Err(_) => {
                    // openssl might not be able to parse it; skip
                    continue;
                }
            }
        }
    }

    Ok(changes)
}

fn diff_changed_binaries(
    base_rootfs: &Path,
    head_rootfs: &Path,
    filesystem: &Option<FilesystemDiff>,
) -> DynResult<Vec<serde_json::Value>> {
    // Collect candidate binary paths to diff
    let candidates: Vec<(PathBuf, PathBuf)> = if let Some(fs) = filesystem {
        // When filesystem diff is available, only diff changed files
        fs.changed
            .iter()
            .map(|f| (base_rootfs.join(&f.path), head_rootfs.join(&f.path)))
            .collect()
    } else {
        // Binary-only mode: discover ELF binaries by walking both rootfs trees
        discover_elf_binary_pairs(base_rootfs, head_rootfs)?
    };

    let mut results = Vec::new();
    for (base_path, head_path) in &candidates {
        if !base_path.is_file() || !head_path.is_file() {
            continue;
        }
        if !is_elf_file(head_path) {
            continue;
        }
        match fat_analyze::binary_diff::diff_binary(base_path, head_path) {
            Ok(diff) => {
                if let Ok(json) = serde_json::to_value(&diff) {
                    results.push(json);
                }
            }
            Err(_) => {
                // r2 not available or binary analysis failed — skip silently
            }
        }
    }
    Ok(results)
}

fn is_elf_file(path: &Path) -> bool {
    std::fs::read(path)
        .map(|d| d.len() >= 4 && d[..4] == [0x7f, b'E', b'L', b'F'])
        .unwrap_or(false)
}

fn discover_elf_binary_pairs(
    base_rootfs: &Path,
    head_rootfs: &Path,
) -> DynResult<Vec<(PathBuf, PathBuf)>> {
    let mut pairs = Vec::new();
    let exec_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "lib"];

    for dir in &exec_dirs {
        let head_dir = head_rootfs.join(dir);
        if !head_dir.is_dir() {
            continue;
        }
        for entry in walkdir::WalkDir::new(&head_dir)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok())
        {
            if !entry.file_type().is_file() {
                continue;
            }
            let rel = entry
                .path()
                .strip_prefix(head_rootfs)
                .unwrap_or(entry.path());
            let base_candidate = base_rootfs.join(rel);
            if base_candidate.is_file() && is_elf_file(entry.path()) {
                // Only diff binaries that exist in both and have different content
                let base_hash = sha256_quick(&base_candidate);
                let head_hash = sha256_quick(entry.path());
                if base_hash != head_hash {
                    pairs.push((base_candidate, entry.path().to_path_buf()));
                }
            }
        }
    }
    Ok(pairs)
}

fn sha256_quick(path: &Path) -> String {
    use sha2::{Digest, Sha256};
    std::fs::read(path)
        .map(|data| format!("{:x}", Sha256::digest(&data)))
        .unwrap_or_default()
}

/// Collect paths of changed shell scripts from all filesystem diffs.
/// Includes init scripts, startup scripts, and any .sh files tagged CONFIG_CHANGE.
fn collect_changed_scripts(
    filesystem: &Option<FilesystemDiff>,
    partitions: &[PartitionDiff],
) -> Vec<String> {
    let all_diffs: Vec<&FilesystemDiff> = filesystem
        .iter()
        .chain(partitions.iter().map(|pd| &pd.diff))
        .collect();

    let mut scripts = Vec::new();
    for fs in all_diffs {
        for entry in &fs.changed {
            if entry.file_type == "shell-script"
                || entry.path.ends_with(".sh")
                || entry.path.contains("init.d")
                || entry.path.contains("rcS")
                || entry.security_tags.contains(&"CONFIG_CHANGE".to_string())
            {
                scripts.push(entry.path.clone());
            }
        }
    }
    scripts
}

/// Strip common r2 symbol prefixes (sym., sym.imp., imp., reloc., sym.go., etc.)
/// so that export names and symbol table names can be compared without namespace noise.
fn normalize_r2_symbol(name: &str) -> String {
    const PREFIXES: &[&str] = &["sym.imp.", "sym.go.", "sym.", "imp.", "reloc.", "flirt."];
    for prefix in PREFIXES {
        if let Some(stripped) = name.strip_prefix(prefix) {
            return stripped.to_string();
        }
    }
    name.to_string()
}

/// Detect library absorption candidates by cross-referencing removed shared libraries
/// with grown binaries. For each removed .so, extract its exports and check if they
/// appear in the symbol table of a significantly-grown binary.
fn detect_library_absorption(
    filesystem: &Option<FilesystemDiff>,
    partitions: &[PartitionDiff],
    base_trees: &[(String, PathBuf)],
    head_trees: &[(String, PathBuf)],
) -> Vec<LibraryAbsorptionCandidate> {
    let mut candidates = Vec::new();

    // Collect all filesystem diffs into a unified view
    let all_diffs: Vec<&FilesystemDiff> = filesystem
        .iter()
        .chain(partitions.iter().map(|pd| &pd.diff))
        .collect();

    // Collect removed shared libraries and significantly-grown binaries
    let mut removed_libs: Vec<(&str, u64)> = Vec::new();
    let mut grown_binaries: Vec<(&str, u64, u64)> = Vec::new(); // (path, base_size, head_size)

    for fs in &all_diffs {
        for entry in &fs.removed {
            if entry.file_type == "shared-library" {
                let size = entry.size_bytes.unwrap_or(0);
                removed_libs.push((&entry.path, size));
            }
        }
        for entry in &fs.changed {
            if let (Some(base_sz), Some(head_sz)) = (entry.base_size_bytes, entry.size_bytes) {
                // Grew by more than 50%
                if head_sz > base_sz + base_sz / 2 {
                    grown_binaries.push((&entry.path, base_sz, head_sz));
                }
            }
        }
    }

    if removed_libs.is_empty() || grown_binaries.is_empty() {
        return candidates;
    }

    // For each removed library, try to find its exports in each grown binary's symbol table
    for (lib_path, lib_size) in &removed_libs {
        // Find the library in the base tree
        let base_lib_full = base_trees
            .iter()
            .map(|(_, root)| root.join(lib_path))
            .find(|p| p.is_file());

        let base_lib_full = match base_lib_full {
            Some(p) => p,
            None => continue,
        };

        // Extract exports from the removed library
        let lib_exports = match fat_analyze::binary_diff::r2_exports(&base_lib_full) {
            Ok(exports) => exports,
            Err(_) => continue,
        };

        if lib_exports.is_empty() {
            continue;
        }

        let export_names: std::collections::BTreeSet<&str> =
            lib_exports.iter().map(|e| e.name.as_str()).collect();

        // Check each grown binary for absorbed symbols
        for (bin_path, base_sz, head_sz) in &grown_binaries {
            let head_bin_full = head_trees
                .iter()
                .map(|(_, root)| root.join(bin_path))
                .find(|p| p.is_file());

            let head_bin_full = match head_bin_full {
                Some(p) => p,
                None => continue,
            };

            // Extract symbol table from the grown binary
            let symbols = match fat_analyze::binary_diff::r2_symbols(&head_bin_full) {
                Ok(s) => s,
                Err(_) => continue,
            };

            // Normalize r2 symbol names: strip common prefixes like sym., sym.imp., imp., etc.
            let normalized_symbols: std::collections::BTreeSet<String> =
                symbols.iter().map(|s| normalize_r2_symbol(s)).collect();
            let norm_sym_refs: std::collections::BTreeSet<&str> =
                normalized_symbols.iter().map(|s| s.as_str()).collect();

            // Also normalize export names (they may have prefixes too)
            let normalized_exports: std::collections::BTreeSet<String> = export_names
                .iter()
                .map(|s| normalize_r2_symbol(s))
                .collect();

            // Compute intersection on normalized names
            let matched: Vec<String> = normalized_exports
                .iter()
                .filter(|name| norm_sym_refs.contains(name.as_str()))
                .cloned()
                .collect();

            let ratio = if normalized_exports.is_empty() {
                0.0
            } else {
                matched.len() as f64 / normalized_exports.len() as f64
            };

            let size_delta = head_sz.saturating_sub(*base_sz);
            let confidence = if ratio >= 0.6 && size_delta >= *lib_size {
                "high"
            } else if ratio >= 0.3 {
                "medium"
            } else {
                continue; // Below threshold, skip
            };

            candidates.push(LibraryAbsorptionCandidate {
                removed_library: lib_path.to_string(),
                removed_library_size: *lib_size,
                absorbing_binary: bin_path.to_string(),
                binary_base_size: *base_sz,
                binary_head_size: *head_sz,
                matched_exports: matched,
                matched_exports_ratio: ratio,
                confidence: confidence.to_string(),
            });
        }
    }

    candidates
}

fn count_fs_stats(fs: &FilesystemDiff) -> (usize, usize, usize, usize, usize, usize, usize) {
    let total = fs.added.len() + fs.removed.len() + fs.changed.len();
    let security = fs
        .added
        .iter()
        .chain(fs.removed.iter())
        .chain(fs.changed.iter())
        .filter(|f| !f.security_tags.is_empty())
        .count();
    let new_attack_surface = fs
        .added
        .iter()
        .filter(|f| f.security_tags.contains(&"ATTACK_SURFACE".to_string()))
        .count();
    let removed_attack_surface = fs
        .removed
        .iter()
        .filter(|f| f.security_tags.contains(&"ATTACK_SURFACE".to_string()))
        .count();
    let crypto_count = fs
        .added
        .iter()
        .chain(fs.removed.iter())
        .chain(fs.changed.iter())
        .filter(|f| f.security_tags.contains(&"CRYPTO_CHANGE".to_string()))
        .count();
    let debug_add = fs
        .added
        .iter()
        .filter(|f| f.security_tags.contains(&"DEBUG_INTERFACE".to_string()))
        .count();
    let debug_rem = fs
        .removed
        .iter()
        .filter(|f| f.security_tags.contains(&"DEBUG_INTERFACE".to_string()))
        .count();

    (
        total,
        security,
        new_attack_surface,
        removed_attack_surface,
        crypto_count,
        debug_add,
        debug_rem,
    )
}

fn compute_summary_multi(
    filesystem: &Option<FilesystemDiff>,
    partitions: &[PartitionDiff],
    config: &Option<ConfigDiff>,
    binaries: &[serde_json::Value],
    library_absorption: &[LibraryAbsorptionCandidate],
    persistent_weaknesses: &[fat_core::firmware_diff::PersistentWeakness],
) -> DiffSummary {
    let (
        mut total_changed,
        mut security_relevant,
        mut new_attack,
        mut removed_attack,
        mut crypto,
        mut debug_added,
        mut debug_removed,
    ) = if let Some(fs) = filesystem {
        count_fs_stats(fs)
    } else {
        (0, 0, 0, 0, 0, 0, 0)
    };

    // Add stats from each partition
    for pd in partitions {
        let (t, s, na, ra, c, da, dr) = count_fs_stats(&pd.diff);
        total_changed += t;
        security_relevant += s;
        new_attack += na;
        removed_attack += ra;
        crypto += c;
        debug_added += da;
        debug_removed += dr;
    }

    // Add config-level security changes
    let config_security = if let Some(cfg) = config {
        cfg.nvram_key_changes.len()
            + cfg.web_endpoint_changes.added_endpoints.len()
            + cfg.web_endpoint_changes.removed_endpoints.len()
            + cfg.certificate_changes.len()
            + cfg.credential_changes.len()
            + cfg.script_changes.len()
    } else {
        0
    };

    // Add binary-level security changes
    let binary_security = binaries
        .iter()
        .filter_map(|b| b.get("security-relevant-changes"))
        .filter_map(|changes| changes.as_array())
        .map(|arr| arr.len())
        .sum::<usize>();

    // Count library absorption and persistent weaknesses as security-relevant
    let absorption_count = library_absorption.len();
    let weakness_count = persistent_weaknesses.len();

    diff_summary(
        total_changed,
        security_relevant + config_security + binary_security + absorption_count + weakness_count,
        new_attack,
        removed_attack,
        crypto,
        debug_added,
        debug_removed,
    )
}

fn chrono_now() -> String {
    // Simple timestamp without depending on chrono crate
    let epoch = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("unix:{}", epoch.as_secs())
}

fn render_text_report(report: &FirmwareDiffReport) {
    let palette = crate::style::Palette::stdout();

    println!("{}", palette.heading("Firmware Diff"));
    println!("{}", palette.kv("base", &report.base_project));
    println!("{}", palette.kv("head", &report.head_project));
    println!("{}", palette.kv("timestamp", &report.diff_timestamp));
    println!();

    if let Some(ref fs) = report.filesystem {
        render_filesystem_section(&palette, fs, None);
    }

    // Render multi-partition filesystem diffs
    for pd in &report.partitions {
        render_filesystem_section(&palette, &pd.diff, Some(&pd.label));
    }

    if let Some(ref cfg) = report.config {
        println!("{}", palette.heading("Configuration"));

        if !cfg.certificate_changes.is_empty() {
            println!(
                "  {} ({})",
                palette.key("Certificate changes"),
                cfg.certificate_changes.len()
            );
            for cert in &cfg.certificate_changes {
                let rotation = if cert.key_rotated {
                    palette.warn("KEY ROTATED")
                } else {
                    "same key".to_string()
                };
                println!("    {} {} {}", palette.bullet("-"), cert.path, rotation);
            }
        }

        if !cfg.nvram_key_changes.is_empty() {
            println!(
                "  {} ({})",
                palette.key("NVRAM key changes"),
                cfg.nvram_key_changes.len()
            );
            for key in &cfg.nvram_key_changes {
                let relevance = key.security_relevance.as_deref().unwrap_or("");
                println!(
                    "    {} {} ({}) {}",
                    palette.bullet("-"),
                    key.key_name,
                    key.status,
                    palette.warn(relevance)
                );
            }
        }

        if !cfg.web_endpoint_changes.added_endpoints.is_empty()
            || !cfg.web_endpoint_changes.removed_endpoints.is_empty()
        {
            println!("  {}", palette.key("Web endpoint changes"));
            for ep in &cfg.web_endpoint_changes.added_endpoints {
                println!("    {} {}", palette.good("+"), ep);
            }
            for ep in &cfg.web_endpoint_changes.removed_endpoints {
                println!("    {} {}", palette.bad("-"), ep);
            }
        }

        // Credential changes
        if !cfg.credential_changes.is_empty() {
            println!(
                "  {} ({})",
                palette.key("Credential changes"),
                cfg.credential_changes.len()
            );
            for cred in &cfg.credential_changes {
                let status = if cred.hash_identical {
                    palette.bad("hash IDENTICAL across versions")
                } else {
                    "hash changed".to_string()
                };
                println!(
                    "    {} {} ({}): {}",
                    palette.bullet("-"),
                    cred.user,
                    cred.path,
                    status,
                );
                if let Some(ref alg) = cred.base_hash_algorithm {
                    println!("      algorithm: {alg}");
                }
                if let (Some(ref base_salt), Some(ref head_salt)) =
                    (&cred.base_salt, &cred.head_salt)
                {
                    if base_salt == head_salt {
                        println!("      salt: {base_salt} (identical)");
                    } else {
                        println!("      salt: {base_salt} -> {head_salt}");
                    }
                }
                if let Some(ref weakness) = cred.algorithm_weakness {
                    println!("      {}", palette.bad(weakness));
                }
            }
        }

        // Script changes
        if !cfg.script_changes.is_empty() {
            for script in &cfg.script_changes {
                println!(
                    "\n  {} ({})",
                    palette.key(format!("Script changes: {}", script.path)),
                    script.added_lines.len() + script.removed_lines.len()
                );
                for line in &script.removed_lines {
                    let cat = line
                        .category
                        .as_deref()
                        .map(|c| format!(" [{c}]"))
                        .unwrap_or_default();
                    println!(
                        "    {} {}{}",
                        palette.bad("-"),
                        line.content,
                        palette.warn(&cat)
                    );
                }
                for line in &script.added_lines {
                    let cat = line
                        .category
                        .as_deref()
                        .map(|c| format!(" [{c}]"))
                        .unwrap_or_default();
                    println!(
                        "    {} {}{}",
                        palette.good("+"),
                        line.content,
                        palette.warn(&cat)
                    );
                }
            }
        }

        println!();
    }

    // Library absorption section
    if !report.library_absorption.is_empty() {
        println!("{}", palette.heading("Library Absorption"));
        for candidate in &report.library_absorption {
            let delta = candidate
                .binary_head_size
                .saturating_sub(candidate.binary_base_size);
            println!(
                "  {} ({}, removed) -> {} (+{} bytes)",
                candidate.removed_library,
                format_size(candidate.removed_library_size),
                candidate.absorbing_binary,
                format_size(delta),
            );
            println!(
                "    {:.0}% of exports found in symbol table — confidence: {}",
                candidate.matched_exports_ratio * 100.0,
                candidate.confidence,
            );
        }
        println!();
    }

    if let Some(ref diag) = report.binary_diagnostic {
        println!("{}", palette.heading("Binaries"));
        println!("  {}", palette.warn(diag));
        println!();
    }

    if !report.binaries.is_empty() {
        println!("{}", palette.heading("Binaries"));
        println!(
            "  {} ({})",
            palette.key("Changed binaries analyzed"),
            report.binaries.len()
        );
        for binary in &report.binaries {
            let path = binary
                .get("binary-path")
                .and_then(|v| v.as_str())
                .unwrap_or("unknown");
            let func_summary = binary.get("function-summary");
            let changed = func_summary
                .and_then(|s| s.get("changed"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let added = func_summary
                .and_then(|s| s.get("added"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            let removed = func_summary
                .and_then(|s| s.get("removed"))
                .and_then(|v| v.as_u64())
                .unwrap_or(0);
            println!(
                "    {} {} (functions: {} changed, {} added, {} removed)",
                palette.bullet("~"),
                path,
                changed,
                added,
                removed
            );

            // Show security-relevant changes
            if let Some(changes) = binary
                .get("security-relevant-changes")
                .and_then(|v| v.as_array())
            {
                for change in changes {
                    let change_type = change
                        .get("change-type")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    let detail = change.get("detail").and_then(|v| v.as_str()).unwrap_or("");
                    let severity = change
                        .get("severity")
                        .and_then(|v| v.as_str())
                        .unwrap_or("info");
                    let marker = match severity {
                        "high" => palette.bad("HIGH"),
                        "medium" => palette.warn("MEDIUM"),
                        _ => palette.info("INFO"),
                    };
                    println!(
                        "      {} [{}] {}: {}",
                        palette.bullet("!"),
                        marker,
                        change_type,
                        detail
                    );
                }
            }
        }
        println!();
    }

    // Persistent weaknesses
    if !report.persistent_weaknesses.is_empty() {
        println!("{}", palette.heading("Persistent Weaknesses"));
        for pw in &report.persistent_weaknesses {
            println!(
                "  {} {}: {}",
                palette.bad(&pw.category),
                pw.path,
                pw.description
            );
        }
        println!();
    }

    println!("{}", palette.heading("Summary"));
    println!(
        "{}",
        palette.kv(
            "total files changed",
            format!("{}", report.summary.total_files_changed)
        )
    );
    println!(
        "{}",
        palette.kv(
            "security-relevant changes",
            format!("{}", report.summary.security_relevant_changes)
        )
    );
    println!(
        "{}",
        palette.kv(
            "new attack surface",
            format!("{}", report.summary.new_attack_surface_count)
        )
    );
    println!(
        "{}",
        palette.kv(
            "security direction",
            palette.status_word(&report.summary.overall_security_direction)
        )
    );
}

fn render_filesystem_section(
    palette: &crate::style::Palette,
    fs: &FilesystemDiff,
    partition_label: Option<&str>,
) {
    let heading = match partition_label {
        Some(label) => format!("Filesystem (partition: {label})"),
        None => "Filesystem".to_string(),
    };
    println!("{}", palette.heading(&heading));
    println!(
        "{}",
        palette.kv("base files", format!("{}", fs.base_file_count))
    );
    println!(
        "{}",
        palette.kv("head files", format!("{}", fs.head_file_count))
    );

    if !fs.added.is_empty() {
        println!("\n  {} ({})", palette.good("Added"), fs.added.len());
        for entry in &fs.added {
            let tags = if entry.security_tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", entry.security_tags.join(", "))
            };
            println!(
                "    {} {}{}",
                palette.bullet("+"),
                entry.path,
                palette.warn(&tags)
            );
        }
    }

    if !fs.removed.is_empty() {
        println!("\n  {} ({})", palette.bad("Removed"), fs.removed.len());
        for entry in &fs.removed {
            let tags = if entry.security_tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", entry.security_tags.join(", "))
            };
            println!(
                "    {} {}{}",
                palette.bullet("-"),
                entry.path,
                palette.warn(&tags)
            );
        }
    }

    if !fs.changed.is_empty() {
        println!("\n  {} ({})", palette.accent("Changed"), fs.changed.len());
        for entry in &fs.changed {
            let tags = if entry.security_tags.is_empty() {
                String::new()
            } else {
                format!(" [{}]", entry.security_tags.join(", "))
            };
            let size_info = match (entry.base_size_bytes, entry.size_bytes) {
                (Some(base_sz), Some(head_sz)) => {
                    let ratio = head_sz as f64 / base_sz.max(1) as f64;
                    format!(
                        " ({} -> {}, {:.2}x)",
                        format_size(base_sz),
                        format_size(head_sz),
                        ratio
                    )
                }
                (None, Some(sz)) => format!(" ({})", format_size(sz)),
                _ => String::new(),
            };
            println!(
                "    {} {}{}{}",
                palette.bullet("~"),
                entry.path,
                size_info,
                palette.warn(&tags)
            );
        }
    }

    if !fs.permissions_changed.is_empty() {
        println!(
            "\n  {} ({})",
            palette.warn("Permission changes"),
            fs.permissions_changed.len()
        );
        for entry in &fs.permissions_changed {
            let impact = entry.security_impact.as_deref().unwrap_or("");
            println!(
                "    {} {} ({} -> {}) {}",
                palette.bullet("!"),
                entry.path,
                entry.base_mode,
                entry.head_mode,
                palette.warn(impact)
            );
        }
    }

    if !fs.symlinks_changed.is_empty() {
        println!(
            "\n  {} ({})",
            palette.info("Symlink changes"),
            fs.symlinks_changed.len()
        );
        for entry in &fs.symlinks_changed {
            println!(
                "    {} {} ({} -> {})",
                palette.bullet("->"),
                entry.path,
                entry.base_target.as_deref().unwrap_or("(none)"),
                entry.head_target.as_deref().unwrap_or("(none)"),
            );
        }
    }

    println!();
}

fn format_size(bytes: u64) -> String {
    if bytes >= 1_000_000 {
        format!(
            "{},{:03},{:03}",
            bytes / 1_000_000,
            (bytes / 1_000) % 1_000,
            bytes % 1_000
        )
    } else if bytes >= 1_000 {
        format!("{},{:03}", bytes / 1_000, bytes % 1_000)
    } else {
        format!("{bytes}")
    }
}
