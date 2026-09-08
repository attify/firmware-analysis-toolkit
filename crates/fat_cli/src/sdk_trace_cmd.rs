//! `fat sdk-trace` — reconstruct local SDK dependency chains across shared libraries.

use fat_taint::recon::r2;
use serde::Serialize;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::error::Error;
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
struct BinaryAnalysis {
    name: String,
    path: PathBuf,
    imports: Vec<r2::Import>,
    exports: Vec<r2::Export>,
    linked_libraries: Vec<String>,
}

#[derive(Debug, Serialize)]
struct SdkTraceReport {
    root: String,
    binaries: Vec<BinaryTrace>,
    dependency_chains: Vec<Vec<String>>,
}

#[derive(Debug, Serialize)]
struct BinaryTrace {
    name: String,
    path: String,
    imported_symbols: usize,
    exported_symbols: usize,
    linked_libraries: Vec<String>,
    local_dependencies: Vec<LocalDependency>,
    risk: SdkRisk,
}

#[derive(Debug, Serialize)]
struct SdkRisk {
    score: u8,
    role: String,
    reasons: Vec<String>,
}

#[derive(Debug, Serialize)]
struct LocalDependency {
    target: String,
    linked_library: bool,
    matched_symbols: Vec<String>,
}

const UPDATE_KEYWORDS: &[&str] = &["update", "updater", "upgrade", "firmware", "ota", "flash"];

const CRYPTO_KEYWORDS: &[&str] = &[
    "rsa", "aes", "md5", "sha", "sign", "verify", "decrypt", "encrypt", "rand", "random",
];

const CONTROL_KEYWORDS: &[&str] = &[
    "session",
    "token",
    "auth",
    "credential",
    "signature",
    "checksum",
];

const SENSITIVE_LIB_HINTS: &[&str] = &[
    "libcrypto",
    "libssl",
    "libmbedtls",
    "libwolfssl",
    "libgcrypt",
    "libcurl",
    "openssl",
];

pub fn run(dir: &Path, json: bool) -> DynResult<()> {
    if !dir.is_dir() {
        return Err(format!("directory not found: {}", dir.display()).into());
    }

    let analyses = scan_sdk(dir)?;
    if analyses.is_empty() {
        return Err(format!(
            "no ELF binaries or shared libraries found in {}",
            dir.display()
        )
        .into());
    }

    let report = build_report(dir, &analyses);

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text(&report);
    }

    Ok(())
}

fn scan_sdk(dir: &Path) -> DynResult<Vec<BinaryAnalysis>> {
    let mut analyses = Vec::new();

    for entry in WalkDir::new(dir).follow_links(false) {
        let entry = entry?;
        if !entry.file_type().is_file() {
            continue;
        }

        let path = entry.path();
        if !is_elf_candidate(path)? {
            continue;
        }

        let imports =
            r2::imports(path).map_err(|e| format!("imports for {}: {e}", path.display()))?;
        let exports =
            r2::exports(path).map_err(|e| format!("exports for {}: {e}", path.display()))?;
        let linked_libraries = r2::linked_libraries(path)
            .map_err(|e| format!("linked libraries for {}: {e}", path.display()))?;

        analyses.push(BinaryAnalysis {
            name: path
                .file_name()
                .map(|name| name.to_string_lossy().into_owned())
                .unwrap_or_else(|| path.display().to_string()),
            path: path.to_path_buf(),
            imports,
            exports,
            linked_libraries,
        });
    }

    analyses.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(analyses)
}

fn is_elf_candidate(path: &Path) -> DynResult<bool> {
    let mut file = File::open(path)?;
    let mut magic = [0u8; 4];
    if file.read_exact(&mut magic).is_ok() && magic == [0x7f, b'E', b'L', b'F'] {
        return Ok(true);
    }
    Ok(path.extension().is_some_and(|ext| ext == "so"))
}

fn build_report(root: &Path, analyses: &[BinaryAnalysis]) -> SdkTraceReport {
    let name_to_index: HashMap<String, usize> = analyses
        .iter()
        .enumerate()
        .map(|(idx, analysis)| (analysis.name.clone(), idx))
        .collect();

    let mut exports_by_symbol: HashMap<String, Vec<usize>> = HashMap::new();
    for (idx, analysis) in analyses.iter().enumerate() {
        for export in &analysis.exports {
            exports_by_symbol
                .entry(export.name.clone())
                .or_default()
                .push(idx);
        }
    }

    let mut adjacency: HashMap<String, Vec<String>> = HashMap::new();
    let mut binaries = Vec::new();

    for (idx, analysis) in analyses.iter().enumerate() {
        let linked_local: HashSet<String> = analysis
            .linked_libraries
            .iter()
            .filter(|lib| name_to_index.contains_key(lib.as_str()))
            .cloned()
            .collect();

        let mut matched_symbols: HashMap<String, BTreeSet<String>> = HashMap::new();
        for import in &analysis.imports {
            if let Some(providers) = exports_by_symbol.get(&import.name) {
                for provider_idx in providers {
                    if *provider_idx == idx {
                        continue;
                    }
                    let provider_name = analyses[*provider_idx].name.clone();
                    matched_symbols
                        .entry(provider_name)
                        .or_default()
                        .insert(import.name.clone());
                }
            }
        }

        let mut dep_names: BTreeSet<String> = linked_local.iter().cloned().collect();
        dep_names.extend(matched_symbols.keys().cloned());

        let mut local_dependencies: Vec<LocalDependency> = dep_names
            .into_iter()
            .map(|target| LocalDependency {
                linked_library: linked_local.contains(&target),
                matched_symbols: matched_symbols
                    .remove(&target)
                    .map(|set| set.into_iter().take(6).collect())
                    .unwrap_or_default(),
                target,
            })
            .collect();

        local_dependencies.sort_by(|a, b| {
            let a_score = usize::from(a.linked_library) + a.matched_symbols.len();
            let b_score = usize::from(b.linked_library) + b.matched_symbols.len();
            b_score.cmp(&a_score).then_with(|| a.target.cmp(&b.target))
        });

        let risk = assess_risk(analysis, &local_dependencies);

        adjacency.insert(
            analysis.name.clone(),
            local_dependencies
                .iter()
                .map(|dep| dep.target.clone())
                .collect(),
        );

        binaries.push(BinaryTrace {
            name: analysis.name.clone(),
            path: analysis.path.display().to_string(),
            imported_symbols: analysis.imports.len(),
            exported_symbols: analysis.exports.len(),
            linked_libraries: analysis.linked_libraries.clone(),
            local_dependencies,
            risk,
        });
    }

    let dependency_chains = find_dependency_chains(&binaries, &adjacency);

    SdkTraceReport {
        root: root.display().to_string(),
        binaries,
        dependency_chains,
    }
}

fn assess_risk(analysis: &BinaryAnalysis, dependencies: &[LocalDependency]) -> SdkRisk {
    let mut score: u16 = 0;
    let mut reasons = Vec::new();

    let name_lower = analysis.name.to_ascii_lowercase();
    if contains_keyword(&name_lower, UPDATE_KEYWORDS) {
        score += 45;
        reasons.push("update-related file naming".to_string());
    }

    if dependency_chain_strength(dependencies) >= 3 {
        score += 15;
        reasons.push("multiple local dependency edges".to_string());
    }

    let import_crypto_hits = count_symbol_keywords(
        analysis
            .imports
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        CRYPTO_KEYWORDS,
    );
    if import_crypto_hits > 0 {
        score += (10 * import_crypto_hits).min(20);
        reasons.push("crypto-linked imports".to_string());
    }

    let export_crypto_hits = count_symbol_keywords(
        analysis
            .exports
            .iter()
            .map(|entry| entry.name.as_str())
            .collect::<Vec<_>>(),
        CRYPTO_KEYWORDS,
    );
    if export_crypto_hits > 0 {
        score += (12 * export_crypto_hits).min(25);
        reasons.push("crypto-related exports".to_string());
    }

    let mut control_symbols = Vec::with_capacity(analysis.imports.len() + analysis.exports.len());
    control_symbols.extend(analysis.imports.iter().map(|entry| entry.name.as_str()));
    control_symbols.extend(analysis.exports.iter().map(|entry| entry.name.as_str()));
    let control_hits = count_symbol_keywords(control_symbols, CONTROL_KEYWORDS);
    if control_hits > 0 {
        score += 10;
        reasons.push("control/credential symbols present".to_string());
    }

    if has_security_library(&analysis.linked_libraries) {
        score += 20;
        reasons.push("links crypto/security libraries".to_string());
    }

    let matched_symbol_total: usize = dependencies
        .iter()
        .map(|dep| dep.matched_symbols.len())
        .sum();
    if matched_symbol_total > 0 {
        score += ((matched_symbol_total * 5).min(20)) as u16;
        reasons.push("symbol-level linkage evidence".to_string());
    }

    let role = match score {
        0..=34 => "utility",
        35..=64 => "orchestrator",
        65..=84 => "crypto-strong",
        _ => "governing-update-candidate",
    };

    let clamped = score.min(100);
    SdkRisk {
        score: clamped as u8,
        role: role.to_string(),
        reasons,
    }
}

fn contains_keyword(value: &str, keywords: &[&str]) -> bool {
    let lower = value.to_ascii_lowercase();
    keywords.iter().any(|keyword| lower.contains(keyword))
}

fn has_security_library(libs: &[String]) -> bool {
    libs.iter().any(|linked| {
        let lower = linked.to_ascii_lowercase();
        SENSITIVE_LIB_HINTS
            .iter()
            .any(|keyword| lower.contains(keyword))
    })
}

fn count_symbol_keywords(symbols: Vec<&str>, keywords: &[&str]) -> u16 {
    let mut count = 0u16;
    for symbol in symbols {
        let lower = symbol.to_ascii_lowercase();
        if keywords.iter().any(|keyword| lower.contains(keyword)) {
            count += 1;
        }
    }
    count
}

fn dependency_chain_strength(dependencies: &[LocalDependency]) -> usize {
    dependencies
        .iter()
        .map(|dep| usize::from(dep.linked_library) + dep.matched_symbols.len())
        .sum()
}

fn find_dependency_chains(
    binaries: &[BinaryTrace],
    adjacency: &HashMap<String, Vec<String>>,
) -> Vec<Vec<String>> {
    let mut all_paths = Vec::new();

    for binary in binaries {
        let mut visited = HashSet::new();
        let mut current = vec![binary.name.clone()];
        visited.insert(binary.name.clone());
        collect_paths(adjacency, &mut visited, &mut current, &mut all_paths);
    }

    let mut unique = BTreeSet::new();
    let mut chains = Vec::new();
    for path in all_paths {
        if path.len() < 2 {
            continue;
        }
        let key = path.join(" -> ");
        if unique.insert(key) {
            chains.push(path);
        }
    }

    chains.sort_by(|a, b| {
        b.len()
            .cmp(&a.len())
            .then_with(|| a.join(" -> ").cmp(&b.join(" -> ")))
    });
    chains.truncate(8);
    chains
}

fn collect_paths(
    adjacency: &HashMap<String, Vec<String>>,
    visited: &mut HashSet<String>,
    current: &mut Vec<String>,
    all_paths: &mut Vec<Vec<String>>,
) {
    all_paths.push(current.clone());

    let Some(last) = current.last() else {
        return;
    };

    if let Some(neighbors) = adjacency.get(last) {
        for next in neighbors {
            if visited.contains(next) {
                continue;
            }
            visited.insert(next.clone());
            current.push(next.clone());
            collect_paths(adjacency, visited, current, all_paths);
            current.pop();
            visited.remove(next);
        }
    }
}

fn render_text(report: &SdkTraceReport) {
    println!("SDK trace: {}", report.root);
    println!("Binaries analyzed: {}", report.binaries.len());
    println!();

    let mut ranked: Vec<&BinaryTrace> = report.binaries.iter().collect();
    ranked.sort_by_key(|r| std::cmp::Reverse(r.risk.score));

    println!("High-risk binaries:");
    for binary in ranked.iter().take(3) {
        if binary.risk.score < 40 {
            break;
        }
        println!(
            "  {} [{}] - {}",
            binary.name, binary.risk.score, binary.risk.role
        );
        if !binary.risk.reasons.is_empty() {
            println!("    reasons: {}", binary.risk.reasons.join(", "));
        }
    }
    println!();

    println!("Dependency chains:");
    if report.dependency_chains.is_empty() {
        println!("  (none)");
    } else {
        for chain in &report.dependency_chains {
            println!("  {}", chain.join(" -> "));
        }
    }
    println!();

    println!("Per-binary evidence:");
    for binary in &report.binaries {
        println!("  {}", binary.name);
        println!("    path: {}", binary.path);
        println!(
            "    imports: {}  exports: {}",
            binary.imported_symbols, binary.exported_symbols
        );
        println!("    risk: {} ({})", binary.risk.score, binary.risk.role);
        if binary.local_dependencies.is_empty() {
            println!("    local dependencies: none");
            continue;
        }

        for dep in &binary.local_dependencies {
            if dep.matched_symbols.is_empty() {
                println!(
                    "    -> {} ({})",
                    dep.target,
                    if dep.linked_library {
                        "linked locally"
                    } else {
                        "symbol-derived"
                    }
                );
            } else {
                let evidence = dep.matched_symbols.join(", ");
                if dep.linked_library {
                    println!(
                        "    -> {} (linked locally; matched symbols: {})",
                        dep.target, evidence
                    );
                } else {
                    println!("    -> {} (matched symbols: {})", dep.target, evidence);
                }
            }
        }
    }
}
