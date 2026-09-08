use regex::Regex;
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::Command;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug)]
pub struct StartupMapRequest<'a> {
    pub rootfs: &'a Path,
    pub profile: Option<&'a str>,
    pub name: Option<&'a str>,
    pub binary: Option<&'a str>,
    pub api: Option<&'a str>,
    pub library: Option<&'a str>,
    pub max: usize,
    pub json: bool,
    pub explain: bool,
    pub emit_actions: bool,
    pub all_scripts: bool,
    pub no_r2: bool,
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
pub struct Evidence {
    pub kind: String,
    pub value: String,
    pub source: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct StartupEntry {
    pub id: String,
    pub kind: String,
    pub path: String,
    pub target: Option<String>,
    pub target_exists: bool,
    pub phase: String,
    pub order: Option<u32>,
    pub init_script: Option<String>,
    pub evidence: Vec<Evidence>,
}

#[derive(Debug, Serialize, Clone)]
pub struct StartupPath {
    pub entry: Option<String>,
    pub init_script: String,
    pub evidence: String,
}

#[derive(Debug, Serialize, Clone)]
pub struct Activation {
    pub level: String,
    pub runtime_proven: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct ProfileMatch {
    pub name: String,
    pub roles: Vec<String>,
    pub score: u32,
    pub confidence: String,
    pub evidence: Vec<Evidence>,
    pub gaps: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct StartupCandidate {
    pub binary: String,
    pub exists: bool,
    pub format: String,
    pub architecture: Option<String>,
    pub startup_paths: Vec<StartupPath>,
    pub activation: Activation,
    pub profiles: Vec<ProfileMatch>,
    pub evidence: Vec<Evidence>,
    pub gaps: Vec<String>,
}

#[derive(Debug, Serialize, Clone)]
pub struct StartupSummary {
    pub startup_entries: usize,
    pub init_scripts: usize,
    pub resolved_binaries: usize,
    pub profile_candidates: usize,
    pub r2_available: bool,
}

#[derive(Debug, Serialize, Clone)]
pub struct StartupMapReport {
    pub schema: &'static str,
    pub rootfs: String,
    pub profiles: Vec<String>,
    pub summary: StartupSummary,
    pub entries: Vec<StartupEntry>,
    pub candidates: Vec<StartupCandidate>,
    pub gaps: Vec<String>,
    pub suggested_actions: Vec<String>,
}

#[derive(Debug, Clone)]
struct ExtractedRef {
    binary: String,
    evidence_kind: String,
    evidence_value: String,
    init_script: String,
    entry: Option<String>,
}

#[derive(Debug, Clone, Default)]
struct CandidateBuilder {
    binary: String,
    startup_paths: Vec<StartupPath>,
    evidence: Vec<Evidence>,
}

#[derive(Debug, Clone, Copy)]
struct ProfileRule {
    name: &'static str,
    filename_signals: &'static [&'static str],
    import_signals: &'static [&'static str],
    library_signals: &'static [&'static str],
    string_signals: &'static [&'static str],
}

const PROFILE_RULES: &[ProfileRule] = &[
    ProfileRule {
        name: "cloud-tls",
        filename_signals: &[
            "cloud", "ipc", "mqtt", "p2p", "tutk", "iotc", "brd", "client",
        ],
        import_signals: &[
            "SSL_connect",
            "SSL_read",
            "SSL_write",
            "getaddrinfo",
            "curl_easy_init",
            "curl_easy_setopt",
            "curl_easy_perform",
        ],
        library_signals: &["libssl", "libcurl"],
        string_signals: &["libssl", "libcurl", "https://", "device-api", "cloud"],
    },
    ProfileRule {
        name: "curl",
        filename_signals: &[],
        import_signals: &[
            "curl_easy_init",
            "curl_easy_setopt",
            "curl_easy_perform",
            "curl_multi_",
        ],
        library_signals: &["libcurl"],
        string_signals: &["CURLOPT_", "libcurl", "curl_easy"],
    },
    ProfileRule {
        name: "dns",
        filename_signals: &[],
        import_signals: &["getaddrinfo", "gethostbyname", "res_query", "res_send"],
        library_signals: &[],
        string_signals: &[".com", ".net", ".org", "dns", "resolver"],
    },
    ProfileRule {
        name: "web",
        filename_signals: &["httpd", "uhttpd", "boa", "lighttpd", "nginx"],
        import_signals: &["listen", "bind", "accept"],
        library_signals: &["libssl"],
        string_signals: &[
            "listen_http",
            "listen_https",
            "DocumentRoot",
            "cgi-bin",
            "httpd",
        ],
    },
    ProfileRule {
        name: "update",
        filename_signals: &["upgrade", "update", "sysupgrade"],
        import_signals: &["RSA_", "sha256", "SHA256", "curl_easy_perform"],
        library_signals: &["libcrypto", "libssl", "libcurl"],
        string_signals: &["firmware", "upgrade", "download_url", "mtd", "sysupgrade"],
    },
];

pub fn run(request: StartupMapRequest<'_>) -> DynResult<()> {
    if !request.rootfs.is_dir() {
        return Err(format!(
            "rootfs path is not a directory: {}",
            request.rootfs.display()
        )
        .into());
    }

    let report = analyze_rootfs(&request)?;
    if request.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        render_text(&report, &request);
    }
    Ok(())
}

fn analyze_rootfs(request: &StartupMapRequest<'_>) -> DynResult<StartupMapReport> {
    let profile = match request.profile {
        Some(name) => Some(profile_rule(name)?),
        None => None,
    };
    let name_filter = compile_filter("name", request.name)?;
    let binary_filter = compile_filter("binary", request.binary)?;
    let api_filter = compile_filter("api", request.api)?;
    let library_filter = compile_filter("library", request.library)?;

    let mut gaps = Vec::new();
    let r2_available = !request.no_r2 && command_available("rabin2");
    if request.no_r2 {
        gaps.push("r2-import-analysis-disabled".to_string());
    } else if !r2_available {
        gaps.push("r2-import-analysis-unavailable".to_string());
    }

    let mut entries = discover_startup_entries(request.rootfs)?;
    if let Some(filter) = &name_filter {
        entries.retain(|entry| filter.is_match(&entry.path));
    }

    let refs = extract_startup_refs(request.rootfs, &entries, request.all_scripts)?;
    let mut builders: BTreeMap<String, CandidateBuilder> = BTreeMap::new();
    for reference in refs {
        if let Some(filter) = &binary_filter {
            if !filter.is_match(&reference.binary) {
                continue;
            }
        }
        let builder =
            builders
                .entry(reference.binary.clone())
                .or_insert_with(|| CandidateBuilder {
                    binary: reference.binary.clone(),
                    ..Default::default()
                });
        let startup_path = StartupPath {
            entry: reference.entry.clone(),
            init_script: reference.init_script.clone(),
            evidence: reference.evidence_value.clone(),
        };
        if !builder.startup_paths.iter().any(|path| {
            path.entry == startup_path.entry
                && path.init_script == startup_path.init_script
                && path.evidence == startup_path.evidence
        }) {
            builder.startup_paths.push(startup_path);
        }
        push_unique_evidence(
            &mut builder.evidence,
            Evidence {
                kind: reference.evidence_kind,
                value: reference.evidence_value,
                source: reference.init_script,
            },
        );
    }

    let mut candidates = Vec::new();
    for builder in builders.into_values() {
        let candidate = build_candidate(
            request.rootfs,
            builder,
            profile,
            r2_available,
            &api_filter,
            &library_filter,
        )?;
        let matches_api = api_filter.as_ref().is_none_or(|filter| {
            candidate
                .profiles
                .iter()
                .flat_map(|profile| profile.evidence.iter())
                .any(|evidence| filter.is_match(&evidence.value))
        });
        let matches_library = library_filter.as_ref().is_none_or(|filter| {
            candidate
                .profiles
                .iter()
                .flat_map(|profile| profile.evidence.iter())
                .any(|evidence| {
                    evidence.kind == "linked-library" && filter.is_match(&evidence.value)
                })
        });
        if matches_api && matches_library {
            candidates.push(candidate);
        }
    }

    candidates.sort_by(|left, right| {
        let left_score = best_score(left);
        let right_score = best_score(right);
        right_score
            .cmp(&left_score)
            .then_with(|| left.binary.cmp(&right.binary))
    });
    if request.max > 0 && candidates.len() > request.max {
        candidates.truncate(request.max);
    }

    let mut init_scripts = BTreeSet::new();
    for entry in &entries {
        if let Some(script) = &entry.init_script {
            init_scripts.insert(script.clone());
        }
    }
    for candidate in &candidates {
        for path in &candidate.startup_paths {
            init_scripts.insert(path.init_script.clone());
        }
    }

    let suggested_actions = if request.emit_actions {
        build_suggested_actions(request.rootfs, &candidates)
    } else {
        Vec::new()
    };

    let profile_candidates = if profile.is_some() {
        candidates
            .iter()
            .filter(|candidate| !candidate.profiles.is_empty())
            .count()
    } else {
        candidates.len()
    };

    Ok(StartupMapReport {
        schema: "startup-map/v1",
        rootfs: request.rootfs.display().to_string(),
        profiles: profile
            .map(|rule| rule.name.to_string())
            .into_iter()
            .collect(),
        summary: StartupSummary {
            startup_entries: entries.len(),
            init_scripts: init_scripts.len(),
            resolved_binaries: candidates.len(),
            profile_candidates,
            r2_available,
        },
        entries,
        candidates,
        gaps,
        suggested_actions,
    })
}

fn discover_startup_entries(rootfs: &Path) -> DynResult<Vec<StartupEntry>> {
    let rc_dir = rootfs.join("etc/rc.d");
    let mut entries = Vec::new();
    if !rc_dir.is_dir() {
        return Ok(entries);
    }

    let mut dir_entries = fs::read_dir(&rc_dir)?.collect::<Result<Vec<_>, _>>()?;
    dir_entries.sort_by_key(|entry| entry.file_name());
    for dir_entry in dir_entries {
        let host_path = dir_entry.path();
        let file_name = dir_entry.file_name().to_string_lossy().to_string();
        let metadata = fs::symlink_metadata(&host_path)?;
        let mut evidence = Vec::new();
        let target = if metadata.file_type().is_symlink() {
            let target = fs::read_link(&host_path)?;
            let target_string = target.to_string_lossy().to_string();
            evidence.push(Evidence {
                kind: "symlink-target".to_string(),
                value: target_string.clone(),
                source: rootfs_relative(rootfs, &host_path),
            });
            Some(target_string)
        } else {
            None
        };
        let init_host = target
            .as_ref()
            .map(|target| resolve_link_target(rootfs, &host_path, target))
            .or_else(|| Some(host_path.clone()))
            .filter(|path| path.exists());
        let init_script = init_host.as_ref().and_then(|path| {
            let rel = rootfs_relative(rootfs, path);
            if rel.starts_with("/etc/init.d/") || rel.starts_with("/etc/rc.d/") {
                Some(rel)
            } else {
                None
            }
        });
        let target_exists = target
            .as_ref()
            .map(|target| resolve_link_target(rootfs, &host_path, target).exists())
            .unwrap_or_else(|| host_path.exists());
        let (phase, order) = parse_rc_name(&file_name);
        evidence.push(Evidence {
            kind: "rc.d-order".to_string(),
            value: order
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            source: rootfs_relative(rootfs, &host_path),
        });
        entries.push(StartupEntry {
            id: format!("startup-entry:{file_name}"),
            kind: if metadata.file_type().is_symlink() {
                "rc.d-symlink".to_string()
            } else {
                "rc.d-entry".to_string()
            },
            path: rootfs_relative(rootfs, &host_path),
            target,
            target_exists,
            phase,
            order,
            init_script,
            evidence,
        });
    }
    Ok(entries)
}

fn extract_startup_refs(
    rootfs: &Path,
    entries: &[StartupEntry],
    all_scripts: bool,
) -> DynResult<Vec<ExtractedRef>> {
    let mut refs = Vec::new();
    let mut scripts = BTreeMap::new();
    for entry in entries {
        if let Some(init_script) = &entry.init_script {
            scripts.insert(init_script.clone(), Some(entry.path.clone()));
        }
    }
    if all_scripts {
        let init_dir = rootfs.join("etc/init.d");
        if init_dir.is_dir() {
            for dir_entry in fs::read_dir(init_dir)?.flatten() {
                let path = dir_entry.path();
                if path.is_file() {
                    scripts
                        .entry(rootfs_relative(rootfs, &path))
                        .or_insert(None);
                }
            }
        }
    }

    for (script_rel, entry_rel) in scripts {
        let script_host = rootfs_join(rootfs, &script_rel);
        if !script_host.is_file() {
            continue;
        }
        let text = fs::read_to_string(&script_host).unwrap_or_default();
        refs.extend(parse_init_script(&text, &script_rel, entry_rel.as_deref()));
    }
    Ok(refs)
}

fn parse_init_script(text: &str, script_rel: &str, entry_rel: Option<&str>) -> Vec<ExtractedRef> {
    let assign_re = Regex::new(r#"^\s*([A-Za-z_][A-Za-z0-9_]*)=(?:"([^"]*)"|'([^']*)'|([^\s;]+))"#)
        .expect("valid assignment regex");
    let path_re =
        Regex::new(r#"(^|[;&|]\s*)(/[A-Za-z0-9_./+@-]+)(?:\s|$|&)"#).expect("valid path regex");
    let var_re = Regex::new(r#"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?"#).expect("valid var regex");

    let mut variables = BTreeMap::new();
    for line in text.lines() {
        let line = strip_comment(line);
        if let Some(captures) = assign_re.captures(line) {
            let name = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .or_else(|| captures.get(4))
                .map(|m| m.as_str())
                .unwrap_or_default();
            variables.insert(name.to_string(), value.to_string());
        }
    }

    let mut refs = Vec::new();
    for line in text.lines() {
        let line = strip_comment(line).trim();
        if line.is_empty() {
            continue;
        }
        if let Some(captures) = assign_re.captures(line) {
            let name = captures.get(1).map(|m| m.as_str()).unwrap_or_default();
            let value = captures
                .get(2)
                .or_else(|| captures.get(3))
                .or_else(|| captures.get(4))
                .map(|m| m.as_str())
                .unwrap_or_default();
            if is_exec_var(name) && value.starts_with('/') {
                push_ref(
                    &mut refs,
                    value,
                    "init-variable",
                    format!("{name}={value:?}"),
                    script_rel,
                    entry_rel,
                );
            }
            continue;
        }

        let tokens = split_shell_words(line);
        for (idx, token) in tokens.iter().enumerate() {
            if matches!(token.as_str(), "service_start" | "daemon") {
                if let Some(next) = tokens.get(idx + 1) {
                    push_resolved_token(
                        &mut refs,
                        next,
                        &variables,
                        "service-start-call",
                        line,
                        script_rel,
                        entry_rel,
                    );
                }
            } else if token == "start-stop-daemon" {
                if let Some(x_idx) = tokens.iter().position(|arg| arg == "-x" || arg == "--exec") {
                    if let Some(next) = tokens.get(x_idx + 1) {
                        push_resolved_token(
                            &mut refs,
                            next,
                            &variables,
                            "service-start-call",
                            line,
                            script_rel,
                            entry_rel,
                        );
                    }
                }
            } else if token == "procd_set_param"
                && tokens.get(idx + 1).map(String::as_str) == Some("command")
            {
                if let Some(next) = tokens.get(idx + 2) {
                    push_resolved_token(
                        &mut refs,
                        next,
                        &variables,
                        "service-start-call",
                        line,
                        script_rel,
                        entry_rel,
                    );
                }
            }
        }

        for captures in path_re.captures_iter(line) {
            if let Some(path) = captures.get(2) {
                push_ref(
                    &mut refs,
                    path.as_str(),
                    "script-exec-call",
                    line.to_string(),
                    script_rel,
                    entry_rel,
                );
            }
        }
        for captures in var_re.captures_iter(line) {
            let Some(var) = captures.get(1).map(|m| m.as_str()) else {
                continue;
            };
            if let Some(value) = variables.get(var) {
                if value.starts_with('/') && is_exec_var(var) {
                    push_ref(
                        &mut refs,
                        value,
                        "script-exec-call",
                        format!("{line} -> {value}"),
                        script_rel,
                        entry_rel,
                    );
                }
            }
        }
    }
    refs
}

fn build_candidate(
    rootfs: &Path,
    builder: CandidateBuilder,
    profile: Option<ProfileRule>,
    r2_available: bool,
    api_filter: &Option<Regex>,
    library_filter: &Option<Regex>,
) -> DynResult<StartupCandidate> {
    let host_path = rootfs_join(rootfs, &builder.binary);
    let (exists, format, architecture) = classify_file(&host_path);
    let mut evidence = builder.evidence;
    if exists {
        push_unique_evidence(
            &mut evidence,
            Evidence {
                kind: "binary-exists".to_string(),
                value: builder.binary.clone(),
                source: builder.binary.clone(),
            },
        );
    }
    if format.starts_with("ELF") {
        push_unique_evidence(
            &mut evidence,
            Evidence {
                kind: "binary-format".to_string(),
                value: format.clone(),
                source: builder.binary.clone(),
            },
        );
    }

    let strings = if exists {
        extract_printable_strings(&host_path)?
    } else {
        Vec::new()
    };
    let (imports, libraries) = if r2_available && exists && format.starts_with("ELF") {
        read_rabin2_evidence(&host_path)
    } else {
        (Vec::new(), Vec::new())
    };

    let mut gaps = vec![
        "runtime-execution-unproven".to_string(),
        "call-path-unproven".to_string(),
    ];
    if !exists {
        gaps.push("binary-missing".to_string());
    }

    let profiles = profile
        .map(|rule| {
            profile_candidate(
                rule,
                &builder.binary,
                &format,
                &evidence,
                &strings,
                &imports,
                &libraries,
                api_filter,
                library_filter,
            )
        })
        .into_iter()
        .flatten()
        .collect();

    Ok(StartupCandidate {
        binary: builder.binary,
        exists,
        format,
        architecture,
        startup_paths: builder.startup_paths,
        activation: Activation {
            level: "startup-intent".to_string(),
            runtime_proven: false,
        },
        profiles,
        evidence,
        gaps,
    })
}

fn profile_candidate(
    rule: ProfileRule,
    binary: &str,
    format: &str,
    startup_evidence: &[Evidence],
    strings: &[String],
    imports: &[String],
    libraries: &[String],
    api_filter: &Option<Regex>,
    library_filter: &Option<Regex>,
) -> Option<ProfileMatch> {
    let mut evidence = Vec::new();
    let mut string_hits = 0u32;
    let mut import_hits = 0u32;
    let mut library_hits = 0u32;
    let mut decisive = false;

    for signal in rule.filename_signals {
        if contains_case_insensitive(binary, signal) {
            push_unique_evidence(
                &mut evidence,
                Evidence {
                    kind: "profile-match".to_string(),
                    value: format!("filename:{signal}"),
                    source: binary.to_string(),
                },
            );
        }
    }
    for value in strings {
        if rule
            .string_signals
            .iter()
            .any(|signal| signal_matches(value, signal))
            && api_filter
                .as_ref()
                .is_none_or(|filter| filter.is_match(value))
        {
            string_hits += 1;
            push_unique_evidence(
                &mut evidence,
                Evidence {
                    kind: "string-hit".to_string(),
                    value: value.clone(),
                    source: binary.to_string(),
                },
            );
        }
    }
    for value in imports {
        if rule
            .import_signals
            .iter()
            .any(|signal| signal_matches(value, signal))
            && api_filter
                .as_ref()
                .is_none_or(|filter| filter.is_match(value))
        {
            if value == "curl_easy_perform" {
                decisive = true;
            }
            import_hits += 1;
            push_unique_evidence(
                &mut evidence,
                Evidence {
                    kind: "elf-import".to_string(),
                    value: value.clone(),
                    source: binary.to_string(),
                },
            );
        }
    }
    for value in libraries {
        if rule
            .library_signals
            .iter()
            .any(|signal| signal_matches(value, signal))
            && library_filter
                .as_ref()
                .is_none_or(|filter| filter.is_match(value))
        {
            library_hits += 1;
            push_unique_evidence(
                &mut evidence,
                Evidence {
                    kind: "linked-library".to_string(),
                    value: value.clone(),
                    source: binary.to_string(),
                },
            );
        }
    }

    if evidence.is_empty() {
        return None;
    }

    let mut score = 0;
    if !startup_evidence.is_empty() {
        score += 20;
    }
    if startup_evidence
        .iter()
        .any(|item| item.kind == "init-variable" || item.kind == "service-start-call")
    {
        score += 25;
    }
    if format.starts_with("ELF") {
        score += 15;
    }
    if startup_evidence
        .iter()
        .any(|item| item.kind == "service-start-call" || item.kind == "script-exec-call")
    {
        score += 15;
    }
    score += (string_hits * 5).min(20);
    score += (import_hits * 10).min(40);
    score += (library_hits * 10).min(20);
    if decisive {
        score += 20;
    }

    let roles = roles_for(rule.name, binary, &evidence);
    Some(ProfileMatch {
        name: rule.name.to_string(),
        roles,
        score,
        confidence: confidence(score).to_string(),
        evidence,
        gaps: vec![
            "call-path-unproven".to_string(),
            "runtime-execution-unproven".to_string(),
        ],
    })
}

fn roles_for(profile: &str, binary: &str, evidence: &[Evidence]) -> Vec<String> {
    let mut roles = BTreeSet::new();
    let has = |needle: &str| {
        evidence
            .iter()
            .any(|item| contains_case_insensitive(&item.value, needle))
    };
    match profile {
        "cloud-tls" => {
            if has("curl_easy") || has("libcurl") {
                roles.insert("libcurl-http-client".to_string());
            }
            if has("SSL_") || has("libssl") {
                if has("curl_easy") || has("libcurl") {
                    roles.insert("openssl-linked-client".to_string());
                } else {
                    roles.insert("direct-openssl-client".to_string());
                }
            }
            if has("getaddrinfo") || has("gethostbyname") {
                roles.insert("dns-resolver-consumer".to_string());
            }
        }
        "curl" => {
            roles.insert("libcurl-consumer".to_string());
            if has("curl_easy_perform") || has("CURLOPT_") {
                roles.insert("curl-transfer-candidate".to_string());
            }
        }
        "dns" => {
            roles.insert("resolver-consumer".to_string());
            if contains_case_insensitive(binary, "cloud") || has(".com") {
                roles.insert("cloud-lookup-candidate".to_string());
            }
        }
        "web" => {
            roles.insert("web-server-candidate".to_string());
            if has("libssl") || has("listen_https") {
                roles.insert("https-listener-candidate".to_string());
            }
        }
        "update" => {
            roles.insert("firmware-update-candidate".to_string());
            if has("download") || has("curl") || has("http") {
                roles.insert("download-client-candidate".to_string());
            }
            roles.insert("trust-boundary-next-hop".to_string());
        }
        _ => {}
    }
    if roles.is_empty() {
        roles.insert(format!("{profile}-candidate"));
    }
    roles.into_iter().collect()
}

fn render_text(report: &StartupMapReport, request: &StartupMapRequest<'_>) {
    let palette = crate::style::Palette::stdout();
    if !palette.enabled() {
        render_text_plain(report, request);
        return;
    }
    render_text_panel(report, request, &palette);
}

/// Plain renderer for piped output, `NO_COLOR`, and non-TTY runs. Kept
/// verbatim so scripts and redirected output stay byte-identical.
fn render_text_plain(report: &StartupMapReport, request: &StartupMapRequest<'_>) {
    println!("FAT Startup Map");
    println!("rootfs: {}", report.rootfs);
    if report.profiles.is_empty() {
        println!("profile: (none)");
    } else {
        println!("profile: {}", report.profiles.join(", "));
    }
    println!();

    if request.explain {
        println!("Stage 1: rc.d entries");
        println!("  What this does: lists startup entries and resolves init-script targets.");
        println!("  Why it matters: rc.d entries are static startup or lifecycle intent.");
        println!();
        println!("Stage 2: init script resolution");
        println!("  What this does: extracts conservative executable references from scripts.");
        println!("  Why it matters: init scripts name concrete binaries for evidence collection.");
        println!();
    }

    println!("Startup entries:");
    if report.entries.is_empty() {
        println!("  (none found)");
    } else {
        for entry in &report.entries {
            let target = entry
                .init_script
                .as_deref()
                .or(entry.target.as_deref())
                .unwrap_or("(unresolved)");
            println!("  {} -> {}", entry.path, target);
        }
    }
    println!();

    println!("Candidates:");
    if report.candidates.is_empty() {
        println!("  (none found)");
    } else {
        for (idx, candidate) in report.candidates.iter().enumerate() {
            let best = candidate
                .profiles
                .iter()
                .max_by_key(|profile| profile.score);
            let score = best.map(|profile| profile.score).unwrap_or(0);
            let confidence = best
                .map(|profile| profile.confidence.as_str())
                .unwrap_or("startup");
            let roles = best
                .map(|profile| profile.roles.join(", "))
                .unwrap_or_else(|| "startup-target".to_string());
            println!(
                "{}. {}  {}  {}",
                idx + 1,
                candidate.binary,
                confidence,
                roles
            );
            println!(
                "   activation: {} (runtime_proven=false)",
                candidate.activation.level
            );
            if let Some(path) = candidate.startup_paths.first() {
                let entry = path.entry.as_deref().unwrap_or("(script)");
                println!("   startup: {} -> {}", entry, path.init_script);
            }
            println!("   score: {score}");
            println!("   format: {}", candidate.format);
            if let Some(profile) = best {
                let preview = profile
                    .evidence
                    .iter()
                    .take(5)
                    .map(|item| format!("{}: {}", item.kind, item.value))
                    .collect::<Vec<_>>();
                if !preview.is_empty() {
                    println!("   evidence: {}", preview.join("; "));
                }
            }
            println!("   bounded verdict: candidate only; call path not proven");
        }
    }

    if !report.gaps.is_empty() {
        println!();
        println!("Gaps:");
        for gap in &report.gaps {
            println!("  - {gap}");
        }
    }

    if request.emit_actions && !report.suggested_actions.is_empty() {
        println!();
        println!("Suggested next commands:");
        for action in &report.suggested_actions {
            println!("  {action}");
        }
    }
}

/// Panel renderer for interactive TTY runs: status dots per entry/candidate,
/// dimmed evidence metadata, and explicit empty states.
fn render_text_panel(
    report: &StartupMapReport,
    request: &StartupMapRequest<'_>,
    palette: &crate::style::Palette,
) {
    if request.explain {
        println!(
            "{}",
            palette.muted("Stage 1: rc.d entries — lists startup entries and resolves init-script targets (static startup or lifecycle intent).")
        );
        println!(
            "{}",
            palette.muted("Stage 2: init script resolution — extracts conservative executable references from scripts (concrete binaries for evidence collection).")
        );
    }
    let mut lines = Vec::new();
    lines.push(palette.kv("rootfs", &report.rootfs));
    let profile = if report.profiles.is_empty() {
        palette.muted("(none)")
    } else {
        report.profiles.join(", ")
    };
    lines.push(palette.kv("profile", profile));

    lines.push(String::new());
    lines.push(palette.heading("Startup entries"));
    if report.entries.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("none found")
        ));
    } else {
        for entry in &report.entries {
            let target = entry
                .init_script
                .as_deref()
                .or(entry.target.as_deref())
                .unwrap_or("(unresolved)");
            lines.push(format!(
                "{} {} {}",
                palette.dot_ok(),
                palette.good(&entry.path),
                palette.muted(format!("→ {target}"))
            ));
        }
    }

    lines.push(String::new());
    lines.push(palette.heading("Candidates"));
    if report.candidates.is_empty() {
        lines.push(format!(
            "{} {}",
            palette.dot_muted(),
            palette.muted("none found")
        ));
    } else {
        for (idx, candidate) in report.candidates.iter().enumerate() {
            let best = candidate
                .profiles
                .iter()
                .max_by_key(|profile| profile.score);
            let score = best.map(|profile| profile.score).unwrap_or(0);
            let confidence = best
                .map(|profile| profile.confidence.as_str())
                .unwrap_or("startup");
            let roles = best
                .map(|profile| profile.roles.join(", "))
                .unwrap_or_else(|| "startup-target".to_string());
            lines.push(format!(
                "{} {}. {} · {} · {}",
                palette.dot_warn(),
                idx + 1,
                palette.good(&candidate.binary),
                confidence,
                roles
            ));
            let mut details = vec![
                format!("score {score}"),
                format!("activation {}", candidate.activation.level),
                format!("format {}", candidate.format),
            ];
            if let Some(path) = candidate.startup_paths.first() {
                let entry = path.entry.as_deref().unwrap_or("(script)");
                details.push(format!("startup {} -> {}", entry, path.init_script));
            }
            lines.push(format!("· {}", palette.muted(details.join(" · "))));
            lines.push(format!(
                "· {}",
                palette.muted("bounded verdict: candidate only; call path not proven")
            ));
            if let Some(profile) = best {
                let preview = profile
                    .evidence
                    .iter()
                    .take(5)
                    .map(|item| format!("{}: {}", item.kind, item.value))
                    .collect::<Vec<_>>();
                if !preview.is_empty() {
                    lines.push(format!("· {}", palette.muted(preview.join("; "))));
                }
            }
        }
    }

    if !report.gaps.is_empty() {
        lines.push(String::new());
        lines.push(palette.heading("Gaps"));
        for gap in &report.gaps {
            lines.push(format!("· {}", palette.warn(gap)));
        }
    }

    println!("{}", palette.panel("FAT Startup Map", &lines));
    if request.emit_actions && !report.suggested_actions.is_empty() {
        for action in &report.suggested_actions {
            println!("{}", palette.next_hint(action));
        }
    }
}

fn build_suggested_actions(rootfs: &Path, candidates: &[StartupCandidate]) -> Vec<String> {
    let mut actions = Vec::new();
    for candidate in candidates.iter().take(3) {
        if candidate.exists {
            let full_path = rootfs_join(rootfs, &candidate.binary);
            actions.push(format!("fat r2-triage --file {}", full_path.display()));
        }
    }
    actions.push(format!(
        "fat search --rootfs {} -i 'CURLOPT|curl_easy|libssl' --summary",
        rootfs.display()
    ));
    actions
}

fn read_rabin2_evidence(path: &Path) -> (Vec<String>, Vec<String>) {
    let imports = run_rabin2_json("-ij", path)
        .and_then(|json| parse_named_array(&json, "imports"))
        .unwrap_or_default();
    let libraries = run_rabin2_json("-lj", path)
        .and_then(|json| {
            json.get("libs").and_then(Value::as_array).map(|items| {
                items
                    .iter()
                    .filter_map(Value::as_str)
                    .map(str::to_string)
                    .collect::<Vec<_>>()
            })
        })
        .unwrap_or_default();
    (imports, libraries)
}

fn run_rabin2_json(mode: &str, path: &Path) -> Option<Value> {
    let output = Command::new("rabin2").arg(mode).arg(path).output().ok()?;
    if !output.status.success() {
        return None;
    }
    serde_json::from_slice(&output.stdout).ok()
}

fn parse_named_array(json: &Value, key: &str) -> Option<Vec<String>> {
    json.get(key)?.as_array().map(|items| {
        items
            .iter()
            .filter_map(|item| item.get("name").and_then(Value::as_str))
            .map(str::to_string)
            .collect()
    })
}

fn classify_file(path: &Path) -> (bool, String, Option<String>) {
    let Ok(bytes) = fs::read(path) else {
        return (false, "missing".to_string(), None);
    };
    if bytes.starts_with(b"#!") {
        return (true, "script".to_string(), None);
    }
    if bytes.len() >= 20 && bytes.starts_with(b"\x7fELF") {
        let class = match bytes[4] {
            1 => "ELF32",
            2 => "ELF64",
            _ => "ELF",
        };
        let endian_little = bytes.get(5).copied().unwrap_or(1) != 2;
        let machine = if endian_little {
            u16::from_le_bytes([bytes[18], bytes[19]])
        } else {
            u16::from_be_bytes([bytes[18], bytes[19]])
        };
        return (
            true,
            class.to_string(),
            elf_machine(machine).map(str::to_string),
        );
    }
    (true, "unknown".to_string(), None)
}

fn extract_printable_strings(path: &Path) -> DynResult<Vec<String>> {
    let bytes = fs::read(path)?;
    let mut out = Vec::new();
    let mut current = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || byte == b' ' {
            current.push(byte);
        } else {
            if current.len() >= 4 {
                out.push(String::from_utf8_lossy(&current).to_string());
            }
            current.clear();
        }
    }
    if current.len() >= 4 {
        out.push(String::from_utf8_lossy(&current).to_string());
    }
    out.sort();
    out.dedup();
    Ok(out)
}

fn push_resolved_token(
    refs: &mut Vec<ExtractedRef>,
    token: &str,
    variables: &BTreeMap<String, String>,
    kind: &str,
    line: &str,
    script_rel: &str,
    entry_rel: Option<&str>,
) {
    let resolved = resolve_token(token, variables);
    if let Some(path) = resolved {
        push_ref(refs, &path, kind, line.to_string(), script_rel, entry_rel);
    }
}

fn resolve_token(token: &str, variables: &BTreeMap<String, String>) -> Option<String> {
    let trimmed = token.trim_matches(|ch| ch == '"' || ch == '\'' || ch == ';');
    if trimmed.starts_with('/') {
        return Some(trimmed.to_string());
    }
    let name = trimmed
        .strip_prefix("${")
        .and_then(|value| value.strip_suffix('}'))
        .or_else(|| trimmed.strip_prefix('$'))?;
    variables
        .get(name)
        .filter(|value| value.starts_with('/'))
        .cloned()
}

fn push_ref(
    refs: &mut Vec<ExtractedRef>,
    binary: &str,
    evidence_kind: &str,
    evidence_value: String,
    script_rel: &str,
    entry_rel: Option<&str>,
) {
    if !binary.starts_with('/') || binary == "/bin/sh" || binary == "/sbin/rc" {
        return;
    }
    let item = ExtractedRef {
        binary: binary.to_string(),
        evidence_kind: evidence_kind.to_string(),
        evidence_value,
        init_script: script_rel.to_string(),
        entry: entry_rel.map(str::to_string),
    };
    if !refs.iter().any(|existing| {
        existing.binary == item.binary
            && existing.evidence_kind == item.evidence_kind
            && existing.evidence_value == item.evidence_value
            && existing.init_script == item.init_script
    }) {
        refs.push(item);
    }
}

fn split_shell_words(line: &str) -> Vec<String> {
    line.split_whitespace()
        .map(|token| token.trim_matches(|ch| ch == '"' || ch == '\'' || ch == ';'))
        .map(str::to_string)
        .collect()
}

fn strip_comment(line: &str) -> &str {
    line.split_once('#')
        .map(|(prefix, _)| prefix)
        .unwrap_or(line)
}

fn is_exec_var(name: &str) -> bool {
    let upper = name.to_ascii_uppercase();
    [
        "_BIN", "_DAEMON", "_EXE", "_EXENAME", "_EXENMAE", "_CMD", "_PROG",
    ]
    .iter()
    .any(|suffix| upper.ends_with(suffix))
        || matches!(upper.as_str(), "BIN" | "DAEMON" | "PROG" | "CMD")
}

fn rootfs_join(rootfs: &Path, rel: &str) -> PathBuf {
    rootfs.join(rel.trim_start_matches('/'))
}

fn rootfs_relative(rootfs: &Path, path: &Path) -> String {
    path.strip_prefix(rootfs)
        .map(|rel| format!("/{}", rel.to_string_lossy().trim_start_matches('/')))
        .unwrap_or_else(|_| path.display().to_string())
}

fn resolve_link_target(rootfs: &Path, link_path: &Path, target: &str) -> PathBuf {
    let target_path = PathBuf::from(target);
    if target_path.is_absolute() {
        rootfs.join(target_path.strip_prefix("/").unwrap_or(&target_path))
    } else {
        normalize_path(link_path.parent().unwrap_or(rootfs).join(target_path))
    }
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn parse_rc_name(name: &str) -> (String, Option<u32>) {
    let phase = match name.chars().next() {
        Some('S') => "start",
        Some('K') => "stop",
        _ => "unknown",
    }
    .to_string();
    let digits = name
        .chars()
        .skip(1)
        .take_while(|ch| ch.is_ascii_digit())
        .collect::<String>();
    let order = digits.parse().ok();
    (phase, order)
}

fn compile_filter(label: &str, pattern: Option<&str>) -> DynResult<Option<Regex>> {
    pattern
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|err| format!("invalid {label} regex {pattern:?}: {err}").into())
        })
        .transpose()
}

fn profile_rule(name: &str) -> DynResult<ProfileRule> {
    PROFILE_RULES
        .iter()
        .copied()
        .find(|rule| rule.name == name)
        .ok_or_else(|| {
            format!(
                "unknown startup-map profile {name:?}; expected one of: cloud-tls, curl, dns, web, update"
            )
            .into()
        })
}

fn command_available(name: &str) -> bool {
    std::env::var_os("PATH")
        .into_iter()
        .flat_map(|paths| std::env::split_paths(&paths).collect::<Vec<_>>())
        .any(|dir| {
            let candidate = dir.join(name);
            candidate.is_file()
        })
}

fn signal_matches(value: &str, signal: &str) -> bool {
    contains_case_insensitive(value, signal)
}

fn contains_case_insensitive(value: &str, needle: &str) -> bool {
    value
        .to_ascii_lowercase()
        .contains(&needle.to_ascii_lowercase())
}

fn best_score(candidate: &StartupCandidate) -> u32 {
    candidate
        .profiles
        .iter()
        .map(|profile| profile.score)
        .max()
        .unwrap_or(0)
}

fn confidence(score: u32) -> &'static str {
    match score {
        80.. => "strong",
        55..=79 => "probable",
        25..=54 => "weak",
        _ => "informational",
    }
}

fn elf_machine(machine: u16) -> Option<&'static str> {
    match machine {
        3 => Some("x86"),
        8 => Some("mips"),
        40 => Some("arm"),
        62 => Some("x86_64"),
        183 => Some("aarch64"),
        _ => None,
    }
}

fn push_unique_evidence(items: &mut Vec<Evidence>, item: Evidence) {
    if !items
        .iter()
        .any(|existing| existing.kind == item.kind && existing.value == item.value)
    {
        items.push(item);
    }
}

#[cfg(test)]
mod tests {
    use super::parse_init_script;

    #[test]
    fn parses_variable_and_service_start_reference() {
        let refs = parse_init_script(
            r#"
            CLOUD_CLIENT_BIN="/bin/cloud-client"
            service_start $CLOUD_CLIENT_BIN
            "#,
            "/etc/init.d/cloud_client",
            Some("/etc/rc.d/S44cloud_client"),
        );

        assert!(refs.iter().any(
            |item| item.binary == "/bin/cloud-client" && item.evidence_kind == "init-variable"
        ));
        assert!(refs
            .iter()
            .any(|item| item.binary == "/bin/cloud-client"
                && item.evidence_kind == "service-start-call"));
    }

    #[test]
    fn ignores_commented_out_start_calls() {
        let refs = parse_init_script(
            r#"
            CLOUD_CLIENT_BIN="/bin/cloud-client"
            # service_start /bin/commented
            /bin/cloud-client &
            "#,
            "/etc/init.d/cloud_client",
            Some("/etc/rc.d/S44cloud_client"),
        );

        assert!(!refs.iter().any(|item| item.binary == "/bin/commented"));
        assert!(refs.iter().any(|item| item.binary == "/bin/cloud-client"));
    }
}
