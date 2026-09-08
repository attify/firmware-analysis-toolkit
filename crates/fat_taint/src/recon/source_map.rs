use regex::Regex;
use serde::Serialize;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use crate::profile::SourceHintModel;

#[derive(Debug, Serialize)]
pub struct SourceMapReport {
    pub rootfs_path: String,
    /// Model selection supplied by the caller; absent when its origin is unknown.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model_provenance: Option<crate::profile::CatalogProvenance>,
    pub frontend_surfaces: Vec<FrontendSurface>,
    pub backend_candidates: Vec<BackendCandidate>,
}

#[derive(Debug, Serialize, Clone)]
pub struct FrontendSurface {
    pub path: String,
    pub kind: String,
    pub endpoint: String,
    pub methods: Vec<String>,
    pub parameters: Vec<SourceMapParameter>,
}

#[derive(Debug, Serialize, Clone)]
pub struct SourceMapParameter {
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraint: Option<ParameterConstraint>,
}

#[derive(Debug, Serialize, Clone)]
pub struct ParameterConstraint {
    pub kind: String,
    pub value: u64,
}

#[derive(Debug, Serialize, Clone)]
pub struct BackendCandidate {
    pub path: String,
    pub matched_terms: Vec<String>,
    pub source_hints: Vec<SourceHint>,
    pub exact_matches: usize,
    pub fuzzy_matches: usize,
    pub score: usize,
}

#[derive(Debug, Serialize, Clone)]
pub struct SourceHint {
    pub function: String,
    pub taint_kind: String,
}

/// Rank backend binaries against the frontend surfaces found under `rootfs`.
///
/// `source_hints` are the symbols whose presence in a binary's strings is worth
/// reporting as a possible taint source. FAT compiles in only the specified
/// ones ([`crate::profile::core_source_hints`]); anything platform-specific
/// arrives here from an operator-selected profile. A hint is a name that was
/// observed, never a proven dataflow.
pub fn analyze_rootfs(
    rootfs: &Path,
    source_hints: &[SourceHintModel],
) -> Result<SourceMapReport, String> {
    if !rootfs.is_dir() {
        return Err(format!(
            "rootfs path is not a directory: {}",
            rootfs.display()
        ));
    }

    let mut frontend_surfaces = Vec::new();
    let mut backend_candidates = Vec::new();
    let mut terms = BTreeSet::new();

    let entries = walkdir::WalkDir::new(rootfs)
        .follow_links(false)
        .into_iter()
        .filter_map(|entry| entry.ok())
        .collect::<Vec<_>>();

    for entry in &entries {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        if is_frontend_file(path) {
            let mut surfaces = parse_frontend_file(path, rootfs);
            for surface in &surfaces {
                for term in surface_terms(surface) {
                    terms.insert(term);
                }
            }
            frontend_surfaces.append(&mut surfaces);
        }
    }

    let collected_terms: Vec<String> = terms.into_iter().collect();
    for entry in &entries {
        let path = entry.path();
        if !path.is_file() || is_frontend_file(path) {
            continue;
        }
        if let Some(candidate) =
            score_backend_candidate(path, rootfs, &collected_terms, source_hints)
        {
            backend_candidates.push(candidate);
        }
    }

    frontend_surfaces.sort_by(|a, b| a.path.cmp(&b.path).then(a.endpoint.cmp(&b.endpoint)));
    backend_candidates.sort_by(|a, b| b.score.cmp(&a.score).then(a.path.cmp(&b.path)));

    Ok(SourceMapReport {
        rootfs_path: rootfs.display().to_string(),
        model_provenance: None,
        frontend_surfaces,
        backend_candidates,
    })
}

fn is_frontend_file(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|ext| ext.to_str()).map(|s| s.to_ascii_lowercase()),
        Some(ext) if matches!(ext.as_str(), "html" | "htm" | "js" | "xml")
    )
}

fn parse_frontend_file(path: &Path, rootfs: &Path) -> Vec<FrontendSurface> {
    let Ok(contents) = std::fs::read_to_string(path) else {
        return Vec::new();
    };

    match path
        .extension()
        .and_then(|ext| ext.to_str())
        .map(|s| s.to_ascii_lowercase())
        .as_deref()
    {
        Some("html") | Some("htm") => parse_html_surfaces(&contents, path, rootfs),
        Some("js") => parse_js_surfaces(&contents, path, rootfs),
        Some("xml") => parse_xml_surfaces(&contents, path, rootfs),
        _ => Vec::new(),
    }
}

fn parse_html_surfaces(contents: &str, path: &Path, rootfs: &Path) -> Vec<FrontendSurface> {
    let form_re = Regex::new(
        r#"(?is)<form[^>]*action="([^"]+)"[^>]*?(?:method="([^"]+)")?[^>]*>(.*?)</form>"#,
    )
    .expect("form regex");
    let input_re =
        Regex::new(r#"(?is)<input[^>]*(?:name|id)="([^"]+)"[^>]*>"#).expect("input regex");
    let maxlength_re = Regex::new(r#"(?is)<input[^>]*(?:name|id)="([^"]+)"[^>]*maxlength="(\d+)""#)
        .expect("maxlength regex");

    let mut surfaces = Vec::new();
    for caps in form_re.captures_iter(contents) {
        let endpoint = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let method = caps
            .get(2)
            .map(|m| m.as_str().to_ascii_uppercase())
            .unwrap_or_else(|| "GET".to_string());
        let body = caps.get(3).map(|m| m.as_str()).unwrap_or_default();

        let mut params = Vec::new();
        let mut seen = BTreeSet::new();
        for input in input_re.captures_iter(body) {
            let name = input
                .get(1)
                .map(|m| m.as_str().to_string())
                .unwrap_or_default();
            if !seen.insert(name.clone()) {
                continue;
            }
            let constraint = maxlength_re.captures(body).and_then(|cap| {
                let constrained_name = cap.get(1)?.as_str();
                if constrained_name != name {
                    return None;
                }
                let value = cap.get(2)?.as_str().parse::<u64>().ok()?;
                Some(ParameterConstraint {
                    kind: "max_length".into(),
                    value,
                })
            });
            params.push(SourceMapParameter { name, constraint });
        }

        surfaces.push(FrontendSurface {
            path: relative_display(path, rootfs),
            kind: "html-form".into(),
            endpoint,
            methods: vec![method],
            parameters: params,
        });
    }
    surfaces
}

fn parse_js_surfaces(contents: &str, path: &Path, rootfs: &Path) -> Vec<FrontendSurface> {
    let endpoint_re =
        Regex::new(r#"["']([^"']+\.(?:cgi|xml))(?:\?([^"']+))?["']"#).expect("js endpoint regex");
    let mut surfaces = Vec::new();
    for caps in endpoint_re.captures_iter(contents) {
        let endpoint = caps
            .get(1)
            .map(|m| m.as_str().to_string())
            .unwrap_or_default();
        let query = caps.get(2).map(|m| m.as_str()).unwrap_or_default();
        let mut params = Vec::new();
        for pair in query.split('&') {
            let mut parts = pair.splitn(2, '=');
            let key = parts.next().unwrap_or_default().trim();
            let value = parts.next().unwrap_or_default().trim();
            if key.is_empty() {
                continue;
            }
            params.push(SourceMapParameter {
                name: if value.is_empty() {
                    key.to_string()
                } else {
                    value.to_string()
                },
                constraint: None,
            });
        }
        surfaces.push(FrontendSurface {
            path: relative_display(path, rootfs),
            kind: "js-endpoint".into(),
            endpoint,
            methods: vec!["GET".into()],
            parameters: params,
        });
    }
    surfaces
}

fn parse_xml_surfaces(contents: &str, path: &Path, rootfs: &Path) -> Vec<FrontendSurface> {
    let control_url_re =
        Regex::new(r#"(?is)<controlURL>\s*([^<]+?)\s*</controlURL>"#).expect("xml controlURL");
    let action_re =
        Regex::new(r#"(?is)<action>\s*<name>\s*([A-Za-z0-9_:-]+)\s*</name>\s*</action>"#)
            .expect("xml action regex");
    let mut actions = BTreeSet::new();
    for caps in action_re.captures_iter(contents) {
        if let Some(m) = caps.get(1) {
            actions.insert(m.as_str().to_string());
        }
    }
    if actions.is_empty() {
        return Vec::new();
    }
    let endpoint = control_url_re
        .captures(contents)
        .and_then(|caps| caps.get(1))
        .map(|value| value.as_str().trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| relative_display(path, rootfs));

    vec![FrontendSurface {
        path: relative_display(path, rootfs),
        kind: "xml-action".into(),
        endpoint,
        methods: vec!["POST".into()],
        parameters: actions
            .into_iter()
            .map(|name| SourceMapParameter {
                name,
                constraint: None,
            })
            .collect(),
    }]
}

fn score_backend_candidate(
    path: &Path,
    rootfs: &Path,
    terms: &[String],
    source_hints: &[SourceHintModel],
) -> Option<BackendCandidate> {
    if terms.is_empty() {
        return None;
    }
    let bytes = std::fs::read(path).ok()?;
    let strings = printable_strings(&bytes);
    if strings.is_empty() {
        return None;
    }
    let haystack = strings.join("\n").to_ascii_lowercase();

    let mut matched = BTreeSet::new();
    let mut exact_matches = 0usize;
    let mut fuzzy_matches = 0usize;
    for term in terms {
        if term.len() < 3 {
            continue;
        }
        let normalized = term.to_ascii_lowercase();
        if haystack.contains(&normalized) {
            matched.insert(term.clone());
            exact_matches += 1;
            continue;
        }

        if strings
            .iter()
            .any(|candidate| similarity(candidate, term) >= 0.82)
        {
            matched.insert(term.clone());
            fuzzy_matches += 1;
        }
    }

    if matched.is_empty() {
        return None;
    }

    Some(BackendCandidate {
        path: relative_display(path, rootfs),
        matched_terms: matched.into_iter().collect(),
        source_hints: detect_source_hints(&strings, source_hints),
        exact_matches,
        fuzzy_matches,
        score: (exact_matches * 2) + fuzzy_matches,
    })
}

fn detect_source_hints(strings: &[String], models: &[SourceHintModel]) -> Vec<SourceHint> {
    let mut hints = Vec::new();
    let mut seen = BTreeSet::new();
    for model in models {
        if strings
            .iter()
            .any(|value| value.contains(model.function.as_str()))
            && seen.insert(model.function.clone())
        {
            hints.push(SourceHint {
                function: model.function.clone(),
                taint_kind: model.taint_kind.clone(),
            });
        }
    }
    hints
}

fn printable_strings(bytes: &[u8]) -> Vec<String> {
    let mut current = Vec::new();
    let mut out = Vec::new();
    for byte in bytes {
        if byte.is_ascii_graphic() || *byte == b' ' {
            current.push(*byte);
        } else {
            if current.len() >= 3 {
                out.push(String::from_utf8_lossy(&current).trim().to_string());
            }
            current.clear();
        }
    }
    if current.len() >= 3 {
        out.push(String::from_utf8_lossy(&current).trim().to_string());
    }
    out.sort();
    out.dedup();
    out
}

fn relative_display(path: &Path, rootfs: &Path) -> String {
    path.strip_prefix(rootfs)
        .map(|rel| format!("/{}", rel.display()))
        .unwrap_or_else(|_| path.display().to_string())
}

fn surface_terms(surface: &FrontendSurface) -> Vec<String> {
    let mut terms = Vec::new();
    let endpoint_name = PathBuf::from(surface.endpoint.trim_start_matches('/'))
        .file_name()
        .and_then(|name| name.to_str())
        .map(|name| name.to_string());
    if let Some(name) = endpoint_name {
        terms.push(name);
    }
    for param in &surface.parameters {
        if !param.name.is_empty() {
            terms.push(param.name.clone());
        }
    }
    terms
}

fn similarity(left: &str, right: &str) -> f64 {
    let left = left.to_ascii_lowercase();
    let right = right.to_ascii_lowercase();
    if left == right {
        return 1.0;
    }
    let lcs = longest_common_subsequence(&left, &right) as f64;
    let denom = left.len().min(right.len()) as f64;
    if denom == 0.0 {
        return 0.0;
    }
    lcs / denom
}

fn longest_common_subsequence(left: &str, right: &str) -> usize {
    let left = left.as_bytes();
    let right = right.as_bytes();
    let mut dp = vec![vec![0usize; right.len() + 1]; left.len() + 1];
    for (i, left_byte) in left.iter().enumerate() {
        for (j, right_byte) in right.iter().enumerate() {
            dp[i + 1][j + 1] = if left_byte == right_byte {
                dp[i][j] + 1
            } else {
                dp[i + 1][j].max(dp[i][j + 1])
            };
        }
    }
    dp[left.len()][right.len()]
}
