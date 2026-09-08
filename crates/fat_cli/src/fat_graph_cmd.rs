use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Command;

use fat_taint::recon::trust_boundary::{analyze_rootfs, check_rabin2, Evidence};
use serde::Serialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::trust_boundary_cmd::{build_trust_map_json_report, TrustMapCandidateJson};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum GraphOutput {
    Json,
}

#[derive(Debug, Serialize, Clone)]
pub(crate) struct EvidenceGraph {
    pub schema_version: &'static str,
    pub repo_id: &'static str,
    pub nodes: Vec<Value>,
    pub edges: Vec<Value>,
}

#[derive(Debug, Clone)]
struct FileView {
    path: String,
    kind: String,
    confidence: f64,
    labels: Vec<String>,
    why: Vec<String>,
    negative: Vec<String>,
}

#[derive(Debug, Default)]
struct GraphBuilder {
    nodes: Vec<Value>,
    edges: Vec<Value>,
    node_ids: BTreeSet<String>,
    edge_ids: BTreeSet<String>,
    files: BTreeMap<String, FileView>,
    rollups: BTreeMap<String, BTreeMap<String, usize>>,
}

impl GraphBuilder {
    fn add_node(&mut self, id: &str, node: Value) {
        if self.node_ids.insert(id.to_string()) {
            self.nodes.push(node);
        }
    }

    fn add_edge(&mut self, edge_type: &str, from: &str, to: &str, props: Option<Value>) {
        let key = format!("{edge_type}\0{from}\0{to}\0{}", props_key(props.as_ref()));
        if !self.edge_ids.insert(key) {
            return;
        }
        let mut edge = json!({
            "type": edge_type,
            "from": from,
            "to": to,
        });
        if let Some(props) = props {
            edge["props"] = props;
        }
        self.edges.push(edge);
    }

    fn add_file(
        &mut self,
        path: &str,
        confidence: f64,
        labels: &[String],
        why: &[String],
        negative: &[String],
    ) {
        let file_id = file_id(path);
        let dir = parent_dir(path);
        let dir_id = dir_id(&dir);

        self.add_node(
            &dir_id,
            json!({
                "type": "Directory",
                "id": dir_id,
                "key": dir_id,
                "path": dir,
            }),
        );
        self.add_node(
            &file_id,
            json!({
                "type": "File",
                "id": file_id,
                "key": file_id,
                "path": path,
                "file_kind": "elf",
            }),
        );
        self.add_edge("CONTAINS", &dir_id, &file_id, None);

        let view = self
            .files
            .entry(path.to_string())
            .or_insert_with(|| FileView {
                path: path.to_string(),
                kind: "ELF".into(),
                confidence,
                labels: Vec::new(),
                why: Vec::new(),
                negative: Vec::new(),
            });
        view.confidence = view.confidence.max(confidence);
        merge_unique(&mut view.labels, labels.iter().cloned());
        merge_unique(&mut view.why, why.iter().cloned());
        merge_unique(&mut view.negative, negative.iter().cloned());

        let rollup = self.rollups.entry(dir).or_default();
        for label in labels {
            *rollup.entry(label.clone()).or_insert(0) += 1;
        }
    }

    fn finish(self) -> EvidenceGraph {
        self.finish_with_repo_id("fat-update-authority")
    }

    fn finish_inventory(self) -> EvidenceGraph {
        self.finish_with_repo_id("fat-inventory")
    }

    fn finish_with_repo_id(mut self, repo_id: &'static str) -> EvidenceGraph {
        let rollups = self.rollups.clone();
        for (dir, counts) in rollups {
            let rollup_id = format!("rollup:{dir}");
            let dir_id = dir_id(&dir);
            self.add_node(
                &rollup_id,
                json!({
                    "type": "LabelRollup",
                    "id": rollup_id,
                    "key": rollup_id,
                    "summary": render_rollup_counts(&counts),
                    "counts": counts,
                }),
            );
            self.add_edge("HAS_LABEL_ROLLUP", &dir_id, &rollup_id, None);
        }

        self.nodes.sort_by_key(value_id);
        self.edges.sort_by(|a, b| {
            (
                value_str(a, "from"),
                value_str(a, "type"),
                value_str(a, "to"),
            )
                .cmp(&(
                    value_str(b, "from"),
                    value_str(b, "type"),
                    value_str(b, "to"),
                ))
        });

        EvidenceGraph {
            schema_version: "0.1",
            repo_id,
            nodes: self.nodes,
            edges: self.edges,
        }
    }
}

pub(crate) fn render_graph_export(
    rootfs: &Path,
    profile: &str,
    format: GraphOutput,
) -> DynResult<String> {
    let graph = build_profile_graph(rootfs, profile)?;
    match format {
        GraphOutput::Json => Ok(serde_json::to_string_pretty(&graph)?),
    }
}

pub(crate) fn write_graph_export(
    rootfs: &Path,
    profile: &str,
    format: GraphOutput,
    output: &Path,
) -> DynResult<()> {
    let rendered = render_graph_export(rootfs, profile, format)?;
    if let Some(parent) = output.parent() {
        if !parent.as_os_str().is_empty() {
            fs::create_dir_all(parent)?;
        }
    }
    fs::write(output, rendered)?;
    Ok(())
}

pub(crate) fn run_graph_export(
    rootfs: &Path,
    profile: &str,
    format: GraphOutput,
    output: Option<&Path>,
) -> DynResult<()> {
    match output {
        Some(path) => write_graph_export(rootfs, profile, format, path)?,
        None => println!("{}", render_graph_export(rootfs, profile, format)?),
    }
    Ok(())
}

pub(crate) fn run_label_scan(
    rootfs: &Path,
    profile: &str,
    emit: GraphOutput,
    output: Option<&Path>,
) -> DynResult<()> {
    run_graph_export(rootfs, profile, emit, output)
}

pub(crate) fn run_ls(rootfs: &Path, profile: &str, tags: bool, json: bool) -> DynResult<()> {
    if profile != "inventory" && !tags {
        return Err("fat ls currently requires --tags".into());
    }
    let views = build_file_views_for_profile(rootfs, profile)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&json_ls(&views))?);
    } else {
        render_ls(&views);
    }
    Ok(())
}

pub(crate) fn run_tree(
    rootfs: &Path,
    profile: &str,
    tags: bool,
    summary: bool,
    json: bool,
) -> DynResult<()> {
    if profile != "inventory" && (!tags || !summary) {
        return Err("fat tree currently requires --tags --summary".into());
    }
    if !summary {
        return Err("fat tree currently requires --summary".into());
    }
    let views = build_file_views_for_profile(rootfs, profile)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&json_tree(&views))?);
    } else {
        render_tree(&views);
    }
    Ok(())
}

pub(crate) fn run_labels_explain(
    rootfs: &Path,
    profile: &str,
    path: &str,
    json: bool,
) -> DynResult<()> {
    ensure_update_authority(profile)?;
    let normalized = normalize_firmware_path(path);
    let views = build_file_views(rootfs)?;
    let Some(view) = views.iter().find(|view| view.path == normalized) else {
        return Err(format!("no labels found for {normalized}").into());
    };
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&json_file_view(view, true))?
        );
    } else {
        render_explain(view);
    }
    Ok(())
}

pub(crate) fn parse_graph_output(raw: &str) -> Result<GraphOutput, String> {
    match raw {
        "json" => Ok(GraphOutput::Json),
        other => Err(format!("unsupported graph format {other:?}; expected json")),
    }
}

fn build_update_authority_graph(rootfs: &Path) -> DynResult<EvidenceGraph> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }
    check_rabin2().map_err(|e| -> Box<dyn Error> { e.into() })?;
    let report = analyze_rootfs(rootfs).map_err(|e| -> Box<dyn Error> { e.into() })?;
    let trust_map = build_trust_map_json_report(&report);

    let mut builder = GraphBuilder::default();
    add_standard_tags(&mut builder);

    for candidate in trust_map.candidates {
        add_candidate(&mut builder, &candidate);
    }

    Ok(builder.finish())
}

fn build_profile_graph(rootfs: &Path, profile: &str) -> DynResult<EvidenceGraph> {
    match profile {
        "inventory" => build_inventory_graph(rootfs),
        "update-authority" => build_update_authority_graph(rootfs),
        other => Err(format!(
            "unsupported profile {other:?}; expected inventory or update-authority"
        )
        .into()),
    }
}

fn build_inventory_graph(rootfs: &Path) -> DynResult<EvidenceGraph> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }

    let mut builder = GraphBuilder::default();
    builder.add_node(
        "dir:/",
        json!({
            "type": "Directory",
            "id": "dir:/",
            "key": "dir:/",
            "path": "/",
        }),
    );

    for entry in WalkDir::new(rootfs).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        let path = entry.path();
        if path == rootfs {
            continue;
        }
        let rel = match path.strip_prefix(rootfs) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let fw_path = normalize_firmware_path(&rel.to_string_lossy());
        let parent = parent_dir(&fw_path);
        let parent_id = dir_id(&parent);

        if entry.file_type().is_dir() {
            let id = dir_id(&fw_path);
            builder.add_node(
                &id,
                json!({
                    "type": "Directory",
                    "id": id,
                    "key": id,
                    "path": fw_path,
                }),
            );
            builder.add_edge("CONTAINS", &parent_id, &id, None);
            continue;
        }

        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
            continue;
        }

        if parent != "/" {
            builder.add_node(
                &parent_id,
                json!({
                    "type": "Directory",
                    "id": parent_id,
                    "key": parent_id,
                    "path": parent,
                }),
            );
        }

        let file_kind = classify_file(path, entry.file_type().is_symlink());
        let id = file_id(&fw_path);
        let sha256 = if entry.file_type().is_file() {
            sha256_file(path).ok()
        } else {
            None
        };
        builder.add_node(
            &id,
            json!({
                "type": "File",
                "id": id,
                "key": id,
                "path": fw_path,
                "file_kind": file_kind,
                "sha256": sha256,
            }),
        );
        builder.add_edge("CONTAINS", &parent_id, &id, None);

        if file_kind == "elf" {
            add_inventory_symbols(&mut builder, path, &fw_path);
        }
    }

    Ok(builder.finish_inventory())
}

fn add_inventory_symbols(builder: &mut GraphBuilder, host_path: &Path, firmware_path: &str) {
    for (mode, edge_type, kind, tier) in [
        ("-ij", "IMPORTS_SYMBOL", "import", "elf-import"),
        ("-Ej", "EXPORTS_SYMBOL", "export", "elf-export"),
    ] {
        let Ok(output) = Command::new("rabin2").arg(mode).arg(host_path).output() else {
            continue;
        };
        if !output.status.success() {
            continue;
        }
        let Ok(value) = serde_json::from_slice::<Value>(&output.stdout) else {
            continue;
        };
        let key = if mode == "-ij" { "imports" } else { "exports" };
        let Some(items) = value.get(key).and_then(|v| v.as_array()) else {
            continue;
        };
        for item in items {
            let Some(name) = item.get("name").and_then(|v| v.as_str()) else {
                continue;
            };
            if name.is_empty() {
                continue;
            }
            let sid = symbol_id(name);
            builder.add_node(
                &sid,
                json!({
                    "type": "Symbol",
                    "id": sid,
                    "key": sid,
                    "name": name,
                    "kind": kind,
                }),
            );
            builder.add_edge(
                edge_type,
                &file_id(firmware_path),
                &sid,
                Some(json!({
                    "source_tool": "rabin2",
                    "evidence_tier": tier,
                    "confidence": 1.0,
                    "artifact_path": firmware_path,
                })),
            );
        }
    }
}

fn classify_file(path: &Path, is_symlink: bool) -> &'static str {
    if is_symlink {
        return "symlink";
    }
    let mut buf = [0u8; 4];
    if let Ok(mut file) = fs::File::open(path) {
        if let Ok(n) = file.read(&mut buf) {
            if n >= 4 && buf == [0x7f, b'E', b'L', b'F'] {
                return "elf";
            }
            if n >= 2 && &buf[..2] == b"#!" {
                return "script";
            }
        }
    }
    let ext = path
        .extension()
        .and_then(|e| e.to_str())
        .unwrap_or_default()
        .to_ascii_lowercase();
    match ext.as_str() {
        "conf" | "cfg" | "ini" | "json" | "xml" | "yaml" | "yml" => "config",
        "sh" | "lua" | "py" | "pl" | "js" => "script",
        "so" => "elf",
        _ => "file",
    }
}

fn sha256_file(path: &Path) -> DynResult<String> {
    let mut file = fs::File::open(path)?;
    let mut hasher = Sha256::new();
    let mut buf = [0u8; 8192];
    loop {
        let n = file.read(&mut buf)?;
        if n == 0 {
            break;
        }
        hasher.update(&buf[..n]);
    }
    Ok(format!("{:x}", hasher.finalize()))
}

fn build_file_views_for_profile(rootfs: &Path, profile: &str) -> DynResult<Vec<FileView>> {
    match profile {
        "inventory" => build_inventory_file_views(rootfs),
        "update-authority" => build_file_views(rootfs),
        other => Err(format!(
            "unsupported profile {other:?}; expected inventory or update-authority"
        )
        .into()),
    }
}

fn build_inventory_file_views(rootfs: &Path) -> DynResult<Vec<FileView>> {
    if !rootfs.is_dir() {
        return Err(format!("rootfs path is not a directory: {}", rootfs.display()).into());
    }

    let mut views = vec![];
    for entry in WalkDir::new(rootfs).follow_links(false).sort_by_file_name() {
        let entry = entry?;
        if !entry.file_type().is_file() && !entry.file_type().is_symlink() {
            continue;
        }
        let rel = match entry.path().strip_prefix(rootfs) {
            Ok(rel) => rel,
            Err(_) => continue,
        };
        let path = normalize_firmware_path(&rel.to_string_lossy());
        let kind = classify_file(entry.path(), entry.file_type().is_symlink());
        views.push(FileView {
            path,
            kind: display_kind(kind).to_string(),
            confidence: 1.0,
            labels: vec![],
            why: vec![],
            negative: vec![],
        });
    }
    Ok(views)
}

fn build_file_views(rootfs: &Path) -> DynResult<Vec<FileView>> {
    let graph = build_update_authority_graph(rootfs)?;
    let mut views: BTreeMap<String, FileView> = BTreeMap::new();
    let mut labels_by_assignment: BTreeMap<String, String> = BTreeMap::new();
    let mut assignment_to_file: BTreeMap<String, String> = BTreeMap::new();

    for edge in &graph.edges {
        match value_str(edge, "type").as_str() {
            "HAS_LABEL_ASSIGNMENT" => {
                assignment_to_file.insert(value_str(edge, "to"), value_str(edge, "from"));
            }
            "APPLIES_TAG" => {
                labels_by_assignment.insert(value_str(edge, "from"), value_str(edge, "to"));
            }
            _ => {}
        }
    }

    let node_by_id: BTreeMap<String, &Value> = graph
        .nodes
        .iter()
        .map(|node| (value_id(node), node))
        .collect();

    for (assignment, file_id) in assignment_to_file {
        let Some(file_node) = node_by_id.get(&file_id) else {
            continue;
        };
        let path = value_str(file_node, "path");
        let Some(label_node_id) = labels_by_assignment.get(&assignment) else {
            continue;
        };
        let Some(tag_node) = node_by_id.get(label_node_id) else {
            continue;
        };
        let Some(label_assignment) = node_by_id.get(&assignment) else {
            continue;
        };
        let label = value_str(tag_node, "name");
        let confidence = label_assignment
            .get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(0.0);
        let reason = value_str(label_assignment, "reason");
        let view = views.entry(path.clone()).or_insert_with(|| FileView {
            path: path.clone(),
            kind: "ELF".into(),
            confidence,
            labels: Vec::new(),
            why: Vec::new(),
            negative: Vec::new(),
        });
        view.confidence = view.confidence.max(confidence);
        if !view.labels.contains(&label) {
            view.labels.push(label);
        }
        if !reason.is_empty() && !view.why.contains(&reason) {
            view.why.push(reason);
        }
    }

    for edge in &graph.edges {
        if value_str(edge, "type") != "DEMOTED_BY" {
            continue;
        }
        let file_id = value_str(edge, "from");
        let neg_id = value_str(edge, "to");
        let Some(file_node) = node_by_id.get(&file_id) else {
            continue;
        };
        let Some(neg_node) = node_by_id.get(&neg_id) else {
            continue;
        };
        let path = value_str(file_node, "path");
        let reason = value_str(neg_node, "reason");
        let view = views.entry(path.clone()).or_insert_with(|| FileView {
            path: path.clone(),
            kind: "ELF".into(),
            confidence: 0.0,
            labels: Vec::new(),
            why: Vec::new(),
            negative: Vec::new(),
        });
        if !reason.is_empty() && !view.negative.contains(&reason) {
            view.negative.push(reason);
        }
    }

    Ok(views.into_values().collect())
}

fn add_candidate(builder: &mut GraphBuilder, candidate: &TrustMapCandidateJson) {
    let path = normalize_firmware_path(&candidate.path);
    let file_id = file_id(&path);
    let labels = labels_for_candidate(candidate);
    let why = candidate.why.clone();

    builder.add_file(
        &path,
        candidate.score,
        &labels,
        &candidate.why,
        &candidate.negative_evidence,
    );

    for label in &labels {
        let assignment_id = label_assignment_id(&path, label);
        builder.add_node(
            &assignment_id,
            json!({
                "type": "LabelAssignment",
                "id": assignment_id,
                "key": assignment_id,
                "label": label,
                "mode": "machine",
                "status": "active",
                "confidence": candidate.score,
                "reason": why.first().cloned().unwrap_or_else(|| candidate.candidate_classification.clone()),
            }),
        );
        builder.add_edge("HAS_LABEL_ASSIGNMENT", &file_id, &assignment_id, None);
        builder.add_edge("APPLIES_TAG", &assignment_id, &tag_id(label), None);
        for evidence in &candidate.evidence {
            let evidence_id = evidence_id(&path, evidence);
            builder.add_edge("SUPPORTED_BY", &assignment_id, &evidence_id, None);
        }
    }

    if labels.iter().any(|label| label == "role:update-candidate") {
        let update_id = format!("ua:candidate:{path}");
        builder.add_node(
            &update_id,
            json!({
                "type": "UpdateCandidate",
                "id": update_id,
                "key": update_id,
                "candidate_path": path,
                "score": candidate.score,
                "status": "candidate",
                "summary": candidate.why.first().cloned().unwrap_or_else(|| "candidate update-authority path".into()),
            }),
        );
        for evidence in &candidate.evidence {
            let evidence_id = evidence_id(&path, evidence);
            builder.add_edge("SUPPORTED_BY", &update_id, &evidence_id, None);
        }
        add_update_authority_decision_model(builder, candidate, &path, &update_id);
    }

    for evidence in &candidate.evidence {
        add_evidence(builder, &path, evidence);
    }

    for reason in &candidate.negative_evidence {
        let neg_id = negative_id(&path, reason);
        builder.add_node(
            &neg_id,
            json!({
                "type": "NegativeEvidence",
                "id": neg_id,
                "key": neg_id,
                "reason": reason,
                "confidence": candidate.score,
            }),
        );
        builder.add_edge("DEMOTED_BY", &file_id, &neg_id, None);
    }
}

fn add_update_authority_decision_model(
    builder: &mut GraphBuilder,
    candidate: &TrustMapCandidateJson,
    path: &str,
    update_id: &str,
) {
    let provider_id = format!("ua:provider:{path}");
    builder.add_node(
        &provider_id,
        json!({
            "type": "DecisionProvider",
            "id": provider_id,
            "key": provider_id,
            "path": path,
            "status": "candidate",
        }),
    );

    if let Some(interface_evidence) = select_decision_interface_evidence(&candidate.evidence) {
        if let Some(symbol) = evidence_symbol(interface_evidence) {
            let interface_id = format!("ua:interface:{symbol}");
            builder.add_node(
                &interface_id,
                json!({
                    "type": "DecisionInterface",
                    "id": interface_id,
                    "key": interface_id,
                    "kind": decision_interface_kind(&symbol, &interface_evidence.kind),
                    "name": symbol,
                }),
            );
            builder.add_edge("USES_DECISION_INTERFACE", update_id, &interface_id, None);
            builder.add_edge("RESOLVES_TO_PROVIDER", &interface_id, &provider_id, None);
        } else {
            builder.add_edge("RESOLVES_TO_PROVIDER", update_id, &provider_id, None);
        }
    } else {
        builder.add_edge("RESOLVES_TO_PROVIDER", update_id, &provider_id, None);
    }

    let verdict_id = format!("ua:verdict:{path}");
    builder.add_node(
        &verdict_id,
        json!({
            "type": "AuthorityVerdict",
            "id": verdict_id,
            "key": verdict_id,
            "verdict": "static-candidate-runtime-unproven",
            "confidence": candidate.score,
            "summary": candidate.why.first().cloned().unwrap_or_else(|| "static update-authority candidate".into()),
            "proof_boundary": "Static filesystem, symbol, and string evidence can identify likely decision owners, but does not prove runtime package acceptance.",
        }),
    );
    builder.add_edge("HAS_AUTHORITY_VERDICT", update_id, &verdict_id, None);
    for evidence in &candidate.evidence {
        let evidence_id = evidence_id(path, evidence);
        builder.add_edge("SUPPORTED_BY", &verdict_id, &evidence_id, None);
    }
}

fn select_decision_interface_evidence(evidence: &[Evidence]) -> Option<&Evidence> {
    evidence
        .iter()
        .filter(|e| evidence_symbol(e).is_some())
        .max_by_key(|e| {
            (
                decision_symbol_rank(&evidence_symbol(e).unwrap_or_default()),
                strength_rank(&e.strength),
            )
        })
}

fn decision_symbol_rank(symbol: &str) -> u8 {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("verify")
        || lower.contains("sign")
        || lower.contains("signature")
        || lower.contains("rsa")
    {
        3
    } else if lower.contains("sha") || lower.contains("hash") || lower.contains("digest") {
        2
    } else if lower.contains("aes") || lower.contains("decrypt") || lower.contains("crypto") {
        1
    } else {
        0
    }
}

fn strength_rank(strength: &str) -> u8 {
    match strength {
        "strong" => 3,
        "medium" => 2,
        "weak" => 1,
        _ => 0,
    }
}

fn decision_interface_kind(symbol: &str, evidence_kind: &str) -> String {
    let lower = symbol.to_ascii_lowercase();
    if lower.contains("verify") || lower.contains("sign") || lower.contains("signature") {
        "verifier-symbol".to_string()
    } else if lower.contains("sha") || lower.contains("hash") || lower.contains("digest") {
        "digest-symbol".to_string()
    } else if lower.contains("aes") || lower.contains("decrypt") || lower.contains("crypto") {
        "crypto-symbol".to_string()
    } else {
        format!("{evidence_kind}-symbol")
    }
}

fn add_evidence(builder: &mut GraphBuilder, path: &str, evidence: &Evidence) {
    let evidence_id = evidence_id(path, evidence);
    builder.add_node(
        &evidence_id,
        json!({
            "type": "Evidence",
            "id": evidence_id,
            "key": evidence_id,
            "kind": evidence.kind,
            "title": evidence.detail,
            "summary": evidence.detail,
            "confidence": strength_confidence(&evidence.strength),
        }),
    );

    if let Some(symbol) = evidence_symbol(evidence) {
        let symbol_id = symbol_id(&symbol);
        builder.add_node(
            &symbol_id,
            json!({
                "type": "Symbol",
                "id": symbol_id,
                "key": symbol_id,
                "name": symbol,
                "kind": evidence.kind,
            }),
        );
        let edge_type = if evidence.kind == "export" {
            "EXPORTS_SYMBOL"
        } else {
            "IMPORTS_SYMBOL"
        };
        builder.add_edge(
            edge_type,
            &file_id(path),
            &symbol_id,
            Some(json!({
                "source_tool": "rabin2",
                "evidence_tier": evidence.tier,
                "confidence": strength_confidence(&evidence.strength),
                "artifact_path": path,
            })),
        );
    }
}

fn add_standard_tags(builder: &mut GraphBuilder) {
    for (name, description) in [
        (
            "role:update-candidate",
            "File belongs in the update-authority candidate set.",
        ),
        (
            "role:decision-provider-candidate",
            "File may provide update acceptance decision behavior.",
        ),
        (
            "role:crypto-provider",
            "File provides cryptographic helper behavior.",
        ),
        (
            "role:helper-only",
            "File has helper evidence without direct update ownership.",
        ),
        (
            "role:supporting-boundary",
            "File is a supporting trust-boundary component.",
        ),
    ] {
        let id = tag_id(name);
        let namespace = name.split(':').next().unwrap_or("role");
        builder.add_node(
            &id,
            json!({
                "type": "Tag",
                "id": id,
                "key": id,
                "name": name,
                "namespace": namespace,
                "description": description,
            }),
        );
    }
}

fn labels_for_candidate(candidate: &TrustMapCandidateJson) -> Vec<String> {
    let mut labels = Vec::new();
    let lower_path = candidate.path.to_ascii_lowercase();
    let lower_role = candidate.candidate_role.to_ascii_lowercase();

    if candidate.candidate_classification == "governing-updater"
        || lower_role.contains("firmware")
        || lower_path.contains("upgrade")
        || lower_path.contains("update")
    {
        labels.push("role:update-candidate".to_string());
    }
    if candidate.candidate_classification == "governing-updater"
        || candidate.candidate_classification == "supporting-boundary"
    {
        labels.push("role:decision-provider-candidate".to_string());
    }
    if candidate.candidate_classification.contains("crypto")
        || candidate.candidate_classification == "helper-only"
        || lower_role.contains("crypto")
    {
        labels.push("role:crypto-provider".to_string());
    }
    if candidate.candidate_classification == "helper-only" {
        labels.push("role:helper-only".to_string());
    }
    if candidate.candidate_classification == "supporting-boundary" {
        labels.push("role:supporting-boundary".to_string());
    }

    labels.sort();
    labels.dedup();
    labels
}

fn render_ls(views: &[FileView]) {
    let mut by_dir: BTreeMap<String, Vec<&FileView>> = BTreeMap::new();
    for view in views {
        by_dir.entry(parent_dir(&view.path)).or_default().push(view);
    }
    for (dir, mut files) in by_dir {
        println!("{dir}/");
        files.sort_by(|a, b| a.path.cmp(&b.path));
        for file in files {
            let name = Path::new(&file.path)
                .file_name()
                .and_then(|name| name.to_str())
                .unwrap_or(&file.path);
            println!(
                "  {:<18} {:<4} {:.2}  {}",
                name,
                file.kind,
                file.confidence,
                file.labels.join(", ")
            );
            if let Some(reason) = file.why.first() {
                println!("                    why: {reason}");
            }
        }
    }
}

fn render_tree(views: &[FileView]) {
    let mut by_dir: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for view in views {
        let counts = by_dir.entry(parent_dir(&view.path)).or_default();
        for label in &view.labels {
            *counts.entry(label.clone()).or_insert(0) += 1;
        }
    }
    for (dir, counts) in by_dir {
        println!(
            "{dir:<16} files={}  {}",
            count_files_in_dir(views, &dir),
            render_rollup_counts(&counts)
        );
    }
}

fn render_explain(view: &FileView) {
    println!("file:{}", view.path);
    println!();
    for label in &view.labels {
        println!("label: {label}");
    }
    println!("confidence: {:.2}", view.confidence);
    println!();
    println!("supporting evidence:");
    for reason in &view.why {
        println!("  - {reason}");
    }
    if !view.negative.is_empty() {
        println!();
        println!("negative evidence:");
        for reason in &view.negative {
            println!("  - {reason}");
        }
    }
}

fn json_ls(views: &[FileView]) -> Value {
    json!({
        "files": views.iter().map(|view| json_file_view(view, false)).collect::<Vec<_>>()
    })
}

fn json_tree(views: &[FileView]) -> Value {
    let mut by_dir: BTreeMap<String, BTreeMap<String, usize>> = BTreeMap::new();
    for view in views {
        let counts = by_dir.entry(parent_dir(&view.path)).or_default();
        *counts.entry("files".to_string()).or_insert(0) += 1;
        for label in &view.labels {
            *counts.entry(label.clone()).or_insert(0) += 1;
        }
        if view.labels.is_empty() {
            *counts.entry(view.kind.to_ascii_lowercase()).or_insert(0) += 1;
        }
    }
    json!({
        "directories": by_dir,
    })
}

fn json_file_view(view: &FileView, include_evidence: bool) -> Value {
    let mut out = json!({
        "id": file_id(&view.path),
        "path": view.path,
        "kind": view.kind,
        "confidence": view.confidence,
        "labels": view.labels,
    });
    if include_evidence {
        out["supporting_evidence"] = json!(view.why);
        out["negative_evidence"] = json!(view.negative);
    } else if let Some(reason) = view.why.first() {
        out["summary"] = json!(reason);
    }
    out
}

fn ensure_update_authority(profile: &str) -> DynResult<()> {
    if profile == "update-authority" {
        Ok(())
    } else {
        Err(format!("unsupported profile {profile:?}; expected update-authority").into())
    }
}

fn display_kind(kind: &str) -> &'static str {
    match kind {
        "elf" => "ELF",
        "script" => "script",
        "config" => "config",
        "symlink" => "symlink",
        _ => "file",
    }
}

fn normalize_firmware_path(path: &str) -> String {
    if path.starts_with('/') {
        path.to_string()
    } else {
        format!("/{path}")
    }
}

fn parent_dir(path: &str) -> String {
    let path = PathBuf::from(path);
    path.parent()
        .and_then(|p| p.to_str())
        .filter(|s| !s.is_empty())
        .unwrap_or("/")
        .to_string()
}

fn file_id(path: &str) -> String {
    format!("file:{path}")
}

fn dir_id(path: &str) -> String {
    format!("dir:{path}")
}

fn tag_id(label: &str) -> String {
    format!("tag:{label}")
}

fn symbol_id(symbol: &str) -> String {
    format!("symbol:{symbol}")
}

fn label_assignment_id(path: &str, label: &str) -> String {
    format!("label:{path}:{label}")
}

fn evidence_id(path: &str, evidence: &Evidence) -> String {
    format!(
        "evidence:{}:{}",
        sanitize_id(path),
        sanitize_id(&evidence.detail)
    )
}

fn negative_id(path: &str, reason: &str) -> String {
    format!("ua:negative:{}:{}", sanitize_id(path), sanitize_id(reason))
}

fn sanitize_id(raw: &str) -> String {
    raw.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.' | '/' | ':') {
                c
            } else {
                '-'
            }
        })
        .collect()
}

fn evidence_symbol(evidence: &Evidence) -> Option<String> {
    if evidence.kind != "import" && evidence.kind != "export" {
        return None;
    }
    evidence
        .detail
        .rsplit_once(':')
        .map(|(_, symbol)| symbol.trim().to_string())
        .filter(|symbol| !symbol.is_empty())
}

fn strength_confidence(strength: &str) -> f64 {
    match strength {
        "strong" => 0.98,
        "medium" => 0.75,
        "weak" => 0.45,
        _ => 0.5,
    }
}

fn merge_unique(target: &mut Vec<String>, values: impl IntoIterator<Item = String>) {
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn render_rollup_counts(counts: &BTreeMap<String, usize>) -> String {
    counts
        .iter()
        .map(|(label, count)| format!("{label}={count}"))
        .collect::<Vec<_>>()
        .join("  ")
}

fn count_files_in_dir(views: &[FileView], dir: &str) -> usize {
    views
        .iter()
        .filter(|view| parent_dir(&view.path) == dir)
        .count()
}

fn value_id(value: &Value) -> String {
    value_str(value, "id")
}

fn value_str(value: &Value, field: &str) -> String {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .unwrap_or_default()
        .to_string()
}

fn props_key(props: Option<&Value>) -> String {
    props.map(|v| v.to_string()).unwrap_or_default()
}
