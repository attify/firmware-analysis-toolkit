use crate::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord};
use crate::result::{InvariantResult, InvariantSiteResult};
use crate::store::InMemoryGraph;
use regex::Regex;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

pub fn index_repo_fixture(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    index_repo(path)
}

pub fn index_repo(path: impl AsRef<Path>) -> Result<InMemoryGraph, String> {
    let root = path.as_ref();
    if !root.is_dir() {
        return Err(format!(
            "source root is not a directory: {}",
            root.display()
        ));
    }

    let mut nodes = Vec::new();
    let mut edges = Vec::new();

    for entry in walkdir::WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if !matches!(
            ext,
            "c" | "cc" | "cpp" | "cxx" | "m" | "mm" | "h" | "hpp" | "rs" | "py"
        ) {
            continue;
        }

        let text = match read_source_file_lossy(path) {
            Ok(text) => text,
            Err(e) => return Err(format!("failed to read {}: {}", path.display(), e)),
        };
        let functions = if ext == "py" {
            parse_python_functions(path, &text)
        } else {
            parse_functions(path, &text)
        };
        for function in functions {
            let function_id = nodes.len() as u32;
            nodes.push(function_node(&function.name));

            if function.body.contains("if (!hasPermission())") {
                let guard_id = nodes.len() as u32;
                nodes.push(guard_node("hasPermission"));
                edges.push(EdgeRecord::new(EdgeKind::GuardedBy, function_id, guard_id));
            }

            for call_name in function
                .calls
                .iter()
                .map(|call| call.name.clone())
                .filter(|name| name != &function.name && name != "if")
            {
                let call_id = nodes.len() as u32;
                nodes.push(call_node(&call_name));
                edges.push(EdgeRecord::new(EdgeKind::Calls, function_id, call_id));
            }
        }
    }

    Ok(InMemoryGraph::from_records(nodes, edges))
}

pub fn evaluate_invariant_rule(
    path: impl AsRef<Path>,
    rule: &str,
) -> Result<InvariantResult, String> {
    let graph = index_repo(path)?;
    let required_call = extract_required_call(rule).unwrap_or_else(|| "enforcePermission".into());
    let mut result = InvariantResult::new(rule);

    for node in graph.nodes() {
        if node.kind != NodeKind::Function {
            continue;
        }
        let Some(name) = node.attr("name") else {
            continue;
        };
        if !name.contains("Override") {
            continue;
        }
        let has_required_call = graph.out_edges(node.id).iter().any(|edge_idx| {
            let edge = graph.edge(*edge_idx);
            if edge.kind != EdgeKind::Calls {
                return false;
            }
            graph.nodes()[edge.to as usize].attr("callee_name") == Some(required_call.as_str())
        });
        if has_required_call {
            result.satisfying.push(InvariantSiteResult {
                site: name.to_string(),
            });
        } else {
            result.violating.push(InvariantSiteResult {
                site: name.to_string(),
            });
        }
    }

    Ok(result)
}

#[derive(Debug, Clone)]
pub struct ParsedCallFact {
    pub name: String,
    pub line: u32,
}

#[derive(Debug, Clone)]
pub struct ParsedFunctionFacts {
    pub name: String,
    pub file: PathBuf,
    pub body: String,
    pub begin_line: u32,
    pub end_line: u32,
    pub calls: Vec<ParsedCallFact>,
}

pub fn scan_source_facts(
    path: impl AsRef<Path>,
) -> Result<crate::slice_expander::ScannedSourceFacts, String> {
    let root = path.as_ref();
    let mut parsed = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .follow_links(true)
        .into_iter()
        .filter_map(Result::ok)
    {
        let path = entry.path();
        if !path.is_file() {
            continue;
        }
        let Some(ext) = path.extension().and_then(|ext| ext.to_str()) else {
            continue;
        };
        if !matches!(
            ext,
            "c" | "cc" | "cpp" | "cxx" | "m" | "mm" | "h" | "hpp" | "rs" | "py"
        ) {
            continue;
        }
        let text = match read_source_file_lossy(path) {
            Ok(text) => text,
            Err(e) => return Err(format!("failed to read {}: {}", path.display(), e)),
        };
        if ext == "py" {
            parsed.extend(parse_python_functions(path, &text));
        } else {
            parsed.extend(parse_functions(path, &text));
        }
    }
    Ok(crate::slice_expander::scanned_source_facts_from_functions(
        &parsed,
    ))
}

/// Read a source file, using lossy UTF-8 decoding for encoding issues
/// but propagating real IO errors (permissions, missing files, etc.).
fn read_source_file_lossy(path: &Path) -> Result<String, std::io::Error> {
    let bytes = std::fs::read(path)?;
    Ok(String::from_utf8_lossy(&bytes).into_owned())
}

fn parse_python_functions(path: &Path, text: &str) -> Vec<ParsedFunctionFacts> {
    let def_re =
        Regex::new(r#"^\s*def\s+([A-Za-z_][A-Za-z0-9_]*)\s*\("#).expect("valid python def regex");
    let call_re =
        Regex::new(r#"([A-Za-z_][A-Za-z0-9_\.]*)\s*\("#).expect("valid python call regex");
    let mut functions = Vec::new();
    let lines = text.lines().collect::<Vec<_>>();
    let mut index = 0usize;

    while index < lines.len() {
        let line = lines[index];
        let Some(captures) = def_re.captures(line) else {
            index += 1;
            continue;
        };
        let name = captures
            .get(1)
            .map(|capture| capture.as_str().to_string())
            .unwrap_or_default();
        let base_indent = line.chars().take_while(|ch| ch.is_whitespace()).count();
        let begin_line = index as u32 + 1;
        let mut body_lines = vec![line.to_string()];
        let mut end_line = begin_line;
        let mut cursor = index + 1;

        while cursor < lines.len() {
            let candidate = lines[cursor];
            if candidate.trim().is_empty() {
                body_lines.push(candidate.to_string());
                end_line = cursor as u32 + 1;
                cursor += 1;
                continue;
            }
            let indent = candidate
                .chars()
                .take_while(|ch| ch.is_whitespace())
                .count();
            if indent <= base_indent && !candidate.trim_start().starts_with('#') {
                break;
            }
            body_lines.push(candidate.to_string());
            end_line = cursor as u32 + 1;
            cursor += 1;
        }

        let body = body_lines.join("\n");
        let calls = call_re
            .captures_iter(&body)
            .filter_map(|capture| capture.get(1).map(|value| value.as_str().to_string()))
            .filter(|call| call != &name && call != "def")
            .enumerate()
            .map(|(offset, call)| ParsedCallFact {
                name: call,
                line: begin_line + offset as u32,
            })
            .collect::<Vec<_>>();

        functions.push(ParsedFunctionFacts {
            name,
            file: path.to_path_buf(),
            body,
            begin_line,
            end_line,
            calls,
        });
        index = cursor;
    }

    functions
}

fn parse_functions(path: &Path, text: &str) -> Vec<ParsedFunctionFacts> {
    let mut functions = Vec::new();
    let call_re = Regex::new(r#"([A-Za-z_][A-Za-z0-9_]*)\s*\("#).expect("valid call regex");
    let mut lines = text.lines().enumerate().peekable();
    let mut pending_signature = String::new();
    let mut signature_start = 0u32;
    while let Some((line_no, line)) = lines.next() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if pending_signature.is_empty()
            && !trimmed.contains('(')
            && !trimmed.ends_with('{')
            && !trimmed.contains("operator")
        {
            continue;
        }
        if pending_signature.is_empty() && is_non_function_scope_opener(trimmed) {
            continue;
        }
        if trimmed.ends_with(';') && !trimmed.contains('{') {
            pending_signature.clear();
            continue;
        }
        if (trimmed == "public:" || trimmed == "private:" || trimmed == "protected:")
            && pending_signature.is_empty()
        {
            continue;
        }
        if pending_signature.is_empty() {
            signature_start = line_no as u32 + 1;
        }
        if pending_signature.is_empty() {
            pending_signature.push_str(trimmed);
        } else {
            pending_signature.push(' ');
            pending_signature.push_str(trimmed);
        }
        if pending_signature.starts_with("if ") {
            pending_signature.clear();
            continue;
        }
        if trimmed.contains('{') && trimmed.contains('}') && trimmed.contains('(') {
            if let Some(function) =
                parse_single_line_function(path, trimmed, line_no as u32 + 1, &call_re)
            {
                functions.push(function);
            }
            pending_signature.clear();
            continue;
        }
        if !trimmed.ends_with('{') {
            continue;
        }
        let Some(signature) = pending_signature.strip_suffix('{') else {
            pending_signature.clear();
            continue;
        };
        let Some(name) = signature
            .split('(')
            .next()
            .and_then(|prefix| prefix.split_whitespace().last())
        else {
            pending_signature.clear();
            continue;
        };
        let function_name = name.to_string();
        pending_signature.clear();
        let mut body = String::new();
        let mut calls = Vec::new();
        let mut depth = 1usize;
        let mut end_line = signature_start;
        for (body_line_no, next_line) in lines.by_ref() {
            let trimmed_line = next_line.trim();
            if trimmed_line.contains('{') {
                depth += trimmed_line.matches('{').count();
            }
            if trimmed_line.contains('}') {
                depth = depth.saturating_sub(trimmed_line.matches('}').count());
                end_line = body_line_no as u32 + 1;
                if depth == 0 {
                    break;
                }
            }
            for call_name in call_re
                .captures_iter(next_line)
                .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
                .filter(|name| name != &function_name && name != "if")
            {
                calls.push(ParsedCallFact {
                    name: call_name,
                    line: body_line_no as u32 + 1,
                });
            }
            body.push_str(next_line);
            body.push('\n');
        }
        functions.push(ParsedFunctionFacts {
            name: function_name,
            file: path.to_path_buf(),
            body,
            begin_line: signature_start,
            end_line,
            calls,
        });
    }
    functions
}

fn parse_single_line_function(
    path: &Path,
    line: &str,
    line_no: u32,
    call_re: &Regex,
) -> Option<ParsedFunctionFacts> {
    let signature = line.split('{').next()?.trim();
    let name = signature
        .split('(')
        .next()
        .and_then(|prefix| prefix.split_whitespace().last())?;
    let body = line
        .split_once('{')
        .and_then(|(_, rest)| rest.rsplit_once('}').map(|(body, _)| body))
        .unwrap_or_default()
        .to_string();
    let calls = call_re
        .captures_iter(&body)
        .filter_map(|caps| caps.get(1).map(|m| m.as_str().to_string()))
        .filter(|call_name| call_name != name && call_name != "if")
        .map(|call_name| ParsedCallFact {
            name: call_name,
            line: line_no,
        })
        .collect::<Vec<_>>();
    Some(ParsedFunctionFacts {
        name: name.to_string(),
        file: path.to_path_buf(),
        body,
        begin_line: line_no,
        end_line: line_no,
        calls,
    })
}

fn is_non_function_scope_opener(trimmed: &str) -> bool {
    if trimmed == "{" {
        return true;
    }
    if !trimmed.ends_with('{') || trimmed.contains('(') {
        return false;
    }
    let stripped = trimmed.trim_end_matches('{').trim_start();
    matches!(
        stripped.split_whitespace().next(),
        Some("class" | "struct" | "namespace" | "enum" | "union" | "extern")
    )
}

fn function_node(name: &str) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("name".into(), name.into());
    NodeRecord {
        id: 0,
        kind: NodeKind::Function,
        label: name.into(),
        attrs,
        provenance: Default::default(),
    }
}

fn call_node(name: &str) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("callee_name".into(), name.into());
    NodeRecord {
        id: 0,
        kind: NodeKind::CallSite,
        label: format!("call {name}"),
        attrs,
        provenance: Default::default(),
    }
}

fn guard_node(name: &str) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("guard_name".into(), name.into());
    NodeRecord {
        id: 0,
        kind: NodeKind::Guard,
        label: format!("guard {name}"),
        attrs,
        provenance: Default::default(),
    }
}

fn extract_required_call(rule: &str) -> Option<String> {
    let re = Regex::new(r#"must call ([A-Za-z_][A-Za-z0-9_]*)\s*\("#).ok()?;
    let caps = re.captures(rule)?;
    Some(caps.get(1)?.as_str().to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scan_source_facts_survives_non_utf8_file() {
        let dir = tempfile::tempdir().expect("tempdir");
        // Write a valid C file
        std::fs::write(dir.path().join("good.c"), b"void foo() { malloc(42); }").unwrap();
        // Write a non-UTF-8 file (Latin-1 encoded comment)
        let mut bad_content = b"void bar() { /* comment: ".to_vec();
        bad_content.push(0xFF); // invalid UTF-8 byte
        bad_content.extend_from_slice(b" */ free(0); }\n");
        std::fs::write(dir.path().join("bad.c"), &bad_content).unwrap();

        // Should not crash — should process both files via lossy decode
        let result = scan_source_facts(dir.path());
        assert!(
            result.is_ok(),
            "scan_source_facts should not crash on non-UTF-8: {result:?}"
        );
    }

    #[test]
    fn scan_source_facts_propagates_real_io_errors() {
        let dir = tempfile::tempdir().expect("tempdir");
        let unreadable = dir.path().join("secret.c");
        std::fs::write(&unreadable, b"void secret() {}").unwrap();

        // Make unreadable
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o000)).unwrap();

            let result = scan_source_facts(dir.path());
            assert!(
                result.is_err(),
                "scan_source_facts should propagate permission errors, not silently skip"
            );

            // Restore for cleanup
            std::fs::set_permissions(&unreadable, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
    }
}
