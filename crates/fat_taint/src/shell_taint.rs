//! Source-to-sink taint analysis for shell scripts (`fat taint --lang shell`).
//!
//! # What this is
//!
//! Scripts are parsed with `tree-sitter-bash` into a real AST, then walked in
//! document order while a variable-taint map is maintained. A finding is
//! emitted when a command that matches a sink family from
//! `sink_profiles/shell-command-exec.yaml` references a variable that the walk
//! has already marked tainted, or embeds a source expression directly.
//!
//! # What this is not
//!
//! This is deliberately **not** a sound analysis. Shell is dynamic enough
//! (`eval`, `source`, command substitution, dynamic variable names) that
//! soundness is unreachable. The bar is the epistemic level of the existing
//! `fat search` regex pass *with provenance attached*: every finding carries
//! the assignment chain that connects a named source to a named sink.
//!
//! The concrete win over a line-oriented regex scan is that the AST removes
//! whole classes of false positive — comments, heredoc bodies, single-quoted
//! strings, and `case` labels are not commands, so they never produce a sink
//! hit. Every taint edge is therefore reported as [`EdgeType::ShellModel`],
//! which lands these findings at `Candidate` status and `WEAK` strength, the
//! same trust tier the shell overlay already uses elsewhere in `fat_taint`.
//!
//! # Known limitations
//!
//! - **One source per sink.** When several tainted variables reach the same
//!   sink, the first in document order is the one reported.
//! - **Flow-insensitive.** The taint map is global to the script: branches are
//!   not modelled, `local` is not scoped to its function, and a variable stays
//!   tainted until it is reassigned to something untainted.
//! - **Intra-script only.** `source` / `.` is not followed, and a script that
//!   hands data to a binary is out of scope. That handoff is cross-layer taint.
//! - **No dynamic names.** Indirect expansion (`${!name}`), arrays, and
//!   variables produced by `eval` are not tracked.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::Path;

use fat_core::finding::FindingSeverity;
use regex::Regex;
use serde::{Deserialize, Serialize};
use tree_sitter::Node;

use crate::finding::{ChainStep, EdgeType, SourceClass, TaintFinding};
use crate::shell_profile::{ShellSourceDef, ShellSourceKind, ShellTaintProfile};
use crate::shell_scan::{is_shell_script, MAX_SCRIPT_BYTES};
use crate::sink_discovery::{Severity, SinkProfile};

/// Label rendering is truncated to keep chain steps readable.
const MAX_LABEL_CHARS: usize = 120;

/// Node kinds whose byte ranges are blanked before sink patterns are applied.
/// These are the constructs a line-oriented regex scan cannot tell apart from
/// real commands.
const REDACTED_KINDS: [&str; 3] = ["raw_string", "heredoc_body", "comment"];

// ── Report types ────────────────────────────────────────────────────────────

/// The source that begins a shell taint chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSourceRef {
    /// Profile source name (`cat`, `positional-parameters`, `environment`, …).
    pub name: String,
    pub kind: ShellSourceKind,
    /// Rendered source expression, e.g. `cat /configs/.wifissid` or `$1`.
    pub label: String,
    pub line: u32,
    pub class: SourceClass,
    /// Writable-mount prefix that upgraded this source to `Primary`, if any.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub writable_mount: Option<String>,
}

/// One assignment hop: `from` was assigned into `$variable` at `line`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellHop {
    /// Rendered right-hand side (`cat /configs/.wifissid`, `$wifissid`, …).
    pub from: String,
    pub variable: String,
    pub line: u32,
}

/// The sink that ends a shell taint chain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellSinkRef {
    /// Sink family key from the shared `shell-command-exec` sink profile.
    pub family: String,
    pub severity: Severity,
    pub line: u32,
    /// Rendered command text with quoted literals and heredocs blanked.
    pub text: String,
}

/// One source → … → sink flow inside a script. Candidate, not proof.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellFlow {
    /// Script path as reported (relative to the rootfs when scanning one).
    pub script: String,
    /// Enclosing shell function, or `<toplevel>`.
    pub function: String,
    pub source: ShellSourceRef,
    /// Assignment chain from the source to the variable the sink reads.
    /// Empty when the source expression is embedded in the sink itself.
    #[serde(default)]
    pub hops: Vec<ShellHop>,
    pub sink: ShellSinkRef,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShellTaintSummary {
    #[serde(default)]
    pub files_scanned: usize,
    #[serde(default)]
    pub scripts_with_flows: usize,
    #[serde(default)]
    pub flows: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub families: BTreeMap<String, usize>,
}

/// JSON-serializable report for a shell taint run.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellTaintReport {
    pub root: String,
    pub profile: String,
    #[serde(default)]
    pub sink_profiles: Vec<String>,
    pub summary: ShellTaintSummary,
    #[serde(default)]
    pub flows: Vec<ShellFlow>,
}

// ── Public API ──────────────────────────────────────────────────────────────

/// Analyze one script's text and return its source → sink flows.
///
/// `script` is the path label carried into every finding; `text` is the script
/// body. Parse errors from `tree-sitter` are not fatal — the grammar is
/// error-tolerant by design, which is what makes it usable on the malformed
/// busybox-ash scripts that ship in firmware.
pub fn analyze_script(
    script: &str,
    text: &str,
    profile: &ShellTaintProfile,
    sinks: &[SinkProfile],
) -> Result<Vec<ShellFlow>, String> {
    let rules = compile_rules(sinks)?;
    let defs = SourceDefs::new(profile);

    let mut parser = tree_sitter::Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|err| format!("failed to load the bash grammar: {err}"))?;
    let tree = parser
        .parse(text, None)
        .ok_or_else(|| format!("tree-sitter failed to parse '{script}'"))?;

    let mut analyzer = Analyzer {
        src: text.as_bytes(),
        script,
        defs: &defs,
        rules: &rules,
        tainted: HashMap::new(),
        flows: Vec::new(),
        seen: HashSet::new(),
    };
    analyzer.visit(tree.root_node(), "<toplevel>");

    let mut flows = analyzer.flows;
    flows.sort_by(|a, b| {
        (a.sink.line, &a.sink.family, &a.source.label).cmp(&(
            b.sink.line,
            &b.sink.family,
            &b.source.label,
        ))
    });
    Ok(flows)
}

/// Analyze every shell script under `root`.
///
/// Candidate selection matches [`crate::shell_scan::scan_rootfs`]: `*.sh` or a
/// shell shebang, under [`MAX_SCRIPT_BYTES`].
pub fn analyze_rootfs(
    root: &Path,
    profile: &ShellTaintProfile,
    sinks: &[SinkProfile],
) -> Result<ShellTaintReport, String> {
    let mut flows = Vec::new();
    let mut files_scanned = 0usize;
    let mut scripts_with_flows = 0usize;

    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|err| format!("walking '{}': {err}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if entry
            .metadata()
            .map_err(|err| format!("stat '{}': {err}", path.display()))?
            .len()
            > MAX_SCRIPT_BYTES
        {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        if !is_shell_script(path, &bytes) {
            continue;
        }
        files_scanned += 1;
        let display = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        let text = String::from_utf8_lossy(&bytes);
        let script_flows = analyze_script(&display, &text, profile, sinks)?;
        if !script_flows.is_empty() {
            scripts_with_flows += 1;
        }
        flows.extend(script_flows);
    }

    flows.sort_by(|a, b| {
        (&a.script, a.sink.line, &a.sink.family, &a.source.label).cmp(&(
            &b.script,
            b.sink.line,
            &b.sink.family,
            &b.source.label,
        ))
    });

    let mut families = BTreeMap::new();
    for flow in &flows {
        *families.entry(flow.sink.family.clone()).or_insert(0) += 1;
    }

    Ok(ShellTaintReport {
        root: root.display().to_string(),
        profile: profile.name.clone(),
        sink_profiles: sinks.iter().map(|p| p.name.clone()).collect(),
        summary: ShellTaintSummary {
            files_scanned,
            scripts_with_flows,
            flows: flows.len(),
            families,
        },
        flows,
    })
}

/// Convert shell flows into the same [`TaintFinding`] shape `fat taint --json`
/// emits, so anything that already deserializes taint findings reads these too.
pub fn flows_to_findings(flows: &[ShellFlow]) -> Vec<TaintFinding> {
    flows
        .iter()
        .enumerate()
        .map(|(index, flow)| flow_to_finding(index, flow))
        .collect()
}

fn flow_to_finding(index: usize, flow: &ShellFlow) -> TaintFinding {
    let mut chain: Vec<ChainStep> = Vec::new();

    if flow.hops.is_empty() {
        chain.push(ChainStep {
            binary: flow.script.clone(),
            function: flow.function.clone(),
            location: format!("{}:{}", flow.script, flow.source.line),
            action: flow.source.label.clone(),
            edge_type: EdgeType::ShellModel {
                script: flow.script.clone(),
                pattern: flow.source.name.clone(),
            },
        });
    } else {
        for hop in &flow.hops {
            chain.push(ChainStep {
                binary: flow.script.clone(),
                function: flow.function.clone(),
                location: format!("{}:{}", flow.script, hop.line),
                action: format!("{} → ${}", hop.from, hop.variable),
                edge_type: EdgeType::ShellModel {
                    script: flow.script.clone(),
                    pattern: flow.source.name.clone(),
                },
            });
        }
    }

    chain.push(ChainStep {
        binary: flow.script.clone(),
        function: flow.function.clone(),
        location: format!("{}:{}", flow.script, flow.sink.line),
        action: format!("{} [{}]", flow.sink.text, flow.sink.family),
        edge_type: EdgeType::ShellModel {
            script: flow.script.clone(),
            pattern: flow.sink.family.clone(),
        },
    });

    let status = TaintFinding::classify(&chain);
    let confidence = TaintFinding::compute_confidence(&chain);
    let hop_note = match flow.hops.len() {
        0 => "source expression embedded in the sink".to_string(),
        1 => "1 assignment hop".to_string(),
        n => format!("{n} assignment hops"),
    };
    let mount_note = flow
        .source
        .writable_mount
        .as_ref()
        .map(|prefix| format!(", writable mount {prefix}"))
        .unwrap_or_default();

    TaintFinding {
        model_provenance: None,
        state_model_provenance: None,
        id: format!("SHELL-{:04}", index + 1),
        title: format!(
            "{} → {} in {}:{}",
            flow.source.label, flow.sink.family, flow.script, flow.sink.line
        ),
        severity: severity_of(flow.sink.severity),
        chain,
        status,
        status_reason: format!(
            "shell-ast: tree-sitter-bash {} source → {} sink ({hop_note}{mount_note})",
            source_kind_word(flow.source.kind),
            flow.sink.family
        ),
        confidence,
        source_class: flow.source.class,
    }
}

fn severity_of(severity: Severity) -> FindingSeverity {
    match severity {
        Severity::High => FindingSeverity::High,
        Severity::Medium => FindingSeverity::Medium,
        Severity::Low => FindingSeverity::Low,
    }
}

fn source_kind_word(kind: ShellSourceKind) -> &'static str {
    match kind {
        ShellSourceKind::Command => "command",
        ShellSourceKind::Positional => "positional-parameter",
        ShellSourceKind::Environment => "environment",
        ShellSourceKind::PathPrefix => "writable-path",
    }
}

// ── Compiled profile views ──────────────────────────────────────────────────

struct CompiledRule {
    family: String,
    severity: Severity,
    pattern: Regex,
}

fn compile_rules(sinks: &[SinkProfile]) -> Result<Vec<CompiledRule>, String> {
    let mut rules = Vec::new();
    for profile in sinks {
        for (family, definition) in &profile.families {
            let Some(pattern) = &definition.pattern else {
                continue;
            };
            let regex = Regex::new(pattern).map_err(|err| {
                format!(
                    "sink profile '{}': family '{family}': invalid pattern: {err}",
                    profile.name
                )
            })?;
            rules.push(CompiledRule {
                family: family.clone(),
                severity: definition.severity.unwrap_or(Severity::Medium),
                pattern: regex,
            });
        }
    }
    if rules.is_empty() {
        return Err("no shell sink families carry a pattern; nothing to match".to_string());
    }
    rules.sort_by(|a, b| a.family.cmp(&b.family));
    Ok(rules)
}

struct CommandSource<'a> {
    def: &'a ShellSourceDef,
    primary: bool,
}

struct WritablePath<'a> {
    prefix: &'a str,
    def: &'a ShellSourceDef,
    primary: bool,
}

struct SourceDefs<'a> {
    commands: Vec<CommandSource<'a>>,
    environment: HashMap<&'a str, CommandSource<'a>>,
    writable: Vec<WritablePath<'a>>,
    positional: Option<CommandSource<'a>>,
}

impl<'a> SourceDefs<'a> {
    fn new(profile: &'a ShellTaintProfile) -> Self {
        let mut commands = Vec::new();
        let mut environment = HashMap::new();
        let mut writable = Vec::new();
        let mut positional = None;

        for (def, primary) in profile.all_sources() {
            match def.kind {
                ShellSourceKind::Command => commands.push(CommandSource { def, primary }),
                ShellSourceKind::Positional => {
                    positional.get_or_insert(CommandSource { def, primary });
                }
                ShellSourceKind::Environment => {
                    for var in &def.vars {
                        environment.insert(var.as_str(), CommandSource { def, primary });
                    }
                }
                ShellSourceKind::PathPrefix => {
                    for prefix in &def.paths {
                        writable.push(WritablePath {
                            prefix: prefix.as_str(),
                            def,
                            primary,
                        });
                    }
                }
            }
        }
        // Longest prefix first so `/mnt/sdcard/` beats `/mnt/`.
        writable.sort_by_key(|entry| std::cmp::Reverse(entry.prefix.len()));

        Self {
            commands,
            environment,
            writable,
            positional,
        }
    }

    fn writable_prefix_for(&self, value: &str) -> Option<&WritablePath<'a>> {
        self.writable
            .iter()
            .find(|entry| value.starts_with(entry.prefix))
    }
}

fn class_of(primary: bool) -> SourceClass {
    if primary {
        SourceClass::Primary
    } else {
        SourceClass::Secondary
    }
}

// ── Analyzer ────────────────────────────────────────────────────────────────

#[derive(Clone)]
struct TaintState {
    source: ShellSourceRef,
    hops: Vec<ShellHop>,
}

/// A resolved taint origin plus the rendering of the expression that carried it.
struct Resolved {
    source: ShellSourceRef,
    hops: Vec<ShellHop>,
    expr: String,
}

struct Analyzer<'a> {
    src: &'a [u8],
    script: &'a str,
    defs: &'a SourceDefs<'a>,
    rules: &'a [CompiledRule],
    tainted: HashMap<String, TaintState>,
    flows: Vec<ShellFlow>,
    seen: HashSet<(u32, String, String)>,
}

impl<'a> Analyzer<'a> {
    fn text(&self, node: Node<'_>) -> String {
        String::from_utf8_lossy(&self.src[node.start_byte()..node.end_byte()]).into_owned()
    }

    /// Node text with quoted literals, heredoc bodies, and comments blanked.
    ///
    /// This is what sink patterns are matched against; it is the difference
    /// between `echo 'eval $x'` and `eval "$x"`.
    fn sanitized_text(&self, node: Node<'_>) -> String {
        let start = node.start_byte();
        let mut bytes = self.src[start..node.end_byte()].to_vec();
        let mut ranges = Vec::new();
        collect_kind_ranges(node, &REDACTED_KINDS, &mut ranges);
        for (from, to) in ranges {
            for byte in bytes
                .iter_mut()
                .take(to.saturating_sub(start))
                .skip(from.saturating_sub(start))
            {
                *byte = b' ';
            }
        }
        String::from_utf8_lossy(&bytes).trim().to_string()
    }

    fn visit(&mut self, node: Node<'a>, function: &str) {
        match node.kind() {
            kind if REDACTED_KINDS.contains(&kind) => return,
            "function_definition" => {
                let name = node
                    .child_by_field_name("name")
                    .map(|n| self.text(n))
                    .unwrap_or_else(|| "<anonymous>".to_string());
                self.visit_children(node, &name);
                return;
            }
            "variable_assignment" => {
                self.handle_assignment(node);
                if let Some(value) = node.child_by_field_name("value") {
                    // Descend so a sink nested in the RHS (`x=$(eval $y)`) is
                    // still seen.
                    self.visit(value, function);
                }
                return;
            }
            "for_statement" => {
                self.handle_for(node);
            }
            "command" => {
                self.handle_read(node);
                self.handle_sinks(node, function);
            }
            _ => {}
        }
        self.visit_children(node, function);
    }

    fn visit_children(&mut self, node: Node<'a>, function: &str) {
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.visit(child, function);
        }
    }

    fn handle_assignment(&mut self, node: Node<'a>) {
        let Some(name_node) = node.child_by_field_name("name") else {
            return;
        };
        let name = self.text(name_node);
        let line = line_of(node);
        let Some(value) = node.child_by_field_name("value") else {
            self.tainted.remove(&name);
            return;
        };
        match self.resolve(value) {
            Some(resolved) => {
                let mut hops = resolved.hops;
                hops.push(ShellHop {
                    from: resolved.expr,
                    variable: name.clone(),
                    line,
                });
                self.tainted.insert(
                    name,
                    TaintState {
                        source: resolved.source,
                        hops,
                    },
                );
            }
            None => {
                self.tainted.remove(&name);
            }
        }
    }

    /// `for v in $tainted; do …` taints the loop variable.
    fn handle_for(&mut self, node: Node<'a>) {
        let Some(var_node) = node.child_by_field_name("variable") else {
            return;
        };
        let name = self.text(var_node);
        let line = line_of(node);
        let body = node.child_by_field_name("body");

        let mut cursor = node.walk();
        let candidates: Vec<Node<'a>> = node
            .named_children(&mut cursor)
            .filter(|child| {
                child.id() != var_node.id() && body.map(|b| b.id() != child.id()).unwrap_or(true)
            })
            .collect();

        for candidate in candidates {
            if let Some(resolved) = self.resolve(candidate) {
                let mut hops = resolved.hops;
                hops.push(ShellHop {
                    from: resolved.expr,
                    variable: name.clone(),
                    line,
                });
                self.tainted.insert(
                    name,
                    TaintState {
                        source: resolved.source,
                        hops,
                    },
                );
                return;
            }
        }
        self.tainted.remove(&name);
    }

    /// `read VAR` binds stdin to VAR — a primary source in its own right.
    fn handle_read(&mut self, node: Node<'a>) {
        if self.command_name(node).as_deref() != Some("read") {
            return;
        }
        let Some(def) = self
            .defs
            .commands
            .iter()
            .find(|entry| entry.def.name == "read")
        else {
            return;
        };
        let line = line_of(node);
        let label = truncate(&self.sanitized_text(node));
        let mut cursor = node.walk();
        let words: Vec<Node<'a>> = node
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "word")
            .collect();
        for word in words {
            let name = self.text(word);
            if name.starts_with('-') || name.contains('=') {
                continue;
            }
            self.tainted.insert(
                name.clone(),
                TaintState {
                    source: ShellSourceRef {
                        name: def.def.name.clone(),
                        kind: ShellSourceKind::Command,
                        label: label.clone(),
                        line,
                        class: class_of(def.primary),
                        writable_mount: None,
                    },
                    hops: vec![ShellHop {
                        from: label.clone(),
                        variable: name,
                        line,
                    }],
                },
            );
        }
    }

    fn handle_sinks(&mut self, node: Node<'a>, function: &str) {
        let text = self.sanitized_text(node);
        if text.is_empty() {
            return;
        }
        let matched: Vec<(String, Severity)> = self
            .rules
            .iter()
            .filter(|rule| rule.pattern.is_match(&text))
            .map(|rule| (rule.family.clone(), rule.severity))
            .collect();
        if matched.is_empty() {
            return;
        }
        // No provenance means no taint finding. Pattern-only hits are what
        // `fat sink-discovery --rootfs` already reports.
        let Some(resolved) = self.resolve(node) else {
            return;
        };
        let line = line_of(node);
        let sink_text = truncate(&text);
        for (family, severity) in matched {
            let key = (line, family.clone(), resolved.source.label.clone());
            if !self.seen.insert(key) {
                continue;
            }
            self.flows.push(ShellFlow {
                script: self.script.to_string(),
                function: function.to_string(),
                source: resolved.source.clone(),
                hops: resolved.hops.clone(),
                sink: ShellSinkRef {
                    family,
                    severity,
                    line,
                    text: sink_text.clone(),
                },
            });
        }
    }

    fn command_name(&self, node: Node<'_>) -> Option<String> {
        node.child_by_field_name("name").map(|n| self.text(n))
    }

    /// Find the taint origin reachable from `node`, if any.
    ///
    /// Resolution order follows document order for variable expansions, then
    /// falls back to source commands embedded in a substitution, then to
    /// literal paths under a writable mount.
    fn resolve(&self, node: Node<'a>) -> Option<Resolved> {
        for (name, line) in self.collect_expansions(node) {
            if let Some(state) = self.tainted.get(&name) {
                return Some(Resolved {
                    source: state.source.clone(),
                    hops: state.hops.clone(),
                    expr: format!("${name}"),
                });
            }
            if let Some(entry) = &self.defs.positional {
                if !name.is_empty() && name != "0" && name.chars().all(|c| c.is_ascii_digit()) {
                    return Some(Resolved {
                        source: ShellSourceRef {
                            name: entry.def.name.clone(),
                            kind: ShellSourceKind::Positional,
                            label: format!("${name}"),
                            line,
                            class: class_of(entry.primary),
                            writable_mount: None,
                        },
                        hops: Vec::new(),
                        expr: format!("${name}"),
                    });
                }
            }
            if let Some(entry) = self.defs.environment.get(name.as_str()) {
                return Some(Resolved {
                    source: ShellSourceRef {
                        name: entry.def.name.clone(),
                        kind: ShellSourceKind::Environment,
                        label: format!("${name}"),
                        line,
                        class: class_of(entry.primary),
                        writable_mount: None,
                    },
                    hops: Vec::new(),
                    expr: format!("${name}"),
                });
            }
        }

        if let Some(source) = self.resolve_source_command(node) {
            let expr = source.label.clone();
            return Some(Resolved {
                source,
                hops: Vec::new(),
                expr,
            });
        }

        self.resolve_writable_literal(node).map(|source| {
            let expr = source.label.clone();
            Resolved {
                source,
                hops: Vec::new(),
                expr,
            }
        })
    }

    /// A command inside `node` whose stdout the profile marks as a source.
    fn resolve_source_command(&self, node: Node<'a>) -> Option<ShellSourceRef> {
        let mut commands = Vec::new();
        collect_kind_nodes(node, "command", &mut commands);
        for command in commands {
            if command.id() == node.id() {
                // A sink command is not its own source.
                continue;
            }
            let Some(name) = self.command_name(command) else {
                continue;
            };
            let words = self.argument_words(command);
            let Some(entry) = self.defs.commands.iter().find(|entry| {
                entry.def.name == name
                    && entry
                        .def
                        .argv
                        .iter()
                        .enumerate()
                        .all(|(index, expected)| words.get(index) == Some(expected))
            }) else {
                continue;
            };
            let label = truncate(&self.sanitized_text(command));
            let writable = words
                .iter()
                .find_map(|word| self.defs.writable_prefix_for(word));
            return Some(ShellSourceRef {
                name: entry.def.name.clone(),
                kind: ShellSourceKind::Command,
                label,
                line: line_of(command),
                // Reading a file out of an attacker-writable mount is direct
                // ingress, not persisted state.
                class: if writable.is_some() {
                    SourceClass::Primary
                } else {
                    class_of(entry.primary)
                },
                writable_mount: writable.map(|entry| entry.prefix.to_string()),
            });
        }
        None
    }

    /// A literal path under a writable mount used directly by the sink, e.g.
    /// `sh /tmp/run.sh`.
    fn resolve_writable_literal(&self, node: Node<'a>) -> Option<ShellSourceRef> {
        let mut words = Vec::new();
        collect_kind_nodes(node, "word", &mut words);
        for word in words {
            let value = self.text(word);
            if let Some(entry) = self.defs.writable_prefix_for(&value) {
                return Some(ShellSourceRef {
                    name: entry.def.name.clone(),
                    kind: ShellSourceKind::PathPrefix,
                    label: truncate(&value),
                    line: line_of(word),
                    class: class_of(entry.primary),
                    writable_mount: Some(entry.prefix.to_string()),
                });
            }
        }
        None
    }

    fn argument_words(&self, command: Node<'a>) -> Vec<String> {
        let mut cursor = command.walk();
        command
            .named_children(&mut cursor)
            .filter(|child| child.kind() == "word")
            .map(|child| self.text(child))
            .collect()
    }

    /// Variable names expanded inside `node`, in document order.
    ///
    /// Single-quoted strings, heredoc bodies, and comments are skipped, so a
    /// `$var` that the shell would never expand never produces a taint edge.
    fn collect_expansions(&self, node: Node<'a>) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        self.collect_expansions_into(node, &mut out);
        out
    }

    fn collect_expansions_into(&self, node: Node<'a>, out: &mut Vec<(String, u32)>) {
        if REDACTED_KINDS.contains(&node.kind()) {
            return;
        }
        if matches!(node.kind(), "simple_expansion" | "expansion") {
            let mut cursor = node.walk();
            let name = node
                .named_children(&mut cursor)
                .find(|child| child.kind() == "variable_name");
            drop(cursor);
            if let Some(name) = name {
                out.push((self.text(name), line_of(node)));
            }
        }
        let mut cursor = node.walk();
        let children: Vec<Node<'a>> = node.named_children(&mut cursor).collect();
        for child in children {
            self.collect_expansions_into(child, out);
        }
    }
}

// ── AST helpers ─────────────────────────────────────────────────────────────

fn line_of(node: Node<'_>) -> u32 {
    node.start_position().row as u32 + 1
}

fn collect_kind_ranges(node: Node<'_>, kinds: &[&str], out: &mut Vec<(usize, usize)>) {
    if kinds.contains(&node.kind()) {
        out.push((node.start_byte(), node.end_byte()));
        return;
    }
    let mut cursor = node.walk();
    for child in node.named_children(&mut cursor) {
        collect_kind_ranges(child, kinds, out);
    }
}

fn collect_kind_nodes<'tree>(node: Node<'tree>, kind: &str, out: &mut Vec<Node<'tree>>) {
    if REDACTED_KINDS.contains(&node.kind()) {
        return;
    }
    if node.kind() == kind {
        out.push(node);
    }
    let mut cursor = node.walk();
    let children: Vec<Node<'tree>> = node.named_children(&mut cursor).collect();
    for child in children {
        collect_kind_nodes(child, kind, out);
    }
}

fn truncate(value: &str) -> String {
    let collapsed = value.split_whitespace().collect::<Vec<_>>().join(" ");
    if collapsed.chars().count() <= MAX_LABEL_CHARS {
        return collapsed;
    }
    let head: String = collapsed.chars().take(MAX_LABEL_CHARS).collect();
    format!("{head}…")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell_profile::{load_shell_profile, load_shell_sink_profiles};

    fn analyze(text: &str) -> Vec<ShellFlow> {
        analyze_with_profile(text, None)
    }

    fn analyze_with_profile(text: &str, overlay: Option<&std::path::Path>) -> Vec<ShellFlow> {
        let profile = load_shell_profile(overlay).unwrap();
        let sinks = load_shell_sink_profiles(&profile).unwrap();
        analyze_script("test.sh", text, &profile, &sinks).unwrap()
    }

    /// Writes an overlay to a temp file so the overlay tests exercise the same
    /// operator-supplied path the CLI uses.
    fn overlay_file(body: &str) -> tempfile::NamedTempFile {
        use std::io::Write;
        let mut file = tempfile::Builder::new().suffix(".yaml").tempfile().unwrap();
        file.write_all(body.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    /// The overlay an operator writes once they have established that `/tmp` is
    /// attacker-writable on the target. Tests about *sink* matching use it so
    /// that `sh /tmp/...` has a source to hang off; the base profile makes no
    /// such claim on its own.
    const TMP_WRITABLE_OVERLAY: &str = r#"
name: shell-example-tmp
sources:
  primary:
    - name: writable-mount-read
      kind: path-prefix
      paths: ["/tmp/"]
"#;

    fn analyze_with_tmp_writable(text: &str) -> Vec<ShellFlow> {
        let overlay = overlay_file(TMP_WRITABLE_OVERLAY);
        analyze_with_profile(text, Some(overlay.path()))
    }

    // ── The motivating chain (CVE-2024-6247 shape, synthesized) ─────────────

    /// Reproduces the *shape* of a Wyze Cam v3 `wifi.sh` chain: a `/configs` provisioning file is read into a variable, the
    /// variable is copied, and the copy lands unquoted inside a `sed -i`
    /// replacement expression.
    #[test]
    fn wyze_wifi_sh_shaped_chain_is_reported_end_to_end() {
        let script = concat!(
            "#!/bin/sh\n",
            "key=ssid\n",
            "file=/etc/wifi.conf\n",
            "wifissid=$(cat /configs/.wifissid)\n",
            "newvalue=\"$wifissid\"\n",
            "sed -i \"s/$key=.*/$key=$newvalue/g\" $file\n",
        );
        let flows = analyze(script);

        let flow = flows
            .iter()
            .find(|f| f.sink.family == "sed-var-injection")
            .expect("sed-var-injection flow");
        assert_eq!(flow.sink.line, 6);
        assert_eq!(flow.sink.severity, Severity::High);
        assert_eq!(flow.source.label, "cat /configs/.wifissid");
        // The read is reported, but the path's name alone does not establish
        // that an attacker controls the file: that is the operator's assertion
        // to make, so the base profile leaves this Secondary.
        assert_eq!(flow.source.class, SourceClass::Secondary);
        assert!(flow.source.writable_mount.is_none());
        assert_eq!(flow.function, "<toplevel>");

        let hops: Vec<(&str, &str, u32)> = flow
            .hops
            .iter()
            .map(|hop| (hop.from.as_str(), hop.variable.as_str(), hop.line))
            .collect();
        assert_eq!(
            hops,
            vec![
                ("cat /configs/.wifissid", "wifissid", 4),
                ("$wifissid", "newvalue", 5),
            ]
        );
    }

    #[test]
    fn wyze_shaped_chain_maps_onto_the_taint_finding_shape() {
        let script = concat!(
            "#!/bin/sh\n",
            "wifissid=$(cat /configs/.wifissid)\n",
            "newvalue=\"$wifissid\"\n",
            "sed -i \"s/$key=.*/$key=$newvalue/g\" $file\n",
        );
        let flows = analyze(script);
        let findings = flows_to_findings(&flows);
        let finding = findings
            .iter()
            .find(|f| f.title.contains("sed-var-injection"))
            .expect("sed finding");

        assert_eq!(finding.id, "SHELL-0001");
        assert_eq!(finding.severity, FindingSeverity::High);
        assert_eq!(finding.source_class, SourceClass::Secondary);
        // Shell taint is an overlay tier: always Candidate / WEAK, never Proven.
        assert_eq!(finding.status, crate::FindingStatus::Candidate);
        assert_eq!(finding.strength_band(), "WEAK");
        assert!(
            (finding.confidence - 0.30).abs() < 1e-9,
            "{}",
            finding.confidence
        );
        assert_eq!(finding.chain.len(), 3);
        assert_eq!(
            finding.chain[0].action,
            "cat /configs/.wifissid → $wifissid"
        );
        assert_eq!(finding.chain[1].action, "$wifissid → $newvalue");
        assert!(finding.chain[2].action.contains("[sed-var-injection]"));
        assert_eq!(finding.chain[0].location, "test.sh:2");
        assert_eq!(finding.chain[2].location, "test.sh:4");
        for step in &finding.chain {
            assert!(matches!(step.edge_type, EdgeType::ShellModel { .. }));
        }
    }

    #[test]
    fn findings_serialize_with_the_same_json_keys_as_binary_taint() {
        let flows = analyze("X=$(cat /tmp/cmd)\neval \"$X\"\n");
        let findings = flows_to_findings(&flows);
        let json = serde_json::to_value(&findings).unwrap();
        let first = &json[0];
        for key in [
            "id",
            "title",
            "severity",
            "chain",
            "status",
            "status_reason",
            "confidence",
            "source_class",
        ] {
            assert!(!first[key].is_null(), "missing key {key}: {first}");
        }
        for key in ["binary", "function", "location", "action", "edge_type"] {
            assert!(
                !first["chain"][0][key].is_null(),
                "missing chain key {key}: {first}"
            );
        }
        // Round-trips back into the shared model.
        let parsed: Vec<TaintFinding> = serde_json::from_value(json).unwrap();
        assert_eq!(parsed.len(), findings.len());
    }

    // ── AST precision: the concrete win over the regex pass ────────────────

    #[test]
    fn comments_never_produce_a_sink() {
        let flows = analyze("X=$(cat /tmp/f)\n# eval \"$X\" would be bad\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    #[test]
    fn single_quoted_strings_never_produce_a_sink() {
        let flows = analyze("X=$(cat /tmp/f)\necho 'eval $X'\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    #[test]
    fn heredoc_bodies_never_produce_a_sink() {
        let flows = analyze("X=$(cat /tmp/f)\ncat <<HEOF\neval $X\nHEOF\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    #[test]
    fn case_labels_never_produce_a_sink() {
        let flows = analyze("X=$(cat /tmp/f)\ncase $mode in\n  eval) echo hi ;;\nesac\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    #[test]
    fn double_quoted_expansion_still_produces_a_sink() {
        let flows = analyze("X=$(cat /tmp/f)\neval \"$X\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "dynamic-eval");
        assert_eq!(flows[0].sink.line, 2);
    }

    // ── Provenance requirement ─────────────────────────────────────────────

    #[test]
    fn sink_pattern_without_a_source_is_not_a_taint_finding() {
        // `eval` on a literal has no provenance; sink-discovery reports it,
        // shell taint does not.
        let flows = analyze("#!/bin/sh\neval \"echo hello\"\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    #[test]
    fn overwriting_a_tainted_variable_with_a_constant_kills_the_taint() {
        let flows = analyze("X=$(cat /tmp/f)\nX=safe\neval \"$X\"\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    // ── Source coverage ────────────────────────────────────────────────────

    #[test]
    fn positional_parameters_are_primary_sources() {
        let flows = analyze("#!/bin/sh\ndev=$1\nmount $dev /mnt/data\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "unquoted-var-as-path");
        assert_eq!(flows[0].source.kind, ShellSourceKind::Positional);
        assert_eq!(flows[0].source.label, "$1");
        assert_eq!(flows[0].source.class, SourceClass::Primary);
    }

    /// Regression on the `fat taint --lang shell` path: the
    /// digit-suffixed mkfs variants are the common ones in firmware and were
    /// silently unreachable as sinks.
    #[test]
    fn digit_suffixed_mkfs_variants_are_sinks() {
        for line in [
            "mkfs.ext2 $dev",
            "mkfs.ext4 $dev",
            "mkfs.f2fs $dev",
            "mkfs.jffs2 $dev",
            // Already matched before the fix; must keep matching.
            "mkfs.vfat $dev",
            "mount $dev /mnt/data",
        ] {
            let flows = analyze(&format!("#!/bin/sh\ndev=$1\n{line}\n"));
            assert_eq!(flows.len(), 1, "{line}: {flows:?}");
            assert_eq!(flows[0].sink.family, "unquoted-var-as-path", "{line}");
            assert_eq!(flows[0].source.label, "$1", "{line}");
        }

        // `mountpoint` merely starts with `mount`; it is not a path sink.
        let flows = analyze("#!/bin/sh\ndev=$1\nmountpoint -q $dev\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    /// Regression on the `fat taint --lang shell` path: a bare
    /// command-name anchor also matched inside a longer word, so unrelated
    /// commands were reported as sinks. The leading `\b` must not cost the
    /// absolute-path invocations, which stay matchable because `/` is a
    /// non-word character.
    #[test]
    fn command_names_embedded_in_longer_words_are_not_sinks() {
        // (script body, expected family) — plain and absolute-path forms.
        for (body, family) in [
            (
                "ver=$1\nsed -i \"s/old/$ver/g\" /etc/config\n",
                "sed-var-injection",
            ),
            (
                "ver=$1\n/bin/sed -i \"s/old/$ver/g\" /etc/config\n",
                "sed-var-injection",
            ),
            ("mod=$1\ninsmod $mod\n", "insmod-var-path"),
            ("mod=$1\n/sbin/insmod $mod\n", "insmod-var-path"),
            ("c=$1\nsh -c \"$c\"\n", "sh-c-var"),
            ("c=$1\n/bin/sh -c \"$c\"\n", "sh-c-var"),
        ] {
            let flows = analyze(&format!("#!/bin/sh\n{body}"));
            assert_eq!(flows.len(), 1, "{body}: {flows:?}");
            assert_eq!(flows[0].sink.family, family, "{body}");
            assert_eq!(flows[0].source.label, "$1", "{body}");
        }

        // `tmpfs-staged-exec` takes its source from the `/tmp/` literal once an
        // overlay declares that mount writable, so it needs no intermediate
        // variable.
        for body in ["sh /tmp/run.sh\n", "/bin/sh /tmp/run.sh\n"] {
            let flows = analyze_with_tmp_writable(&format!("#!/bin/sh\n{body}"));
            assert_eq!(flows.len(), 1, "{body}: {flows:?}");
            assert_eq!(flows[0].sink.family, "tmpfs-staged-exec", "{body}");
        }

        // The false positives from the issue: none of these is a shell sink.
        for body in [
            "ver=$1\nparsed -i \"s/old/$ver/g\" /etc/config\n",
            "mod=$1\nxinsmod $mod\n",
            "c=$1\nflush -c \"$c\"\n",
            "flash /tmp/run.sh\n",
        ] {
            let flows = analyze(&format!("#!/bin/sh\n{body}"));
            assert!(flows.is_empty(), "{body}: {flows:?}");
        }
    }

    /// Shell-alternation regression on the `fat taint --lang
    /// shell` path. `ash` is busybox's shell, so `ash -c "$x"` is the single
    /// most likely shape of this sink in a real rootfs; a bare `\bsh` anchor
    /// dropped it entirely. Every named shell must produce a flow, plain and
    /// by absolute path, and no word that merely ends in a shell name may.
    #[test]
    fn every_named_shell_is_a_sink_and_no_longer_word_is() {
        const SHELL_NAMES: &[&str] = &["sh", "ash", "bash", "dash", "hush", "mksh", "ksh"];
        const NOT_SHELLS: &[&str] = &["flush", "refresh", "publish", "flash", "splash"];

        for shell in SHELL_NAMES {
            for invocation in [
                shell.to_string(),
                format!("/bin/{shell}"),
                format!("/system/bin/{shell}"),
                format!("busybox {shell}"),
            ] {
                // `sh-c-var`: the command string carries the tainted variable.
                let script = format!("#!/bin/sh\nc=$1\n{invocation} -c \"$c\"\n");
                let flows = analyze(&script);
                assert_eq!(flows.len(), 1, "{invocation} -c: {flows:?}");
                assert_eq!(flows[0].sink.family, "sh-c-var", "{invocation} -c");
                assert_eq!(flows[0].source.label, "$1", "{invocation} -c");

                // `tmpfs-staged-exec`: the `/tmp/` literal is itself the source
                // once the overlay declares that mount writable.
                let script = format!("#!/bin/sh\n{invocation} /tmp/run.sh\n");
                let flows = analyze_with_tmp_writable(&script);
                assert_eq!(flows.len(), 1, "{invocation} /tmp/: {flows:?}");
                assert_eq!(
                    flows[0].sink.family, "tmpfs-staged-exec",
                    "{invocation} /tmp/"
                );
                assert_eq!(flows[0].source.label, "/tmp/run.sh", "{invocation} /tmp/");
            }
        }

        for word in NOT_SHELLS {
            for invocation in [word.to_string(), format!("/usr/sbin/{word}")] {
                let flows = analyze(&format!("#!/bin/sh\nc=$1\n{invocation} -c \"$c\"\n"));
                assert!(flows.is_empty(), "{invocation} -c: {flows:?}");

                let flows =
                    analyze_with_tmp_writable(&format!("#!/bin/sh\n{invocation} /tmp/run.sh\n"));
                assert!(flows.is_empty(), "{invocation} /tmp/: {flows:?}");
            }
        }
    }

    #[test]
    fn cgi_environment_variables_are_primary_sources() {
        let flows = analyze("#!/bin/sh\nq=$QUERY_STRING\neval \"$q\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].source.kind, ShellSourceKind::Environment);
        assert_eq!(flows[0].source.label, "$QUERY_STRING");
        assert_eq!(flows[0].source.class, SourceClass::Primary);
    }

    #[test]
    fn read_builtin_binds_a_primary_source() {
        let flows = analyze("#!/bin/sh\nread -r line\neval \"$line\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].source.name, "read");
        assert_eq!(flows[0].source.class, SourceClass::Primary);
        assert_eq!(flows[0].hops[0].variable, "line");
    }

    #[test]
    fn uci_get_is_a_secondary_source() {
        let flows = analyze("#!/bin/sh\nip=$(uci get network.lan.ipaddr)\neval \"$ip\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].source.name, "uci");
        assert_eq!(flows[0].source.class, SourceClass::Secondary);
        assert_eq!(flows[0].source.label, "uci get network.lan.ipaddr");
    }

    #[test]
    fn uci_without_the_get_argv_prefix_is_not_a_source() {
        let flows = analyze("#!/bin/sh\nx=$(uci show network)\neval \"$x\"\n");
        assert!(flows.is_empty(), "{flows:?}");
    }

    /// A platform's nvram helper is not a core model: the base profile has no
    /// entry for it, and an overlay is what makes it a source.
    #[test]
    fn a_platform_nvram_helper_needs_an_overlay() {
        let script = "#!/bin/sh\nv=`nvram_get boot_cmd`\neval \"$v\"\n";
        assert!(analyze(script).is_empty(), "nvram_get is not a core model");

        let overlay = overlay_file(
            "name: shell-example\nsources:\n  secondary:\n    - name: nvram_get\n      kind: command\n",
        );
        let flows = analyze_with_profile(script, Some(overlay.path()));
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].source.name, "nvram_get");
        assert_eq!(flows[0].source.class, SourceClass::Secondary);
    }

    /// A literal path in the sink is provenance only once an overlay says the
    /// mount is attacker-writable. Without one there is no source, so the sink
    /// hit belongs to `fat sink-discovery`, which reports sinks without claiming
    /// a source.
    #[test]
    fn a_path_literal_in_the_sink_is_a_source_only_under_a_supplied_overlay() {
        let script = "#!/bin/sh\nsh /tmp/factory_run.sh\n";
        assert!(
            analyze(script).is_empty(),
            "a path name alone established attacker control"
        );

        let overlay = overlay_file(
            r#"
name: shell-example
sources:
  primary:
    - name: writable-mount-read
      kind: path-prefix
      paths: ["/tmp/"]
"#,
        );
        let flows = analyze_with_profile(script, Some(overlay.path()));
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "tmpfs-staged-exec");
        assert_eq!(flows[0].source.kind, ShellSourceKind::PathPrefix);
        assert_eq!(flows[0].source.label, "/tmp/factory_run.sh");
        assert!(flows[0].hops.is_empty());

        let findings = flows_to_findings(&flows);
        assert_eq!(findings[0].chain.len(), 2);
        assert_eq!(findings[0].chain[0].action, "/tmp/factory_run.sh");
    }

    /// The two reads differ only in the directory they name. Neither file has
    /// to exist and neither script is executed, so with no overlay the two must
    /// be classified identically — a directory name is not evidence.
    #[test]
    fn a_path_name_alone_never_raises_the_source_class() {
        for path in [
            "/configs/value",
            "/config/value",
            "/mnt/sdcard/value",
            "/tmp/value",
            "/run/value",
            "/etc/value",
        ] {
            let flows = analyze(&format!("#!/bin/sh\nv=$(cat {path})\neval \"$v\"\n"));
            assert_eq!(flows.len(), 1, "{path}: {flows:?}");
            assert_eq!(
                flows[0].source.class,
                SourceClass::Secondary,
                "{path} was promoted on its name alone"
            );
            assert!(
                flows[0].source.writable_mount.is_none(),
                "{path} claimed a writable mount"
            );
        }
    }

    // ── Propagation shapes ─────────────────────────────────────────────────

    #[test]
    fn taint_propagates_through_a_for_loop_variable() {
        let flows =
            analyze("#!/bin/sh\nlist=$(cat /tmp/mods)\nfor m in $list; do insmod $m; done\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "insmod-var-path");
        assert_eq!(flows[0].hops.len(), 2);
        assert_eq!(flows[0].hops[1].variable, "m");
    }

    #[test]
    fn function_context_is_recorded_on_the_finding() {
        let flows = analyze("#!/bin/sh\nrun() {\n  local c=$1\n  sh -c \"$c\"\n}\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].function, "run");
        assert_eq!(flows[0].sink.family, "sh-c-var");
    }

    #[test]
    fn a_source_embedded_in_the_sink_needs_no_intermediate_variable() {
        let flows = analyze("#!/bin/sh\neval \"$(cat /tmp/payload)\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "dynamic-eval");
        assert!(flows[0].hops.is_empty());
        assert_eq!(flows[0].source.label, "cat /tmp/payload");
    }

    #[test]
    fn one_sink_line_reports_each_matched_family_once() {
        let flows = analyze("#!/bin/sh\nd=$1\ncp $d /tmp/out\n");
        let families: Vec<&str> = flows.iter().map(|f| f.sink.family.as_str()).collect();
        assert!(families.contains(&"unquoted-var-as-path"), "{families:?}");
        let mut deduped = families.clone();
        deduped.sort_unstable();
        deduped.dedup();
        assert_eq!(
            families.len(),
            deduped.len(),
            "duplicate families {families:?}"
        );
    }

    #[test]
    fn findings_are_numbered_in_report_order() {
        let flows = analyze("#!/bin/sh\na=$1\neval \"$a\"\nb=$2\nsh -c \"$b\"\n");
        let findings = flows_to_findings(&flows);
        assert!(findings.len() >= 2, "{findings:?}");
        assert_eq!(findings[0].id, "SHELL-0001");
        assert_eq!(findings[1].id, "SHELL-0002");
    }

    // ── Operator-supplied overlay ──────────────────────────────────────────

    #[test]
    fn a_supplied_overlay_promotes_a_path_to_a_writable_mount() {
        let script = "#!/bin/sh\nv=$(cat /params/boot_cmd)\neval \"$v\"\n";
        let base = analyze(script);
        assert_eq!(base[0].source.class, SourceClass::Secondary);
        assert!(base[0].source.writable_mount.is_none());

        let overlay = overlay_file(
            r#"
name: shell-example
sources:
  primary:
    - name: writable-mount-read
      kind: path-prefix
      paths: ["/params/"]
"#,
        );
        let overlaid = analyze_with_profile(script, Some(overlay.path()));
        assert_eq!(overlaid[0].source.class, SourceClass::Primary);
        assert_eq!(
            overlaid[0].source.writable_mount.as_deref(),
            Some("/params/")
        );
    }

    #[test]
    fn a_supplied_overlay_adds_a_platform_command_as_a_source() {
        let script = "#!/bin/sh\nv=$(config_get cfg option)\neval \"$v\"\n";
        assert!(
            analyze(script).is_empty(),
            "a platform config command is not a core model"
        );

        let overlay = overlay_file(
            r#"
name: shell-example
sources:
  secondary:
    - name: config_get
      kind: command
"#,
        );
        let overlaid = analyze_with_profile(script, Some(overlay.path()));
        assert_eq!(overlaid.len(), 1, "{overlaid:?}");
        assert_eq!(overlaid[0].source.name, "config_get");
    }

    // ── Robustness ─────────────────────────────────────────────────────────

    #[test]
    fn truncated_script_still_yields_flows_from_the_recovered_commands() {
        // Missing `fi`. tree-sitter inserts a MISSING node and keeps the rest
        // of the tree intact — the property that makes it usable on the
        // half-broken busybox-ash scripts that ship in firmware.
        let flows = analyze("#!/bin/sh\nv=$(cat /tmp/x)\nif [ -n \"$v\" ]; then\neval \"$v\"\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "dynamic-eval");
    }

    #[test]
    fn hard_syntax_errors_recover_rather_than_failing_the_run() {
        // `done` with no loop: the whole body lands under an ERROR node, but
        // the well-formed commands inside it are still typed.
        let flows = analyze("#!/bin/sh\nv=$(cat /tmp/x)\nif [ -n $v ]\neval \"$v\"\ndone\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "dynamic-eval");
    }

    #[test]
    fn an_unterminated_quote_is_not_an_error() {
        // The closing quote never arrives; tree-sitter still types the command
        // and the flow survives. The contract is only that this does not fail
        // the run.
        let flows = analyze("#!/bin/sh\nv=$(cat /tmp/x)\neval \"$v\n");
        assert_eq!(flows.len(), 1, "{flows:?}");
        assert_eq!(flows[0].sink.family, "dynamic-eval");
    }

    #[test]
    fn empty_script_yields_no_flows() {
        assert!(analyze("").is_empty());
    }

    #[test]
    fn analyze_rootfs_walks_scripts_and_reports_relative_paths() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("wyze_app/init")).unwrap();
        std::fs::write(
            dir.path().join("wyze_app/init/wifi.sh"),
            "#!/bin/sh\nwifissid=$(cat /configs/.wifissid)\nsed -i \"s/ssid=.*/ssid=$wifissid/g\" /etc/wifi.conf\n",
        )
        .unwrap();
        std::fs::write(
            dir.path().join("factory"),
            "#!/bin/sh\nsh /tmp/factory_run.sh\n",
        )
        .unwrap();
        std::fs::write(dir.path().join("notes.txt"), "eval $x\n").unwrap();

        // The `/tmp` chain needs the operator's claim that the mount is
        // writable; the `cat` chain does not.
        let overlay = overlay_file(TMP_WRITABLE_OVERLAY);
        let profile = load_shell_profile(Some(overlay.path())).unwrap();
        let sinks = load_shell_sink_profiles(&profile).unwrap();
        let report = analyze_rootfs(dir.path(), &profile, &sinks).unwrap();

        assert_eq!(report.summary.files_scanned, 2);
        assert_eq!(report.summary.scripts_with_flows, 2);
        assert_eq!(report.summary.flows, 2);
        assert_eq!(report.profile, "shell-base+shell-example-tmp");
        assert_eq!(report.sink_profiles, vec!["shell-command-exec".to_string()]);

        let scripts: Vec<&str> = report.flows.iter().map(|f| f.script.as_str()).collect();
        assert!(scripts.contains(&"wyze_app/init/wifi.sh"), "{scripts:?}");
        assert!(scripts.contains(&"factory"), "{scripts:?}");
        assert_eq!(report.summary.families.get("sed-var-injection"), Some(&1));
        assert_eq!(report.summary.families.get("tmpfs-staged-exec"), Some(&1));
    }

    #[test]
    fn rootfs_report_serializes_to_json() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("run.sh"), "#!/bin/sh\nc=$1\nsh -c \"$c\"\n").unwrap();
        let profile = load_shell_profile(None).unwrap();
        let sinks = load_shell_sink_profiles(&profile).unwrap();
        let report = analyze_rootfs(dir.path(), &profile, &sinks).unwrap();
        let json = serde_json::to_value(&report).unwrap();
        assert_eq!(json["flows"][0]["sink"]["family"], "sh-c-var");
        assert_eq!(json["flows"][0]["source"]["kind"], "positional");
        assert_eq!(json["summary"]["flows"], 1);
    }
}
