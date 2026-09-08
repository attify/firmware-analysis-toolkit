//! Binary reconnaissance via rabin2 and r2pipe.
//!
//! One-shot queries (profile, exports, imports, strings, libraries) use `rabin2`
//! directly via `std::process::Command`. The `function_list` query opens an r2pipe
//! session to run `aaa; aflj`.

use serde::Deserialize;
use std::path::Path;

// ── Public data structs ──────────────────────────────────────────────────────

/// High-level binary profile extracted from `rabin2 -Ij`.
#[derive(Debug, Clone)]
pub struct BinaryProfile {
    pub arch: String,
    pub bits: u32,
    pub compiler: String,
    pub canary: bool,
    pub nx: bool,
    pub pie: bool,
    pub relro: String,
    pub stripped: bool,
    pub class: String,
}

#[derive(Debug, Clone)]
pub struct Export {
    pub name: String,
    pub size: u64,
}

#[derive(Debug, Clone)]
pub struct Import {
    pub name: String,
}

#[derive(Debug, Clone)]
pub struct BinaryString {
    pub value: String,
    pub address: u64,
    pub length: usize,
}

#[derive(Debug, Clone)]
pub struct FunctionInfo {
    pub name: String,
    pub address: u64,
    pub size: u64,
    pub basic_blocks: u64,
    pub cyclomatic_complexity: u64,
}

#[derive(Debug, Clone)]
pub struct ConstantCallsiteArg {
    pub callsite_addr: u64,
    pub constant_addr: Option<u64>,
}

#[derive(Debug, Clone, Default)]
pub struct R2OpenOptions {
    pub arch: Option<String>,
    pub bits: Option<u32>,
    pub base: Option<u32>,
    pub cpu: Option<String>,
}

// ── Internal deserialization helpers ─────────────────────────────────────────

/// Represents the full JSON blob returned by `rabin2 -Ij`.
#[derive(Deserialize)]
struct Rabin2InfoRoot {
    info: Option<Rabin2Info>,
}

#[derive(Deserialize)]
struct Rabin2Info {
    #[serde(default)]
    arch: String,
    #[serde(default)]
    bits: u32,
    #[serde(default)]
    compiler: String,
    #[serde(default)]
    canary: bool,
    #[serde(default)]
    nx: bool,
    #[serde(default)]
    pic: bool,
    #[serde(default)]
    relro: String,
    #[serde(default)]
    stripped: bool,
    #[serde(default)]
    class: String,
}

#[derive(Deserialize)]
struct Rabin2ExportEntry {
    #[serde(default)]
    name: String,
    #[serde(default)]
    size: u64,
}

#[derive(Deserialize)]
struct Rabin2ImportEntry {
    #[serde(default)]
    name: String,
}

#[derive(Deserialize)]
struct Rabin2StringEntry {
    #[serde(default, alias = "string")]
    string: String,
    #[serde(default, alias = "vaddr")]
    vaddr: u64,
    #[serde(default)]
    length: usize,
}

#[derive(Deserialize)]
struct AflEntry {
    #[serde(default)]
    name: String,
    #[serde(default, alias = "addr")]
    offset: u64,
    #[serde(default)]
    size: u64,
    #[serde(default)]
    nbbs: u64,
    #[serde(default)]
    cc: u64,
}

#[derive(Debug, Deserialize)]
struct XrefEntry {
    #[serde(default)]
    from: u64,
    #[serde(default)]
    fcn_addr: u64,
    #[serde(default)]
    r#type: String,
}

#[derive(Debug, Deserialize)]
struct DisasmRef {
    #[serde(default)]
    addr: u64,
    #[serde(default)]
    r#type: String,
}

#[derive(Debug, Deserialize)]
struct DisasmEntry {
    #[serde(default)]
    addr: u64,
    #[serde(default)]
    disasm: String,
    #[serde(default)]
    opcode: String,
    #[serde(default)]
    refs: Vec<DisasmRef>,
}

// ── Parsing functions (pure, no I/O) ────────────────────────────────────────

/// Parse `BinaryProfile` from the JSON string returned by `rabin2 -Ij`.
pub fn parse_binary_profile(json_str: &str) -> Result<BinaryProfile, String> {
    let root: Rabin2InfoRoot = serde_json::from_str(strip_rabin2_json_prefix(json_str))
        .map_err(|e| format!("failed to parse rabin2 -Ij JSON: {e}"))?;

    let info = root
        .info
        .ok_or_else(|| "rabin2 -Ij: missing 'info' key".to_string())?;

    Ok(BinaryProfile {
        arch: info.arch,
        bits: info.bits,
        compiler: info.compiler,
        canary: info.canary,
        nx: info.nx,
        pie: info.pic,
        relro: if info.relro.is_empty() {
            "none".to_string()
        } else {
            info.relro
        },
        stripped: info.stripped,
        class: info.class,
    })
}

/// Parse exports from the JSON string returned by `rabin2 -Ej`.
///
/// Handles both bare arrays `[{...}]` and wrapped objects `{"exports": [{...}]}`.
pub fn parse_exports(json_str: &str) -> Result<Vec<Export>, String> {
    let json_str = strip_rabin2_json_prefix(json_str);
    let entries: Vec<Rabin2ExportEntry> = if let Ok(arr) = serde_json::from_str(json_str) {
        arr
    } else {
        // Try wrapped format: {"exports": [...]}
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("failed to parse rabin2 -Ej JSON: {e}"))?;
        let arr = val
            .get("exports")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "rabin2 -Ej: expected array or object with 'exports' key".to_string())?;
        serde_json::from_value(serde_json::Value::Array(arr.clone()))
            .map_err(|e| format!("failed to parse exports array: {e}"))?
    };

    Ok(entries
        .into_iter()
        .map(|e| Export {
            name: e.name,
            size: e.size,
        })
        .collect())
}

/// Parse imports from the JSON string returned by `rabin2 -ij`.
///
/// Handles both bare arrays `[{...}]` and wrapped objects `{"imports": [{...}]}`.
pub fn parse_imports(json_str: &str) -> Result<Vec<Import>, String> {
    let json_str = strip_rabin2_json_prefix(json_str);
    let entries: Vec<Rabin2ImportEntry> = if let Ok(arr) = serde_json::from_str(json_str) {
        arr
    } else {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("failed to parse rabin2 -ij JSON: {e}"))?;
        let arr = val
            .get("imports")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "rabin2 -ij: expected array or object with 'imports' key".to_string())?;
        serde_json::from_value(serde_json::Value::Array(arr.clone()))
            .map_err(|e| format!("failed to parse imports array: {e}"))?
    };

    Ok(entries
        .into_iter()
        .map(|e| Import { name: e.name })
        .collect())
}

/// Parse strings from the JSON string returned by `rabin2 -zj`, filtering by minimum length.
///
/// Handles both bare arrays `[{...}]` and wrapped objects `{"strings": [{...}]}`.
pub fn parse_strings(json_str: &str, min_len: usize) -> Result<Vec<BinaryString>, String> {
    let json_str = strip_rabin2_json_prefix(json_str);
    let entries: Vec<Rabin2StringEntry> = if let Ok(arr) = serde_json::from_str(json_str) {
        arr
    } else {
        let val: serde_json::Value = serde_json::from_str(json_str)
            .map_err(|e| format!("failed to parse rabin2 -zj JSON: {e}"))?;
        let arr = val
            .get("strings")
            .and_then(|v| v.as_array())
            .ok_or_else(|| "rabin2 -zj: expected array or object with 'strings' key".to_string())?;
        serde_json::from_value(serde_json::Value::Array(arr.clone()))
            .map_err(|e| format!("failed to parse strings array: {e}"))?
    };

    Ok(entries
        .into_iter()
        .filter(|e| e.length >= min_len)
        .map(|e| BinaryString {
            value: e.string,
            address: e.vaddr,
            length: e.length,
        })
        .collect())
}

/// Parse linked libraries from the JSON returned by `rabin2 -lj`.
///
/// rabin2 -lj may return a flat array of strings: `["libc.so.6","libpthread.so.0"]`
/// or an array of objects: `[{"name":"libc.so.6"}]`, or an object with a `libs` key.
pub fn parse_linked_libraries(json_str: &str) -> Result<Vec<String>, String> {
    let json_str = strip_rabin2_json_prefix(json_str);
    // Try as an object with a "libs" key first.
    if let Ok(obj) = serde_json::from_str::<serde_json::Value>(json_str) {
        if let Some(libs_arr) = obj.get("libs").and_then(|v| v.as_array()) {
            let mut result = Vec::new();
            for item in libs_arr {
                if let Some(s) = item.as_str() {
                    result.push(s.to_string());
                } else if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                    result.push(name.to_string());
                }
            }
            return Ok(result);
        }
        // Try as a flat array.
        if let Some(arr) = obj.as_array() {
            let mut result = Vec::new();
            for item in arr {
                if let Some(s) = item.as_str() {
                    result.push(s.to_string());
                } else if let Some(name) = item.get("name").and_then(|v| v.as_str()) {
                    result.push(name.to_string());
                }
            }
            return Ok(result);
        }
    }
    Err("failed to parse rabin2 -lj JSON".to_string())
}

/// Parse function list from the JSON string returned by r2 `aflj`.
pub fn parse_function_list(json_str: &str) -> Result<Vec<FunctionInfo>, String> {
    let json_str = strip_rabin2_json_prefix(json_str);
    let entries: Vec<AflEntry> =
        serde_json::from_str(json_str).map_err(|e| format!("failed to parse aflj JSON: {e}"))?;

    Ok(entries
        .into_iter()
        .map(|e| FunctionInfo {
            name: e.name,
            address: e.offset,
            size: e.size,
            basic_blocks: e.nbbs,
            cyclomatic_complexity: e.cc,
        })
        .collect())
}

pub(crate) fn strip_rabin2_json_prefix(text: &str) -> &str {
    let trimmed = text.trim_start();
    if trimmed.starts_with('{') || trimmed.starts_with('[') {
        return trimmed;
    }
    let object_start = trimmed.find('{');
    let array_start = trimmed.find('[');
    match (object_start, array_start) {
        (Some(obj), Some(arr)) => {
            let start = obj.min(arr);
            &trimmed[start..]
        }
        (Some(obj), None) => &trimmed[obj..],
        (None, Some(arr)) => &trimmed[arr..],
        (None, None) => trimmed,
    }
}

// ── Live I/O functions (call rabin2 / r2pipe) ───────────────────────────────

/// Run a rabin2 command and return its stdout as a string.
fn run_rabin2(args: &[&str], path: &Path) -> Result<String, String> {
    let mut cmd_args: Vec<&str> = args.to_vec();
    let path_str = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    cmd_args.push(path_str);

    let output = std::process::Command::new("rabin2")
        .args(&cmd_args)
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "rabin2 not found — install radare2 (https://github.com/radareorg/radare2)"
                    .to_string()
            } else {
                format!("failed to run rabin2: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("rabin2 exited with error: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("rabin2 output is not valid UTF-8: {e}"))
}

fn run_r2(script: &str, path: &Path) -> Result<String, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    let output = std::process::Command::new("r2")
        .args([
            "-q",
            "-e",
            "scr.color=0",
            "-e",
            "bin.relocs.apply=true",
            "-c",
            script,
            path_str,
        ])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "r2 not found — install radare2 (https://github.com/radareorg/radare2)".to_string()
            } else {
                format!("failed to run r2: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("r2 exited with error: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("r2 output is not valid UTF-8: {e}"))
}

fn build_spawn_args(options: Option<&R2OpenOptions>) -> Vec<String> {
    let mut args = vec![
        "-2".to_string(),
        "-e".to_string(),
        "bin.relocs.apply=true".to_string(),
        "-e".to_string(),
        "scr.color=0".to_string(),
        "-e".to_string(),
        "scr.interactive=false".to_string(),
    ];

    if let Some(options) = options {
        if let Some(arch) = options.arch.as_deref() {
            args.push("-a".to_string());
            args.push(arch.to_string());
        }
        if let Some(bits) = options.bits {
            args.push("-b".to_string());
            args.push(bits.to_string());
        }
        if let Some(base) = options.base {
            args.push("-m".to_string());
            args.push(format!("0x{base:08x}"));
        }
        if let Some(cpu) = options.cpu.as_deref() {
            args.push("-e".to_string());
            args.push(format!("asm.cpu={cpu}"));
        }
    }

    args
}

fn leak_spawn_args(args: &[String]) -> Vec<&'static str> {
    args.iter()
        .cloned()
        .map(|arg| Box::leak(arg.into_boxed_str()) as &'static str)
        .collect()
}

/// Extract binary profile via `rabin2 -Ij`.
pub fn binary_profile(path: &Path) -> Result<BinaryProfile, String> {
    let json_str = run_rabin2(&["-Ij"], path)?;
    parse_binary_profile(&json_str)
}

/// Extract exports via `rabin2 -Ej`.
pub fn exports(path: &Path) -> Result<Vec<Export>, String> {
    let json_str = run_rabin2(&["-Ej"], path)?;
    parse_exports(&json_str)
}

/// Extract imports via `rabin2 -ij`.
pub fn imports(path: &Path) -> Result<Vec<Import>, String> {
    let json_str = run_rabin2(&["-ij"], path)?;
    parse_imports(&json_str)
}

/// Extract strings via `rabin2 -zj`, filtering by minimum length.
pub fn strings(path: &Path, min_len: usize) -> Result<Vec<BinaryString>, String> {
    let json_str = run_rabin2(&["-zj"], path)?;
    parse_strings(&json_str, min_len)
}

/// Extract linked libraries via `rabin2 -lj`.
pub fn linked_libraries(path: &Path) -> Result<Vec<String>, String> {
    let json_str = run_rabin2(&["-lj"], path)?;
    parse_linked_libraries(&json_str)
}

/// Extract function list via r2pipe (`aaa; aflj`).
///
/// This opens an r2 session, runs full analysis, then queries the function list.
pub fn function_list(path: &Path) -> Result<Vec<FunctionInfo>, String> {
    function_list_with_options(path, None)
}

pub fn function_list_with_options(
    path: &Path,
    options: Option<&R2OpenOptions>,
) -> Result<Vec<FunctionInfo>, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    let spawn_opts = r2pipe::R2PipeSpawnOptions {
        args: leak_spawn_args(&build_spawn_args(options)),
        ..Default::default()
    };

    let mut r2 = r2pipe::R2Pipe::spawn(path_str, Some(spawn_opts))
        .map_err(|e| format!("failed to open r2 session — is radare2 installed? error: {e}"))?;

    let json_str = r2
        .cmd("aaa; aflj")
        .map_err(|e| format!("r2 aflj failed: {e}"))?;
    r2.close();

    // r2 may return empty string if no functions found.
    if json_str.trim().is_empty() || json_str.trim() == "[]" {
        return Ok(Vec::new());
    }

    parse_function_list(&json_str)
}

/// Extract a small entrypoint disassembly snippet via r2.
///
/// Uses reloc application so early symbol references are more readable in thin
/// launcher/bootstrapper binaries.
pub fn entrypoint_disassembly(path: &Path, instruction_count: usize) -> Result<String, String> {
    let path_str = path
        .to_str()
        .ok_or_else(|| "path is not valid UTF-8".to_string())?;
    let script = format!("s entry0; pd {instruction_count}");

    let output = std::process::Command::new("r2")
        .args([
            "-e",
            "scr.color=0",
            "-e",
            "bin.relocs.apply=true",
            "-Aqc",
            &script,
            path_str,
        ])
        .output()
        .map_err(|e| {
            if e.kind() == std::io::ErrorKind::NotFound {
                "r2 not found — install radare2 (https://github.com/radareorg/radare2)".to_string()
            } else {
                format!("failed to run r2: {e}")
            }
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(format!("r2 entrypoint disassembly failed: {stderr}"));
    }

    String::from_utf8(output.stdout).map_err(|e| format!("r2 output is not valid UTF-8: {e}"))
}

/// Inspect callsites to a callee and report those that load a constant value
/// into the requested argument register immediately before the call.
pub fn constant_callsite_args(
    path: &Path,
    callee_addr: u64,
    caller_addr: Option<u64>,
    arg_register: &str,
) -> Result<Vec<ConstantCallsiteArg>, String> {
    let xrefs_json = run_r2(&format!("aaa; axtj @ {callee_addr:#x}"), path)?;
    if xrefs_json.trim().is_empty() || xrefs_json.trim() == "[]" {
        return Ok(Vec::new());
    }

    let xrefs: Vec<XrefEntry> =
        serde_json::from_str(&xrefs_json).map_err(|e| format!("failed to parse axtj JSON: {e}"))?;
    let mut results = Vec::new();

    for xref in xrefs {
        if xref.r#type != "CALL" {
            continue;
        }
        if let Some(expected_caller_addr) = caller_addr {
            if xref.fcn_addr != expected_caller_addr {
                continue;
            }
        }

        let window_start = xref.from.saturating_sub(24);
        let ops_json = run_r2(&format!("aaa; pdj 12 @ {window_start:#x}"), path)?;
        if ops_json.trim().is_empty() || ops_json.trim() == "[]" {
            continue;
        }
        let ops: Vec<DisasmEntry> = serde_json::from_str(&ops_json)
            .map_err(|e| format!("failed to parse pdj JSON: {e}"))?;
        if let Some(constant_addr) = constant_arg_ref_before_call(&ops, xref.from, arg_register) {
            results.push(ConstantCallsiteArg {
                callsite_addr: xref.from,
                constant_addr: Some(constant_addr),
            });
        }
    }

    Ok(results)
}

fn constant_arg_ref_before_call(
    ops: &[DisasmEntry],
    callsite_addr: u64,
    arg_register: &str,
) -> Option<u64> {
    let call_index = ops.iter().position(|op| op.addr == callsite_addr)?;
    for op in ops[..call_index].iter().rev().take(6) {
        if !instruction_writes_register(op, arg_register) {
            continue;
        }
        if let Some(data_ref) = op.refs.iter().find(|r| r.r#type == "DATA" && r.addr != 0) {
            return Some(data_ref.addr);
        }
    }
    None
}

fn instruction_writes_register(op: &DisasmEntry, register: &str) -> bool {
    let text = if op.disasm.is_empty() {
        op.opcode.as_str()
    } else {
        op.disasm.as_str()
    };
    let mut parts = text
        .split(|c: char| {
            c.is_whitespace() || c == ',' || c == '[' || c == ']' || c == '(' || c == ')'
        })
        .filter(|part| !part.is_empty());
    let _mnemonic = parts.next();
    matches!(parts.next(), Some(dst) if dst == register)
}

// ── Tests ───────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    // ── BinaryProfile parsing ───────────────────────────────────────────

    #[test]
    fn test_parse_binary_profile_full() {
        let json = r#"{
            "info": {
                "arch": "arm",
                "bits": 32,
                "compiler": "GCC: (Ubuntu 9.4.0) 9.4.0",
                "canary": true,
                "nx": true,
                "relro": "partial",
                "stripped": false,
                "bintype": "elf",
                "class": "ELF32"
            }
        }"#;
        let profile = parse_binary_profile(json).unwrap();
        assert_eq!(profile.arch, "arm");
        assert_eq!(profile.bits, 32);
        assert!(profile.compiler.contains("GCC"));
        assert!(profile.canary);
        assert!(profile.nx);
        assert_eq!(profile.relro, "partial");
        assert!(!profile.stripped);
    }

    #[test]
    fn test_parse_binary_profile_missing_info() {
        let json = r#"{}"#;
        let result = parse_binary_profile(json);
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("missing 'info' key"));
    }

    #[test]
    fn test_parse_binary_profile_empty_relro_defaults_to_none() {
        let json = r#"{"info": {"arch": "x86", "bits": 64, "relro": ""}}"#;
        let profile = parse_binary_profile(json).unwrap();
        assert_eq!(profile.relro, "none");
    }

    // ── Exports parsing ─────────────────────────────────────────────────

    #[test]
    fn test_parse_exports() {
        let json = r#"[
            {"name": "httpd_main", "size": 512},
            {"name": "auth_check", "size": 128}
        ]"#;
        let exports = parse_exports(json).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "httpd_main");
        assert_eq!(exports[0].size, 512);
        assert_eq!(exports[1].name, "auth_check");
    }

    #[test]
    fn test_parse_exports_empty() {
        let json = r#"[]"#;
        let exports = parse_exports(json).unwrap();
        assert!(exports.is_empty());
    }

    // ── Imports parsing ─────────────────────────────────────────────────

    #[test]
    fn test_parse_imports() {
        let json = r#"[
            {"name": "strcpy"},
            {"name": "malloc"},
            {"name": "system"}
        ]"#;
        let imports = parse_imports(json).unwrap();
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].name, "strcpy");
        assert_eq!(imports[2].name, "system");
    }

    // ── Strings parsing ─────────────────────────────────────────────────

    #[test]
    fn test_parse_strings_filters_by_min_length() {
        let json = r#"[
            {"string": "hi", "vaddr": 4096, "length": 2},
            {"string": "password=admin", "vaddr": 8192, "length": 14},
            {"string": "key", "vaddr": 12288, "length": 3}
        ]"#;
        let strings = parse_strings(json, 4).unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "password=admin");
        assert_eq!(strings[0].address, 8192);
        assert_eq!(strings[0].length, 14);
    }

    #[test]
    fn test_parse_strings_all_pass_min_1() {
        let json = r#"[
            {"string": "a", "vaddr": 100, "length": 1},
            {"string": "ab", "vaddr": 200, "length": 2}
        ]"#;
        let strings = parse_strings(json, 1).unwrap();
        assert_eq!(strings.len(), 2);
    }

    // ── Linked libraries parsing ────────────────────────────────────────

    #[test]
    fn test_parse_linked_libraries_flat_array() {
        let json = r#"["libc.so.6", "libpthread.so.0", "libssl.so.1.1"]"#;
        let libs = parse_linked_libraries(json).unwrap();
        assert_eq!(libs.len(), 3);
        assert_eq!(libs[0], "libc.so.6");
        assert_eq!(libs[2], "libssl.so.1.1");
    }

    #[test]
    fn test_parse_linked_libraries_object_with_libs_key() {
        let json = r#"{"libs": ["libc.so.6", "libcrypto.so.1.1"]}"#;
        let libs = parse_linked_libraries(json).unwrap();
        assert_eq!(libs.len(), 2);
        assert_eq!(libs[1], "libcrypto.so.1.1");
    }

    // ── Function list parsing ───────────────────────────────────────────

    #[test]
    fn test_parse_function_list() {
        let json = r#"[
            {"name": "main", "offset": 4096, "size": 256, "nbbs": 8, "cc": 5},
            {"name": "auth_check", "offset": 8192, "size": 128, "nbbs": 4, "cc": 3}
        ]"#;
        let funcs = parse_function_list(json).unwrap();
        assert_eq!(funcs.len(), 2);
        assert_eq!(funcs[0].name, "main");
        assert_eq!(funcs[0].address, 4096);
        assert_eq!(funcs[0].size, 256);
        assert_eq!(funcs[0].basic_blocks, 8);
        assert_eq!(funcs[0].cyclomatic_complexity, 5);
    }

    #[test]
    fn test_parse_function_list_empty() {
        let json = r#"[]"#;
        let funcs = parse_function_list(json).unwrap();
        assert!(funcs.is_empty());
    }

    #[test]
    fn test_parse_function_list_accepts_addr_field() {
        let json = r#"[{"name":"fcn.080004f4","addr":134218996,"size":122,"nbbs":19,"cc":9}]"#;
        let funcs = parse_function_list(json).unwrap();
        assert_eq!(funcs.len(), 1);
        assert_eq!(funcs[0].address, 134218996);
    }

    #[test]
    fn test_parse_binary_profile_invalid_json() {
        let result = parse_binary_profile("not json at all");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_binary_profile_tolerates_warn_prefix() {
        let json = "WARN: relocations not applied\n{\"info\":{\"arch\":\"arm\",\"bits\":64,\"relro\":\"full\"}}";
        let profile = parse_binary_profile(json).unwrap();
        assert_eq!(profile.arch, "arm");
        assert_eq!(profile.bits, 64);
    }

    // ── Wrapped JSON format (rabin2 newer versions) ─────────────────────

    #[test]
    fn test_parse_exports_wrapped_object() {
        let json =
            r#"{"exports":[{"name":"__mh_execute_header","size":0},{"name":"main","size":128}]}"#;
        let exports = parse_exports(json).unwrap();
        assert_eq!(exports.len(), 2);
        assert_eq!(exports[0].name, "__mh_execute_header");
        assert_eq!(exports[1].name, "main");
        assert_eq!(exports[1].size, 128);
    }

    #[test]
    fn test_parse_imports_wrapped_object() {
        let json = r#"{"imports":[{"name":"strcpy"},{"name":"system"},{"name":"malloc"}]}"#;
        let imports = parse_imports(json).unwrap();
        assert_eq!(imports.len(), 3);
        assert_eq!(imports[0].name, "strcpy");
        assert_eq!(imports[1].name, "system");
    }

    #[test]
    fn test_parse_imports_tolerates_warn_prefix() {
        let json = "WARN: malformed relocation metadata\n[{\"name\":\"memcpy\"}]";
        let imports = parse_imports(json).unwrap();
        assert_eq!(imports.len(), 1);
        assert_eq!(imports[0].name, "memcpy");
    }

    #[test]
    fn test_parse_strings_wrapped_object() {
        let json = r#"{"strings":[{"string":"hello world","vaddr":4096,"length":11},{"string":"pw","vaddr":8192,"length":2}]}"#;
        let strings = parse_strings(json, 4).unwrap();
        assert_eq!(strings.len(), 1);
        assert_eq!(strings[0].value, "hello world");
    }

    #[test]
    fn test_parse_linked_libraries_tolerates_warn_prefix() {
        let json = "WARN: unsupported bind opcode\n{\"libs\":[\"libc.so.6\",\"libssl.so.1.1\"]}";
        let libs = parse_linked_libraries(json).unwrap();
        assert_eq!(libs, vec!["libc.so.6", "libssl.so.1.1"]);
    }

    #[test]
    fn instruction_writes_register_matches_dest_operand() {
        let op = DisasmEntry {
            addr: 0x1000,
            disasm: "movw r0, 0xb670".into(),
            opcode: String::new(),
            refs: Vec::new(),
        };
        assert!(instruction_writes_register(&op, "r0"));
        assert!(!instruction_writes_register(&op, "r1"));
    }

    #[test]
    fn constant_arg_ref_before_call_extracts_data_ref() {
        let ops = vec![
            DisasmEntry {
                addr: 0xa24c,
                disasm: "movw r0, 0xb670".into(),
                opcode: String::new(),
                refs: vec![DisasmRef {
                    addr: 0xb670,
                    r#type: "DATA".into(),
                }],
            },
            DisasmEntry {
                addr: 0xa250,
                disasm: "movt r0, 0".into(),
                opcode: String::new(),
                refs: vec![DisasmRef {
                    addr: 0xb670,
                    r#type: "DATA".into(),
                }],
            },
            DisasmEntry {
                addr: 0xa25c,
                disasm: "bl fcn.0000aea0".into(),
                opcode: String::new(),
                refs: Vec::new(),
            },
        ];

        assert_eq!(
            constant_arg_ref_before_call(&ops, 0xa25c, "r0"),
            Some(0xb670)
        );
    }

    #[test]
    fn constant_arg_ref_before_call_ignores_other_registers() {
        let ops = vec![
            DisasmEntry {
                addr: 0xa24c,
                disasm: "movw r1, 0xb670".into(),
                opcode: String::new(),
                refs: vec![DisasmRef {
                    addr: 0xb670,
                    r#type: "DATA".into(),
                }],
            },
            DisasmEntry {
                addr: 0xa25c,
                disasm: "bl fcn.0000aea0".into(),
                opcode: String::new(),
                refs: Vec::new(),
            },
        ];

        assert_eq!(constant_arg_ref_before_call(&ops, 0xa25c, "r0"), None);
    }

    #[test]
    fn build_spawn_args_adds_raw_cortex_m_loader_flags() {
        let args = build_spawn_args(Some(&R2OpenOptions {
            arch: Some("arm".into()),
            bits: Some(16),
            base: Some(0x0800_0000),
            cpu: Some("cortex".into()),
        }));
        assert!(args.iter().any(|arg| arg == "-a"));
        assert!(args.iter().any(|arg| arg == "arm"));
        assert!(args.iter().any(|arg| arg == "-b"));
        assert!(args.iter().any(|arg| arg == "16"));
        assert!(args.iter().any(|arg| arg == "-m"));
        assert!(args.iter().any(|arg| arg == "0x08000000"));
        assert!(args.iter().any(|arg| arg == "asm.cpu=cortex"));
    }
}
