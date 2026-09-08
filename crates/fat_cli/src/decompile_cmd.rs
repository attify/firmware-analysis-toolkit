//! Mechanical function decompilation through radare2 and r2ghidra.

use fat_analyze::loader::{resolve_loader_hints, LoaderHints};
use serde::Serialize;
use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use crate::style::Palette;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Serialize)]
struct RawDecompileReport {
    schema_version: &'static str,
    binary: String,
    function_address: String,
    decompiler: &'static str,
    loader_hints: LoaderHintReport,
    raw_output: String,
}

#[derive(Debug, Serialize)]
struct LoaderHintReport {
    arch: Option<String>,
    bits: Option<u32>,
    base: Option<String>,
    family: Option<String>,
    cpu: Option<String>,
    raw_blob: bool,
}

impl From<&LoaderHints> for LoaderHintReport {
    fn from(hints: &LoaderHints) -> Self {
        Self {
            arch: hints.arch.clone(),
            bits: hints.bits,
            base: hints.base.map(|value| format!("0x{value:08x}")),
            family: hints.family.clone(),
            cpu: hints.cpu.clone(),
            raw_blob: hints.is_raw_blob,
        }
    }
}

pub fn run(
    file: &Path,
    function_addr: &str,
    arch: Option<&str>,
    base: Option<&str>,
    family: Option<&str>,
    output_dir: Option<&Path>,
    json: bool,
    context_depth: usize,
) -> DynResult<()> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }

    let address = parse_hex_address(function_addr)?;
    let user_base = parse_base_address(base)?;
    let loader_hints = resolve_loader_hints(file, arch, user_base, family)
        .map_err(|error| -> Box<dyn Error> { error.into() })?;
    let raw_output = decompile_function(file, address, context_depth, &loader_hints)?;
    let address_text = format!("0x{address:08x}");
    let binary = file
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();

    let out_dir = output_dir
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("fat-decompile-output"));
    fs::create_dir_all(&out_dir)?;
    let raw_path = out_dir.join(format!("{binary}_{address_text}.raw.c"));
    fs::write(&raw_path, &raw_output)?;

    if json {
        let report = RawDecompileReport {
            schema_version: "fat-decompile-raw/v1",
            binary,
            function_address: address_text,
            decompiler: "r2ghidra",
            loader_hints: (&loader_hints).into(),
            raw_output,
        };
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        let pal = Palette::stderr();
        eprintln!(
            "{} {}",
            pal.heading("fat decompile"),
            pal.info(format!("{}:{}", file.display(), address_text))
        );
        eprintln!("raw output: {}", raw_path.display());
        println!("{raw_output}");
    }
    Ok(())
}

pub(crate) fn raw_decompile_to_string(
    file: &Path,
    function_addr: &str,
    arch: Option<&str>,
    base: Option<&str>,
    family: Option<&str>,
    context_depth: usize,
) -> DynResult<String> {
    if !file.is_file() {
        return Err(format!("file not found: {}", file.display()).into());
    }
    let address = parse_hex_address(function_addr)?;
    let user_base = parse_base_address(base)?;
    let loader_hints = resolve_loader_hints(file, arch, user_base, family)
        .map_err(|error| -> Box<dyn Error> { error.into() })?;
    decompile_function(file, address, context_depth, &loader_hints)
}

fn decompile_function(
    file: &Path,
    address: u64,
    _context_depth: usize,
    loader_hints: &LoaderHints,
) -> DynResult<String> {
    let file_text = file.to_str().ok_or("file path is not valid UTF-8")?;
    let spawn_args = leak_spawn_args(&build_spawn_args(loader_hints));
    let spawn_options = r2pipe::R2PipeSpawnOptions {
        args: spawn_args,
        ..Default::default()
    };
    let mut session = r2pipe::R2Pipe::spawn(file_text, Some(spawn_options))
        .map_err(|error| format!("failed to open r2 session: {error}"))?;
    session
        .cmd("aaa")
        .map_err(|error| format!("r2 analysis failed: {error}"))?;
    let output = session
        .cmd(&format!("s {address:#x}; af; pdg"))
        .map_err(|error| format!("r2ghidra decompilation failed: {error}"))?;
    session.close();

    if output.trim().is_empty() {
        return Err(format!(
            "r2ghidra produced no output for function at {address:#x}; ensure r2ghidra is installed and provide explicit loader hints for raw firmware"
        )
        .into());
    }
    Ok(output)
}

fn build_spawn_args(loader_hints: &LoaderHints) -> Vec<String> {
    let mut args = vec![
        "-2".to_string(),
        "-e".to_string(),
        "bin.relocs.apply=true".to_string(),
        "-e".to_string(),
        "scr.color=0".to_string(),
        "-e".to_string(),
        "scr.interactive=false".to_string(),
    ];
    if let Some(arch) = loader_hints.arch.as_deref() {
        args.extend(["-a".to_string(), arch.to_string()]);
    }
    if let Some(bits) = loader_hints.bits {
        args.extend(["-b".to_string(), bits.to_string()]);
    }
    if let Some(base) = loader_hints.base {
        args.extend(["-m".to_string(), format!("0x{base:08x}")]);
    }
    if let Some(cpu) = loader_hints.cpu.as_deref() {
        args.extend(["-e".to_string(), format!("asm.cpu={cpu}")]);
    }
    args
}

fn leak_spawn_args(args: &[String]) -> Vec<&'static str> {
    args.iter()
        .cloned()
        .map(|arg| Box::leak(arg.into_boxed_str()) as &'static str)
        .collect()
}

fn parse_hex_address(raw: &str) -> DynResult<u64> {
    let value = raw
        .strip_prefix("0x")
        .or_else(|| raw.strip_prefix("0X"))
        .unwrap_or(raw);
    u64::from_str_radix(value, 16).map_err(|_| format!("invalid function address: {raw}").into())
}

fn parse_base_address(base: Option<&str>) -> DynResult<Option<u32>> {
    let Some(base) = base else {
        return Ok(None);
    };
    if let Some(hex) = base.strip_prefix("0x").or_else(|| base.strip_prefix("0X")) {
        u32::from_str_radix(hex, 16)
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    } else {
        base.parse::<u32>()
            .map(Some)
            .map_err(|_| invalid_base_error(base))
    }
}

fn invalid_base_error(base: &str) -> Box<dyn Error> {
    format!("invalid --base value '{base}' (expected decimal or 0x-prefixed hex)").into()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_function_addresses() {
        assert_eq!(parse_hex_address("0x440b3c").unwrap(), 0x440b3c);
        assert_eq!(parse_hex_address("440b3c").unwrap(), 0x440b3c);
        assert!(parse_hex_address("not-hex").is_err());
    }

    #[test]
    fn parses_base_addresses() {
        assert_eq!(
            parse_base_address(Some("0x08000000")).unwrap(),
            Some(0x0800_0000)
        );
        assert_eq!(
            parse_base_address(Some("134217728")).unwrap(),
            Some(0x0800_0000)
        );
        assert!(parse_base_address(Some("invalid")).is_err());
    }

    #[test]
    fn raw_blob_spawn_args_include_loader_hints() {
        let hints = LoaderHints {
            arch: Some("arm".to_string()),
            bits: Some(16),
            base: Some(0x0800_0000),
            family: Some("example-mcu".to_string()),
            cpu: Some("cortex".to_string()),
            is_raw_blob: true,
        };
        let args = build_spawn_args(&hints);
        let args: Vec<&str> = args.iter().map(String::as_str).collect();
        assert!(args.windows(2).any(|pair| pair == ["-a", "arm"]));
        assert!(args.windows(2).any(|pair| pair == ["-b", "16"]));
        assert!(args.windows(2).any(|pair| pair == ["-m", "0x08000000"]));
    }
}
