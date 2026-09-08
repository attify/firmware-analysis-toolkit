//! Ghidra headless batch decompilation — ELF binaries → C pseudocode.

use std::path::{Path, PathBuf};
use std::process::Command;
use thiserror::Error;
use tracing::{info, warn};

#[derive(Debug, Error)]
pub enum DecompileError {
    #[error("Ghidra not found at {0}")]
    GhidraNotFound(String),
    #[error("Ghidra headless failed for {binary}: {msg}")]
    GhidraFailed { binary: String, msg: String },
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Configuration for the decompiler.
pub struct DecompileConfig {
    /// Path to Ghidra installation (e.g., set via `GHIDRA_HOME`, or `/opt/ghidra`)
    pub ghidra_home: PathBuf,
    /// Path to the export Java script
    pub export_script: PathBuf,
    /// Output directory for decompiled .c files
    pub output_dir: PathBuf,
}

impl DecompileConfig {
    /// Auto-detect Ghidra installation.
    pub fn auto_detect(output_dir: PathBuf) -> Result<Self, DecompileError> {
        let ghidra_home = find_ghidra()?;
        let export_script = ensure_export_script(&ghidra_home)?;

        Ok(Self {
            ghidra_home,
            export_script,
            output_dir,
        })
    }
}

/// Decompile a single ELF binary to C pseudocode.
pub fn decompile_binary(
    binary: &Path,
    config: &DecompileConfig,
) -> Result<PathBuf, DecompileError> {
    let stem = binary
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .replace('.', "_");
    let output_path = config.output_dir.join(format!("{stem}.c"));

    // Skip if already decompiled
    if output_path.exists()
        && std::fs::metadata(&output_path)
            .map(|m| m.len() > 100)
            .unwrap_or(false)
    {
        info!("Skip (cached): {}", binary.display());
        return Ok(output_path);
    }

    info!("Decompiling: {}", binary.display());

    let project_dir = tempfile::tempdir()?;
    let analyze_headless = config.ghidra_home.join("support").join("analyzeHeadless");

    let output = Command::new(&analyze_headless)
        .arg(project_dir.path())
        .arg("fat_taint_decompile")
        .arg("-import")
        .arg(binary)
        .arg("-postScript")
        .arg(&config.export_script)
        .arg("-scriptPath")
        .arg(config.export_script.parent().unwrap_or(Path::new("/tmp")))
        .arg("-deleteProject")
        .env("DECOMPILE_OUTPUT_DIR", &config.output_dir)
        .output()
        .map_err(|e| DecompileError::GhidraFailed {
            binary: binary.display().to_string(),
            msg: e.to_string(),
        })?;

    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        // Ghidra reports errors in stdout too
        let stdout = String::from_utf8_lossy(&output.stdout);
        if !output_path.exists() {
            return Err(DecompileError::GhidraFailed {
                binary: binary.display().to_string(),
                msg: format!("stderr: {stderr}\nstdout: {stdout}"),
            });
        }
        // Script may have "failed" but still produced output
        warn!(
            "Ghidra reported errors but output exists for {}",
            binary.display()
        );
    }

    Ok(output_path)
}

/// Decompile all binaries in a cluster.
pub fn decompile_cluster(
    binaries: &[&Path],
    config: &DecompileConfig,
) -> Result<Vec<PathBuf>, DecompileError> {
    std::fs::create_dir_all(&config.output_dir)?;
    binaries
        .iter()
        .map(|b| decompile_binary(b, config))
        .collect()
}

fn find_ghidra() -> Result<PathBuf, DecompileError> {
    // Check common locations
    let candidates = [
        std::env::var("GHIDRA_HOME").unwrap_or_default(),
        "/opt/ghidra".into(),
        "/usr/local/share/ghidra".into(),
    ];

    for candidate in &candidates {
        let path = PathBuf::from(candidate);
        if path.join("support/analyzeHeadless").exists() {
            return Ok(path);
        }
    }

    // Try PATH
    if let Ok(output) = Command::new("which").arg("ghidra").output() {
        if output.status.success() {
            let path_str = String::from_utf8_lossy(&output.stdout).trim().to_string();
            // ghidra binary is usually in $GHIDRA_HOME/ghidra
            let path = PathBuf::from(&path_str);
            if let Some(parent) = path.parent() {
                if parent.join("support/analyzeHeadless").exists() {
                    return Ok(parent.to_path_buf());
                }
            }
        }
    }

    Err(DecompileError::GhidraNotFound(
        "Set GHIDRA_HOME environment variable".into(),
    ))
}

/// Ensure the Ghidra export script exists, creating it if needed.
fn ensure_export_script(ghidra_home: &Path) -> Result<PathBuf, DecompileError> {
    let script_dir = ghidra_home.join("fat_scripts");
    std::fs::create_dir_all(&script_dir)?;

    let script_path = script_dir.join("ExportDecompiledC.java");
    if !script_path.exists() {
        std::fs::write(&script_path, EXPORT_SCRIPT_JAVA)?;
    }

    Ok(script_path)
}

const EXPORT_SCRIPT_JAVA: &str = r#"
import ghidra.app.script.GhidraScript;
import ghidra.app.decompiler.*;
import ghidra.program.model.listing.*;
import java.io.*;

public class ExportDecompiledC extends GhidraScript {
    @Override
    public void run() throws Exception {
        String outDir = System.getenv("DECOMPILE_OUTPUT_DIR");
        if (outDir == null || outDir.isEmpty()) {
            outDir = "/tmp/fat_taint_decompiled";
        }
        new File(outDir).mkdirs();

        DecompInterface decomp = new DecompInterface();
        decomp.openProgram(currentProgram);

        String progName = currentProgram.getName().replace(".", "_");
        File outFile = new File(outDir, progName + ".c");
        PrintWriter pw = new PrintWriter(new FileWriter(outFile));

        pw.println("// Decompiled from: " + currentProgram.getName());
        pw.println("// Generated by fat_taint ExportDecompiledC");
        pw.println("");

        // Extern declarations for imported functions
        FunctionIterator extFuncs = currentProgram.getFunctionManager().getExternalFunctions();
        while (extFuncs.hasNext()) {
            Function func = extFuncs.next();
            pw.println("extern void " + func.getName() + "();");
        }
        pw.println("");

        // Decompile all internal functions
        int count = 0;
        FunctionIterator funcs = currentProgram.getFunctionManager().getFunctions(true);
        while (funcs.hasNext()) {
            Function func = funcs.next();
            if (func.isExternal()) continue;
            try {
                DecompileResults results = decomp.decompileFunction(func, 60, monitor);
                if (results != null && results.getDecompiledFunction() != null) {
                    String c = results.getDecompiledFunction().getC();
                    if (c != null && !c.isEmpty()) {
                        pw.println("// " + func.getName() + " @ " + func.getEntryPoint());
                        pw.println(c);
                        pw.println("");
                        count++;
                    }
                }
            } catch (Exception e) {
                pw.println("// FAILED: " + func.getName() + " - " + e.getMessage());
            }
        }

        pw.close();
        println("fat_taint: exported " + count + " functions to " + outFile.getAbsolutePath());
    }
}
"#;
