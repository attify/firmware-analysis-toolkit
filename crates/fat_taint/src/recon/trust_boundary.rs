//! Trust boundary analysis: identify binaries that govern firmware updates,
//! crypto operations, and authentication across an extracted firmware rootfs.

use crate::recon::r2::strip_rabin2_json_prefix;
use serde::Serialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// The complete report produced by `analyze_rootfs`.
#[derive(Debug, Serialize)]
pub struct TrustBoundaryReport {
    pub rootfs_path: String,
    pub binaries_scanned: usize,
    pub update_binaries: Vec<BinaryRole>,
    pub auth_binaries: Vec<BinaryRole>,
    pub crypto_binaries: Vec<BinaryRole>,
    pub dependency_chains: Vec<DependencyChain>,
}

/// A binary classified into a trust-boundary role.
#[derive(Debug, Serialize, Clone)]
pub struct BinaryRole {
    /// Path relative to the rootfs.
    pub path: String,
    /// One of: "firmware-update", "authentication", "crypto".
    pub role: String,
    pub evidence: Vec<Evidence>,
    pub linked_libraries: Vec<String>,
}

/// A single piece of evidence supporting a classification.
#[derive(Debug, Serialize, Clone)]
pub struct Evidence {
    /// One of: "executed-entrypoint", "linked-dependency", "crypto-or-verify-symbol",
    /// "string-hint", "artifact-only".
    pub tier: String,
    /// One of: "import", "export", "init-script", "string-reference", "library-link".
    pub kind: String,
    /// One of: "strong", "medium", "weak".
    pub strength: String,
    pub detail: String,
}

/// Dependency chain for a classified binary.
#[derive(Debug, Serialize, Clone)]
pub struct DependencyChain {
    pub binary: String,
    pub links: Vec<String>,
    pub imports_from: Vec<ImportFrom>,
}

/// Symbols imported from a particular library.
#[derive(Debug, Serialize, Clone)]
pub struct ImportFrom {
    pub library: String,
    pub symbols: Vec<String>,
}

// ---------------------------------------------------------------------------
// Pattern constants
// ---------------------------------------------------------------------------

const UPDATE_PATTERNS: &[&str] = &[
    "rsaVerify",
    "rsaDecrypt",
    "RSA_verify",
    "RSA_public_decrypt",
    "EVP_DecryptInit",
    "EVP_VerifyFinal",
    "fwupgrade",
    "firmware_update",
    "flash_write",
    "mtd_write",
    "sysupgrade",
    "fwup",
];

const AUTH_PATTERNS: &[&str] = &[
    "authenticate",
    "check_auth",
    "validate_session",
    "verify_token",
    "check_password",
    "http_passwd",
    "is_auth",
    "PAM_",
    "pam_",
];

const CRYPTO_PATTERNS: &[&str] = &[
    "RSA_", "AES_", "DES_", "EVP_", "SHA", "MD5", "mbedtls_", "wolfSSL_", "gcry_", "encrypt",
    "decrypt",
];

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// ELF magic bytes.
const ELF_MAGIC: [u8; 4] = [0x7f, b'E', b'L', b'F'];

/// Check whether `path` is an ELF file by reading the first 4 bytes.
fn is_elf(path: &Path) -> bool {
    let Ok(mut f) = std::fs::File::open(path) else {
        return false;
    };
    let mut buf = [0u8; 4];
    use std::io::Read;
    if f.read_exact(&mut buf).is_err() {
        return false;
    }
    buf == ELF_MAGIC
}

/// Collect all ELF files under the standard rootfs binary/library directories.
/// Deduplicates by inode to avoid scanning busybox symlinks multiple times.
fn collect_elfs(rootfs: &Path) -> Vec<PathBuf> {
    use std::collections::HashSet;

    let search_dirs = ["bin", "sbin", "usr/bin", "usr/sbin", "usr/lib", "lib"];
    let mut elfs = Vec::new();
    let mut seen_inodes: HashSet<u64> = HashSet::new();

    for dir in &search_dirs {
        let full = rootfs.join(dir);
        if !full.is_dir() {
            continue;
        }
        let walker = walkdir::WalkDir::new(&full)
            .follow_links(true)
            .into_iter()
            .filter_map(|e| e.ok());
        for entry in walker {
            let p = entry.path().to_path_buf();
            if p.is_file() && is_elf(&p) {
                // Deduplicate by inode (handles busybox symlinks, hardlinks)
                #[cfg(unix)]
                {
                    use std::os::unix::fs::MetadataExt;
                    if let Ok(meta) = std::fs::metadata(&p) {
                        let ino = meta.ino();
                        if !seen_inodes.insert(ino) {
                            continue; // Already scanned this binary via another name
                        }
                    }
                }
                elfs.push(p);
            }
        }
    }
    elfs
}

/// Parsed result from `rabin2 -ij`.
#[derive(Debug, Default)]
struct Rabin2Imports {
    imports: Vec<String>,
}

/// Parsed result from `rabin2 -lj`.
#[derive(Debug, Default)]
struct Rabin2Libs {
    libs: Vec<String>,
}

/// Parsed result from `rabin2 -Ej`.
#[derive(Debug, Default)]
struct Rabin2Exports {
    exports: Vec<String>,
}

fn rabin2_imports(path: &Path) -> Rabin2Imports {
    let output = Command::new("rabin2")
        .args(["-ij", &path.to_string_lossy()])
        .output();
    let Ok(output) = output else {
        return Rabin2Imports::default();
    };
    let Ok(text) = String::from_utf8(output.stdout) else {
        return Rabin2Imports::default();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(strip_rabin2_json_prefix(&text)) else {
        return Rabin2Imports::default();
    };
    let imports = val
        .get("imports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name").and_then(|n| n.as_str()).map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Rabin2Imports { imports }
}

fn rabin2_libs(path: &Path) -> Rabin2Libs {
    let output = Command::new("rabin2")
        .args(["-lj", &path.to_string_lossy()])
        .output();
    let Ok(output) = output else {
        return Rabin2Libs::default();
    };
    let Ok(text) = String::from_utf8(output.stdout) else {
        return Rabin2Libs::default();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(strip_rabin2_json_prefix(&text)) else {
        return Rabin2Libs::default();
    };
    let libs = val
        .get("libs")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default();
    Rabin2Libs { libs }
}

fn rabin2_exports(path: &Path) -> Rabin2Exports {
    let output = Command::new("rabin2")
        .args(["-Ej", &path.to_string_lossy()])
        .output();
    let Ok(output) = output else {
        return Rabin2Exports::default();
    };
    let Ok(text) = String::from_utf8(output.stdout) else {
        return Rabin2Exports::default();
    };
    let Ok(val) = serde_json::from_str::<serde_json::Value>(strip_rabin2_json_prefix(&text)) else {
        return Rabin2Exports::default();
    };
    let exports = val
        .get("exports")
        .and_then(|v| v.as_array())
        .map(|arr| {
            arr.iter()
                .filter_map(|e| e.get("name").and_then(|n| n.as_str()).map(String::from))
                .filter(|name| {
                    // Filter out internal linker symbols
                    !name.starts_with('_')
                        && name != "__bss_start"
                        && !name.contains("cxa_finalize")
                })
                .collect()
        })
        .unwrap_or_default();
    Rabin2Exports { exports }
}

/// Return a relative path from `base` for display purposes.
fn relative_display(path: &Path, rootfs: &Path) -> String {
    path.strip_prefix(rootfs)
        .map(|p| format!("/{}", p.display()))
        .unwrap_or_else(|_| path.display().to_string())
}

/// Check whether a symbol matches any of the given pattern prefixes.
fn matches_any(symbol: &str, patterns: &[&str]) -> bool {
    patterns.iter().any(|pat| symbol.contains(pat))
}

/// Libraries that are too generic to be interesting as evidence.
const BORING_LIBS: &[&str] = &[
    "libc.so",
    "libm.so",
    "libdl.so",
    "libgcc",
    "libpthread",
    "librt.so",
    "libresolv",
    "libnss",
];

/// Returns true if a library name is security-relevant (not generic C runtime).
fn is_interesting_lib(lib: &str) -> bool {
    !BORING_LIBS.iter().any(|boring| lib.starts_with(boring))
}

/// Scan init script directories and return a map from binary basename to the
/// init scripts that reference it.
fn scan_init_scripts(rootfs: &Path) -> HashMap<String, Vec<String>> {
    let init_dirs = [
        "etc/init.d",
        "etc/rc.d",
        "etc/systemd/system",
        "usr/lib/systemd/system",
    ];
    let mut references: HashMap<String, Vec<String>> = HashMap::new();

    for dir in &init_dirs {
        let full = rootfs.join(dir);
        if !full.is_dir() {
            continue;
        }
        let walker = walkdir::WalkDir::new(&full)
            .follow_links(true)
            .max_depth(2)
            .into_iter()
            .filter_map(|e| e.ok());
        for entry in walker {
            let p = entry.path();
            if !p.is_file() {
                continue;
            }
            let Ok(contents) = std::fs::read_to_string(p) else {
                continue;
            };
            let script_rel = p
                .strip_prefix(rootfs)
                .map(|r| format!("/{}", r.display()))
                .unwrap_or_else(|_| p.display().to_string());

            // We store the script content for later matching
            references.entry(script_rel).or_default().push(contents);
        }
    }
    references
}

/// For a given binary basename, find which init scripts mention it.
fn find_init_references(
    binary_basename: &str,
    init_scripts: &HashMap<String, Vec<String>>,
) -> Vec<String> {
    let mut refs = Vec::new();
    for (script_path, contents_list) in init_scripts {
        for contents in contents_list {
            if contents.contains(binary_basename) {
                refs.push(script_path.clone());
                break;
            }
        }
    }
    refs
}

/// Classify a single binary's imports against our pattern sets and build evidence.
fn classify_binary(
    path: &Path,
    rootfs: &Path,
    imports: &Rabin2Imports,
    exports: &Rabin2Exports,
    libs: &Rabin2Libs,
    init_scripts: &HashMap<String, Vec<String>>,
) -> (Vec<BinaryRole>, Vec<DependencyChain>) {
    let rel = relative_display(path, rootfs);
    let basename = path
        .file_name()
        .map(|f| f.to_string_lossy().to_string())
        .unwrap_or_default();

    let all_symbols: Vec<&str> = imports
        .imports
        .iter()
        .chain(exports.exports.iter())
        .map(|s| s.as_str())
        .collect();

    let linked: Vec<String> = libs.libs.clone();

    let init_refs = find_init_references(&basename, init_scripts);

    let mut roles = Vec::new();

    // -- Firmware update classification --
    let update_symbols: Vec<&str> = all_symbols
        .iter()
        .copied()
        .filter(|s| matches_any(s, UPDATE_PATTERNS))
        .collect();
    if !update_symbols.is_empty() {
        let mut evidence = Vec::new();
        for sym in &update_symbols {
            evidence.push(Evidence {
                tier: "crypto-or-verify-symbol".to_string(),
                kind: "import".to_string(),
                strength: "strong".to_string(),
                detail: format!("Imports/exports firmware-verification symbol: {sym}"),
            });
        }
        for lib in linked.iter().filter(|l| is_interesting_lib(l)) {
            evidence.push(Evidence {
                tier: "linked-dependency".to_string(),
                kind: "library-link".to_string(),
                strength: "medium".to_string(),
                detail: format!("Links {lib}"),
            });
        }
        for script in &init_refs {
            evidence.push(Evidence {
                tier: "executed-entrypoint".to_string(),
                kind: "init-script".to_string(),
                strength: "medium".to_string(),
                detail: format!("Referenced in {script}"),
            });
        }
        roles.push(BinaryRole {
            path: rel.clone(),
            role: "firmware-update".to_string(),
            evidence,
            linked_libraries: linked.clone(),
        });
    }

    // -- Authentication classification --
    let auth_symbols: Vec<&str> = all_symbols
        .iter()
        .copied()
        .filter(|s| matches_any(s, AUTH_PATTERNS))
        .collect();
    if !auth_symbols.is_empty() {
        let mut evidence = Vec::new();
        for sym in &auth_symbols {
            evidence.push(Evidence {
                tier: "crypto-or-verify-symbol".to_string(),
                kind: "import".to_string(),
                strength: "strong".to_string(),
                detail: format!("Imports/exports auth symbol: {sym}"),
            });
        }
        for script in &init_refs {
            evidence.push(Evidence {
                tier: "executed-entrypoint".to_string(),
                kind: "init-script".to_string(),
                strength: "medium".to_string(),
                detail: format!("Referenced in {script}"),
            });
        }
        roles.push(BinaryRole {
            path: rel.clone(),
            role: "authentication".to_string(),
            evidence,
            linked_libraries: linked.clone(),
        });
    }

    // -- Crypto classification --
    let crypto_symbols: Vec<&str> = all_symbols
        .iter()
        .copied()
        .filter(|s| matches_any(s, CRYPTO_PATTERNS))
        .collect();
    if !crypto_symbols.is_empty() {
        let mut evidence = Vec::new();
        for sym in &crypto_symbols {
            let is_export = exports.exports.iter().any(|e| e == sym);
            evidence.push(Evidence {
                tier: "crypto-or-verify-symbol".to_string(),
                kind: if is_export { "export" } else { "import" }.to_string(),
                strength: "strong".to_string(),
                detail: format!(
                    "{} crypto symbol: {}",
                    if is_export { "Exports" } else { "Imports" },
                    sym
                ),
            });
        }
        for script in &init_refs {
            evidence.push(Evidence {
                tier: "executed-entrypoint".to_string(),
                kind: "init-script".to_string(),
                strength: "medium".to_string(),
                detail: format!("Referenced in {script}"),
            });
        }
        roles.push(BinaryRole {
            path: rel.clone(),
            role: "crypto".to_string(),
            evidence,
            linked_libraries: linked.clone(),
        });
    }

    // -- Dependency chain (for any classified binary) --
    let mut chains = Vec::new();
    if !roles.is_empty() {
        // Build per-library import map for security-relevant symbols
        let security_relevant: Vec<&str> = all_symbols
            .iter()
            .copied()
            .filter(|s| {
                matches_any(s, UPDATE_PATTERNS)
                    || matches_any(s, AUTH_PATTERNS)
                    || matches_any(s, CRYPTO_PATTERNS)
            })
            .collect();

        // We attribute imports to libraries heuristically:
        // If the binary links libsecurity.so and imports rsaVerifySign*, it likely comes from there.
        // For now, group all security-relevant imports under a single ImportFrom per linked library.
        let mut imports_from = Vec::new();
        if !security_relevant.is_empty() && !linked.is_empty() {
            // Try to attribute symbols to libraries by name heuristic
            for lib in &linked {
                let lib_lower = lib.to_lowercase();
                let attributed: Vec<String> = security_relevant
                    .iter()
                    .filter(|sym| {
                        let sym_lower = sym.to_lowercase();
                        // Heuristic: security/crypto libs get crypto symbols
                        (lib_lower.contains("security")
                            && (sym_lower.contains("rsa")
                                || sym_lower.contains("des")
                                || sym_lower.contains("md5")
                                || sym_lower.contains("sha")))
                            || (lib_lower.contains("crypto")
                                && (sym_lower.contains("rsa")
                                    || sym_lower.contains("evp")
                                    || sym_lower.contains("aes")
                                    || sym_lower.contains("des")
                                    || sym_lower.contains("encrypt")
                                    || sym_lower.contains("decrypt")
                                    || sym_lower.contains("pem")
                                    || sym_lower.contains("bio")))
                            || (lib_lower.contains("ssl")
                                && (sym_lower.contains("ssl") || sym_lower.contains("tls")))
                    })
                    .map(|s| s.to_string())
                    .collect();
                if !attributed.is_empty() {
                    imports_from.push(ImportFrom {
                        library: lib.clone(),
                        symbols: attributed,
                    });
                }
            }

            // Any unattributed symbols go into an "unresolved" bucket only if we have no attribution at all
            let all_attributed: Vec<&str> = imports_from
                .iter()
                .flat_map(|i| i.symbols.iter().map(|s| s.as_str()))
                .collect();
            let unattributed: Vec<String> = security_relevant
                .iter()
                .filter(|s| !all_attributed.contains(s))
                .map(|s| s.to_string())
                .collect();
            if !unattributed.is_empty() {
                // Attribute to first non-libc library, or just list them
                let non_libc = linked.iter().find(|l| !l.starts_with("libc"));
                if let Some(lib) = non_libc {
                    // Check if we already have an entry for this lib
                    if let Some(existing) = imports_from.iter_mut().find(|i| &i.library == lib) {
                        for s in unattributed {
                            if !existing.symbols.contains(&s) {
                                existing.symbols.push(s);
                            }
                        }
                    } else {
                        imports_from.push(ImportFrom {
                            library: lib.clone(),
                            symbols: unattributed,
                        });
                    }
                }
            }
        }

        chains.push(DependencyChain {
            binary: rel,
            links: linked,
            imports_from,
        });
    }

    (roles, chains)
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Check whether rabin2 is available on the system.
pub fn check_rabin2() -> Result<(), String> {
    match Command::new("which").arg("rabin2").output() {
        Ok(output) if output.status.success() => Ok(()),
        _ => Err("rabin2 not found in PATH. Install radare2: https://rada.re/n/".to_string()),
    }
}

/// Analyze an extracted firmware rootfs and produce a trust-boundary report.
pub fn analyze_rootfs(rootfs: &Path) -> Result<TrustBoundaryReport, String> {
    if !rootfs.is_dir() {
        return Err(format!(
            "rootfs path is not a directory: {}",
            rootfs.display()
        ));
    }

    check_rabin2()?;

    let elfs = collect_elfs(rootfs);
    let binaries_scanned = elfs.len();

    let init_scripts = scan_init_scripts(rootfs);

    let mut update_binaries = Vec::new();
    let mut auth_binaries = Vec::new();
    let mut crypto_binaries = Vec::new();
    let mut dependency_chains = Vec::new();

    for elf in &elfs {
        let imports = rabin2_imports(elf);
        let exports = rabin2_exports(elf);
        let libs = rabin2_libs(elf);

        let (roles, chains) =
            classify_binary(elf, rootfs, &imports, &exports, &libs, &init_scripts);

        for role in roles {
            match role.role.as_str() {
                "firmware-update" => update_binaries.push(role),
                "authentication" => auth_binaries.push(role),
                "crypto" => crypto_binaries.push(role),
                _ => {}
            }
        }
        dependency_chains.extend(chains);
    }

    Ok(TrustBoundaryReport {
        rootfs_path: rootfs.display().to_string(),
        binaries_scanned,
        update_binaries,
        auth_binaries,
        crypto_binaries,
        dependency_chains,
    })
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    // -- Unit tests for pattern matching --

    #[test]
    fn test_matches_update_patterns() {
        assert!(matches_any(
            "rsaVerifySignByBase64EncodePublicKeyBlob",
            UPDATE_PATTERNS
        ));
        assert!(matches_any("firmware_update", UPDATE_PATTERNS));
        assert!(matches_any("mtd_write", UPDATE_PATTERNS));
        assert!(!matches_any("printf", UPDATE_PATTERNS));
        assert!(!matches_any("malloc", UPDATE_PATTERNS));
    }

    #[test]
    fn test_matches_auth_patterns() {
        assert!(matches_any("check_auth", AUTH_PATTERNS));
        assert!(matches_any("validate_session", AUTH_PATTERNS));
        assert!(matches_any("authenticate", AUTH_PATTERNS));
        assert!(matches_any("PAM_authenticate", AUTH_PATTERNS));
        assert!(!matches_any("printf", AUTH_PATTERNS));
        assert!(!matches_any("crypt", AUTH_PATTERNS)); // removed: too broad
        assert!(!matches_any("login", AUTH_PATTERNS)); // removed: too broad
    }

    #[test]
    fn test_matches_crypto_patterns() {
        assert!(matches_any("RSA_private_decrypt", CRYPTO_PATTERNS));
        assert!(matches_any("DES_ecb_encrypt", CRYPTO_PATTERNS));
        assert!(matches_any("MD5_Init", CRYPTO_PATTERNS));
        assert!(matches_any("EVP_DecryptInit", CRYPTO_PATTERNS));
        assert!(matches_any("mbedtls_aes_crypt", CRYPTO_PATTERNS));
        assert!(!matches_any("printf", CRYPTO_PATTERNS));
    }

    // -- Unit tests for ELF detection --

    #[test]
    fn test_is_elf_with_non_elf_file() {
        let dir = tempfile::tempdir().unwrap();
        let script = dir.path().join("test.sh");
        std::fs::write(&script, "#!/bin/sh\necho hello\n").unwrap();
        assert!(!is_elf(&script));
    }

    #[test]
    fn test_is_elf_with_empty_file() {
        let dir = tempfile::tempdir().unwrap();
        let empty = dir.path().join("empty");
        std::fs::write(&empty, "").unwrap();
        assert!(!is_elf(&empty));
    }

    #[test]
    fn test_is_elf_with_nonexistent_file() {
        assert!(!is_elf(Path::new("/nonexistent/file")));
    }

    // -- Unit tests for relative_display --

    #[test]
    fn test_relative_display() {
        let rootfs = Path::new("/tmp/rootfs");
        let binary = Path::new("/tmp/rootfs/usr/bin/httpd");
        assert_eq!(relative_display(binary, rootfs), "/usr/bin/httpd");
    }

    #[test]
    fn test_relative_display_outside_rootfs() {
        let rootfs = Path::new("/tmp/rootfs");
        let binary = Path::new("/other/path/bin");
        assert_eq!(relative_display(binary, rootfs), "/other/path/bin");
    }

    // -- Unit tests for classify_binary --

    #[test]
    fn test_classify_update_binary() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let bin_dir = rootfs.join("sbin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let binary = bin_dir.join("slpupgrade");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports {
            imports: vec![
                "rsaVerifySignByBase64EncodePublicKeyBlob".to_string(),
                "memcpy".to_string(),
                "system".to_string(),
            ],
        };
        let exports = Rabin2Exports::default();
        let libs = Rabin2Libs {
            libs: vec!["libsecurity.so".to_string(), "libc.so.0".to_string()],
        };
        let init_scripts = HashMap::new();

        let (roles, chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        // Should be classified as firmware-update
        assert!(
            roles.iter().any(|r| r.role == "firmware-update"),
            "expected firmware-update role, got: {:?}",
            roles.iter().map(|r| &r.role).collect::<Vec<_>>()
        );

        // Should have a dependency chain
        assert!(!chains.is_empty(), "expected dependency chain");
        let chain = &chains[0];
        assert!(chain.links.contains(&"libsecurity.so".to_string()));
    }

    #[test]
    fn test_classify_crypto_library() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let lib_dir = rootfs.join("usr/lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        let binary = lib_dir.join("libdecrypter.so");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports {
            imports: vec![
                "RSA_private_decrypt".to_string(),
                "RSA_public_encrypt".to_string(),
                "BIO_new_mem_buf".to_string(),
                "PEM_read_bio_RSAPrivateKey".to_string(),
            ],
        };
        let exports = Rabin2Exports::default();
        let libs = Rabin2Libs {
            libs: vec!["libcrypto.so.1.0.0".to_string(), "libc.so.0".to_string()],
        };
        let init_scripts = HashMap::new();

        let (roles, _chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        // Should be classified as crypto
        assert!(
            roles.iter().any(|r| r.role == "crypto"),
            "expected crypto role, got: {:?}",
            roles.iter().map(|r| &r.role).collect::<Vec<_>>()
        );

        // Should NOT be classified as firmware-update (it's a credential library)
        // Note: RSA_private_decrypt doesn't match UPDATE_PATTERNS which use RSA_verify/rsaVerify
        assert!(
            !roles.iter().any(|r| r.role == "firmware-update"),
            "libdecrypter should not be classified as firmware-update"
        );
    }

    #[test]
    fn test_classify_crypto_export_library() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let lib_dir = rootfs.join("lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        let binary = lib_dir.join("libsecurity.so");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports::default();
        let exports = Rabin2Exports {
            exports: vec![
                "rsaVerifySignByBase64EncodePublicKeyBlob".to_string(),
                "DES_ecb_encrypt".to_string(),
                "DES_ede3_cbc_encrypt".to_string(),
                "MD5_Init".to_string(),
                "MD5_Update".to_string(),
                "MD5_Final".to_string(),
                "RSA_modpow".to_string(),
            ],
        };
        let libs = Rabin2Libs {
            libs: vec!["libc.so.0".to_string()],
        };
        let init_scripts = HashMap::new();

        let (roles, _chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        // Should be classified as both firmware-update (rsaVerifySign) and crypto
        assert!(
            roles.iter().any(|r| r.role == "firmware-update"),
            "expected firmware-update role for libsecurity.so"
        );
        assert!(
            roles.iter().any(|r| r.role == "crypto"),
            "expected crypto role for libsecurity.so"
        );

        // Crypto evidence should use "export" kind
        let crypto_role = roles.iter().find(|r| r.role == "crypto").unwrap();
        assert!(
            crypto_role.evidence.iter().any(|e| e.kind == "export"),
            "expected export evidence for crypto symbols"
        );
    }

    #[test]
    fn test_classify_plain_binary_no_role() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let bin_dir = rootfs.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();
        let binary = bin_dir.join("ls");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports {
            imports: vec![
                "printf".to_string(),
                "malloc".to_string(),
                "free".to_string(),
            ],
        };
        let exports = Rabin2Exports::default();
        let libs = Rabin2Libs {
            libs: vec!["libc.so.0".to_string()],
        };
        let init_scripts = HashMap::new();

        let (roles, chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        assert!(roles.is_empty(), "plain binary should have no roles");
        assert!(
            chains.is_empty(),
            "plain binary should have no dependency chains"
        );
    }

    #[test]
    fn test_init_script_evidence() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();

        // Create init script directory with a script referencing slpupgrade
        let init_dir = rootfs.join("etc/init.d");
        std::fs::create_dir_all(&init_dir).unwrap();
        std::fs::write(
            init_dir.join("upgrade_daemon"),
            "#!/bin/sh\n/sbin/slpupgrade -d &\n",
        )
        .unwrap();

        let init_scripts = scan_init_scripts(rootfs);
        let refs = find_init_references("slpupgrade", &init_scripts);

        assert!(
            !refs.is_empty(),
            "expected init script reference for slpupgrade"
        );
        assert!(
            refs[0].contains("upgrade_daemon"),
            "expected reference to upgrade_daemon script, got: {}",
            refs[0]
        );
    }

    #[test]
    fn test_init_script_no_false_positive() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();

        let init_dir = rootfs.join("etc/init.d");
        std::fs::create_dir_all(&init_dir).unwrap();
        std::fs::write(init_dir.join("network"), "#!/bin/sh\nifup wan\n").unwrap();

        let init_scripts = scan_init_scripts(rootfs);
        let refs = find_init_references("slpupgrade", &init_scripts);

        assert!(
            refs.is_empty(),
            "should not find slpupgrade in network script"
        );
    }

    #[test]
    fn test_collect_elfs_skips_non_elf() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();

        // Create a bin directory with a script and an ELF-like file
        let bin_dir = rootfs.join("bin");
        std::fs::create_dir_all(&bin_dir).unwrap();

        // Shell script — should be skipped
        std::fs::write(bin_dir.join("myscript.sh"), "#!/bin/sh\necho hello\n").unwrap();

        // Fake ELF — should be collected
        let mut elf_content = vec![0x7f, b'E', b'L', b'F'];
        elf_content.extend_from_slice(&[0u8; 100]);
        std::fs::write(bin_dir.join("myelf"), &elf_content).unwrap();

        let elfs = collect_elfs(rootfs);
        assert_eq!(elfs.len(), 1, "should only find the ELF file");
        assert!(
            elfs[0].ends_with("myelf"),
            "expected myelf, got: {}",
            elfs[0].display()
        );
    }

    #[test]
    fn test_analyze_rootfs_rejects_nonexistent() {
        let result = analyze_rootfs(Path::new("/nonexistent/rootfs/path"));
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("not a directory"));
    }

    // -- Dependency chain tests --

    #[test]
    fn test_dependency_chain_attributes_rsa_to_security_lib() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let sbin_dir = rootfs.join("sbin");
        std::fs::create_dir_all(&sbin_dir).unwrap();
        let binary = sbin_dir.join("slpupgrade");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports {
            imports: vec!["rsaVerifySignByBase64EncodePublicKeyBlob".to_string()],
        };
        let exports = Rabin2Exports::default();
        let libs = Rabin2Libs {
            libs: vec![
                "libsecurity.so".to_string(),
                "libuci.so".to_string(),
                "libc.so.0".to_string(),
            ],
        };
        let init_scripts = HashMap::new();

        let (_roles, chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        assert!(!chains.is_empty());
        let chain = &chains[0];

        // The rsaVerifySign symbol should be attributed to libsecurity.so
        let security_import = chain
            .imports_from
            .iter()
            .find(|i| i.library.contains("security"));
        assert!(
            security_import.is_some(),
            "expected imports attributed to libsecurity.so, got: {:?}",
            chain.imports_from
        );
        assert!(security_import
            .unwrap()
            .symbols
            .iter()
            .any(|s| s.contains("rsaVerify")));
    }

    #[test]
    fn test_dependency_chain_attributes_rsa_decrypt_to_crypto_lib() {
        let dir = tempfile::tempdir().unwrap();
        let rootfs = dir.path();
        let lib_dir = rootfs.join("usr/lib");
        std::fs::create_dir_all(&lib_dir).unwrap();
        let binary = lib_dir.join("libdecrypter.so");
        std::fs::write(&binary, "dummy").unwrap();

        let imports = Rabin2Imports {
            imports: vec![
                "RSA_private_decrypt".to_string(),
                "RSA_public_encrypt".to_string(),
            ],
        };
        let exports = Rabin2Exports::default();
        let libs = Rabin2Libs {
            libs: vec!["libcrypto.so.1.0.0".to_string(), "libc.so.0".to_string()],
        };
        let init_scripts = HashMap::new();

        let (_roles, chains) =
            classify_binary(&binary, rootfs, &imports, &exports, &libs, &init_scripts);

        assert!(!chains.is_empty());
        let chain = &chains[0];

        let crypto_import = chain
            .imports_from
            .iter()
            .find(|i| i.library.contains("crypto"));
        assert!(
            crypto_import.is_some(),
            "expected imports attributed to libcrypto.so, got: {:?}",
            chain.imports_from
        );
        assert!(crypto_import
            .unwrap()
            .symbols
            .iter()
            .any(|s| s.contains("RSA_private_decrypt")));
    }
}
