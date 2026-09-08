use regex::Regex;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

const GENERIC_LIBRARY_PATTERNS: &[&str] = &[
    "libsystem",
    "libc.",
    "libm.",
    "libdl.",
    "libpthread",
    "libobjc",
    "libutil",
    "libncurses",
    "libiconv",
    "ld-linux",
    "ld-uclibc",
    "ld-musl",
    "libgcc_s",
    "libstdc++",
    "libsupc++",
    "libgomp",
    "libatomic",
    "libunwind",
    "libresolv",
    "libcrypt",
    "foundation.framework/foundation",
    "corefoundation.framework/corefoundation",
    "appkit.framework/appkit",
    "uikit.framework/uikit",
];

const GENERIC_ENTRYPOINT_CLUES: &[&str] = &[
    "objc_autoreleasepoolpush",
    "objc_autoreleasepoolpop",
    "objc_release",
    "objc_retainautoreleasedreturnvalue",
    "nsrunloop",
    "nsdate",
    "__stack_chk_guard",
    "fixup.currentrunloop",
    "internalbuild",
];

const BOOTSTRAP_PATTERNS: &[&str] = &[
    "sharedinstance",
    "dispatch_main",
    "runloop",
    "start",
    "bootstrap",
    "manager",
    "service",
    "xpc",
    "dlopen",
    "exec",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct DownstreamCandidate {
    pub path: PathBuf,
    pub score: i32,
    pub linked: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ArtifactRealityReport {
    pub target: Option<PathBuf>,
    pub notes: Vec<String>,
}

pub(crate) fn extract_entrypoint_clues(entrypoint: &str) -> Vec<String> {
    let reloc_re = Regex::new(r"reloc\.([A-Za-z0-9_.$:+-]+)").expect("valid reloc regex");
    let import_re = Regex::new(r"sym\.imp\.([A-Za-z0-9_.$:+-]+)").expect("valid import regex");
    let mut clues = BTreeSet::new();

    for cap in reloc_re.captures_iter(entrypoint) {
        let clue = cap[1].to_string();
        if !is_generic_entrypoint_clue(&clue) {
            clues.insert(clue);
        }
    }

    for cap in import_re.captures_iter(entrypoint) {
        let clue = cap[1].to_string();
        if is_bootstrap_pattern(&clue) && !is_generic_entrypoint_clue(&clue) {
            clues.insert(clue);
        }
    }

    clues.into_iter().collect()
}

pub(crate) fn filter_non_runtime_libraries(libraries: &[String]) -> Vec<String> {
    libraries
        .iter()
        .filter(|lib| !is_generic_library(lib))
        .cloned()
        .collect()
}

pub(crate) fn infer_runtime_root(binary: &Path) -> Option<PathBuf> {
    for ancestor in binary.ancestors() {
        if let Some(name) = ancestor.file_name().and_then(|n| n.to_str()) {
            if matches!(name, "bin" | "sbin" | "lib" | "libexec") {
                if let Some(parent) = ancestor.parent() {
                    if parent.file_name().and_then(|n| n.to_str()) == Some("usr") {
                        return parent.parent().map(PathBuf::from);
                    }
                }
            }
            if matches!(name, "usr" | "System" | "bin" | "sbin" | "lib" | "libexec") {
                return ancestor.parent().map(PathBuf::from);
            }
        }
    }
    None
}

pub(crate) fn resolve_linked_target(binary: &Path, linked: &str) -> Option<PathBuf> {
    let linked_path = Path::new(linked);
    if linked.starts_with('/') {
        if let Some(root) = infer_runtime_root(binary) {
            return Some(root.join(linked.trim_start_matches('/')));
        }
    }
    if !linked.contains('/') {
        if let Some(root) = infer_runtime_root(binary) {
            if let Some(candidate) = resolve_soname_under_runtime_root(&root, linked) {
                return Some(candidate);
            }
        }
    }
    if linked_path.exists() {
        return Some(linked_path.to_path_buf());
    }
    None
}

pub(crate) fn rank_downstream_candidates(
    binary: &Path,
    linked_libraries: &[String],
) -> Vec<DownstreamCandidate> {
    rank_downstream_candidates_with_context(
        binary,
        linked_libraries,
        &crate::semantic_profile::SemanticContext { profile: None },
    )
}

pub(crate) fn rank_downstream_candidates_with_context(
    binary: &Path,
    linked_libraries: &[String],
    semantic_context: &crate::semantic_profile::SemanticContext,
) -> Vec<DownstreamCandidate> {
    let mut candidates = Vec::new();

    for linked in filter_non_runtime_libraries(linked_libraries) {
        let path = resolve_linked_target(binary, &linked).unwrap_or_else(|| PathBuf::from(&linked));
        let mut score = 100;

        if path.to_string_lossy().contains(".framework/") {
            score += 25;
        }
        if path.is_file() {
            score += 10;
        }
        if path.exists() {
            score += 5;
        }
        if linked.starts_with('/') {
            score += 5;
        }
        score += crate::semantic_profile::classify_candidate(&linked, &path, semantic_context)
            .score_adjustment;

        candidates.push(DownstreamCandidate {
            path,
            score,
            linked,
        });
    }

    candidates.sort_by(|left, right| {
        right
            .score
            .cmp(&left.score)
            .then_with(|| left.path.cmp(&right.path))
    });
    candidates
}

pub(crate) fn inspect_linked_target_reality(binary: &Path, linked: &str) -> ArtifactRealityReport {
    let mut notes = Vec::new();
    let target = resolve_linked_target(binary, linked);

    match &target {
        Some(path) if path.is_file() => {
            notes.push(format!(
                "filesystem-reality match: {} exists as a regular file.",
                path.display()
            ));
        }
        Some(path) if path.exists() => {
            notes.push(format!(
                "filesystem-reality match: {} exists, but not as a regular file.",
                path.display()
            ));
        }
        Some(path) => {
            notes.push(format!(
                "filesystem-reality mismatch: resolved target does not exist plainly on disk: {}.",
                path.display()
            ));
        }
        None => {
            notes.push(format!(
                "filesystem-reality mismatch: unable to resolve linked target {linked}."
            ));
        }
    }

    ArtifactRealityReport { target, notes }
}

pub(crate) fn framework_bundle_root(linked_path: &Path) -> Option<PathBuf> {
    linked_path.ancestors().find_map(|ancestor| {
        ancestor
            .file_name()
            .and_then(|name| name.to_str())
            .filter(|name| name.ends_with(".framework"))
            .map(|_| ancestor.to_path_buf())
    })
}

pub(crate) fn bundle_executable_path(bundle_root: &Path, bundle_executable: &str) -> PathBuf {
    bundle_root.join(bundle_executable)
}

pub(crate) fn inspect_framework_bundle_reality(
    bundle_root: &Path,
    bundle_executable: &str,
) -> ArtifactRealityReport {
    let direct_target = bundle_executable_path(bundle_root, bundle_executable);
    let mut notes = Vec::new();
    let info_plist = locate_framework_metadata(bundle_root);
    let versioned_target = find_versioned_framework_executable(bundle_root, bundle_executable);
    let target = versioned_target
        .clone()
        .unwrap_or_else(|| direct_target.clone());

    if let Some(info_plist) = info_plist {
        notes.push(format!(
            "bundle metadata exists at {}.",
            info_plist.display()
        ));
    } else if bundle_root.is_dir() {
        notes.push(format!(
            "bundle directory exists, but metadata file is missing from expected locations under {}.",
            bundle_root.display()
        ));
    } else {
        notes.push(format!(
            "bundle root is not present on disk: {}.",
            bundle_root.display()
        ));
    }

    if let Some(versioned_target) = versioned_target {
        notes.push(format!(
            "versioned framework executable found at {}.",
            versioned_target.display()
        ));
        if versioned_target.is_file() {
            notes.push(format!(
                "bundle executable exists as a regular file in a versioned layout: {}.",
                versioned_target.display()
            ));
        } else if versioned_target.exists() {
            notes.push(format!(
                "bundle executable exists in a versioned layout, but not as a regular file: {}.",
                versioned_target.display()
            ));
        }
    } else if direct_target.is_file() {
        notes.push(format!(
            "bundle executable exists as a regular file: {}.",
            target.display()
        ));
    } else if direct_target.exists() {
        notes.push(format!(
            "bundle executable exists, but not as a regular file: {}.",
            direct_target.display()
        ));
    } else {
        notes.push(format!(
            "bundle executable is missing from the bundle at the top-level location: {}.",
            direct_target.display()
        ));
    }

    ArtifactRealityReport {
        target: Some(target),
        notes,
    }
}

fn find_versioned_framework_executable(
    bundle_root: &Path,
    bundle_executable: &str,
) -> Option<PathBuf> {
    let versions_dir = bundle_root.join("Versions");
    if !versions_dir.is_dir() {
        return None;
    }

    let version_candidates = std::fs::read_dir(&versions_dir).ok()?;
    for entry in version_candidates.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let candidate = path.join(bundle_executable);
        if candidate.exists() {
            return Some(candidate);
        }
    }

    None
}

fn locate_framework_metadata(bundle_root: &Path) -> Option<PathBuf> {
    let direct = bundle_root.join("Info.plist");
    if direct.is_file() {
        return Some(direct);
    }

    let versions_dir = bundle_root.join("Versions");
    if !versions_dir.is_dir() {
        return None;
    }

    let version_candidates = std::fs::read_dir(&versions_dir).ok()?;
    for entry in version_candidates.flatten() {
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }

        let candidate = path.join("Resources/Info.plist");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    None
}

fn resolve_soname_under_runtime_root(runtime_root: &Path, soname: &str) -> Option<PathBuf> {
    let search_roots = [
        runtime_root.join("lib"),
        runtime_root.join("usr/lib"),
        runtime_root.join("lib64"),
        runtime_root.join("usr/lib64"),
    ];

    for base in search_roots {
        let direct = base.join(soname);
        if direct.exists() {
            return Some(direct);
        }

        let entries = match std::fs::read_dir(&base) {
            Ok(entries) => entries,
            Err(_) => continue,
        };

        for entry in entries.flatten() {
            let subdir = entry.path();
            if !subdir.is_dir() {
                continue;
            }

            let candidate = subdir.join(soname);
            if candidate.exists() {
                return Some(candidate);
            }
        }
    }

    None
}

fn is_generic_library(lib: &str) -> bool {
    let lower = lib.to_ascii_lowercase();
    GENERIC_LIBRARY_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

fn is_generic_entrypoint_clue(clue: &str) -> bool {
    let lower = clue.to_ascii_lowercase();
    GENERIC_ENTRYPOINT_CLUES
        .iter()
        .any(|pattern| lower.contains(pattern))
}

fn is_bootstrap_pattern(clue: &str) -> bool {
    let lower = clue.to_ascii_lowercase();
    BOOTSTRAP_PATTERNS
        .iter()
        .any(|pattern| lower.contains(pattern))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn extract_entrypoint_clues_filters_generic_runtime_symbols() {
        let entrypoint = r#"
0x100000758      a01a40f9       ldr x0, [x21, 0x30]
; reloc.ExampleStreamManager
; reloc.objc_autoreleasePoolPush
0x10000075c      bl sym.imp.dispatch_main
"#;

        let clues = extract_entrypoint_clues(entrypoint);

        assert_eq!(
            clues,
            vec![
                "ExampleStreamManager".to_string(),
                "dispatch_main".to_string()
            ]
        );
    }

    #[test]
    fn extract_entrypoint_clues_filters_more_platform_runtime_noise() {
        let entrypoint = r#"
; reloc.IsInternalBuild
; reloc.__stack_chk_guard
; reloc.fixup.currentRunLoop
; reloc.ExampleReceiverServer
"#;

        let clues = extract_entrypoint_clues(entrypoint);
        assert_eq!(clues, vec!["ExampleReceiverServer".to_string()]);
    }

    #[test]
    fn filter_non_runtime_libraries_removes_common_frameworks() {
        let libraries = vec![
            "/usr/lib/libobjc.A.dylib".to_string(),
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
        ];

        let filtered = filter_non_runtime_libraries(&libraries);

        assert_eq!(
            filtered,
            vec![
                "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .to_string()
            ]
        );
    }

    #[test]
    fn filter_non_runtime_libraries_removes_common_elf_runtime_libraries() {
        let libraries = vec![
            "/lib64/ld-linux-x86-64.so.2".to_string(),
            "/lib/ld-uClibc.so.0".to_string(),
            "/usr/lib/gcc/x86_64-linux-gnu/12/libgcc_s.so.1".to_string(),
            "/usr/lib/x86_64-linux-gnu/libstdc++.so.6".to_string(),
            "/opt/vendor/libvendor.so".to_string(),
        ];

        let filtered = filter_non_runtime_libraries(&libraries);

        assert_eq!(filtered, vec!["/opt/vendor/libvendor.so".to_string()]);
    }

    #[test]
    fn rank_downstream_candidates_prefers_non_runtime_libraries() {
        let binary = Path::new("/tmp/example-rootfs/usr/libexec/service-launcher");
        let linked_libraries = vec![
            "/usr/lib/libSystem.B.dylib".to_string(),
            "/System/Library/Frameworks/Foundation.framework/Foundation".to_string(),
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                .to_string(),
        ];

        let ranked = rank_downstream_candidates(binary, &linked_libraries);

        assert_eq!(ranked.len(), 1);
        assert_eq!(
            ranked.first().map(|candidate| candidate.path.display().to_string()),
            Some(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
                    .to_string()
            )
        );
    }

    #[test]
    fn infer_runtime_root_maps_usr_binary_to_rootfs_prefix() {
        let root = infer_runtime_root(Path::new(
            "/tmp/example-rootfs/usr/libexec/service-launcher",
        ));
        assert_eq!(root, Some(PathBuf::from("/tmp/example-rootfs")));
    }

    #[test]
    fn infer_runtime_root_maps_usr_bin_binary_to_rootfs_prefix() {
        let root = infer_runtime_root(Path::new("/tmp/example-rootfs/usr/bin/agent"));
        assert_eq!(root, Some(PathBuf::from("/tmp/example-rootfs")));
    }

    #[test]
    fn infer_runtime_root_maps_root_level_libexec_binary_to_rootfs_prefix() {
        let root = infer_runtime_root(Path::new("/tmp/example-rootfs/libexec/agent"));
        assert_eq!(root, Some(PathBuf::from("/tmp/example-rootfs")));
    }

    #[test]
    fn resolve_linked_target_joins_absolute_link_against_inferred_root() {
        let resolved = resolve_linked_target(
            Path::new("/tmp/example-rootfs/usr/libexec/service-launcher"),
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit",
        );
        assert_eq!(
            resolved,
            Some(PathBuf::from(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
            ))
        );
    }

    #[test]
    fn resolve_linked_target_prefers_runtime_root_over_host_absolute_path() {
        let host_root = TempDir::new().expect("host tempdir");
        let runtime_root = TempDir::new().expect("runtime tempdir");
        let binary_dir = runtime_root.path().join("usr/libexec");
        let binary = binary_dir.join("service-launcher");
        let linked = host_root
            .path()
            .join("System/Library/Frameworks/Foundation.framework/Foundation");
        let rebased = runtime_root.path().join(
            linked
                .strip_prefix(Path::new("/"))
                .expect("absolute linked path"),
        );

        std::fs::create_dir_all(linked.parent().expect("host linked parent"))
            .expect("host linked dir");
        std::fs::write(&linked, b"host framework").expect("host linked file");
        std::fs::create_dir_all(&binary_dir).expect("binary dir");
        std::fs::write(&binary, b"stub").expect("binary file");

        assert_ne!(linked, rebased);
        assert!(
            linked.exists(),
            "host path should exist to trigger the regression"
        );

        let resolved = resolve_linked_target(&binary, linked.to_str().expect("utf8 path"));

        assert_eq!(resolved, Some(rebased));
    }

    #[test]
    fn resolve_linked_target_falls_back_to_host_absolute_path_without_runtime_root() {
        let host_root = TempDir::new().expect("host tempdir");
        let linked = host_root
            .path()
            .join("System/Library/Frameworks/Foundation.framework/Foundation");

        std::fs::create_dir_all(linked.parent().expect("host linked parent"))
            .expect("host linked dir");
        std::fs::write(&linked, b"host framework").expect("host linked file");

        let resolved =
            resolve_linked_target(Path::new("tool"), linked.to_str().expect("utf8 path"));

        assert_eq!(resolved, Some(linked));
    }

    #[test]
    fn resolve_linked_target_finds_soname_under_inferred_runtime_root() {
        let root = TempDir::new().expect("runtime root");
        let binary_dir = root.path().join("usr/sbin");
        let binary = binary_dir.join("httpd");
        let vendor_lib = root.path().join("usr/lib/libvendor.so");

        std::fs::create_dir_all(&binary_dir).expect("binary dir");
        std::fs::create_dir_all(vendor_lib.parent().expect("vendor lib parent"))
            .expect("vendor lib dir");
        std::fs::write(&binary, b"stub").expect("binary file");
        std::fs::write(&vendor_lib, b"stub").expect("vendor lib file");

        let resolved = resolve_linked_target(&binary, "libvendor.so");

        assert_eq!(resolved, Some(vendor_lib));
    }

    #[test]
    fn resolve_linked_target_finds_soname_under_arch_specific_runtime_subdir() {
        let root = TempDir::new().expect("runtime root");
        let binary_dir = root.path().join("usr/bin");
        let binary = binary_dir.join("agent");
        let vendor_lib = root.path().join("lib/mips-linux-gnu/libvendor.so");

        std::fs::create_dir_all(&binary_dir).expect("binary dir");
        std::fs::create_dir_all(vendor_lib.parent().expect("vendor lib parent"))
            .expect("vendor lib dir");
        std::fs::write(&binary, b"stub").expect("binary file");
        std::fs::write(&vendor_lib, b"stub").expect("vendor lib file");

        let resolved = resolve_linked_target(&binary, "libvendor.so");

        assert_eq!(resolved, Some(vendor_lib));
    }

    #[test]
    fn missing_linked_target_yields_a_filesystem_reality_mismatch_note() {
        let root = TempDir::new().expect("missing-linked-target");
        let binary_dir = root.path().join("usr/libexec");
        let binary = binary_dir.join("service-launcher");
        let linked =
            "/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit";

        std::fs::create_dir_all(&binary_dir).expect("test directory should be creatable");
        std::fs::write(&binary, b"stub").expect("test binary should be writable");

        let report = inspect_linked_target_reality(&binary, linked);

        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("filesystem-reality mismatch")),
            "expected a note about the linked target existing only as metadata or an unresolved reference"
        );
    }

    #[test]
    fn detects_framework_bundle_path_from_linked_executable_path() {
        let linked = Path::new(
            "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit",
        );

        assert_eq!(
            framework_bundle_root(linked),
            Some(PathBuf::from(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework"
            ))
        );
    }

    #[test]
    fn joins_cf_bundle_executable_to_bundle_path() {
        let bundle_root = Path::new(
            "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework",
        );

        assert_eq!(
            bundle_executable_path(bundle_root, "ExampleRuntimeKit"),
            PathBuf::from(
                "/tmp/example-rootfs/System/Library/PrivateFrameworks/ExampleRuntimeKit.framework/ExampleRuntimeKit"
            )
        );
    }

    #[test]
    fn reports_bundle_metadata_vs_missing_executable_mismatch() {
        let root = TempDir::new().expect("bundle-metadata-mismatch");
        let bundle_root = root
            .path()
            .join("System/Library/PrivateFrameworks/ExampleRuntimeKit.framework");
        std::fs::create_dir_all(&bundle_root).expect("bundle root should be creatable");
        std::fs::write(
            bundle_root.join("Info.plist"),
            br#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>CFBundleExecutable</key>
    <string>ExampleRuntimeKit</string>
    <key>CFBundleIdentifier</key>
    <string>com.example.ExampleRuntimeKit</string>
    <key>CFBundlePackageType</key>
    <string>FMWK</string>
</dict>
</plist>
"#,
        )
        .expect("bundle metadata plist should be writable");

        let report = inspect_framework_bundle_reality(&bundle_root, "ExampleRuntimeKit");

        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("bundle metadata exists")),
            "expected a note explaining the bundle metadata / executable mismatch"
        );
    }

    #[test]
    fn reports_versioned_framework_executable_before_declaring_missing() {
        let root = TempDir::new().expect("versioned-bundle");
        let bundle_root = root.path().join("System/Library/Frameworks/Foo.framework");
        let versioned_dir = bundle_root.join("Versions/A");
        std::fs::create_dir_all(&versioned_dir).expect("versioned framework dir should exist");
        std::fs::write(versioned_dir.join("Foo"), b"stub").expect("versioned executable");

        let report = inspect_framework_bundle_reality(&bundle_root, "Foo");

        assert_eq!(
            report.target,
            Some(versioned_dir.join("Foo")),
            "expected the versioned framework executable to be selected"
        );
        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("versioned framework executable found")),
            "expected a note about the versioned framework layout"
        );
        assert!(
            report
                .notes
                .iter()
                .all(|note| !note.contains("missing from the bundle at the top-level location")),
            "should not describe the executable as missing when a versioned layout exists"
        );
    }

    #[test]
    fn reports_versioned_framework_metadata_before_declaring_missing() {
        let root = TempDir::new().expect("versioned-metadata-bundle");
        let bundle_root = root.path().join("System/Library/Frameworks/Foo.framework");
        let versioned_resources = bundle_root.join("Versions/A/Resources");
        std::fs::create_dir_all(&versioned_resources).expect("versioned resources dir");
        std::fs::write(versioned_resources.join("Info.plist"), b"stub").expect("versioned plist");

        let report = inspect_framework_bundle_reality(&bundle_root, "Foo");

        assert!(
            report
                .notes
                .iter()
                .any(|note| note.contains("bundle metadata exists")),
            "expected versioned bundle metadata to be recognized"
        );
        assert!(
            report
                .notes
                .iter()
                .all(|note| !note.contains("metadata file is missing")),
            "should not say metadata is missing when versioned metadata exists"
        );
    }
}
