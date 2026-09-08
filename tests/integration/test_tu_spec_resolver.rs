use fat_query::toolchain_profile::ToolchainProfile;
use fat_query::tu_spec::{resolve_tu_spec, resolve_tu_spec_for_codeql_database, TUSpecSource};
use std::fs;

#[test]
fn tu_spec_prefers_compile_commands_with_deterministic_ranking() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("sample.mm");
    fs::write(&sample, "int main() { return 0; }\n").expect("write source");
    fs::write(
        root.join("compile_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-o", "sample.o", "{}"],
  "output": "sample.o"
}}, {{
  "directory": "{}",
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17", "-target", "arm64-apple-darwin", "-o", "sample.mm", "{}"],
  "output": "sample.mm"
}}]"#,
            root.display(),
            sample.display(),
            sample.display(),
            root.display(),
            sample.display(),
            sample.display(),
        ),
    )
    .expect("write compile commands");

    let spec = resolve_tu_spec(root, Some(&sample)).expect("resolve tu spec");

    assert_eq!(spec.source, TUSpecSource::CompileCommands);
    assert!(spec.selection_reason.contains("deterministic ranking"));
    assert_eq!(spec.file, sample);
    assert!(
        spec.output.is_some(),
        "expected ranked output to be preserved"
    );
}

#[test]
fn tu_spec_uses_compile_flags_before_fixture_metadata() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    let sample = root.join("sample.mm");
    fs::write(&sample, "int main() { return 0; }\n").expect("write source");
    fs::write(
        root.join("compile_flags.txt"),
        "-x\nobjective-c++\n-std=c++17\n-target\narm64-apple-darwin\n",
    )
    .expect("write compile flags");
    fs::write(
        root.join("fat-tuspec.json"),
        format!(
            r#"{{
  "file": "{}",
  "arguments": ["clang++", "-x", "objective-c++", "-std=c++17"]
}}"#,
            sample.display()
        ),
    )
    .expect("write fixture tuspec");

    let spec = resolve_tu_spec(root, None).expect("resolve compile flags");
    assert_eq!(spec.source, TUSpecSource::CompileFlags);
    assert!(spec.selection_reason.contains("triage-grade"));
}

#[test]
fn toolchain_profile_merges_fixture_metadata_with_arguments() {
    let dir = tempfile::tempdir().expect("tempdir");
    let root = dir.path();
    fs::write(
        root.join("fat-toolchain-profile.json"),
        r#"{
  "target_triple": "arm64-apple-darwin",
  "runtime_hints": ["metal-fixture"]
}"#,
    )
    .expect("write toolchain profile");

    let inferred = ToolchainProfile::from_arguments(&[
        "clang++".into(),
        "-isysroot".into(),
        "/tmp/fake-sdk".into(),
    ]);
    let merged = inferred.merge(Some(
        fat_query::toolchain_profile::load_toolchain_profile(root)
            .expect("load toolchain")
            .expect("profile"),
    ));

    assert_eq!(merged.target_triple.as_deref(), Some("arm64-apple-darwin"));
    assert_eq!(
        merged.sdk_root.as_deref(),
        Some(std::path::Path::new("/tmp/fake-sdk"))
    );
    assert!(merged.is_complete());
    assert!(!merged.hash().is_empty());
}

#[test]
fn tu_spec_resolves_from_codeql_extraction_commands() {
    let dir = tempfile::tempdir().expect("tempdir");
    let source_root = dir.path().join("kernel-src");
    let db_root = dir.path().join("binder-db");
    fs::create_dir_all(source_root.join("drivers/android")).expect("source root");
    fs::create_dir_all(db_root.join("log")).expect("db log");
    let sample = source_root.join("drivers/android/binder_alloc.c");
    fs::write(&sample, "int binder_alloc() { return 0; }\n").expect("write source");
    fs::write(
        db_root.join("log/extraction_commands.json"),
        format!(
            r#"[{{
  "directory": "{}",
  "file": "{}",
  "arguments": ["--mimic", "/usr/bin/clang", "-I{}", "-c", "{}"]
}}]"#,
            source_root.join("drivers/android").display(),
            sample.display(),
            source_root.join("drivers/android").display(),
            sample.display()
        ),
    )
    .expect("write extraction commands");

    let spec =
        resolve_tu_spec_for_codeql_database(&source_root, &db_root, Some(&sample)).expect("spec");

    assert_eq!(spec.source, TUSpecSource::CodeQlExtractionCommands);
    assert_eq!(spec.file, sample);
    assert_eq!(
        spec.arguments.first().map(String::as_str),
        Some("/usr/bin/clang")
    );
    assert!(spec.selection_reason.contains("CodeQL extraction_commands"));
}
