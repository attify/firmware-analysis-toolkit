//! `fat taint-cross` — the shared-state catalog is operator-supplied.
//!
//! Deciding that one function writes a config store and another reads it is a
//! claim about a particular platform's API, so FAT ships no such catalog. These
//! tests pin the CLI contract: with no `--state-profile` the command still runs
//! but assigns no read/write role and produces no findings; with one, the run
//! says which profile it used. JSON output is an array even without findings.

use std::fs;
use std::process::{Command, Output};

use tempfile::tempdir;

fn fat(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .output()
        .expect("fat runs")
}

/// A minimal ELF-magic file. Nothing here needs a real binary: the point is
/// which catalog the run selects, which is decided before any analysis.
fn write_binary(dir: &std::path::Path, name: &str, body: &str) -> String {
    let path = dir.join(name);
    let mut bytes = b"\x7fELF".to_vec();
    bytes.extend_from_slice(body.as_bytes());
    fs::write(&path, bytes).expect("write binary");
    path.to_string_lossy().into_owned()
}

const STATE_PROFILE: &str = concat!(
    "name: example-target-state\n",
    "families:\n",
    "  - id: config-store\n",
    "    write: [example_store_set]\n",
    "    read: [example_store_get]\n",
    "    flush: [example_store_commit]\n",
);

#[test]
fn review_no_profile_produces_valid_empty_json_in_both_output_modes() {
    let dir = tempdir().unwrap();
    let binary = write_binary(dir.path(), "empty", "no modeled functions");
    for flag in ["--json", "--as-taint-json"] {
        let output = fat(&["taint-cross", "--file", &binary, flag]);
        assert!(output.status.success(), "{output:?}");
        let findings: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)
            .expect("a successful JSON invocation must emit a JSON array");
        assert!(findings.is_empty());
    }
}

#[test]
fn without_a_state_profile_the_catalog_is_empty_and_stitching_is_disabled() {
    let dir = tempdir().expect("tempdir");
    let writer = write_binary(dir.path(), "httpd", "example_store_set(\"Password\")");
    let reader = write_binary(dir.path(), "daemon", "example_store_get(\"Password\")");

    let output = fat(&["taint-cross", "--file", &writer, "--file", &reader]);

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Shared-state catalog: none (no shared-state profile selected)"),
        "{stderr}"
    );
    assert!(
        stderr.contains("role assignment and cross-binary stitching are disabled"),
        "{stderr}"
    );
    // Nothing was classified, so nothing was stitched.
    assert!(
        stderr.contains("No shared-state observations found"),
        "{stderr}"
    );
    assert!(!stderr.contains("cross-binary flows found."), "{stderr}");
}

/// The names the built-in catalog used to carry get no special treatment: with
/// no profile they are as unclassified as any other symbol.
#[test]
fn platform_config_names_are_not_privileged_without_a_profile() {
    let dir = tempdir().expect("tempdir");
    let writer = write_binary(dir.path(), "httpd", "nvram_set(\"AdminPassword\")");
    let reader = write_binary(dir.path(), "daemon", "nvram_get(\"AdminPassword\")");

    let output = fat(&["taint-cross", "--file", &writer, "--file", &reader]);

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("No shared-state observations found"),
        "{stderr}"
    );
}

#[test]
fn a_selected_state_profile_is_reported_with_its_path() {
    let dir = tempdir().expect("tempdir");
    let binary = write_binary(dir.path(), "httpd", "example_store_set(\"Password\")");
    let profile = dir.path().join("state.yaml");
    fs::write(&profile, STATE_PROFILE).expect("write profile");
    let profile = profile.to_string_lossy().into_owned();

    let output = fat(&[
        "taint-cross",
        "--file",
        &binary,
        "--state-profile",
        &profile,
    ]);

    assert!(output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains(&format!(
            "Shared-state catalog: profile example-target-state ({profile})"
        )),
        "{stderr}"
    );
    assert!(!stderr.contains("stitching are disabled"), "{stderr}");
    // The profile's write pattern is what makes this a write observation.
    assert!(stderr.contains("strings: 1 hint observations"), "{stderr}");
}

#[test]
fn a_missing_state_profile_is_an_error_not_a_silent_fallback() {
    let dir = tempdir().expect("tempdir");
    let binary = write_binary(dir.path(), "httpd", "example_store_set(\"Password\")");
    let missing = dir.path().join("missing.yaml");

    let output = fat(&[
        "taint-cross",
        "--file",
        &binary,
        "--state-profile",
        missing.to_str().expect("utf8"),
    ]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read shared-state profile"),
        "{stderr}"
    );
}

#[test]
fn an_invalid_state_profile_is_rejected_with_the_path() {
    let dir = tempdir().expect("tempdir");
    let binary = write_binary(dir.path(), "httpd", "example_store_set(\"Password\")");
    let profile = dir.path().join("bad.yaml");
    fs::write(&profile, "name: bad\nfamilies:\n  - id: empty\n").expect("write profile");

    let output = fat(&[
        "taint-cross",
        "--file",
        &binary,
        "--state-profile",
        profile.to_str().expect("utf8"),
    ]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("invalid shared-state profile"), "{stderr}");
    assert!(
        stderr.contains("declares no read or write functions"),
        "{stderr}"
    );
}

#[test]
fn taint_cross_help_documents_the_state_profile_flag() {
    let output = fat(&["taint-cross", "--help"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--state-profile"), "{stdout}");
    assert!(stdout.contains("FAT ships no such catalog"), "{stdout}");
}

#[cfg(unix)]
mod profile_flow_regressions {
    use super::*;
    use sha2::{Digest, Sha256};
    use std::os::unix::fs::PermissionsExt;
    use std::path::{Path, PathBuf};

    // Mock only the external process; exercise FAT's real profile loading,
    // materialization, result conversion, classification and serialization.
    struct Fixture {
        dir: tempfile::TempDir,
        writer: String,
        reader: String,
        state: PathBuf,
        models: PathBuf,
        python: PathBuf,
    }

    impl Fixture {
        fn new() -> Self {
            let dir = tempdir().unwrap();
            let writer = write_binary(dir.path(), "writer", "example_store_set");
            let reader = write_binary(dir.path(), "reader", "example_store_get");
            let state = dir.path().join("state.yaml");
            fs::write(&state, STATE_PROFILE).unwrap();
            let models = dir.path().join("core.yaml");
            fs::write(
                &models,
                concat!(
                    "name: example-binary-models\nsources:\n  secondary:\n",
                    "    - name: example_store_get\nsinks:\n",
                    "  - name: example_store_set\n    arg: 1\n    category: config-write\n"
                ),
            )
            .unwrap();
            for (file, source, sink, class) in [
                ("writer.json", "getenv", "example_store_set", "primary"),
                ("reader.json", "example_store_get", "system", "secondary"),
            ] {
                fs::write(
                    dir.path().join(file),
                    serde_json::to_vec(&serde_json::json!([{
                        "function": "synthetic_handler", "source": source,
                        "sink": sink, "source_class": class, "method": "co-occurrence-only"
                    }]))
                    .unwrap(),
                )
                .unwrap();
            }
            let python = dir.path().join("python");
            fs::write(
                &python,
                r#"#!/bin/sh
if [ "$1" = -c ]; then exit 0; fi
printf 'run\n' >> "$FAT_TEST_DIR/runs"
cat "$5"/*.yaml > "$FAT_TEST_DIR/delivered.yaml"
if [ "$FAT_TEST_EMPTY" = 1 ]; then printf '[]' > "$3"; exit 0; fi
if [ "$FAT_TEST_REQUIRE_MODELS" = 1 ] && [ ! -f "$5/external.yaml" ]; then
    printf '[]' > "$3"; exit 0
fi
case "$2" in
    */writer) cp "$FAT_TEST_DIR/writer.json" "$3" ;;
    *) cp "$FAT_TEST_DIR/reader.json" "$3" ;;
esac
"#,
            )
            .unwrap();
            fs::set_permissions(&python, fs::Permissions::from_mode(0o755)).unwrap();
            Self {
                dir,
                writer,
                reader,
                state,
                models,
                python,
            }
        }

        fn command(&self, mode: &str, models: Option<&Path>) -> Command {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_fat"));
            cmd.args([
                "taint-cross",
                "--file",
                &self.writer,
                "--file",
                &self.reader,
                "--state-profile",
                self.state.to_str().unwrap(),
                mode,
            ])
            .env("FAT_PYTHON", &self.python)
            .env("FAT_TEST_DIR", self.dir.path());
            if let Some(models) = models {
                cmd.arg("--source-profile").arg(models);
            }
            cmd
        }

        fn run(&self, mode: &str, models: Option<&Path>) -> serde_json::Value {
            let out = self.command(mode, models).output().unwrap();
            assert!(out.status.success(), "{out:?}");
            serde_json::from_slice(&out.stdout).unwrap()
        }
    }

    fn assert_profile(value: &serde_json::Value, path: &Path, name: &str) {
        assert_eq!(value["kind"], "external_profile");
        assert_eq!(value["name"], name);
        assert_eq!(value["path"], path.to_str().unwrap());
        assert_eq!(
            value["sha256"],
            format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
        );
    }

    #[test]
    fn selected_binary_models_reach_the_cross_binary_producer() {
        let f = Fixture::new();
        let out = f
            .command("--json", Some(&f.models))
            .env("FAT_TEST_REQUIRE_MODELS", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        let delivered = fs::read_to_string(f.dir.path().join("delivered.yaml")).unwrap();
        assert!(
            delivered.contains("name: core"),
            "core models were overwritten"
        );
        assert!(
            delivered.contains("example_store_get"),
            "selected read model missing"
        );
        assert!(
            delivered.contains("example_store_set"),
            "selected write model missing"
        );
        let findings: Vec<serde_json::Value> = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(
            findings.len(),
            1,
            "the delivered models must enable the fixture's pair"
        );
    }

    #[test]
    fn cross_json_modes_preserve_both_profile_identities_and_edits() {
        let f = Fixture::new();
        for mode in ["--json", "--as-taint-json"] {
            let core = f.run(mode, None);
            assert_eq!(core[0]["model_provenance"]["kind"], "core");
            assert_profile(
                &core[0]["state_model_provenance"],
                &f.state,
                "example-target-state",
            );

            let selected = f.run(mode, Some(&f.models));
            assert_profile(
                &selected[0]["model_provenance"],
                &f.models,
                "example-binary-models",
            );
            assert_profile(
                &selected[0]["state_model_provenance"],
                &f.state,
                "example-target-state",
            );
            for path in [&f.models, &f.state] {
                let contents = fs::read_to_string(path).unwrap();
                fs::write(path, format!("{contents}\n# selected revision\n")).unwrap();
            }
            let edited = f.run(mode, Some(&f.models));
            for field in ["model_provenance", "state_model_provenance"] {
                assert_ne!(edited[0][field]["sha256"], selected[0][field]["sha256"]);
            }
            if mode == "--as-taint-json" {
                let typed: Vec<fat_taint::TaintFinding> =
                    serde_json::from_value(edited.clone()).unwrap();
                let saved = serde_json::to_value(typed).unwrap();
                assert_eq!(
                    saved[0]["state_model_provenance"],
                    edited[0]["state_model_provenance"]
                );
                // Historical records remain readable without invented metadata.
                let mut historical = edited;
                historical[0]
                    .as_object_mut()
                    .unwrap()
                    .remove("state_model_provenance");
                historical[0]
                    .as_object_mut()
                    .unwrap()
                    .remove("model_provenance");
                let typed: Vec<fat_taint::TaintFinding> =
                    serde_json::from_value(historical).unwrap();
                let saved = serde_json::to_value(typed).unwrap();
                assert!(saved[0].get("state_model_provenance").is_none());
            }
        }
    }

    #[test]
    fn missing_or_invalid_binary_profiles_fail_before_running_the_producer() {
        let f = Fixture::new();
        let bad = f.dir.path().join("bad.yaml");
        for contents in [None, Some("name: [not-a-string]\n")] {
            if let Some(contents) = contents {
                fs::write(&bad, contents).unwrap();
            }
            let out = f.command("--json", Some(&bad)).output().unwrap();
            assert!(!out.status.success());
            assert!(
                String::from_utf8_lossy(&out.stderr).contains("taint profile"),
                "{out:?}"
            );
            assert!(
                !f.dir.path().join("runs").exists(),
                "invalid profile reached the producer"
            );
        }
    }

    #[test]
    fn strings_provider_excludes_flushes_but_retains_writes() {
        let f = Fixture::new();
        fs::write(&f.state, "name: example\nfamilies:\n  - id: store\n    write: [example_store]\n    read: [example_read]\n    flush: [example_store_commit]\n").unwrap();
        fs::write(&f.writer, b"\x7fELF\0example_store_commit\0").unwrap();
        fs::write(&f.reader, b"\x7fELF\0unrelated\0").unwrap();
        let out = f
            .command("--json", None)
            .env("FAT_TEST_EMPTY", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            !String::from_utf8_lossy(&out.stderr).contains("hint observations"),
            "flush classified as write: {out:?}"
        );
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap(),
            serde_json::json!([])
        );
        fs::write(&f.writer, b"\x7fELF\0example_store_set\0").unwrap();
        let out = f
            .command("--json", None)
            .env("FAT_TEST_EMPTY", "1")
            .output()
            .unwrap();
        assert!(out.status.success(), "{out:?}");
        assert!(
            String::from_utf8_lossy(&out.stderr).contains("strings: 1 hint observations"),
            "valid write dropped: {out:?}"
        );
    }
}
