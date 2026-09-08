//! `fat taint --lang shell` — CLI surface for shell source-to-sink taint.
//!
//! The rootfs fixture reproduces representative firmware shell data flows:
//! a `/configs` provisioning read reaching a `sed -i` replacement expression
//! (CVE-2024-6247 shape), a tmpfs-staged `sh /tmp/...`, an nvram read reaching
//! `insmod`, and `$1` reaching an unquoted path argument. The rootfs samples
//! these are drawn from are not available here, so they are synthesized.
//!
//! Two of the four chains depend on claims about the target — that `/configs`
//! and `/tmp` are attacker-writable there, that `nvram_get` reads persisted
//! state — so they are reported only when an operator supplies a profile
//! saying so. The tests below assert both halves: what the always-loaded
//! profile alone will say, and what it says once an overlay is selected.

use std::fs;
use std::path::Path;
use std::process::{Command, Output};

use tempfile::{tempdir, TempDir};

fn fat(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(args)
        .output()
        .expect("fat runs")
}

fn write(root: &Path, rel: &str, body: &str) {
    let path = root.join(rel);
    fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
    fs::write(path, body).expect("write");
}

/// A rootfs with one chain per sink family the issue calls out.
fn fixture_rootfs() -> TempDir {
    let dir = tempdir().expect("tempdir");
    let root = dir.path();

    // CVE-2024-6247 shape: /configs provisioning read → $wifissid → $newvalue
    // → sed -i replacement. The trailing comment and single-quoted echo must
    // not produce findings — that is the AST win over the regex pass.
    write(
        root,
        "wyze_app/init/wifi.sh",
        concat!(
            "#!/bin/sh\n",
            "key=ssid\n",
            "file=/etc/wifi.conf\n",
            "wifissid=$(cat /configs/.wifissid)\n",
            "newvalue=\"$wifissid\"\n",
            "sed -i \"s/$key=.*/$key=$newvalue/g\" $file\n",
            "# sed -i \"s/x/$evil/g\" f\n",
            "echo 'sed -i \"s/x/$evil/g\" f'\n",
        ),
    );
    write(
        root,
        "etc/init.d/check_upgrade",
        "#!/bin/sh\nsh /tmp/upgrade_stage.sh\nmod=`nvram_get modname`\ninsmod $mod\n",
    );
    write(
        root,
        "bin/format_sd.sh",
        "#!/bin/sh\ndev=$1\nmount $dev /mnt/sdcard\n",
    );
    // Not a script: must not be scanned.
    write(root, "etc/version", "eval $x\n");
    // A script with a sink but no source: sink-discovery territory, not taint.
    write(root, "bin/clean.sh", "#!/bin/sh\neval \"echo ready\"\n");

    dir
}

/// What an operator writes once they have established these facts about the
/// target: two mounts an attacker can write, and the platform's nvram helper.
const TARGET_OVERLAY: &str = concat!(
    "name: shell-example-target\n",
    "sources:\n",
    "  primary:\n",
    "    - name: writable-mount-read\n",
    "      kind: path-prefix\n",
    "      paths: [\"/configs/\", \"/tmp/\"]\n",
    "  secondary:\n",
    "    - name: nvram_get\n",
    "      kind: command\n",
);

fn overlay_in(dir: &Path) -> String {
    write(dir, "overlay.yaml", TARGET_OVERLAY);
    dir.join("overlay.yaml").to_string_lossy().into_owned()
}

#[test]
fn shell_taint_reports_the_configs_to_sed_chain_end_to_end() {
    let dir = fixture_rootfs();
    let script = dir.path().join("wyze_app/init/wifi.sh");
    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--file",
        script.to_str().expect("utf8"),
        "--json",
    ]);

    assert!(output.status.success(), "{output:?}");
    let findings: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("findings parse as JSON");
    let findings = findings.as_array().expect("array");
    assert_eq!(findings.len(), 1, "{findings:#?}");

    let finding = &findings[0];
    assert_eq!(finding["id"], "SHELL-0001");
    assert_eq!(finding["severity"], "High");
    assert_eq!(finding["status"], "Candidate");
    // The read is reported; the directory it names does not make it Primary.
    assert_eq!(finding["source_class"], "Secondary");
    assert!(
        finding["title"]
            .as_str()
            .expect("title")
            .contains("cat /configs/.wifissid → sed-var-injection"),
        "{finding:#?}"
    );

    let chain = finding["chain"].as_array().expect("chain");
    assert_eq!(chain.len(), 3, "{chain:#?}");
    assert_eq!(chain[0]["action"], "cat /configs/.wifissid → $wifissid");
    assert_eq!(chain[1]["action"], "$wifissid → $newvalue");
    assert!(
        chain[2]["action"]
            .as_str()
            .expect("action")
            .contains("[sed-var-injection]"),
        "{chain:#?}"
    );
    assert!(chain[2]["location"]
        .as_str()
        .expect("location")
        .ends_with("wifi.sh:6"));
}

#[test]
fn shell_taint_findings_use_the_same_json_shape_as_binary_taint() {
    let dir = fixture_rootfs();
    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--rootfs",
        dir.path().to_str().expect("utf8"),
        "--json",
    ]);

    assert!(output.status.success(), "{output:?}");
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let first = &findings.as_array().expect("array")[0];

    // The `fat taint --json` finding shape, key for key.
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
        assert!(!first[key].is_null(), "missing {key}: {first:#?}");
    }
    for key in ["binary", "function", "location", "action", "edge_type"] {
        assert!(
            !first["chain"][0][key].is_null(),
            "missing chain key {key}: {first:#?}"
        );
    }
    // Shell edges are the overlay tier, so every shell finding is a Candidate.
    assert!(
        first["chain"][0]["edge_type"]["ShellModel"].is_object(),
        "{first:#?}"
    );
    assert_eq!(first["status"], "Candidate");
}

/// Without a profile the sweep reports the chains whose sources are specified
/// constructs, and only those. The two chains that need a claim about the
/// target are absent — the scripts were still scanned, so this is a decision
/// not to assert, not a parsing gap.
#[test]
fn shell_taint_rootfs_sweep_reports_only_the_specified_sources() {
    let dir = fixture_rootfs();
    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--rootfs",
        dir.path().to_str().expect("utf8"),
        "--json",
    ]);

    assert!(output.status.success(), "{output:?}");
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let findings = findings.as_array().expect("array");
    assert_eq!(findings.len(), 2, "{findings:#?}");

    let joined = findings
        .iter()
        .map(|f| f["title"].as_str().expect("title"))
        .collect::<Vec<_>>()
        .join("\n");
    assert!(joined.contains("sed-var-injection"), "{joined}");
    assert!(joined.contains("unquoted-var-as-path"), "{joined}");
    // These need the operator's overlay, below.
    assert!(!joined.contains("tmpfs-staged-exec"), "{joined}");
    assert!(!joined.contains("insmod-var-path"), "{joined}");

    // The sink-only script and the non-script file contribute nothing.
    assert!(!joined.contains("clean.sh"), "{joined}");
    assert!(!joined.contains("etc/version"), "{joined}");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("4 script(s) scanned"), "{stderr}");
}

/// With the operator's overlay every synthesized chain is reported, and the
/// `/configs` read is Primary because the overlay asserted that mount is
/// attacker-writable — the finding records which mount did so.
#[test]
fn a_supplied_overlay_restores_the_target_dependent_chains() {
    let dir = fixture_rootfs();
    let overlay = overlay_in(dir.path());
    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--rootfs",
        dir.path().to_str().expect("utf8"),
        "--source-profile",
        &overlay,
        "--json",
    ]);

    assert!(output.status.success(), "{output:?}");
    let findings: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
    let findings = findings.as_array().expect("array");
    assert_eq!(findings.len(), 4, "{findings:#?}");

    let joined = findings
        .iter()
        .map(|f| f["title"].as_str().expect("title"))
        .collect::<Vec<_>>()
        .join("\n");
    for family in [
        "sed-var-injection",
        "tmpfs-staged-exec",
        "insmod-var-path",
        "unquoted-var-as-path",
    ] {
        assert!(joined.contains(family), "{family} missing: {joined}");
    }

    let sed = findings
        .iter()
        .find(|f| {
            f["title"]
                .as_str()
                .expect("title")
                .contains("sed-var-injection")
        })
        .expect("sed finding");
    assert_eq!(sed["source_class"], "Primary");
    assert!(
        sed["status_reason"]
            .as_str()
            .expect("reason")
            .contains("writable mount /configs/"),
        "{sed:#?}"
    );
}

/// The review's repro, at the CLI. Two reads that differ only in the directory
/// they name must be classified identically: neither file exists, and neither
/// script is executed, so the path name is not evidence of anything.
#[test]
fn a_path_name_alone_does_not_raise_the_source_class() {
    let dir = tempdir().expect("tempdir");
    for (name, path) in [
        ("configs.sh", "/configs/value"),
        ("etc.sh", "/etc/value"),
        ("sdcard.sh", "/mnt/sdcard/value"),
        ("tmp.sh", "/tmp/value"),
    ] {
        write(
            dir.path(),
            name,
            &format!("#!/bin/sh\nv=$(cat {path})\neval \"$v\"\n"),
        );
        let script = dir.path().join(name);
        let output = fat(&[
            "taint",
            "--lang",
            "shell",
            "--file",
            script.to_str().expect("utf8"),
            "--json",
        ]);
        assert!(output.status.success(), "{output:?}");
        let findings: serde_json::Value = serde_json::from_slice(&output.stdout).expect("JSON");
        let findings = findings.as_array().expect("array");
        assert_eq!(findings.len(), 1, "{path}: {findings:#?}");
        assert_eq!(
            findings[0]["source_class"], "Secondary",
            "{path} was promoted on its name alone"
        );
        assert!(
            !findings[0]["status_reason"]
                .as_str()
                .expect("reason")
                .contains("writable mount"),
            "{path} claimed a writable mount: {findings:#?}"
        );
    }
}

#[test]
fn shell_taint_summary_and_severity_filter_work() {
    let dir = fixture_rootfs();
    let overlay = overlay_in(dir.path());
    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--rootfs",
        dir.path().to_str().expect("utf8"),
        "--source-profile",
        &overlay,
        "--severity",
        "high",
        "--summary",
    ]);

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("4 finding(s) total, 2 shown"), "{stdout}");
    assert!(stdout.contains("sed-var-injection"), "{stdout}");
    assert!(stdout.contains("tmpfs-staged-exec"), "{stdout}");
    assert!(!stdout.contains("insmod-var-path"), "{stdout}");
}

#[test]
fn shell_taint_reports_nothing_for_a_script_with_no_source_to_sink_flow() {
    let dir = tempdir().expect("tempdir");
    write(dir.path(), "clean.sh", "#!/bin/sh\necho hello\nls /etc\n");

    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--file",
        dir.path().join("clean.sh").to_str().expect("utf8"),
        "--json",
    ]);

    assert!(output.status.success(), "{output:?}");
    assert_eq!(String::from_utf8_lossy(&output.stdout).trim(), "[]");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("No shell taint findings"), "{stderr}");
}

#[test]
fn a_supplied_shell_overlay_promotes_a_path_to_a_writable_mount() {
    let dir = tempdir().expect("tempdir");
    write(
        dir.path(),
        "boot.sh",
        "#!/bin/sh\nv=$(cat /params/boot_cmd)\neval \"$v\"\n",
    );
    write(
        dir.path(),
        "overlay.yaml",
        "name: shell-example\nsources:\n  primary:\n    - name: writable-mount-read\n      kind: path-prefix\n      paths: [\"/params/\"]\n",
    );
    let script = dir.path().join("boot.sh");
    let script = script.to_str().expect("utf8");
    let overlay = dir.path().join("overlay.yaml");
    let overlay = overlay.to_str().expect("utf8");

    let base: serde_json::Value = serde_json::from_slice(
        &fat(&["taint", "--lang", "shell", "--file", script, "--json"]).stdout,
    )
    .expect("JSON");
    assert_eq!(base[0]["source_class"], "Secondary");

    let overlaid: serde_json::Value = serde_json::from_slice(
        &fat(&[
            "taint",
            "--lang",
            "shell",
            "--file",
            script,
            "--source-profile",
            overlay,
            "--json",
        ])
        .stdout,
    )
    .expect("JSON");
    assert_eq!(overlaid[0]["source_class"], "Primary");
    assert!(
        overlaid[0]["status_reason"]
            .as_str()
            .expect("reason")
            .contains("writable mount /params/"),
        "{overlaid:#?}"
    );
}

#[test]
fn a_shell_overlay_path_that_does_not_exist_is_an_error() {
    let dir = tempdir().expect("tempdir");
    write(dir.path(), "a.sh", "#!/bin/sh\necho hi\n");

    let output = fat(&[
        "taint",
        "--lang",
        "shell",
        "--file",
        dir.path().join("a.sh").to_str().expect("utf8"),
        "--source-profile",
        dir.path().join("missing.yaml").to_str().expect("utf8"),
    ]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("failed to read shell source profile"),
        "{stderr}"
    );
}

#[test]
fn taint_on_a_shell_script_without_lang_shell_points_at_the_flag() {
    let dir = tempdir().expect("tempdir");
    write(dir.path(), "a.sh", "#!/bin/sh\necho hi\n");

    let output = fat(&[
        "taint",
        "--file",
        dir.path().join("a.sh").to_str().expect("utf8"),
    ]);

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("rerun with `--lang shell`"), "{stderr}");
}

#[test]
fn shell_taint_rejects_binary_only_flags_and_bad_argument_combinations() {
    let dir = tempdir().expect("tempdir");
    write(dir.path(), "a.sh", "#!/bin/sh\necho hi\n");
    let script = dir.path().join("a.sh");
    let script = script.to_str().expect("utf8");
    let root = dir.path().to_str().expect("utf8");

    let cases: [(&[&str], &str); 6] = [
        (
            &["taint", "--lang", "shell", "--file", "X", "--arch", "arm"],
            "--arch applies to binary taint only",
        ),
        (
            &["taint", "--lang", "shell", "--file", "X", "--decompile"],
            "--decompile applies to binary taint only",
        ),
        (
            &["taint", "--lang", "shell"],
            "--lang shell requires --file <script> or --rootfs <dir>",
        ),
        (
            &["taint", "--lang", "shell", "--file", "X", "--rootfs", "R"],
            "either --file or --rootfs, not both",
        ),
        (
            &["taint", "--lang", "rust", "--file", "X"],
            "unknown --lang 'rust'",
        ),
        (
            &["taint", "--rootfs", "R"],
            "--rootfs is only supported with --lang shell",
        ),
    ];

    for (args, expected) in cases {
        let resolved: Vec<&str> = args
            .iter()
            .map(|arg| match *arg {
                "X" => script,
                "R" => root,
                other => other,
            })
            .collect();
        let output = fat(&resolved);
        assert!(!output.status.success(), "{resolved:?} -> {output:?}");
        let stderr = String::from_utf8_lossy(&output.stderr);
        assert!(stderr.contains(expected), "{resolved:?}: {stderr}");
    }
}

#[test]
fn taint_help_documents_the_shell_language_mode() {
    let output = fat(&["taint", "--help"]);
    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        stdout.contains("fat taint --lang shell --rootfs <dir>"),
        "{stdout}"
    );
    assert!(stdout.contains("tree-sitter-bash"), "{stdout}");
    assert!(
        stdout.contains("fat taint --lang shell --file ./app/init/wifi.sh --summary"),
        "{stdout}"
    );
}
