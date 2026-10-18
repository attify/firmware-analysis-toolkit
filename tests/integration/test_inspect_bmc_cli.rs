use serde_json::Value;
use std::{
    path::Path,
    process::{Command, Output},
};
use tempfile::tempdir;
#[path = "../support/bmc_firmware.rs"]
mod fixture;

fn run(file: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_fat"))
        .envs([("FAT_COLOR", "never"), ("COLUMNS", "48")])
        .args(["inspect", "bmc", "--file"])
        .arg(file)
        .args(args)
        .output()
        .unwrap()
}
fn json(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn bmc_json_tracks_fit_offsets_and_details_never_change_analysis() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("flash.mtd");
    let mut image = vec![0xff; 0x1000];
    image.extend(fixture::fit(false));
    std::fs::write(&file, image).unwrap();
    let report = json(&run(&file, &["--json"]));
    assert_eq!(report, json(&run(&file, &["--json", "--details"])));
    assert_eq!(report["fit"]["blobs"][0]["offset"], 4096);
    assert_eq!(report["fit"]["blobs"][0]["default_configuration"], "conf-1");
    assert!(report["findings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|f| f["rule_id"] == "BOOT-FIT-HASH-ONLY"));
    let text = run(&file, &["--details"]);
    assert!(text.status.success());
    let text = String::from_utf8(text.stdout).unwrap();
    for expected in [
        "BMC inspection",
        "OpenBMC",
        "kernel-1",
        "conf-1",
        "sha256",
        "0x00001000",
    ] {
        assert!(text.contains(expected), "missing {expected}: {text}");
    }
}

#[test]
fn configuration_signature_is_metadata_and_prevents_hash_only_finding() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("signed.itb");
    std::fs::write(&file, fixture::fit(true)).unwrap();
    let report = json(&run(&file, &["--json"]));
    let findings = report["findings"].as_array().unwrap();
    assert!(!findings
        .iter()
        .any(|f| f["rule_id"] == "BOOT-FIT-HASH-ONLY"));
    assert!(findings
        .iter()
        .any(|f| f["rule_id"] == "BOOT-FIT-SIGNATURE-METADATA"));
    assert!(!report.to_string().contains("\"verified\":true"));
}

#[test]
fn sarif_has_rules_byte_locations_and_explicit_warning_gate() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("flash with spaces.mtd");
    std::fs::write(&file, fixture::fit(false)).unwrap();
    let report = json(&run(&file, &["--sarif"]));
    assert_eq!(report["version"], "2.1.0");
    let run_report = &report["runs"][0];
    let result = &run_report["results"][0];
    assert_eq!(result["ruleId"], "BOOT-FIT-HASH-ONLY");
    assert_eq!(
        result["locations"][0]["physicalLocation"]["region"]["byteOffset"],
        0
    );
    assert!(run_report["tool"]["driver"]["rules"]
        .as_array()
        .unwrap()
        .iter()
        .any(|r| r["id"] == "BOOT-FIT-HASH-ONLY"));
    assert!(
        result["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
            .as_str()
            .unwrap()
            .contains("%20")
    );
    let gated = run(&file, &["--sarif", "--fail-on-warning"]);
    assert!(!gated.status.success());
    let gated_json: Value = serde_json::from_slice(&gated.stdout).unwrap();
    assert_eq!(gated_json, report);
}

#[test]
fn explicit_environment_region_and_invalid_options_are_handled() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("env.bin");
    let mut image = vec![0xff; 17];
    image.extend(fixture::environment());
    std::fs::write(&file, image).unwrap();
    let report = json(&run(
        &file,
        &["--json", "--env-offset", "0x11", "--env-size", "4096"],
    ));
    assert_eq!(report["environment_scan"]["environments"][0]["offset"], 17);
    assert!(!run(&file, &["--env-offset", "17"]).status.success());
    assert!(!run(&file, &["--json", "--sarif"]).status.success());
    assert!(!run(&file, &["--env-offset", "9999", "--env-size", "4096"])
        .status
        .success());
}

#[test]
fn malformed_fdt_is_diagnostic_and_does_not_become_hash_only() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("bad.itb");
    let mut image = fixture::fit(false);
    image[4..8].copy_from_slice(&u32::MAX.to_be_bytes());
    std::fs::write(&file, image).unwrap();
    let report = json(&run(&file, &["--json"]));
    assert!(report["fit"]["blobs"].as_array().unwrap().is_empty());
    assert!(!report["fit"]["diagnostics"].as_array().unwrap().is_empty());
    assert!(report["findings"].as_array().unwrap().is_empty());
}

#[cfg(unix)]
#[test]
fn sarif_preserves_unix_backslashes_and_non_utf8_filename_bytes() {
    use std::{ffi::OsString, os::unix::ffi::OsStringExt};
    let dir = tempdir().unwrap();
    for (name, suffix) in [
        (b"flash\\dump.itb".to_vec(), "flash%5Cdump.itb"),
        (b"flash\xff.itb".to_vec(), "flash%FF.itb"),
    ] {
        // APFS rejects non-UTF8 names before the command can receive them.
        if name.contains(&0xff) && !cfg!(target_os = "linux") {
            continue;
        }
        let file = dir.path().join(OsString::from_vec(name));
        std::fs::write(&file, fixture::fit(false)).unwrap();
        let report = json(&run(&file, &["--sarif"]));
        let uri = report["runs"][0]["artifacts"][0]["location"]["uri"]
            .as_str()
            .unwrap();
        assert!(uri.ends_with(suffix), "{uri}");
    }
}

#[test]
fn generic_headers_exposes_the_shared_fit_evidence() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("shared.itb");
    std::fs::write(&file, fixture::fit(false)).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "headers", "--file"])
        .arg(file)
        .arg("--json")
        .output()
        .unwrap();
    let report = json(&output);
    assert_eq!(report["fit"]["blobs"][0]["images"][0]["name"], "kernel-1");
}
