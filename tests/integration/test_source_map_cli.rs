//! `fat source-map` — frontend surfaces and ranked backend candidates.
//!
//! A backend candidate's `source_hints` name symbols observed in its strings.
//! Which platform symbol carries request data is a claim about one target, so
//! FAT compiles in only the specified models and the rest arrive from a
//! profile the operator names by path. Both halves are asserted below.

use std::process::Command;

use tempfile::tempdir;

/// A profile an operator writes after establishing what these symbols do on
/// the target in front of them.
const TARGET_PROFILE: &str = concat!(
    "name: example-target\n",
    "sources:\n",
    "  primary:\n",
    "    - name: websGetVarN\n",
    "      taint_kind: buffer\n",
    "      note: writes the named request variable into a caller buffer\n",
    "    - name: soap_get_param\n",
    "      taint_kind: return\n",
    "      note: returns the named SOAP request parameter\n",
);

#[test]
fn fat_source_map_discovers_frontend_params_constraints_and_backend_candidates() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    let www = rootfs.join("www");
    let bin = rootfs.join("bin");
    std::fs::create_dir_all(&www).expect("create www");
    std::fs::create_dir_all(&bin).expect("create bin");

    std::fs::write(
        www.join("index.html"),
        r#"
        <html>
          <body>
            <form action="/apply.cgi" method="post">
              <input name="machine_name" maxlength="32" />
              <input type="hidden" name="action" value="apply" />
            </form>
          </body>
        </html>
        "#,
    )
    .expect("write html");

    std::fs::write(
        www.join("api.js"),
        r#"
        fetch("/soap.cgi?action=GetInfo");
        const param = "machine_name";
        "#,
    )
    .expect("write js");

    std::fs::write(
        bin.join("httpd"),
        r#"
        apply.cgi
        soap.cgi
        GetInfo
        machine_name
        websGetVarN
        soap_get_param
        "#,
    )
    .expect("write backend candidate");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "source-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .output()
        .expect("fat source-map runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("source-map returns JSON");

    let surfaces = report["frontend_surfaces"].as_array().expect("surfaces");
    assert_eq!(surfaces.len(), 2);
    let html_surface = surfaces
        .iter()
        .find(|surface| surface["kind"] == "html-form")
        .expect("html form surface");
    let html_params = html_surface["parameters"].as_array().expect("html params");
    let machine_name = html_params
        .iter()
        .find(|param| param["name"] == "machine_name")
        .expect("machine_name param");
    assert_eq!(machine_name["constraint"]["kind"], "max_length");
    assert_eq!(machine_name["constraint"]["value"], 32);
    assert_eq!(report["backend_candidates"][0]["path"], "/bin/httpd");
    assert!(report["backend_candidates"][0]["matched_terms"]
        .as_array()
        .expect("matched terms")
        .iter()
        .any(|term| term == "machine_name"));
    assert!(report["backend_candidates"][0]["matched_terms"]
        .as_array()
        .expect("matched terms")
        .iter()
        .any(|term| term == "GetInfo"));
    // With no profile selected, a platform symbol observed in the strings is
    // not reported as a source hint. The binary is still ranked on its matched
    // terms — the observation is kept, the role is not asserted.
    let source_hints = report["backend_candidates"][0]["source_hints"]
        .as_array()
        .expect("source hints");
    assert!(
        source_hints.is_empty(),
        "platform source hints appeared with no profile selected: {source_hints:#?}"
    );
}

#[test]
fn fat_source_map_reports_platform_source_hints_only_from_a_selected_profile() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    let www = rootfs.join("www");
    let bin = rootfs.join("bin");
    std::fs::create_dir_all(&www).expect("create www");
    std::fs::create_dir_all(&bin).expect("create bin");

    std::fs::write(
        www.join("index.html"),
        r#"<form action="/apply.cgi" method="post"><input name="machine_name" /></form>"#,
    )
    .expect("write html");
    std::fs::write(
        bin.join("httpd"),
        "apply.cgi\nmachine_name\nwebsGetVarN\nsoap_get_param\ngetenv\n",
    )
    .expect("write backend candidate");

    let profile = dir.path().join("example-target.yaml");
    std::fs::write(&profile, TARGET_PROFILE).expect("write profile");

    let run = |args: &[&str]| -> serde_json::Value {
        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .args(args)
            .output()
            .expect("fat source-map runs");
        assert!(output.status.success(), "{output:?}");
        serde_json::from_slice(&output.stdout).expect("source-map returns JSON")
    };

    let rootfs_arg = rootfs.to_str().expect("rootfs path");
    let base = run(&["source-map", "--rootfs", rootfs_arg, "--json"]);
    let base_hints: Vec<&str> = base["backend_candidates"][0]["source_hints"]
        .as_array()
        .expect("source hints")
        .iter()
        .map(|hint| hint["function"].as_str().expect("function"))
        .collect();
    // getenv is ISO C, so it is compiled in; the platform getters are not.
    assert_eq!(base_hints, ["getenv"], "{base_hints:?}");

    let selected = run(&[
        "source-map",
        "--rootfs",
        rootfs_arg,
        "--source-profile",
        profile.to_str().expect("profile path"),
        "--json",
    ]);
    let hints = selected["backend_candidates"][0]["source_hints"]
        .as_array()
        .expect("source hints");
    assert!(hints
        .iter()
        .any(|hint| hint["function"] == "websGetVarN" && hint["taint_kind"] == "buffer"));
    assert!(hints
        .iter()
        .any(|hint| hint["function"] == "soap_get_param" && hint["taint_kind"] == "return"));
    assert!(hints.iter().any(|hint| hint["function"] == "getenv"));
}

#[test]
fn fat_source_map_rejects_a_missing_source_profile() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    std::fs::create_dir_all(rootfs.join("www")).expect("create www");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "source-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--source-profile",
            dir.path().join("missing.yaml").to_str().expect("path"),
            "--json",
        ])
        .output()
        .expect("fat source-map runs");

    assert!(!output.status.success(), "{output:?}");
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("failed to read taint profile"), "{stderr}");
}

#[test]
fn fat_source_map_uses_control_url_for_xml_action_surfaces() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    let www = rootfs.join("www");
    let bin = rootfs.join("bin");
    std::fs::create_dir_all(&www).expect("create www");
    std::fs::create_dir_all(&bin).expect("create bin");

    std::fs::write(
        www.join("igd.xml"),
        r#"
        <root>
          <service>
            <controlURL>/soap.cgi</controlURL>
            <actionList>
              <action><name>GetInfo</name></action>
              <action><name>SetConfig</name></action>
            </actionList>
          </service>
        </root>
        "#,
    )
    .expect("write xml");

    std::fs::write(
        bin.join("miniigd"),
        r#"
        soap.cgi
        GetInfo
        SetConfig
        soap_get_param
        "#,
    )
    .expect("write backend candidate");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "source-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .output()
        .expect("fat source-map runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("source-map returns JSON");

    let xml_surface = report["frontend_surfaces"]
        .as_array()
        .expect("surfaces")
        .iter()
        .find(|surface| surface["kind"] == "xml-action")
        .cloned()
        .expect("xml action surface");

    assert_eq!(xml_surface["endpoint"], "/soap.cgi");
    assert!(xml_surface["parameters"]
        .as_array()
        .expect("xml params")
        .iter()
        .any(|param| param["name"] == "GetInfo"));
    assert_eq!(report["backend_candidates"][0]["path"], "/bin/miniigd");
}

#[test]
fn fat_source_map_ignores_symlinked_rootfs_subtrees() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("rootfs");
    let www = rootfs.join("www");
    let bin = rootfs.join("bin");
    std::fs::create_dir_all(&www).expect("create www");
    std::fs::create_dir_all(&bin).expect("create bin");

    std::fs::write(
        www.join("index.html"),
        r#"
        <html>
          <body>
            <form action="/apply.cgi" method="post">
              <input name="machine_name" maxlength="32" />
            </form>
          </body>
        </html>
        "#,
    )
    .expect("write html");

    std::fs::write(
        bin.join("httpd"),
        r#"
        apply.cgi
        machine_name
        websGetVarN
        "#,
    )
    .expect("write backend candidate");

    #[cfg(unix)]
    std::os::unix::fs::symlink(&www, rootfs.join("www-link")).expect("create symlink");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "source-map",
            "--rootfs",
            rootfs.to_str().expect("rootfs path"),
            "--json",
        ])
        .output()
        .expect("fat source-map runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let report: serde_json::Value = serde_json::from_str(&stdout).expect("source-map returns JSON");

    let surfaces = report["frontend_surfaces"].as_array().expect("surfaces");
    assert_eq!(surfaces.len(), 1);
    assert_eq!(surfaces[0]["path"], "/www/index.html");
}

#[test]
fn source_map_preserves_profile_identity_and_content_revision() {
    use sha2::{Digest, Sha256};
    let dir = tempdir().unwrap();
    let root = dir.path().join("rootfs");
    std::fs::create_dir_all(root.join("www")).unwrap();
    std::fs::write(
        root.join("www/index.html"),
        "<form action=\"/apply\"><input name=\"marker\"></form>",
    )
    .unwrap();
    std::fs::write(root.join("backend"), "marker\nexample_input\ngetenv\n").unwrap();
    let profile = dir.path().join("source.yaml");
    let run = |selected: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_fat"));
        cmd.arg("source-map")
            .arg("--rootfs")
            .arg(&root)
            .arg("--json");
        if selected {
            cmd.arg("--source-profile").arg(&profile);
        }
        let out = cmd.output().unwrap();
        assert!(out.status.success(), "{out:?}");
        serde_json::from_slice::<serde_json::Value>(&out.stdout).unwrap()
    };
    assert_eq!(run(false)["model_provenance"]["kind"], "core");
    let mut previous_digest = serde_json::Value::Null;
    for kind in ["buffer", "return"] {
        let yaml = format!("name: example\nsources:\n  primary:\n    - name: example_input\n      taint_kind: {kind}\n");
        std::fs::write(&profile, &yaml).unwrap();
        let result = run(true);
        let provenance = &result["model_provenance"];
        assert_eq!(provenance["name"], "example");
        assert_eq!(provenance["path"], profile.to_str().unwrap());
        assert_eq!(
            provenance["sha256"],
            format!("{:x}", Sha256::digest(yaml.as_bytes()))
        );
        assert_ne!(provenance["sha256"], previous_digest);
        previous_digest = provenance["sha256"].clone();
        assert!(result["backend_candidates"][0]["source_hints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|hint| hint["function"] == "example_input" && hint["taint_kind"] == kind));
    }
    // Even a no-match result records the selected model set.
    std::fs::remove_file(root.join("backend")).unwrap();
    assert_eq!(run(true)["model_provenance"]["name"], "example");
}
