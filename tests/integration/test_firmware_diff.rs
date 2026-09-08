use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::process::Command;
use tempfile::tempdir;

use fat_core::firmware_diff::{
    diff_certificates, diff_filesystems, diff_nvram_keys, diff_summary, diff_web_endpoints,
    extract_nvram_keys_from_scripts, scan_persistent_weaknesses,
};

#[test]
fn filesystem_diff_detects_added_cgi_as_attack_surface() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Base has a simple config file
    let base_etc = base_dir.path().join("etc");
    fs::create_dir_all(&base_etc).unwrap();
    fs::write(base_etc.join("hostname"), "router").unwrap();

    // Head adds a CGI script (attack surface)
    let head_etc = head_dir.path().join("etc");
    let head_cgi = head_dir.path().join("www").join("cgi-bin");
    fs::create_dir_all(&head_etc).unwrap();
    fs::create_dir_all(&head_cgi).unwrap();
    fs::write(head_etc.join("hostname"), "router").unwrap();
    fs::write(head_cgi.join("setup.cgi"), "#!/bin/sh\necho setup").unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    // The CGI file should be in the added list
    assert!(
        diff.added.iter().any(|f| f.path.contains("setup.cgi")),
        "expected setup.cgi in added files, got: {:?}",
        diff.added
    );

    // The CGI file should be tagged as ATTACK_SURFACE
    let cgi_entry = diff
        .added
        .iter()
        .find(|f| f.path.contains("setup.cgi"))
        .unwrap();
    assert!(
        cgi_entry
            .security_tags
            .contains(&"ATTACK_SURFACE".to_string()),
        "expected ATTACK_SURFACE tag, got: {:?}",
        cgi_entry.security_tags
    );

    // Head should have more files than base
    assert!(diff.head_file_count > diff.base_file_count);
}

#[test]
fn filesystem_diff_detects_removed_file() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Base has a debug binary
    let base_usr = base_dir.path().join("usr").join("bin");
    fs::create_dir_all(&base_usr).unwrap();
    fs::write(base_usr.join("telnetd"), "#!/bin/sh\ntelnet daemon").unwrap();

    // Head does not have the debug binary
    let head_usr = head_dir.path().join("usr").join("bin");
    fs::create_dir_all(&head_usr).unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    assert!(
        diff.removed.iter().any(|f| f.path.contains("telnetd")),
        "expected telnetd in removed files, got: {:?}",
        diff.removed
    );

    // telnetd should be tagged as DEBUG_INTERFACE
    let removed_entry = diff
        .removed
        .iter()
        .find(|f| f.path.contains("telnetd"))
        .unwrap();
    assert!(
        removed_entry
            .security_tags
            .contains(&"DEBUG_INTERFACE".to_string()),
        "expected DEBUG_INTERFACE tag, got: {:?}",
        removed_entry.security_tags
    );
}

#[test]
fn filesystem_diff_detects_permission_change_without_content_change() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Both have the same file content
    let base_etc = base_dir.path().join("etc");
    let head_etc = head_dir.path().join("etc");
    fs::create_dir_all(&base_etc).unwrap();
    fs::create_dir_all(&head_etc).unwrap();

    let base_file = base_etc.join("config.sh");
    let head_file = head_etc.join("config.sh");
    fs::write(&base_file, "#!/bin/sh\necho hello").unwrap();
    fs::write(&head_file, "#!/bin/sh\necho hello").unwrap();

    // Change permissions on the head version (make world-writable)
    let mut perms = fs::metadata(&head_file).unwrap().permissions();
    perms.set_mode(0o777);
    fs::set_permissions(&head_file, perms).unwrap();

    let mut base_perms = fs::metadata(&base_file).unwrap().permissions();
    base_perms.set_mode(0o644);
    fs::set_permissions(&base_file, base_perms).unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    // Content hash is the same, so it should NOT be in changed
    assert!(
        diff.changed.is_empty(),
        "expected no content changes, got: {:?}",
        diff.changed
    );

    // But permission change should be tracked independently
    assert!(
        diff.permissions_changed
            .iter()
            .any(|p| p.path.contains("config.sh")),
        "expected permission change for config.sh, got: {:?}",
        diff.permissions_changed
    );

    let perm_entry = diff
        .permissions_changed
        .iter()
        .find(|p| p.path.contains("config.sh"))
        .unwrap();
    assert_ne!(perm_entry.base_mode, perm_entry.head_mode);
}

#[test]
fn filesystem_diff_detects_symlink_retarget() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    let base_bin = base_dir.path().join("bin");
    let head_bin = head_dir.path().join("bin");
    fs::create_dir_all(&base_bin).unwrap();
    fs::create_dir_all(&head_bin).unwrap();

    // Both have a symlink, but pointing to different targets
    std::os::unix::fs::symlink("/usr/bin/busybox", base_bin.join("sh")).unwrap();
    std::os::unix::fs::symlink("/usr/bin/ash", head_bin.join("sh")).unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    assert!(
        diff.symlinks_changed.iter().any(|s| s.path.contains("sh")),
        "expected symlink change for sh, got: {:?}",
        diff.symlinks_changed
    );

    let sym_entry = diff
        .symlinks_changed
        .iter()
        .find(|s| s.path.contains("sh"))
        .unwrap();
    assert_eq!(sym_entry.base_target.as_deref(), Some("/usr/bin/busybox"));
    assert_eq!(sym_entry.head_target.as_deref(), Some("/usr/bin/ash"));
}

#[test]
fn diff_summary_computes_security_direction() {
    // Improved: more security-relevant removals than additions
    let summary = diff_summary(
        /* total_files_changed */ 10, /* security_relevant_changes */ 3,
        /* new_attack_surface_count */ 0, /* removed_attack_surface_count */ 2,
        /* crypto_changes */ 0, /* debug_changes_added */ 0,
        /* debug_changes_removed */ 1,
    );
    assert_eq!(summary.overall_security_direction, "improved");

    // Degraded: new attack surface added
    let summary = diff_summary(
        5, 3, 3, // new attack surface
        0, 0, 2, // debug added
        0,
    );
    assert_eq!(summary.overall_security_direction, "degraded");

    // Unchanged: no security-relevant changes
    let summary = diff_summary(0, 0, 0, 0, 0, 0, 0);
    assert_eq!(summary.overall_security_direction, "unchanged");

    // Mixed: both improvements and regressions
    let summary = diff_summary(8, 4, 1, 1, 1, 0, 1);
    assert_eq!(summary.overall_security_direction, "mixed");
}

#[test]
fn certificate_diff_detects_key_rotation() {
    // Check if openssl is available; skip test if not
    let openssl_check = Command::new("openssl").arg("version").output();
    if openssl_check.is_err() || !openssl_check.unwrap().status.success() {
        eprintln!("openssl not available, skipping certificate_diff_detects_key_rotation");
        return;
    }

    let dir = tempdir().expect("temp dir");
    let base_cert = dir.path().join("base.pem");
    let head_cert = dir.path().join("head.pem");
    let base_key = dir.path().join("base.key");
    let head_key = dir.path().join("head.key");

    // Generate two different self-signed certificates (different keys = key rotation)
    let gen_base = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:2048",
            "-keyout",
            base_key.to_str().unwrap(),
            "-out",
            base_cert.to_str().unwrap(),
            "-days",
            "365",
            "-nodes",
            "-subj",
            "/CN=base-router/O=TestCorp",
        ])
        .output()
        .expect("generate base cert");
    assert!(
        gen_base.status.success(),
        "base cert generation failed: {}",
        String::from_utf8_lossy(&gen_base.stderr)
    );

    let gen_head = Command::new("openssl")
        .args([
            "req",
            "-x509",
            "-newkey",
            "rsa:4096",
            "-keyout",
            head_key.to_str().unwrap(),
            "-out",
            head_cert.to_str().unwrap(),
            "-days",
            "730",
            "-nodes",
            "-subj",
            "/CN=head-router/O=TestCorp",
        ])
        .output()
        .expect("generate head cert");
    assert!(
        gen_head.status.success(),
        "head cert generation failed: {}",
        String::from_utf8_lossy(&gen_head.stderr)
    );

    let diff = diff_certificates(&base_cert, &head_cert).expect("cert diff");

    // Key rotation: different keys were used
    assert!(diff.key_rotated, "expected key rotation to be detected");

    // Different subjects
    assert_ne!(diff.base_subject, diff.head_subject);

    // Different key sizes
    assert_eq!(diff.base_key_bits, Some(2048));
    assert_eq!(diff.head_key_bits, Some(4096));

    // Both should have modulus hashes
    assert!(diff.base_modulus_hash.is_some());
    assert!(diff.head_modulus_hash.is_some());
    assert_ne!(diff.base_modulus_hash, diff.head_modulus_hash);
}

#[test]
fn nvram_key_diff_detects_added_key() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Base has a script that reads one NVRAM key
    let base_etc = base_dir.path().join("etc").join("init.d");
    fs::create_dir_all(&base_etc).unwrap();
    fs::write(
        base_etc.join("rcS"),
        "#!/bin/sh\nWAN_IP=$(nvram_get 2860 wan_ipaddr)\nifconfig eth0 $WAN_IP\n",
    )
    .unwrap();

    // Head has a script that reads two NVRAM keys (added admin_password)
    let head_etc = head_dir.path().join("etc").join("init.d");
    fs::create_dir_all(&head_etc).unwrap();
    fs::write(
        head_etc.join("rcS"),
        "#!/bin/sh\nWAN_IP=$(nvram_get 2860 wan_ipaddr)\nADMIN_PW=$(nvram_get 2860 admin_password)\nifconfig eth0 $WAN_IP\n",
    )
    .unwrap();

    let base_keys = extract_nvram_keys_from_scripts(base_dir.path()).expect("base keys");
    let head_keys = extract_nvram_keys_from_scripts(head_dir.path()).expect("head keys");

    let diff = diff_nvram_keys(&base_keys, &head_keys);

    // admin_password should be added
    assert!(
        diff.iter()
            .any(|d| d.key_name == "admin_password" && d.status == "added"),
        "expected admin_password added, got: {diff:?}"
    );

    // wan_ipaddr should not appear in the diff (present in both)
    assert!(
        !diff.iter().any(|d| d.key_name == "wan_ipaddr"),
        "wan_ipaddr should not be in diff, got: {diff:?}"
    );
}

#[test]
fn web_endpoint_diff_detects_new_cgi() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    // Base CGI directory with one endpoint
    let base_cgi = base_dir.path().join("www").join("cgi-bin");
    fs::create_dir_all(&base_cgi).unwrap();
    fs::write(
        base_cgi.join("status.cgi"),
        "#!/bin/sh\necho Content-Type: text/html\necho\necho status ok",
    )
    .unwrap();

    // Head has original plus a new upload endpoint
    let head_cgi = head_dir.path().join("www").join("cgi-bin");
    fs::create_dir_all(&head_cgi).unwrap();
    fs::write(
        head_cgi.join("status.cgi"),
        "#!/bin/sh\necho Content-Type: text/html\necho\necho status ok",
    )
    .unwrap();
    fs::write(
        head_cgi.join("upload.cgi"),
        "#!/bin/sh\necho Content-Type: text/html\necho\necho upload handler",
    )
    .unwrap();

    let diff = diff_web_endpoints(base_dir.path(), head_dir.path()).expect("web diff");

    assert!(
        diff.added_endpoints
            .iter()
            .any(|e| e.contains("upload.cgi")),
        "expected upload.cgi in added endpoints, got: {:?}",
        diff.added_endpoints
    );

    // status.cgi should not be in added (present in both)
    assert!(
        !diff
            .added_endpoints
            .iter()
            .any(|e| e.contains("status.cgi")),
        "status.cgi should not be in added endpoints"
    );
}

#[test]
fn filesystem_diff_detects_changed_file_content() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    let base_etc = base_dir.path().join("etc").join("init.d");
    let head_etc = head_dir.path().join("etc").join("init.d");
    fs::create_dir_all(&base_etc).unwrap();
    fs::create_dir_all(&head_etc).unwrap();

    // Same path, different content
    fs::write(base_etc.join("rcS"), "#!/bin/sh\necho starting v1\n").unwrap();
    fs::write(
        head_etc.join("rcS"),
        "#!/bin/sh\necho starting v2\ntelnetd &\n",
    )
    .unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    // rcS changed content
    assert!(
        diff.changed.iter().any(|f| f.path.contains("rcS")),
        "expected rcS in changed files, got: {:?}",
        diff.changed
    );

    // rcS should be tagged as CONFIG_CHANGE
    let changed_entry = diff
        .changed
        .iter()
        .find(|f| f.path.contains("rcS"))
        .unwrap();
    assert!(
        changed_entry
            .security_tags
            .contains(&"CONFIG_CHANGE".to_string()),
        "expected CONFIG_CHANGE tag, got: {:?}",
        changed_entry.security_tags
    );

    // Should not be in added or removed
    assert!(diff.added.is_empty() || !diff.added.iter().any(|f| f.path.contains("rcS")));
    assert!(diff.removed.is_empty() || !diff.removed.iter().any(|f| f.path.contains("rcS")));
}

#[test]
fn filesystem_diff_classifies_crypto_files() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    let base_ssl = base_dir.path().join("etc").join("ssl");
    let head_ssl = head_dir.path().join("etc").join("ssl");
    fs::create_dir_all(&base_ssl).unwrap();
    fs::create_dir_all(&head_ssl).unwrap();

    // Base has no certs; head adds one
    fs::write(
        head_ssl.join("server.pem"),
        "-----BEGIN CERTIFICATE-----\nfake\n-----END CERTIFICATE-----\n",
    )
    .unwrap();

    let diff = diff_filesystems(base_dir.path(), head_dir.path()).expect("diff");

    let pem_entry = diff
        .added
        .iter()
        .find(|f| f.path.contains("server.pem"))
        .unwrap();
    assert!(
        pem_entry
            .security_tags
            .contains(&"CRYPTO_CHANGE".to_string()),
        "expected CRYPTO_CHANGE tag for .pem file, got: {:?}",
        pem_entry.security_tags
    );
    assert_eq!(pem_entry.file_type, "certificate");
}

#[test]
fn firmware_diff_report_serializes_to_json() {
    use fat_core::firmware_diff::{DiffSummary, FilesystemDiff, FirmwareDiffReport};

    let report = FirmwareDiffReport {
        base_project: "/lab/v2.01".to_string(),
        head_project: "/lab/v2.17".to_string(),
        base_version: Some("2.01".to_string()),
        head_version: Some("2.17".to_string()),
        diff_timestamp: "unix:1234567890".to_string(),
        filesystem: Some(FilesystemDiff {
            base_file_count: 100,
            head_file_count: 105,
            added: vec![],
            removed: vec![],
            changed: vec![],
            permissions_changed: vec![],
            symlinks_changed: vec![],
        }),
        partitions: vec![],
        config: None,
        binaries: vec![],
        binary_diagnostic: None,
        library_absorption: vec![],
        persistent_weaknesses: vec![],
        summary: DiffSummary {
            total_files_changed: 5,
            security_relevant_changes: 2,
            new_attack_surface_count: 1,
            removed_attack_surface_count: 0,
            crypto_changes: 1,
            debug_changes_added: 0,
            debug_changes_removed: 0,
            overall_security_direction: "degraded".to_string(),
        },
    };

    let json = serde_json::to_string_pretty(&report).expect("serialize");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("parse");

    assert_eq!(
        parsed.get("base-project").and_then(|v| v.as_str()),
        Some("/lab/v2.01")
    );
    assert_eq!(
        parsed
            .get("summary")
            .and_then(|s| s.get("overall-security-direction"))
            .and_then(|v| v.as_str()),
        Some("degraded")
    );
}

#[test]
fn persistent_weakness_scan_detects_wyze_app_init_layout() {
    let base_dir = tempdir().expect("base dir");
    let head_dir = tempdir().expect("head dir");

    for root in [base_dir.path(), head_dir.path()] {
        let init_dir = root.join("init");
        fs::create_dir_all(&init_dir).unwrap();
        fs::write(
            init_dir.join("app_init.sh"),
            "#!/bin/sh\n#telnetd &\n/system/bin/ver-comp\n",
        )
        .unwrap();
        fs::write(
            init_dir.join("wifi.sh"),
            r#"#! /bin/sh
rewrite_config_value()
{
    file=$1
    key=$2
    newvalue=$3
    if [ -f $file ]; then
        sed -i "s/$key=.*/$key=$newvalue/g" $file
    fi
}
wifissid=$(cat /configs/.wifissid)
wifipasswd=$(cat /configs/.wifipasswd)
rewrite_config_value $wpaconf_file  ssid  "\"$wifissid\""
rewrite_config_value $wpaconf_file  psk  "\"$wifipasswd\""
"#,
        )
        .unwrap();
    }

    let weaknesses = scan_persistent_weaknesses(base_dir.path(), head_dir.path());

    assert!(
        weaknesses.iter().any(|w| {
            w.category == "debug-surface"
                && w.path == "init/app_init.sh"
                && w.description.contains("telnetd")
        }),
        "expected commented telnetd weakness in app init layout, got: {weaknesses:?}"
    );
    assert!(
        weaknesses.iter().any(|w| {
            w.category == "injection"
                && w.path == "init/wifi.sh"
                && w.description.contains("wifi.sh")
        }),
        "expected wifi.sh injection weakness in app init layout, got: {weaknesses:?}"
    );
}
