use fat_analyze::nvram_diff::{
    classify_security_relevance, diff_nvram_keys, extract_nvram_keys, NvramKeyRef,
};
use std::fs;
use tempfile::tempdir;

#[test]
fn nvram_extraction_finds_keys_in_shell_scripts() {
    let dir = tempdir().unwrap();
    let rootfs = dir.path();

    // Create sbin/ with a shell script containing nvram_get calls
    let sbin = rootfs.join("sbin");
    fs::create_dir_all(&sbin).unwrap();
    fs::write(
        sbin.join("startup.sh"),
        r#"#!/bin/sh
PASS=$(nvram_get 2860 Password)
SSID=$(nvram_get 2860 SSID)
nvram_set 2860 WanEnabled 1
"#,
    )
    .unwrap();

    let keys = extract_nvram_keys(rootfs).unwrap();

    // Should find Password (get), SSID (get), and WanEnabled (set)
    assert!(
        keys.len() >= 3,
        "Expected at least 3 keys, got {}",
        keys.len()
    );

    let password_key = keys.iter().find(|k| k.key_name == "Password");
    assert!(password_key.is_some(), "Should find 'Password' key");
    assert_eq!(password_key.unwrap().access_type, "get");

    let ssid_key = keys.iter().find(|k| k.key_name == "SSID");
    assert!(ssid_key.is_some(), "Should find 'SSID' key");
    assert_eq!(ssid_key.unwrap().access_type, "get");

    let wan_key = keys.iter().find(|k| k.key_name == "WanEnabled");
    assert!(wan_key.is_some(), "Should find 'WanEnabled' key");
    assert_eq!(wan_key.unwrap().access_type, "set");
}

#[test]
fn nvram_diff_detects_added_key() {
    let base_keys = vec![NvramKeyRef {
        key_name: "SSID".into(),
        source_file: "etc/startup.sh".into(),
        access_type: "get".into(),
    }];
    let head_keys = vec![
        NvramKeyRef {
            key_name: "SSID".into(),
            source_file: "etc/startup.sh".into(),
            access_type: "get".into(),
        },
        NvramKeyRef {
            key_name: "DebugLevel".into(),
            source_file: "sbin/debug.sh".into(),
            access_type: "get".into(),
        },
    ];

    let diffs = diff_nvram_keys(&base_keys, &head_keys);

    let added = diffs.iter().find(|d| d.key_name == "DebugLevel");
    assert!(added.is_some(), "DebugLevel should appear in diff");
    assert_eq!(added.unwrap().status, "added");
    assert!(added.unwrap().head_source.is_some());
    assert!(added.unwrap().base_source.is_none());

    let unchanged = diffs.iter().find(|d| d.key_name == "SSID");
    assert!(unchanged.is_some(), "SSID should appear in diff");
    assert_eq!(unchanged.unwrap().status, "unchanged");
}

#[test]
fn nvram_diff_detects_removed_key() {
    let base_keys = vec![
        NvramKeyRef {
            key_name: "SSID".into(),
            source_file: "etc/startup.sh".into(),
            access_type: "get".into(),
        },
        NvramKeyRef {
            key_name: "TelnetEnabled".into(),
            source_file: "sbin/telnetd.sh".into(),
            access_type: "get".into(),
        },
    ];
    let head_keys = vec![NvramKeyRef {
        key_name: "SSID".into(),
        source_file: "etc/startup.sh".into(),
        access_type: "get".into(),
    }];

    let diffs = diff_nvram_keys(&base_keys, &head_keys);

    let removed = diffs.iter().find(|d| d.key_name == "TelnetEnabled");
    assert!(removed.is_some(), "TelnetEnabled should appear in diff");
    assert_eq!(removed.unwrap().status, "removed");
    assert!(removed.unwrap().base_source.is_some());
    assert!(removed.unwrap().head_source.is_none());
}

#[test]
fn nvram_key_classification_identifies_credentials() {
    // Credential keys
    assert_eq!(
        classify_security_relevance("AdminPassword"),
        Some("credential".into())
    );
    assert_eq!(
        classify_security_relevance("WPA_Key"),
        Some("credential".into())
    );
    assert_eq!(
        classify_security_relevance("httpPasswd"),
        Some("credential".into())
    );
    assert_eq!(
        classify_security_relevance("api_secret"),
        Some("credential".into())
    );
    assert_eq!(
        classify_security_relevance("auth_token"),
        Some("credential".into())
    );

    // Network keys
    assert_eq!(
        classify_security_relevance("lan_ipaddr"),
        Some("network".into())
    );
    assert_eq!(
        classify_security_relevance("wan_gateway"),
        Some("network".into())
    );
    assert_eq!(
        classify_security_relevance("dns_server"),
        Some("network".into())
    );

    // Feature keys
    assert_eq!(
        classify_security_relevance("SSHEnable"),
        Some("feature".into())
    );
    assert_eq!(
        classify_security_relevance("TelnetDisable"),
        Some("feature".into())
    );

    // Debug keys
    assert_eq!(
        classify_security_relevance("DebugLevel"),
        Some("debug".into())
    );
    assert_eq!(
        classify_security_relevance("syslog_enable"),
        Some("debug".into())
    );

    // Unclassified key
    assert_eq!(classify_security_relevance("SSID"), None);
    assert_eq!(classify_security_relevance("Channel"), None);
}
