use fat_core::rehosting_pack::{parse_rehosting_pack_yaml, validate_rehosting_pack};

const VALID_EXAMPLE_PACK: &str = r#"
id: example/camera
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
  paths:
    - /system/init/app_init.sh
partitions:
  roles:
    - source: rootfs
      mount: /
      materialization: staged-copy
    - source: app
      mount: /system
      materialization: staged-copy
runtime:
  substrate: system
  qemu_machine: malta
  network:
    interface: eth0
    mode: dhcp
    fallback_ip: 10.0.2.15
repairs:
  init:
    skip_module_loads_matching:
      - tx-isp-*.ko
      - rtl8189*.ko
    skip_commands:
      - devmem
    materialize_paths:
      - /configs
      - /configs/.parameters
validators:
  - goal: init-handoff
    kind: serial-log-pattern
    pattern: app_init.sh
  - goal: http-reply
    kind: http
    port: 80
caveats:
  - no camera ISP fidelity
  - cloud daemons are not validated
"#;

#[test]
fn valid_rehosting_pack_parses_and_validates() {
    let pack = parse_rehosting_pack_yaml(VALID_EXAMPLE_PACK).expect("valid yaml parses");
    assert_eq!(pack.id, "example/camera");
    assert_eq!(pack.match_rules.architecture.as_deref(), Some("mipsel"));
    assert_eq!(pack.validators.len(), 2);

    let report = validate_rehosting_pack(&pack);

    assert!(report.valid, "{report:#?}");
    assert!(report.errors.is_empty(), "{report:#?}");
    assert_eq!(report.pack_id.as_deref(), Some("example/camera"));
}

#[test]
fn rehosting_pack_rejects_architecture_only_matchers_as_overbroad() {
    let pack = parse_rehosting_pack_yaml(
        r#"
id: generic/mipsel
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
validators:
  - goal: shell-access
    kind: surface-ready
"#,
    )
    .expect("yaml parses");

    let report = validate_rehosting_pack(&pack);

    assert!(!report.valid, "{report:#?}");
    assert!(report
        .errors
        .iter()
        .any(|message| message.code == "matcher-overbroad"));
}

#[test]
fn rehosting_pack_rejects_unscoped_fixture_mutations() {
    let pack = parse_rehosting_pack_yaml(
        r#"
id: example/camera-modified
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
validators:
  - goal: fixture-mutated
    kind: file-exists
    path: /var/www/cgi-bin/shell.cgi
fixture_mutations:
  - kind: cgi-command-shell
    path: /var/www/cgi-bin/shell.cgi
"#,
    )
    .expect("yaml parses");

    let report = validate_rehosting_pack(&pack);

    assert!(!report.valid, "{report:#?}");
    assert!(report
        .errors
        .iter()
        .any(|message| message.code == "fixture-mutation-requires-modified-fixture"));
}

#[test]
fn rehosting_pack_allows_explicit_modified_fixture_mutations_with_warning() {
    let pack = parse_rehosting_pack_yaml(
        r#"
id: example/camera-modified
kind: rehosting-pack
version: "0.1"
modified_fixture: true
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
validators:
  - goal: fixture-mutated
    kind: file-exists
    path: /var/www/cgi-bin/shell.cgi
fixture_mutations:
  - kind: cgi-command-shell
    path: /var/www/cgi-bin/shell.cgi
"#,
    )
    .expect("yaml parses");

    let report = validate_rehosting_pack(&pack);

    assert!(report.valid, "{report:#?}");
    assert!(report
        .warnings
        .iter()
        .any(|message| message.code == "modified-fixture-mutation"));
}

#[test]
fn rehosting_pack_requires_validator_kind_parameters() {
    for (kind, expected_code) in [
        ("serial-log-pattern", "validator-missing-pattern"),
        ("process", "validator-missing-name"),
        ("file-exists", "validator-missing-path"),
        ("listener", "validator-missing-port"),
        ("http", "validator-missing-port"),
    ] {
        let pack = parse_rehosting_pack_yaml(&format!(
            r#"
id: test/{kind}
kind: rehosting-pack
version: "0.1"
match:
  architecture: armel
  signals: ["fs:squashfs", "init:busybox"]
validators:
  - goal: test-goal
    kind: {kind}
"#
        ))
        .expect("yaml parses");

        let report = validate_rehosting_pack(&pack);
        assert!(
            report
                .errors
                .iter()
                .any(|message| message.code == expected_code),
            "{kind} must report {expected_code}: {report:#?}"
        );
    }
}

#[test]
fn rehosting_pack_rejects_unsafe_guest_adaptation_tokens() {
    let pack = parse_rehosting_pack_yaml(
        r#"
id: test/unsafe-adaptation
kind: rehosting-pack
version: "0.1"
match:
  architecture: mipsel
  signals: ["fs:squashfs", "init:busybox"]
repairs:
  init:
    skip_commands: ["../devmem", "devmem;reboot", "mount"]
    skip_module_loads_matching: ["../../host.ko", "*.ko;reboot"]
validators:
  - goal: shell-access
    kind: surface-ready
caveats: ["invalid fixture"]
"#,
    )
    .expect("yaml parses");

    let report = validate_rehosting_pack(&pack);

    assert!(!report.valid, "{report:#?}");
    assert!(report
        .errors
        .iter()
        .any(|message| message.code == "invalid-skip-command"));
    assert!(report
        .errors
        .iter()
        .any(|message| message.code == "invalid-module-skip-pattern"));
}

/// A misspelling of `modified_fixture` must not be silently read as an absent
/// declaration.
#[test]
fn rehosting_pack_rejects_a_misspelled_fidelity_key() {
    let error = parse_rehosting_pack_yaml(
        r#"
id: example/camera-typo
kind: rehosting-pack
version: "0.1"
modifed_fixture: true
match:
  architecture: mipsel
  signals:
    - soc:ingenic-t31
    - fs:squashfs
"#,
    )
    .expect_err("a misspelled fidelity key must not parse");

    assert!(
        error.contains("modifed_fixture"),
        "the error should name the offending key, got: {error}"
    );
}
