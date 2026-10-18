use fat_analyze::boot_env::{scan, EnvScanOptions};

fn env_blob(size: usize, redundant: bool, big_endian: bool) -> Vec<u8> {
    let mut bytes = vec![0xff; size];
    let header = if redundant { 5 } else { 4 };
    let vars = b"bootcmd=bootm 0x80000\0verify=no\0\0";
    bytes[header..header + vars.len()].copy_from_slice(vars);
    if redundant {
        bytes[4] = 1;
    }
    let crc = crc32fast::hash(&bytes[header..]);
    bytes[..4].copy_from_slice(&if big_endian {
        crc.to_be_bytes()
    } else {
        crc.to_le_bytes()
    });
    bytes
}

#[test]
fn discovers_crc_valid_env_at_flash_offset_without_requiring_baudrate() {
    let mut image = vec![0xff; 0x3000];
    image.extend(env_blob(0x2000, false, false));
    let result = scan(&image, &EnvScanOptions::default()).unwrap();
    assert_eq!(result.environments.len(), 1);
    let env = &result.environments[0];
    assert_eq!(env.offset, 0x3000);
    assert_eq!(env.size, 0x2000);
    assert_eq!(env.format, "legacy");
    assert_eq!(env.crc_endianness, "little");
    assert_eq!(env.variables[0].key, "bootcmd");
    assert_eq!(env.variables[1].value, "no");
    assert!(env.crc_valid);
}

#[test]
fn preserves_redundant_flags_and_crc_endianness_without_selecting_active_copy() {
    let result = scan(&env_blob(4096, true, true), &EnvScanOptions::default()).unwrap();
    assert_eq!(result.environments.len(), 1);
    assert_eq!(result.environments[0].format, "redundant");
    assert_eq!(result.environments[0].redundancy_flag, Some(1));
    assert_eq!(result.environments[0].crc_endianness, "big");
}

#[test]
fn corruption_or_unterminated_records_do_not_become_environments() {
    let mut corrupt = env_blob(4096, false, false);
    corrupt[100] ^= 1;
    assert!(scan(&corrupt, &EnvScanOptions::default())
        .unwrap()
        .environments
        .is_empty());
    let mut unterminated = vec![b'a'; 4096];
    unterminated[4..8].copy_from_slice(b"key=");
    let crc = crc32fast::hash(&unterminated[4..]);
    unterminated[..4].copy_from_slice(&crc.to_le_bytes());
    assert!(scan(&unterminated, &EnvScanOptions::default())
        .unwrap()
        .environments
        .is_empty());
}

#[test]
fn explicit_region_handles_unaligned_nonstandard_size_and_reports_bad_crc() {
    let mut image = vec![0xff; 17];
    image.extend(env_blob(6000, false, false));
    assert!(scan(&image, &EnvScanOptions::default())
        .unwrap()
        .environments
        .is_empty());
    let options = EnvScanOptions {
        region: Some((17, 6000)),
        ..Default::default()
    };
    assert_eq!(scan(&image, &options).unwrap().environments.len(), 1);
    image[30] ^= 1;
    let result = scan(&image, &options).unwrap();
    assert!(result.environments.is_empty());
    assert!(!result.diagnostics.is_empty());
}

#[test]
fn explicit_out_of_bounds_and_overflowing_regions_are_errors() {
    for region in [(0, 0), (u64::MAX, 4096), (1, 4096)] {
        assert!(scan(
            &vec![0xff; 4096],
            &EnvScanOptions {
                region: Some(region),
                ..Default::default()
            }
        )
        .is_err());
    }
}

#[test]
fn search_budget_is_explicit_and_erased_flash_has_no_environment() {
    let result = scan(
        &vec![0xff; 16384],
        &EnvScanOptions {
            max_scan_bytes: 4096,
            ..Default::default()
        },
    )
    .unwrap();
    assert_eq!(result.scanned_bytes, 4096);
    assert!(result.search_limited);
    assert!(result.environments.is_empty());
}

#[test]
fn raw_assignments_do_not_become_environment_or_policy_evidence() {
    let text = "U-Boot 2024.01\nbootcmd=bootm 0x80000\nbootdelay=0\nverify=no\nsig_check=%s\nrecovery_mode=0\nrollback_ctr=0\n";
    let raw = fat_analyze::bootloader::analyze_text(text);
    assert!(raw.env_variables.is_empty());
    assert!(raw.findings.is_empty());
    let json = serde_json::to_value(&raw).unwrap();
    assert_eq!(json["raw_env_hints"].as_array().unwrap().len(), 6);

    let valid = env_blob(4096, false, false);
    let crc_scan = scan(&valid, &EnvScanOptions::default()).unwrap();
    assert_eq!(crc_scan.environments.len(), 1);
    assert!(crc_scan.environments[0].crc_valid);
    assert_eq!(crc_scan.environments[0].variables[1].value, "no");
    let mut invalid = valid;
    invalid[0] ^= 1;
    assert!(scan(&invalid, &EnvScanOptions::default())
        .unwrap()
        .environments
        .is_empty());
}

#[test]
fn raw_hints_merge_without_duplicates_and_old_snapshots_still_load() {
    let raw = fat_analyze::bootloader::analyze_text("bootcmd=bootm 0x80000\n");
    let merged = fat_analyze::bootloader::merge_snapshots(raw.clone(), raw);
    assert_eq!(merged.raw_env_hints.len(), 1);
    assert!(merged.env_variables.is_empty());
    let mut legacy = serde_json::to_value(&merged).unwrap();
    legacy.as_object_mut().unwrap().remove("raw_env_hints");
    let restored: fat_core::bootloader::BootloaderSnapshot =
        serde_json::from_value(legacy).unwrap();
    assert!(restored.raw_env_hints.is_empty());
}
