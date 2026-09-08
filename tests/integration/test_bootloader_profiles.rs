#[test]
fn camera_profile_generates_vendor_style_u_boot_env() {
    let profile = fat_bootloader::load_profile("consumer-iot-camera").unwrap();
    let env = fat_bootloader::render_env(&profile, None).unwrap();

    assert!(env.contains("bootdelay=3"));
    assert!(env.contains("bootcmd="));
    assert!(env.contains("sig_check=yes"));
    assert!(env.contains("verify=yes"));
}

#[test]
fn imported_values_override_profile_defaults() {
    let profile = fat_bootloader::load_profile("consumer-iot-camera").unwrap();
    let snapshot = fat_core::bootloader::BootloaderSnapshot {
        env_variables: vec![
            fat_core::bootloader::BootEnvVariable {
                key: "sig_check".into(),
                value: "no".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "bootdelay".into(),
                value: "0".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    let env = fat_bootloader::render_env(&profile, Some(&snapshot)).unwrap();

    assert!(env.contains("sig_check=no"));
    assert!(env.contains("bootdelay=0"));
    assert!(!env.contains("sig_check=yes"));
    assert!(!env.contains("bootdelay=3"));
}

#[test]
fn profiles_can_be_loaded_from_an_explicit_runtime_data_root() {
    let temp = tempfile::tempdir().expect("tempdir");
    let profile_dir = temp.path().join("profiles/bootloader");
    std::fs::create_dir_all(&profile_dir).unwrap();
    std::fs::write(
        profile_dir.join("consumer-iot-camera.json"),
        include_str!("../../profiles/bootloader/consumer-iot-camera.json"),
    )
    .unwrap();
    let resolver = fat_core::data_dir::DataResolver::from_paths(
        Some(temp.path().to_path_buf()),
        None,
        None,
        None,
        None,
    );

    let profile = fat_bootloader::load_profile_with_resolver("consumer-iot-camera", &resolver)
        .expect("runtime profile should load");
    assert_eq!(profile.name, "consumer-iot-camera");
}

#[test]
fn export_env_filters_untrusted_garbage_variables() {
    let profile = fat_bootloader::load_profile("consumer-iot-camera").unwrap();
    let snapshot = fat_core::bootloader::BootloaderSnapshot {
        env_variables: vec![
            fat_core::bootloader::BootEnvVariable {
                key: "baudrate".into(),
                value: "115200".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "%s".into(),
                value: "%s".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "x".into(),
                value: "junk".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
            fat_core::bootloader::BootEnvVariable {
                key: "ACTION".into(),
                value: "%s".into(),
                source: fat_core::bootloader::BootValueSource::Imported,
            },
        ],
        ..Default::default()
    };

    let env = fat_bootloader::render_env(&profile, Some(&snapshot)).unwrap();

    assert!(env.contains("baudrate=115200"));
    assert!(!env.contains("%s=%s"));
    assert!(!env.contains("x=junk"));
    assert!(!env.contains("ACTION=%s"));
}
