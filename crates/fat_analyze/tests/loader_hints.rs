use fat_analyze::loader::resolve_loader_hints;

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

#[test]
fn resolve_loader_hints_detects_cortex_m_blob_defaults() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");

    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, 0x0800_0201);
    write_u32(&mut bytes, 0x0800_1001);
    write_u32(&mut bytes, 0x0800_1101);
    bytes.resize(0x400, 0xFF);
    std::fs::write(&blob, bytes).expect("blob");

    let hints = resolve_loader_hints(&blob, None, None, None).expect("loader hints");
    assert!(hints.is_raw_blob);
    assert_eq!(hints.arch.as_deref(), Some("arm"));
    assert_eq!(hints.bits, Some(16));
    assert_eq!(hints.base, Some(0x0800_0000));
    assert_eq!(hints.cpu.as_deref(), Some("cortex"));
    assert_eq!(hints.family.as_deref(), Some("STM32H7"));
}

#[test]
fn resolve_loader_hints_preserves_explicit_cortex_m_override() {
    let dir = tempfile::tempdir().expect("tempdir");
    let blob = dir.path().join("raw.bin");
    std::fs::write(&blob, vec![0x41u8; 128]).expect("blob");

    let hints = resolve_loader_hints(&blob, Some("cortex-m"), Some(0x0800_0000), Some("STM32H7"))
        .expect("loader hints");
    assert!(hints.is_raw_blob);
    assert_eq!(hints.arch.as_deref(), Some("arm"));
    assert_eq!(hints.bits, Some(16));
    assert_eq!(hints.base, Some(0x0800_0000));
    assert_eq!(hints.cpu.as_deref(), Some("cortex"));
    assert_eq!(hints.family.as_deref(), Some("STM32H7"));
}
