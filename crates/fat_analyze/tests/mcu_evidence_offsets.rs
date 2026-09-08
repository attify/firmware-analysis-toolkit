use fat_analyze::mcu_inspect::{inspect_file, McuInspectRequest};
use tempfile::NamedTempFile;

#[test]
fn vector_evidence_uses_the_nonzero_vector_table_file_offset() {
    let vector_offset = 0x200usize;
    let mut bytes = vec![0xAA; vector_offset];
    for word in [
        0x2401_A058u32,
        0x0800_6201,
        0x0800_6301,
        0x0800_6401,
        0x0800_6501,
        0x0800_6501,
        0x0800_6501,
        0x0800_6501,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    bytes.resize(4096, 0xFF);

    let file = NamedTempFile::new().expect("temporary firmware");
    std::fs::write(file.path(), bytes).expect("write firmware");
    let report = inspect_file(&McuInspectRequest {
        file: file.path().to_path_buf(),
        user_base: None,
        user_family: Some("STM32H7".to_string()),
        bundle_root: None,
        backend_preference: None,
    })
    .expect("inspection report");

    let vector_zero = report
        .evidence
        .expect("evidence")
        .into_iter()
        .find(|record| record.evidence_id == "vector-word-0")
        .expect("vector word evidence");
    assert_eq!(
        vector_zero.location.and_then(|location| location.offset),
        Some(vector_offset as u64)
    );
}
