use fat_analyze::image_measurements::measure_image;

#[test]
fn measures_uniform_ff_suffix_and_both_entropy_domains() {
    let mut bytes: Vec<u8> = (0u8..=255).rev().cycle().take(1024).collect();
    bytes.extend(std::iter::repeat_n(0xff, 3072));

    let report = measure_image("sample.bin", &bytes);

    assert_eq!(report.identity.total_bytes, 4096);
    assert_eq!(report.bytes.content_prefix_bytes, 1024);
    assert_eq!(report.bytes.trailing_uniform_byte, Some(0xff));
    assert_eq!(report.bytes.trailing_uniform_offset, Some(1024));
    assert_eq!(report.bytes.trailing_uniform_bytes, 3072);
    assert!((report.bytes.trailing_uniform_percent - 75.0).abs() < 0.0001);
    assert!((report.bytes.content_entropy_bits_per_byte.unwrap() - 8.0).abs() < 0.0001);
    assert!(report.bytes.whole_entropy_bits_per_byte < 3.0);
}

#[test]
fn all_fill_has_no_content_entropy() {
    let report = measure_image("blank.bin", &[0xff; 4096]);

    assert_eq!(report.bytes.content_prefix_bytes, 0);
    assert_eq!(report.bytes.trailing_uniform_byte, Some(0xff));
    assert_eq!(report.bytes.trailing_uniform_offset, Some(0));
    assert_eq!(report.bytes.trailing_uniform_bytes, 4096);
    assert_eq!(report.bytes.content_entropy_bits_per_byte, None);
}

#[test]
fn empty_image_has_stable_zero_measurements() {
    let report = measure_image("empty.bin", &[]);

    assert_eq!(report.identity.total_bytes, 0);
    assert_eq!(report.bytes.trailing_uniform_byte, None);
    assert_eq!(report.bytes.trailing_uniform_offset, None);
    assert_eq!(report.bytes.trailing_uniform_bytes, 0);
    assert_eq!(report.bytes.whole_entropy_bits_per_byte, 0.0);
}

#[test]
fn identity_binds_path_bytes_and_sha256() {
    let report = measure_image("abc.bin", b"abc");

    assert_eq!(report.identity.path, "abc.bin");
    assert_eq!(report.identity.total_bytes, 3);
    assert_eq!(
        report.identity.sha256,
        "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    );
}

#[test]
fn trailing_run_measurement_is_not_limited_to_flash_fill_bytes() {
    let report = measure_image("generic.bin", &[1, 2, 3, 0x7e, 0x7e, 0x7e]);

    assert_eq!(report.bytes.content_prefix_bytes, 3);
    assert_eq!(report.bytes.trailing_uniform_byte, Some(0x7e));
    assert_eq!(report.bytes.trailing_uniform_offset, Some(3));
    assert_eq!(report.bytes.trailing_uniform_bytes, 3);
    assert_eq!(report.bytes.trailing_uniform_percent, 50.0);
}
