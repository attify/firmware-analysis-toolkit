use serde_json::Value;
use std::process::Command;
use tempfile::tempdir;

// Human reports wrap and align to the available terminal width. Assertions
// compare content, not incidental line breaks or padding before colons.
fn readable_output(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .replace(" :", ":")
}

#[path = "../support/firmware_formats.rs"]
mod firmware_formats;

#[test]
fn fat_identify_classifies_valid_jffs2_as_structured_firmware() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("camera-jffs2.bin");
    let mut bytes = vec![0xff; 0x20];
    bytes.extend_from_slice(&firmware_formats::jffs2_fixture(
        firmware_formats::FixtureEndian::Little,
    ));
    std::fs::write(&firmware, bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    assert!(report["structure"]["filesystem_headers"]
        .as_array()
        .is_some_and(|headers| headers.iter().any(|header| header["format"] == "jffs2")));
}

#[test]
fn fat_identify_reports_ubi_with_nested_ubifs() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("nand-ubi.bin");
    let fixture = firmware_formats::ubi_ubifs_fixture();
    std::fs::write(&firmware, fixture.image).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    let headers = report["structure"]["filesystem_headers"]
        .as_array()
        .expect("filesystem headers");
    assert!(headers.iter().any(|header| header["format"] == "ubi"));
    assert!(headers
        .iter()
        .any(|header| { header["format"] == "ubifs" && header["scope"] == "nested" }));
}

#[test]
fn fat_identify_classifies_complete_cpio_newc_archive() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("initramfs.cpio");
    let archive = firmware_formats::cpio_newc_fixture();
    std::fs::write(&firmware, &archive).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    let header = report["structure"]["filesystem_headers"]
        .as_array()
        .and_then(|headers| {
            headers
                .iter()
                .find(|header| header["format"] == "cpio-newc")
        })
        .expect("CPIO newc header");
    assert_eq!(header["offset"], 0);
    assert_eq!(header["image_size"], archive.len() as u64);
}

#[test]
fn fat_identify_reports_embedded_ext4_geometry() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("disk-wrapper.bin");
    let image = firmware_formats::ext_filesystem_fixture(firmware_formats::ExtFixtureKind::Ext4);
    let mut bytes = vec![0xa5; 0x200];
    bytes.extend_from_slice(&image);
    std::fs::write(&firmware, bytes).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    let header = report["structure"]["filesystem_headers"]
        .as_array()
        .and_then(|headers| headers.iter().find(|header| header["format"] == "ext4"))
        .expect("ext4 header");
    assert_eq!(header["offset"], 0x200);
    assert_eq!(header["block_size"], 1_024);
    assert_eq!(header["image_size"], image.len() as u64);
}

#[test]
fn fat_identify_reports_fit_as_a_container_without_claiming_generic_fdt_is_a_kernel() {
    for (fit, expected) in [(false, "fdt"), (true, "fit")] {
        let dir = tempdir().expect("tempdir");
        let firmware = dir
            .path()
            .join(if fit { "firmware.itb" } else { "board.dtb" });
        let fixture = firmware_formats::fdt_fixture(fit);
        std::fs::write(&firmware, fixture.image).expect("firmware");

        let output = Command::new(env!("CARGO_BIN_EXE_fat"))
            .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
            .output()
            .expect("fat identify runs");
        assert!(output.status.success(), "{output:?}");
        let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
        assert_eq!(report["likely_class"], "structured-firmware-container");
        assert!(report["structure"]["container_headers"]
            .as_array()
            .is_some_and(|headers| headers.iter().any(|header| header["format"] == expected)));
        assert!(
            report.get("next_steps").is_none(),
            "unexpected next_steps: {report}"
        );
        if !fit {
            assert!(report["structure"]["image_headers"]
                .as_array()
                .is_some_and(Vec::is_empty));
            assert!(report["structure"]["dominant_boot_image"].is_null());
        }
    }
}

#[test]
fn fat_identify_reports_crc_valid_trx_partition_container() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("router.trx");
    let fixture = firmware_formats::trx_fixture();
    std::fs::write(&firmware, fixture.image).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    let header = report["structure"]["container_headers"]
        .as_array()
        .and_then(|headers| headers.iter().find(|header| header["format"] == "trx"))
        .expect("TRX header");
    assert_eq!(header["offset"], 0);
    assert_eq!(header["role"], "partitioned firmware container");
}

fn pseudo_random_bytes(len: usize) -> Vec<u8> {
    let mut state: u32 = 0xCAFEBABE;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        state ^= state << 13;
        state ^= state >> 17;
        state ^= state << 5;
        out.push((state & 0xff) as u8);
    }
    out
}

fn write_u32(buf: &mut Vec<u8>, value: u32) {
    buf.extend_from_slice(&value.to_le_bytes());
}

fn thumb_b(from: u32, to: u32) -> [u8; 2] {
    let pc = from.wrapping_add(4);
    let offset = to.wrapping_sub(pc) as i32;
    let imm11 = ((offset >> 1) as u16) & 0x07ff;
    (0xe000u16 | imm11).to_le_bytes()
}

fn build_mcu_blob() -> Vec<u8> {
    let reset = 0x0800_0200u32;
    let mut bytes = Vec::new();
    write_u32(&mut bytes, 0x2401_A058);
    write_u32(&mut bytes, reset | 1);
    write_u32(&mut bytes, 0x0800_2001);
    write_u32(&mut bytes, 0x0800_3001);
    for _ in 4..32 {
        write_u32(&mut bytes, 0x0800_4001);
    }
    bytes.resize(0x900, 0xFF);
    let reset_offset = (reset - 0x0800_0000) as usize;
    bytes[reset_offset..reset_offset + 2].copy_from_slice(&thumb_b(reset, reset + 0x10));
    bytes[reset_offset + 2..reset_offset + 4].copy_from_slice(&[0x00, 0xBF]);
    let payload = b"shared_flag update ota crc32 erase program uart comms flash";
    bytes[0x300..0x300 + payload.len()].copy_from_slice(payload);
    bytes
}

// Synthetic vectors/identity text, not a redistributed vendor ROM.
fn build_rom_blob() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x4000];
    for (slot, value) in [0x1000_0ffcu32, 0x1fff_0105, 0x1fff_0fa9, 0x1fff_0fab]
        .into_iter()
        .enumerate()
    {
        bytes[slot * 4..slot * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    let identity = b"NXP     LPC134X IFLASH  1.0";
    bytes[0x300..0x300 + identity.len()].copy_from_slice(identity);
    for (i, word) in "NXP LPC13XX IFLASH".encode_utf16().enumerate() {
        bytes[0x380 + i * 2..0x382 + i * 2].copy_from_slice(&word.to_le_bytes());
    }
    bytes[0x104..0x108].copy_from_slice(&[0x00, 0xbf, 0x70, 0x47]);
    bytes.extend_from_within(..);
    bytes
}

fn identify_blob_json(bytes: &[u8]) -> serde_json::Value {
    let dir = tempdir().unwrap();
    let path = dir.path().join("unknown.bin");
    std::fs::write(&path, bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[test]
fn identify_rom_preserves_independent_identity_and_duplication_evidence() {
    let report = identify_blob_json(&build_rom_blob());
    assert_eq!(report["mcu"]["architecture"], "ARM Cortex-M");
    assert_eq!(report["mcu"]["family"], "NXP LPC134x");
    assert_eq!(report["mcu"]["base_hypothesis"], "0x1FFF0000");
    assert_eq!(
        report["mcu"]["identification"]["image_role"],
        "boot-rom-likely"
    );
    assert_eq!(
        report["envelope"]["repetition"]["repeated_unit_bytes"],
        16384
    );
    assert_eq!(report["envelope"]["repetition"]["copies"], 2);
    assert_eq!(report["envelope"]["ecb_assessment"], "not-indicated");
    assert!(report["mcu"]["identification"]["identity_strings"]
        .as_array()
        .unwrap()
        .iter()
        .any(|s| s["encoding"] == "utf-16le" && s["offset"] == 0x380));
}

#[test]
fn identify_retains_architecture_when_code_mapping_is_unknown() {
    let mut bytes = build_rom_blob();
    bytes.truncate(0x4000);
    bytes[0..4].copy_from_slice(&0x2000_2000u32.to_le_bytes());
    for (offset, address) in [(4, 0x6000_0105u32), (8, 0x6000_0201), (12, 0x6000_0301)] {
        bytes[offset..offset + 4].copy_from_slice(&address.to_le_bytes());
    }
    let report = identify_blob_json(&bytes);
    assert_eq!(report["mcu"]["architecture"], "ARM Cortex-M");
    assert_eq!(report["mcu"]["family"], "unresolved");
    assert!(report["mcu"]["base_hypothesis"].is_null());
}

#[test]
fn identity_strings_alone_do_not_establish_mcu_architecture() {
    let mut bytes = build_rom_blob();
    bytes[..64].fill(0);
    bytes[0x4000..0x4040].fill(0);
    let report = identify_blob_json(&bytes);
    assert!(report["mcu"].is_null());
    assert_eq!(report["likely_class"], "unknown");
    assert!(!report["mcu_diagnostics"]["identity_strings"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn identify_and_inspect_share_rom_identification_and_measurements() {
    let bytes = build_rom_blob();
    let identified = identify_blob_json(&bytes);
    let dir = tempdir().unwrap();
    let path = dir.path().join("image.bin");
    std::fs::write(&path, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["inspect", "mcu", "--file", path.to_str().unwrap(), "--json"])
        .output()
        .unwrap();
    assert!(output.status.success());
    let inspected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        identified["mcu"]["identification"],
        inspected["identification"]
    );
    assert_eq!(
        identified["envelope"]["repetition"],
        inspected["byte_measurements"]["repetition"]
    );
    assert_eq!(
        inspected["image_layout"]["kind"]["value"],
        "bootloader-only-image"
    );
    assert_eq!(
        inspected["startup_chain"]["steps"][0]["address"],
        0x1fff0104
    );
}

#[test]
fn explicit_base_maps_unknown_architecture_without_asserting_a_family() {
    let mut bytes = build_rom_blob();
    bytes.truncate(0x4000);
    bytes[0..4].copy_from_slice(&0x2000_2000u32.to_le_bytes());
    for (offset, address) in [(4, 0x6000_0105u32), (8, 0x6000_0201), (12, 0x6000_0301)] {
        bytes[offset..offset + 4].copy_from_slice(&address.to_le_bytes());
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("image.bin");
    std::fs::write(&path, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            path.to_str().unwrap(),
            "--base",
            "0x60000000",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let inspected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(inspected["identification"]["family"].is_null());
    assert_eq!(inspected["analysis_provenance"]["user_base"], 0x60000000);
    assert_eq!(
        inspected["address_hypotheses"][0]["rationale"][0],
        "user-specified base"
    );
    assert_eq!(inspected["image_layout"]["vector_address"], 0x60000000);
    assert_eq!(
        inspected["vector_table"]["entries"][1]["address"],
        0x60000105
    );
    assert_eq!(
        inspected["startup_chain"]["steps"][0]["address"],
        0x60000104
    );
}

#[test]
fn explicit_base_preserves_partial_vector_evidence_through_inspection() {
    let base = 0x6000_0000u32;
    let mut bytes = Vec::new();
    for word in [
        0x2000_2000,
        base + 0x21,
        base + 0x25,
        base + 0x29,
        base + 0x25,
        base + 0x25,
        base + 0x25,
        0,
    ] {
        bytes.extend_from_slice(&word.to_le_bytes());
    }
    for _ in 0..16 {
        bytes.extend_from_slice(&0x4770_d100u32.to_le_bytes());
    }
    let dir = tempdir().unwrap();
    let path = dir.path().join("partial.bin");
    std::fs::write(&path, &bytes).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "mcu",
            "--file",
            path.to_str().unwrap(),
            "--base",
            "0x60000000",
            "--json",
        ])
        .output()
        .unwrap();
    assert!(output.status.success());
    let inspected: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(inspected["identification"]["architecture"], "ARM Cortex-M");
    assert_eq!(
        inspected["identification"]["architecture_confidence"],
        "medium"
    );
    assert_eq!(inspected["image_layout"]["vector_address"], base);
    assert_eq!(
        inspected["startup_chain"]["steps"][0]["address"],
        base + 0x20
    );
    assert!(
        inspected["identification"]["vector_candidates"][0]["evidence"]
            .as_array()
            .unwrap()
            .iter()
            .any(|e| e.as_str().unwrap().contains("partial vector table"))
    );
}

fn write_uimage_header(target: &mut [u8], image_type: u8, compression: u8, name: &str) {
    write_uimage_header_with_size(target, 0x008E_F000, image_type, compression, name);
}

fn write_uimage_header_with_size(
    target: &mut [u8],
    data_size: u32,
    image_type: u8,
    compression: u8,
    name: &str,
) {
    target[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    target[4..8].copy_from_slice(&0xF459_1363u32.to_be_bytes());
    target[8..12].copy_from_slice(&0x633B_BA09u32.to_be_bytes());
    target[12..16].copy_from_slice(&data_size.to_be_bytes());
    target[16..20].copy_from_slice(&0x0000_0000u32.to_be_bytes());
    target[20..24].copy_from_slice(&0x0000_0000u32.to_be_bytes());
    target[24..28].copy_from_slice(&0x3118_9874u32.to_be_bytes());
    target[28] = 0x05;
    target[29] = 0x05;
    target[30] = image_type;
    target[31] = compression;
    target[32..32 + name.len()].copy_from_slice(name.as_bytes());
}

fn uimage_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x200];
    write_uimage_header(&mut bytes[0x00..0x40], 0x05, 0x00, "jz_fw");
    write_uimage_header(
        &mut bytes[0x40..0x80],
        0x02,
        0x03,
        "Linux-3.10.14__isvp_swan_1.0__",
    );
    bytes
}

fn wyze_partitioned_firmware_fixture() -> Vec<u8> {
    let cmdline = b"Linux version 3.10.14 console=ttyS1,115200n8 mem=96M@0x0 init=/linuxrc rootfstype=squashfs root=/dev/mtdblock2 rw mtdparts=jz_sfc:256K(boot),1984K(kernel),3904K(rootfs),3904K(app),1984K(kback),3904K(aback),384K(cfg),64K(para)\0";
    let mut compressed = Vec::new();
    lzma_rs::lzma_compress(&mut std::io::Cursor::new(cmdline), &mut compressed)
        .expect("compress cmdline");

    let app_image_size = 3_337_822u64;
    let mut bytes = vec![0u8; 0x005C_0040 + app_image_size as usize + 0x100];
    let outer_size = (bytes.len() - 0x40) as u32;
    write_uimage_header_with_size(&mut bytes[0x00..0x40], outer_size, 0x05, 0x00, "jz_fw");
    write_uimage_header_with_size(
        &mut bytes[0x40..0x80],
        compressed.len() as u32,
        0x02,
        0x03,
        "Linux-3.10.14__isvp_swan_1.0__",
    );
    bytes[0x80..0x80 + compressed.len()].copy_from_slice(&compressed);
    write_squashfs_header(&mut bytes, 0x001F_0040, 2_816_072, 358);
    write_squashfs_header(&mut bytes, 0x005C_0040, app_image_size, 161);
    bytes
}

fn write_squashfs_header(bytes: &mut [u8], offset: usize, image_size: u64, inode_count: u32) {
    bytes[offset..offset + 4].copy_from_slice(b"hsqs");
    bytes[offset + 4..offset + 8].copy_from_slice(&inode_count.to_le_bytes());
    bytes[offset + 8..offset + 12].copy_from_slice(&1_636_595_875u32.to_le_bytes());
    bytes[offset + 12..offset + 16].copy_from_slice(&262_144u32.to_le_bytes());
    bytes[offset + 20..offset + 22].copy_from_slice(&2u16.to_le_bytes());
    bytes[offset + 28..offset + 30].copy_from_slice(&4u16.to_le_bytes());
    bytes[offset + 30..offset + 32].copy_from_slice(&0u16.to_le_bytes());
    bytes[offset + 40..offset + 48].copy_from_slice(&image_size.to_le_bytes());
}

fn minimal_elf_shared_object() -> Vec<u8> {
    let shstrtab = b"\0.text\0.plt\0.got.plt\0.dynamic\0.shstrtab\0";

    let text_off = 0x40u64;
    let plt_off = 0x50u64;
    let got_plt_off = 0x60u64;
    let dynamic_off = 0x70u64;
    let shstrtab_off = 0x90u64;
    let section_headers_off = 0xC0u64;
    let program_headers_off = 0x280u64;
    let file_len = (program_headers_off as usize) + (2 * 56);

    let mut bytes = vec![0u8; file_len];
    bytes[0..4].copy_from_slice(b"\x7fELF");
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;

    write_u16_at(&mut bytes, 16, 3);
    write_u16_at(&mut bytes, 18, 62);
    write_u32_at(&mut bytes, 20, 1);
    write_u64_at(&mut bytes, 24, 0);
    write_u64_at(&mut bytes, 32, program_headers_off);
    write_u64_at(&mut bytes, 40, section_headers_off);
    write_u32_at(&mut bytes, 48, 0);
    write_u16_at(&mut bytes, 52, 64);
    write_u16_at(&mut bytes, 54, 56);
    write_u16_at(&mut bytes, 56, 2);
    write_u16_at(&mut bytes, 58, 64);
    write_u16_at(&mut bytes, 60, 6);
    write_u16_at(&mut bytes, 62, 5);

    bytes[text_off as usize..text_off as usize + 16].copy_from_slice(&[
        0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x48, 0x31, 0xC0, 0xC3, 0x90, 0x90, 0x90,
        0x90,
    ]);
    bytes[plt_off as usize..plt_off as usize + 16]
        .copy_from_slice(&[0xff, 0x25, 0, 0, 0, 0, 0x68, 0, 0, 0, 0, 0xe9, 0, 0, 0, 0]);
    bytes[got_plt_off as usize..got_plt_off as usize + 16].copy_from_slice(&[0u8; 16]);
    bytes[dynamic_off as usize..dynamic_off as usize + 32].copy_from_slice(&[0u8; 32]);
    bytes[shstrtab_off as usize..shstrtab_off as usize + shstrtab.len()].copy_from_slice(shstrtab);

    let ph1 = program_headers_off as usize;
    let ph2 = ph1 + 56;
    write_u64_at(&mut bytes, ph1, 1);
    write_u32_at(&mut bytes, ph1 + 4, 5);
    write_u64_at(&mut bytes, ph1 + 8, text_off);
    write_u64_at(&mut bytes, ph1 + 16, 0x1000);
    write_u64_at(&mut bytes, ph1 + 24, 0);
    write_u64_at(&mut bytes, ph1 + 32, 0x80);
    write_u64_at(&mut bytes, ph1 + 40, 0x80);
    write_u64_at(&mut bytes, ph1 + 48, 0x1000);

    write_u64_at(&mut bytes, ph2, 2);
    write_u32_at(&mut bytes, ph2 + 4, 4);
    write_u64_at(&mut bytes, ph2 + 8, dynamic_off);
    write_u64_at(&mut bytes, ph2 + 16, 0x2000);
    write_u64_at(&mut bytes, ph2 + 24, 0);
    write_u64_at(&mut bytes, ph2 + 32, 0x20);
    write_u64_at(&mut bytes, ph2 + 40, 0x20);
    write_u64_at(&mut bytes, ph2 + 48, 0x8);

    let sh0 = section_headers_off as usize;
    let sh1 = sh0 + 64;
    let sh2 = sh1 + 64;
    let sh3 = sh2 + 64;
    let sh4 = sh3 + 64;
    let sh5 = sh4 + 64;

    write_section_header_at(&mut bytes, sh1, 1, 1, 0x6, text_off, 16, 0, 0, 16, 0);
    write_section_header_at(&mut bytes, sh2, 7, 1, 0x6, plt_off, 16, 0, 0, 16, 0);
    write_section_header_at(&mut bytes, sh3, 12, 1, 0x3, got_plt_off, 16, 0, 0, 8, 0);
    write_section_header_at(&mut bytes, sh4, 21, 6, 0x3, dynamic_off, 32, 0, 0, 8, 16);
    write_section_header_at(
        &mut bytes,
        sh5,
        30,
        3,
        0,
        shstrtab_off,
        shstrtab.len() as u64,
        0,
        0,
        1,
        0,
    );

    bytes
}

#[allow(clippy::too_many_arguments)]
fn write_section_header_at(
    bytes: &mut [u8],
    offset: usize,
    name: u32,
    sh_type: u32,
    flags: u64,
    data_offset: u64,
    size: u64,
    link: u32,
    info: u32,
    addralign: u64,
    entsize: u64,
) {
    write_u32_at(bytes, offset, name);
    write_u32_at(bytes, offset + 4, sh_type);
    write_u64_at(bytes, offset + 8, flags);
    write_u64_at(bytes, offset + 16, 0);
    write_u64_at(bytes, offset + 24, data_offset);
    write_u64_at(bytes, offset + 32, size);
    write_u32_at(bytes, offset + 40, link);
    write_u32_at(bytes, offset + 44, info);
    write_u64_at(bytes, offset + 48, addralign);
    write_u64_at(bytes, offset + 56, entsize);
}

fn write_u16_at(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32_at(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64_at(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}

fn compression_only_firmware_fixture() -> Vec<u8> {
    let gzip = [
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ];
    let mut bytes = vec![0xA5; 0x500];
    bytes[0..4].copy_from_slice(b"SHRS");
    for offset in [0x100usize, 0x340usize] {
        bytes[offset..offset + gzip.len()].copy_from_slice(&gzip);
    }
    bytes
}

fn unitree_upk_fixture() -> Vec<u8> {
    let payload = [b"TEA\0".as_slice(), &(0u8..16).collect::<Vec<_>>()].concat();
    let mut bytes = vec![0u8; 112 + payload.len()];
    bytes[0..4].copy_from_slice(b"UTPK");
    bytes[5] = 1;
    bytes[8..16].copy_from_slice(&1_700_000_000u64.to_le_bytes());
    bytes[16..24].copy_from_slice(&(payload.len() as u64).to_le_bytes());
    bytes[24] = 3;
    bytes[28..32].copy_from_slice(&[0x11, 0x22, 0x33, 0x44]);
    bytes[32..48].copy_from_slice(&[
        0x82, 0xc0, 0xa1, 0xb6, 0x7a, 0xd4, 0x81, 0xe8, 0xbd, 0x5e, 0xf1, 0xce, 0xbe, 0x0a, 0x22,
        0x34,
    ]);
    bytes[48..60].copy_from_slice(b"package_test");
    bytes[112..].copy_from_slice(&payload);
    bytes
}

fn high_entropy_shrs_firmware_fixture() -> Vec<u8> {
    let gzip = [
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ];
    let mut bytes = pseudo_random_bytes(8192);
    bytes[0..4].copy_from_slice(b"SHRS");
    for offset in [0x100usize, 0x340usize] {
        bytes[offset..offset + gzip.len()].copy_from_slice(&gzip);
    }
    for offset in [0x480usize, 0x490usize, 0x4A0usize] {
        bytes[offset..offset + 16].copy_from_slice(&[0x42; 16]);
    }
    bytes
}

#[test]
fn fat_identify_help_mentions_file_json_and_details() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--help"])
        .output()
        .expect("fat identify help runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("identify"),
        "help did not mention identify:\n{stdout}"
    );
    assert!(
        stdout.contains("--file"),
        "help did not mention --file:\n{stdout}"
    );
    assert!(
        stdout.contains("--json"),
        "help did not mention --json:\n{stdout}"
    );
    assert!(
        stdout.contains("--details"),
        "help did not mention --details:\n{stdout}"
    );
}

#[test]
fn fat_identify_reports_firmware_indicators_for_compression_only_blob() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("compression-only.bin");
    std::fs::write(&firmware, compression_only_firmware_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: raw-firmware-blob",
        "Firmware indicators",
        "gzip @ 0x00000100",
        "Known top-level header: SHRS",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
}

#[test]
fn fat_identify_labels_shrs_without_unsupported_vendor_attribution() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("shrs.bin");
    std::fs::write(&firmware, compression_only_firmware_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("Known top-level header: SHRS"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("SGE/T&W factory firmware envelope"),
        "stdout:\n{stdout}"
    );
    assert!(!stdout.contains("D-Link"), "stdout:\n{stdout}");
    assert!(stdout.contains("detection only"), "stdout:\n{stdout}");
    assert!(
        !stdout.contains("Unknown top-level header: SHRS"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn fat_identify_labels_unitree_upk_as_supported_vendor_update_package() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("package_test.upk");
    std::fs::write(&firmware, unitree_upk_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("vendor-update-package"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Known top-level header: UTPK (Unitree UPK firmware package; parsed)"),
        "stdout:\n{stdout}"
    );
    assert!(stdout.contains("package_test"), "stdout:\n{stdout}");
    assert!(stdout.contains("MD5 ok"), "stdout:\n{stdout}");
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_explains_high_entropy_structured_blob() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("high-entropy-shrs.bin");
    std::fs::write(&firmware, high_entropy_shrs_firmware_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("High-entropy structured blob"),
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("Entropy"),
        "default includes detailed metrics:\n{stdout}"
    );
    assert!(!stdout.contains("Interpretation:"), "stdout:\n{stdout}");
    assert!(!stdout.contains("does not suggest"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_reports_moxa_rom_map_kernel_and_cramfs() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("moxa-like.rom");
    std::fs::write(&firmware, moxa_like_identify_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: structured-firmware-container",
        "[high]",
        "Moxa ROM map",
        "Firmware version: 5.7",
        "gzip @ 0x00000020",
        "vmlinux.64",
        "pad @ 0x00000055 .. 0x0000041F",
        "cramfs @ 0x00000420",
        "Dominant rootfs",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(
        !stdout.contains("gzip @ 0x000004A0"),
        "nested gzip must not be a peer hit:\n{stdout}"
    );
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_json_exposes_first_class_region_relationships() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("moxa-region-tree.rom");
    std::fs::write(&firmware, moxa_like_identify_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    let regions = report["structure"]["regions"]
        .as_array()
        .expect("first-class regions");
    let container = regions
        .iter()
        .find(|region| region["format"] == "moxa-rom-map")
        .expect("container");
    assert_eq!(container["kind"], "container");
    assert_eq!(container["scope"], "top-level");
    let kernel = regions
        .iter()
        .find(|region| region["format"] == "gzip")
        .expect("kernel");
    assert_eq!(kernel["original_name"], "vmlinux.64");
    assert_eq!(kernel["parent_offset"], 0);
    assert_eq!(kernel["scope"], "nested");
}

#[test]
fn fat_identify_reports_bounded_gzip_kernel_identity() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("vmlinux.gz");
    std::fs::write(&firmware, firmware_formats::gzip_elf_fixture(true, false)).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    let kernel = report["structure"]["regions"]
        .as_array()
        .and_then(|regions| regions.iter().find(|region| region["format"] == "gzip"))
        .expect("gzip kernel");
    assert_eq!(kernel["kernel_format"], "ELF");
    assert_eq!(kernel["architecture"], "mips64 (big-endian)");
    assert_eq!(kernel["uncompressed_size"], 64);
}

#[test]
fn fat_identify_reports_exact_span_for_a_single_known_member_without_next_steps() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("single-member.bin");
    std::fs::write(&firmware, firmware_formats::named_gzip_member()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", firmware.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    let report: Value = serde_json::from_slice(&output.stdout).expect("identify json");
    let gzip = report["structure"]["regions"]
        .as_array()
        .and_then(|regions| regions.iter().find(|region| region["format"] == "gzip"))
        .expect("gzip region");
    assert_eq!(gzip["offset"], 0);
    assert_eq!(gzip["span_is_exact"], true);
    assert_eq!(gzip["fills_to_eof"], true);
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
}

#[test]
fn fat_identify_reports_project_extraction_state_without_next_steps() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("camera.bin");
    std::fs::write(&firmware, firmware_formats::named_gzip_member()).expect("firmware");
    let create = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "new",
            firmware.to_str().unwrap(),
            "--projects-dir",
            dir.path().to_str().unwrap(),
        ])
        .output()
        .expect("fat new");
    assert!(create.status.success(), "{create:?}");
    let project = dir.path().join("camera");
    let rootfs = project.join("work/extractions/native/cramfs-root");
    std::fs::create_dir_all(rootfs.join("bin")).expect("rootfs");
    std::fs::create_dir_all(project.join("work")).expect("work");
    std::fs::write(rootfs.join("bin/busybox"), b"busybox").expect("marker");
    let manifest = serde_json::json!({
        "rootfs_path": rootfs,
        "kernel_paths": [],
        "file_count": 1
    });
    std::fs::write(
        project.join("work/extraction-manifest.json"),
        serde_json::to_vec(&manifest).expect("manifest JSON"),
    )
    .expect("manifest");

    let report = identify_json(&project);
    assert_eq!(report["likely_class"], "fat-project");
    assert!(report["summary"]
        .as_array()
        .is_some_and(|lines| lines.iter().any(|line| line
            .as_str()
            .is_some_and(|line| line.starts_with("Reusable extracted rootfs:")))));
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );

    std::fs::remove_file(project.join("work/extraction-manifest.json")).expect("remove manifest");
    let unextracted = identify_json(&project);
    assert!(unextracted["summary"].as_array().is_some_and(|lines| lines
        .iter()
        .any(|line| line == "No reusable extracted rootfs is recorded yet.")));
    assert!(
        unextracted.get("next_steps").is_none(),
        "unexpected next_steps: {unextracted}"
    );

    let outside_rootfs = dir.path().join("outside-rootfs");
    std::fs::create_dir_all(outside_rootfs.join("bin")).expect("outside rootfs");
    std::fs::write(outside_rootfs.join("bin/busybox"), b"busybox").expect("outside marker");
    let outside_manifest = serde_json::json!({
        "rootfs_path": outside_rootfs,
        "kernel_paths": [],
        "file_count": 1
    });
    std::fs::write(
        project.join("work/extraction-manifest.json"),
        serde_json::to_vec(&outside_manifest).expect("outside manifest JSON"),
    )
    .expect("outside manifest");
    let escaped = identify_json(&project);
    assert!(
        escaped["summary"].as_array().is_some_and(|lines| lines
            .iter()
            .any(|line| line == "No reusable extracted rootfs is recorded yet.")),
        "an out-of-project manifest path must not advance project state: {escaped}"
    );
    assert!(
        escaped.get("next_steps").is_none(),
        "unexpected next_steps: {escaped}"
    );
}

fn identify_json(path: &std::path::Path) -> Value {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", path.to_str().unwrap(), "--json"])
        .output()
        .expect("fat identify runs");
    assert!(output.status.success(), "{output:?}");
    serde_json::from_slice(&output.stdout).expect("identify JSON")
}

fn moxa_like_identify_fixture() -> Vec<u8> {
    let kernel = [
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ];
    let nested = [
        0x1f, 0x8b, 0x08, 0x00, 0xff, 0xf1, 0x53, 0x65, 0x02, 0x03, 0xcb, 0x48, 0xcd, 0xc9, 0xc9,
        0x57, 0x28, 0xcf, 0x2f, 0xca, 0x49, 0x51, 0x04, 0x00, 0x6d, 0xc2, 0xb4, 0x03, 0x0c, 0x00,
        0x00, 0x00,
    ];
    let kernel_slot = 0x400u32;
    let rootfs_size = 0x200u32;
    let kernel_off = 0x20u32;
    let rootfs_off = (kernel_off + kernel_slot) as usize;
    let mut bytes = vec![0u8; rootfs_off + rootfs_size as usize];
    bytes[0..4].copy_from_slice(&kernel_slot.to_be_bytes());
    bytes[4..8].copy_from_slice(&rootfs_size.to_be_bytes());
    bytes[8..12].copy_from_slice(&kernel_off.to_be_bytes());
    bytes[12..16].copy_from_slice(&1u32.to_be_bytes());
    bytes[16..20].copy_from_slice(&0x0f85_509cu32.to_be_bytes());
    bytes[20..24].copy_from_slice(&[0x05, 0x07, 0x00, 0x00]);
    bytes[24..28].copy_from_slice(&[0x15, 0x0c, 0x0e, 0x13]);
    bytes[0x20..0x20 + kernel.len()].copy_from_slice(&kernel);
    let sb = &mut bytes[rootfs_off..rootfs_off + 64];
    sb[0..4].copy_from_slice(&0x28cd_3d45u32.to_be_bytes());
    sb[4..8].copy_from_slice(&rootfs_size.to_be_bytes());
    sb[8..12].copy_from_slice(&0x3u32.to_be_bytes());
    sb[16..32].copy_from_slice(b"Compressed ROMFS");
    sb[32..36].copy_from_slice(&0xd081_fdcdu32.to_be_bytes());
    sb[44..48].copy_from_slice(&16u32.to_be_bytes());
    sb[48..58].copy_from_slice(b"Compressed");
    bytes[rootfs_off + 0x80..rootfs_off + 0x80 + nested.len()].copy_from_slice(&nested);
    bytes
}

#[test]
fn fat_identify_json_keeps_nested_filesystem_inside_uimage() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("nested-rootfs.bin");
    std::fs::write(&firmware, uimage_with_nested_squashfs_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat identify json runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let structure = report.get("structure").expect("structure");
    assert_eq!(structure["dominant_rootfs"], "squashfs @ 0x00000080");
    let filesystems = structure["filesystem_headers"]
        .as_array()
        .expect("filesystem headers");
    assert!(
        filesystems
            .iter()
            .any(|hit| hit["format"] == "squashfs" && hit["offset"] == 0x80),
        "nested squashfs must remain in filesystem_headers: {filesystems:?}"
    );
}

fn uimage_crc32(header: &[u8]) -> u32 {
    let mut crc: u32 = 0xFFFF_FFFF;
    for &byte in header {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

fn uimage_with_nested_squashfs_fixture() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x200];
    bytes[..4].copy_from_slice(&0x2705_1956u32.to_be_bytes());
    bytes[4..8].fill(0);
    bytes[8..12].copy_from_slice(&0x633B_BA09u32.to_be_bytes());
    bytes[12..16].copy_from_slice(&0x1C0u32.to_be_bytes());
    bytes[28] = 0x05;
    bytes[29] = 0x05;
    bytes[30] = 0x05;
    bytes[31] = 0x00;
    bytes[32..37].copy_from_slice(b"jz_fw");
    let crc = uimage_crc32(&bytes[..64]);
    bytes[4..8].copy_from_slice(&crc.to_be_bytes());
    write_squashfs_header(&mut bytes, 0x80, 0x100, 8);
    bytes
}

#[test]
fn fat_identify_file_reports_structured_firmware_container() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    std::fs::write(&firmware, uimage_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Identification",
        "Likely class: structured-firmware-container",
        "Envelope",
        "Structure",
        "uimage @ 0x00000000",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_reports_partition_interpretation_for_split_root_firmware() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("wyze-partitioned.bin");
    std::fs::write(&firmware, wyze_partitioned_firmware_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "squashfs @ 0x001F0040",
        "mtdblock2/rootfs",
        "squashfs @ 0x005C0040",
        "mtdblock3/app",
        "/system",
        "Partitioning",
        "Source: kernel cmdline (lzma @ 0x00000080)",
        "Flash map: 8 MTD partitions, 16.00 MiB (16,777,216 bytes) total",
        "Root: mtdblock2/rootfs, squashfs, mounted as /",
        "App/system: mtdblock3/app, squashfs, likely mounted as /system",
        "Backups: mtdblock4/kback, mtdblock5/aback",
        "Config/data: mtdblock6/cfg, mtdblock7/para",
        "Inferences",
        "Layout pattern: split-root embedded Linux firmware",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_json_reports_partition_interpretation_for_split_root_firmware() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("wyze-partitioned.bin");
    std::fs::write(&firmware, wyze_partitioned_firmware_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            firmware.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat identify json runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    let structure = report.get("structure").expect("structure");
    assert_eq!(structure["partitioning"]["device"], "jz_sfc");
    assert_eq!(structure["partitioning"]["partition_count"], 8);
    assert_eq!(structure["partitioning"]["root_device"], "/dev/mtdblock2");
    assert_eq!(structure["partitioning"]["root_fstype"], "squashfs");
    assert_eq!(
        structure["partitioning"]["flash_size_bytes"],
        16 * 1024 * 1024
    );
    assert_eq!(
        structure["partitioning"]["firmware_offset_delta"],
        0x0003_FFC0
    );

    let filesystems = structure["filesystem_headers"]
        .as_array()
        .expect("filesystem headers");
    assert_eq!(filesystems[0]["partition"]["mtdblock"], 2);
    assert_eq!(filesystems[0]["partition"]["name"], "rootfs");
    assert_eq!(filesystems[0]["partition"]["mount_point"], "/");
    assert_eq!(filesystems[0]["partition"]["mount_confidence"], "confirmed");
    assert_eq!(filesystems[1]["partition"]["mtdblock"], 3);
    assert_eq!(filesystems[1]["partition"]["name"], "app");
    assert_eq!(filesystems[1]["partition"]["mount_point"], "/system");
    assert_eq!(filesystems[1]["partition"]["mount_confidence"], "inferred");

    let inferences = structure["inferences"].as_array().expect("inferences");
    assert_eq!(inferences[0]["id"], "layout.split-root");
    assert_eq!(inferences[0]["confidence"], "high");
}

#[test]
fn fat_identify_elf_reports_header_summary() {
    let dir = tempdir().expect("tempdir");
    let elf = dir.path().join("libdemo.so");
    std::fs::write(&elf, minimal_elf_shared_object()).expect("elf");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg(elf.to_str().expect("elf path"))
        .output()
        .expect("fat bare elf runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: executable-binary",
        "ELF64 little-endian",
        "Machine: x86-64",
        "Entry point: 0x0000000000000000",
        "Linking: dynamic",
        "Sections: 5",
        "Stripped: yes",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_positional_file_emits_stable_json() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    std::fs::write(&firmware, uimage_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            firmware.to_str().expect("firmware path"),
            "--json",
        ])
        .output()
        .expect("fat identify json runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(report["schema_version"], "identify-report/v1");
    assert_eq!(report["path_kind"], "RawBlob");
    assert_eq!(report["likely_class"], "structured-firmware-container");
    assert!(
        report.get("envelope").is_some(),
        "missing envelope: {report}"
    );
    assert!(
        report.get("structure").is_some(),
        "missing structure: {report}"
    );
    assert!(
        report.get("next_steps").is_none(),
        "unexpected next_steps: {report}"
    );
}

#[test]
fn fat_identify_rejects_missing_input_source() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg("identify")
        .output()
        .expect("fat identify runs");

    assert!(
        !output.status.success(),
        "identify without input should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exactly one input source is required"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn fat_identify_rejects_positional_and_file_together() {
    let dir = tempdir().expect("tempdir");
    let left = dir.path().join("left.bin");
    let right = dir.path().join("right.bin");
    std::fs::write(&left, uimage_fixture()).expect("left");
    std::fs::write(&right, uimage_fixture()).expect("right");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            left.to_str().expect("left"),
            "--file",
            right.to_str().expect("right"),
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        !output.status.success(),
        "identify with two inputs should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("exactly one input source is required"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn fat_identify_reports_unknown_for_unrecognized_directory() {
    let dir = tempdir().expect("tempdir");
    let empty_dir = dir.path().join("mystery");
    std::fs::create_dir(&empty_dir).expect("empty dir");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", empty_dir.to_str().expect("dir path")])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("Likely class: unknown"),
        "expected unknown directory class, got:\n{stdout}"
    );
    assert!(
        stdout.contains("Identification"),
        "expected identify output, got:\n{stdout}"
    );
}

#[test]
fn fat_identify_rootfs_directory_reports_markers_without_next_steps() {
    let dir = tempdir().expect("tempdir");
    let rootfs = dir.path().join("extracted-rootfs");
    for path in ["bin", "etc/init.d", "lib", "usr", "www"] {
        std::fs::create_dir_all(rootfs.join(path)).expect("rootfs marker dir");
    }

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", rootfs.to_str().expect("rootfs path")])
        .output()
        .expect("fat identify rootfs runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: rootfs-directory",
        "Rootfs markers:",
        "/bin",
        "/etc",
        "/etc/init.d",
        "/lib",
        "/usr",
        "/www",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_directory_with_firmware_blobs_reports_collection() {
    let dir = tempdir().expect("tempdir");
    let collection = dir.path().join("vendor-downloads");
    std::fs::create_dir(&collection).expect("collection");
    std::fs::write(collection.join("a.bin"), uimage_fixture()).expect("a");
    std::fs::write(
        collection.join("b.bin"),
        compression_only_firmware_fixture(),
    )
    .expect("b");
    std::fs::write(collection.join("notes.txt"), b"download notes").expect("notes");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            collection.to_str().expect("collection path"),
        ])
        .output()
        .expect("fat identify collection runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: firmware-blob-collection",
        "Candidate firmware blobs: 2",
        "a.bin",
        "b.bin",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
    assert!(
        !stdout.contains("Shallow directory scan"),
        "stdout:\n{stdout}"
    );
}

#[test]
fn fat_identify_unknown_directory_json_is_low_confidence() {
    let dir = tempdir().expect("tempdir");
    let empty_dir = dir.path().join("mystery");
    std::fs::create_dir(&empty_dir).expect("empty dir");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "identify",
            "--file",
            empty_dir.to_str().expect("dir path"),
            "--json",
        ])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: Value = serde_json::from_slice(&output.stdout).expect("valid json");
    assert_eq!(report["likely_class"], "unknown");
    assert_eq!(report["confidence"], "low");
}

#[test]
fn fat_identify_propagates_invalid_codeql_metadata_errors() {
    let dir = tempdir().expect("tempdir");
    let codeql_dir = dir.path().join("broken-codeql");
    std::fs::create_dir(&codeql_dir).expect("codeql dir");
    std::fs::write(
        codeql_dir.join("codeql-database.yml"),
        "sourceLocationPrefix: [unterminated\nprimaryLanguage: cpp\n",
    )
    .expect("broken codeql metadata");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", codeql_dir.to_str().expect("dir path")])
        .output()
        .expect("fat identify runs");

    assert!(
        !output.status.success(),
        "malformed codeql metadata should fail"
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid CodeQL metadata") || stderr.contains("target detection failed"),
        "stderr:\n{stderr}"
    );
}

#[test]
fn fat_identify_reports_opaque_wrapper_evidence_without_guidance() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque.bin");
    std::fs::write(&blob, pseudo_random_bytes(8192)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("Likely class: opaque-wrapper-likely"),
        "stdout:\n{stdout}"
    );
    assert!(
        stdout.contains("Opaque wrapper likely"),
        "stdout:\n{stdout}"
    );
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_renders_human_readable_byte_sizes() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("tapo-sized.bin");
    std::fs::write(&blob, pseudo_random_bytes(8_128_512)).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(stdout.contains("Size: 7.75 MiB"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_reports_mcu_firmware_without_requiring_inspect_mcu() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("mcu.bin");
    std::fs::write(&blob, build_mcu_blob()).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    for needle in [
        "Likely class: mcu-firmware-likely",
        "MCU: ARM Cortex-M",
        "ARM Cortex-M",
        "STM32H7",
        "Base hypothesis: 0x08000000",
    ] {
        assert!(stdout.contains(needle), "missing {needle} in:\n{stdout}");
    }
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_identify_suppresses_mcu_signal_for_opaque_wrapper_with_ivt_like_header() {
    let dir = tempdir().expect("tempdir");
    let blob = dir.path().join("opaque_ivt.bin");
    let mut bytes = pseudo_random_bytes(8192);
    bytes[0..4].copy_from_slice(&0x2401_A058u32.to_le_bytes());
    bytes[4..8].copy_from_slice(&0x0800_0201u32.to_le_bytes());
    bytes[8..12].copy_from_slice(&0x0800_2001u32.to_le_bytes());
    bytes[12..16].copy_from_slice(&0x0800_3001u32.to_le_bytes());
    std::fs::write(&blob, bytes).expect("blob");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", "--file", blob.to_str().expect("blob")])
        .output()
        .expect("fat identify runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(
        stdout.contains("Likely class: opaque-wrapper-likely"),
        "stdout:\n{stdout}"
    );
    assert!(
        !stdout.contains("ARM Cortex-M"),
        "unexpected MCU summary in:\n{stdout}"
    );
    assert!(!stdout.contains("MCU:"), "stdout:\n{stdout}");
    assert!(!stdout.contains("not indicated"), "stdout:\n{stdout}");
    assert!(!stdout.contains("Next steps"), "stdout:\n{stdout}");
}

#[test]
fn fat_bare_file_path_routes_to_identify() {
    let dir = tempdir().expect("tempdir");
    let firmware = dir.path().join("firmware.bin");
    std::fs::write(&firmware, uimage_fixture()).expect("firmware");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .arg(firmware.to_str().expect("firmware path"))
        .output()
        .expect("fat bare path runs");

    assert!(
        output.status.success(),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = readable_output(&output.stdout);
    assert!(stdout.contains("Identification"), "stdout:\n{stdout}");
    assert!(
        stdout.contains("structured-firmware-container"),
        "stdout:\n{stdout}"
    );
}

fn strip_terminal_style(text: &str) -> String {
    let mut plain = String::new();
    let mut chars = text.chars();
    while let Some(ch) = chars.next() {
        if ch == '\u{1b}' && chars.next() == Some('[') {
            for code in chars.by_ref() {
                if code.is_ascii_alphabetic() {
                    break;
                }
            }
        } else {
            plain.push(ch);
        }
    }
    plain
}

fn identify_presentation(file: &std::path::Path, color: &str, json: bool) -> String {
    identify_presentation_with_details(file, color, json, false)
}

fn identify_presentation_with_details(
    file: &std::path::Path,
    color: &str,
    json: bool,
    details: bool,
) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command
        .args(["identify", file.to_str().unwrap()])
        .env("FAT_COLOR", color)
        .env("COLUMNS", "100")
        .env_remove("NO_COLOR");
    if json {
        command.arg("--json");
    }
    if details {
        command.arg("--details");
    }
    let output = command.output().unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).unwrap()
}

#[test]
fn identify_color_and_plain_share_content_without_invented_confidence_percentages() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("unlabeled.bin");
    std::fs::write(&file, build_rom_blob()).unwrap();
    let plain = identify_presentation_with_details(&file, "never", false, true);
    let colored = identify_presentation_with_details(&file, "always", false, true);
    assert!(
        colored.contains('\u{1b}'),
        "forced color should style the same report"
    );
    assert!(!plain.contains('\u{1b}'));
    assert_eq!(strip_terminal_style(&colored), plain);
    assert_eq!(
        strip_terminal_style(&identify_presentation(&file, "always", false)),
        identify_presentation(&file, "never", false),
        "color must preserve compact overview content and layout"
    );
    for required in [
        "Identification",
        "Image",
        "Envelope",
        "Metric",
        "Value",
        "ARM Cortex-M",
        "File offset",
        "Encoding",
        "ascii",
        "utf-16le",
        "LPC134X",
        "0x300",
    ] {
        assert!(plain.contains(required), "missing {required}: {plain}");
    }
    assert_eq!(
        plain.matches("LPC134X").count(),
        1,
        "identical identity text should be grouped"
    );
    assert_eq!(
        plain.matches("LPC13XX").count(),
        1,
        "identical wide identity text should be grouped"
    );
    assert!(
        plain.contains("0x4300") && plain.contains("0x4380"),
        "grouping must retain every file offset"
    );
    assert!(
        !plain.contains("75%"),
        "qualitative confidence is not a measured percentage"
    );
    assert!(
        !plain.contains("50%"),
        "qualitative confidence is not a measured percentage"
    );
    assert!(
        !colored.contains('╭'),
        "do not enclose the report in a large panel"
    );
    assert!(!plain.contains("Next steps"));
    assert!(!plain.contains("fat inspect-mcu"));
    let plain_json: Value =
        serde_json::from_str(&identify_presentation(&file, "never", true)).unwrap();
    let color_json: Value =
        serde_json::from_str(&identify_presentation(&file, "always", true)).unwrap();
    assert_eq!(
        plain_json, color_json,
        "presentation controls must not change report data"
    );
}

#[test]
fn identify_narrow_no_color_report_keeps_identity_evidence_readable() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_rom_blob()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args(["identify", file.to_str().unwrap(), "--details"])
        .env("FAT_COLOR", "auto")
        .env("NO_COLOR", "1")
        .env("COLUMNS", "43")
        .output()
        .unwrap();
    assert!(output.status.success());
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(!text.contains('\u{1b}'));
    assert!(
        text.lines().all(|line| line.chars().count() <= 43),
        "narrow report overflow: {text}"
    );
    let content = readable_output(text.as_bytes());
    for required in [
        "ARM Cortex-M",
        "NXP LPC134x",
        "0x300",
        "utf-16le",
        "LPC13XX",
    ] {
        assert!(content.contains(required), "missing {required}: {text}");
    }
    assert!(!text.contains("Next steps"));
}

#[test]
fn identify_default_is_compact_and_details_preserve_evidence_and_json() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    std::fs::write(&file, build_rom_blob()).unwrap();
    let plain = identify_presentation(&file, "never", false);
    let content = readable_output(plain.as_bytes());
    assert!(
        plain.starts_with("Identification · anonymous.bin"),
        "{plain}"
    );
    assert!(
        !plain.contains(file.to_str().unwrap()),
        "default should use the basename: {plain}"
    );
    assert!(
        plain.lines().count() <= 15,
        "default overview is too long: {plain}"
    );
    for omitted in [
        "Note:",
        "Family evidence",
        "plausible SRAM",
        "collection is bounded",
        "Unexplained duplicates",
        "Entropy",
        "Uniform file range",
        "Vector offset",
        "Initial SP",
        "Identity text",
        "Encoding",
    ] {
        assert!(!plain.contains(omitted), "unnecessary {omitted}: {plain}");
    }
    for retained in [
        "ARM Cortex-M",
        "NXP LPC134x",
        "corroborated",
        "Likely class: mcu-firmware-likely [medium]",
        "Size: 32.00 KiB",
        "2 exact copies of 16.00 KiB",
        "Likely boot ROM",
        "Base hypothesis: 0x1FFF0000",
        "Reset handler: 0x1FFF0104",
    ] {
        assert!(content.contains(retained), "missing {retained}: {plain}");
    }
    let details = identify_presentation_with_details(&file, "never", false, true);
    let detail_content = readable_output(details.as_bytes());
    assert!(details.lines().count() > plain.lines().count());
    assert!(
        details
            .split_whitespace()
            .collect::<String>()
            .contains(file.to_str().unwrap()),
        "details should preserve the full input path: {details}"
    );
    for retained in [
        "32.00 KiB (32,768 bytes)",
        "16.00 KiB (16,384 bytes)",
        "Entropy",
        "Uniform file range",
        "Vector offset",
        "Initial SP",
        "0x10000FFC",
        "0x1FFF0105",
        "Identity text",
        "ascii",
        "utf-16le",
        "0x300",
        "0x4300",
    ] {
        assert!(
            detail_content.contains(retained),
            "missing {retained}: {details}"
        );
    }
    assert!(
        !details.contains("Notes") && !details.contains("Limits"),
        "{details}"
    );
    let json_text = identify_presentation(&file, "never", true);
    assert_eq!(
        json_text,
        identify_presentation_with_details(&file, "never", true, true),
        "--details must not change serialized output"
    );
    let json: Value = serde_json::from_str(&json_text).unwrap();
    assert!(!json["mcu"]["identification"]["notes"]
        .as_array()
        .unwrap()
        .is_empty());
    assert!(!json["mcu"]["identification"]["family_evidence"]
        .as_array()
        .unwrap()
        .is_empty());
}

#[test]
fn identify_details_show_all_retained_uniform_regions_and_collection_truncation() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("uniform-regions.bin");
    for count in [4u8, 6, 70] {
        let bytes = (0..count)
            .flat_map(|byte| vec![byte; 128])
            .collect::<Vec<_>>();
        std::fs::write(&file, bytes).unwrap();
        let plain = identify_presentation_with_details(&file, "never", false, true);
        let content = readable_output(plain.as_bytes());
        let json: Value =
            serde_json::from_str(&identify_presentation(&file, "never", true)).unwrap();
        let repetition = &json["envelope"]["repetition"];
        let collected = repetition["uniform_regions"].as_array().unwrap().len();
        assert_eq!(collected, usize::from(count).min(64));
        assert_eq!(repetition["uniform_regions_truncated"], count > 64);
        let last_range = format!("[0x{:X}, 0x{:X})", (collected - 1) * 128, collected * 128);
        assert!(
            content.contains(&last_range),
            "missing {last_range}: {plain}"
        );
        if count > 64 {
            let expected = format!("Shown: {collected} of {collected}+ uniform regions");
            assert!(content.contains(&expected), "missing {expected}: {plain}");
        } else {
            assert!(!content.contains("Shown:"), "{plain}");
        }
        assert!(
            !content.contains("Notes") && !content.contains("Limits"),
            "{plain}"
        );
    }
}

#[test]
fn identify_unknown_directory_still_has_classification_without_empty_sections() {
    let dir = tempdir().unwrap();
    let plain = identify_presentation(dir.path(), "never", false);
    let content = readable_output(plain.as_bytes());
    assert!(content.contains("Likely class: unknown"));
    assert!(content.contains("Likely class: unknown [low]"));
    for omitted in [
        "MCU: ARM Cortex-M",
        "not indicated",
        "Summary",
        "Note:",
        "not specific enough",
    ] {
        assert!(!plain.contains(omitted), "unnecessary {omitted}: {plain}");
    }
    let json: Value =
        serde_json::from_str(&identify_presentation(dir.path(), "never", true)).unwrap();
    assert!(
        !json["summary"].as_array().unwrap().is_empty(),
        "JSON retains diagnostic context"
    );
}

#[test]
fn identify_recognized_architecture_omits_unresolved_family_row() {
    let dir = tempdir().unwrap();
    let file = dir.path().join("anonymous.bin");
    let mut bytes = build_rom_blob();
    for (index, word) in [0x2000_2000u32, 0x6000_0105, 0x6000_0fa9, 0x6000_0fab]
        .into_iter()
        .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    std::fs::write(&file, bytes).unwrap();
    let plain = identify_presentation(&file, "never", false);
    assert!(readable_output(plain.as_bytes()).contains("MCU: ARM Cortex-M"));
    assert!(
        !plain.contains("Family") && !plain.contains("unresolved"),
        "{plain}"
    );
    let json: Value = serde_json::from_str(&identify_presentation(&file, "never", true)).unwrap();
    assert_eq!(json["mcu"]["family"], "unresolved");
    assert_eq!(
        json["mcu"]["identification"]["family_confidence"],
        "unresolved"
    );
}
