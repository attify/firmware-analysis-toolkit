use std::process::Command;
use tempfile::tempdir;

#[test]
fn fat_inspect_headers_supports_elf_shared_objects() {
    let temp = tempdir().expect("temp dir");
    let elf_path = temp.path().join("libdemo.so");
    std::fs::write(&elf_path, minimal_elf_shared_object()).expect("elf file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "headers",
            "--file",
            elf_path.to_str().expect("elf path"),
        ])
        .output()
        .expect("fat inspect headers runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in ["ELF header", "shared object", "x86-64", "Section headers"] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
}

#[test]
fn fat_inspect_layout_supports_elf_shared_objects() {
    let temp = tempdir().expect("temp dir");
    let elf_path = temp.path().join("libdemo.so");
    std::fs::write(&elf_path, minimal_elf_shared_object()).expect("elf file");

    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .args([
            "inspect",
            "layout",
            "--file",
            elf_path.to_str().expect("elf path"),
        ])
        .output()
        .expect("fat inspect layout runs");

    assert!(
        output.status.success(),
        "expected success, got status {:?}\nstderr:\n{}",
        output.status,
        String::from_utf8_lossy(&output.stderr)
    );

    let stdout = String::from_utf8_lossy(&output.stdout);
    for needle in [
        "ELF layout summary",
        "ELF program headers",
        ".text",
        ".dynamic",
        ".got.plt",
    ] {
        assert!(
            stdout.contains(needle),
            "expected output to contain {needle}, got:\n{stdout}"
        );
    }
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
    bytes[4] = 2; // ELF64
    bytes[5] = 1; // little-endian
    bytes[6] = 1; // version

    write_u16(&mut bytes, 16, 3); // ET_DYN
    write_u16(&mut bytes, 18, 62); // EM_X86_64
    write_u32(&mut bytes, 20, 1);
    write_u64(&mut bytes, 24, 0);
    write_u64(&mut bytes, 32, program_headers_off);
    write_u64(&mut bytes, 40, section_headers_off);
    write_u32(&mut bytes, 48, 0);
    write_u16(&mut bytes, 52, 64);
    write_u16(&mut bytes, 54, 56);
    write_u16(&mut bytes, 56, 2);
    write_u16(&mut bytes, 58, 64);
    write_u16(&mut bytes, 60, 6);
    write_u16(&mut bytes, 62, 5);

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
    write_u64(&mut bytes, ph1, 1); // PT_LOAD
    write_u32(&mut bytes, ph1 + 4, 5); // PF_R | PF_X
    write_u64(&mut bytes, ph1 + 8, text_off); // p_offset
    write_u64(&mut bytes, ph1 + 16, 0x1000); // p_vaddr
    write_u64(&mut bytes, ph1 + 24, 0); // p_paddr
    write_u64(&mut bytes, ph1 + 32, 0x80); // p_filesz
    write_u64(&mut bytes, ph1 + 40, 0x80); // p_memsz
    write_u64(&mut bytes, ph1 + 48, 0x1000); // p_align

    write_u64(&mut bytes, ph2, 2); // PT_DYNAMIC
    write_u32(&mut bytes, ph2 + 4, 4); // PF_R
    write_u64(&mut bytes, ph2 + 8, dynamic_off); // p_offset
    write_u64(&mut bytes, ph2 + 16, 0x2000); // p_vaddr
    write_u64(&mut bytes, ph2 + 24, 0); // p_paddr
    write_u64(&mut bytes, ph2 + 32, 0x20); // p_filesz
    write_u64(&mut bytes, ph2 + 40, 0x20); // p_memsz
    write_u64(&mut bytes, ph2 + 48, 0x8); // p_align

    let sh0 = section_headers_off as usize;
    let sh1 = sh0 + 64;
    let sh2 = sh1 + 64;
    let sh3 = sh2 + 64;
    let sh4 = sh3 + 64;
    let sh5 = sh4 + 64;

    write_section_header(&mut bytes, sh1, 1, 1, 0x6, text_off, 16, 0, 0, 16, 0);
    write_section_header(&mut bytes, sh2, 7, 1, 0x6, plt_off, 16, 0, 0, 16, 0);
    write_section_header(&mut bytes, sh3, 12, 1, 0x3, got_plt_off, 16, 0, 0, 8, 0);
    write_section_header(&mut bytes, sh4, 21, 6, 0x3, dynamic_off, 32, 0, 0, 8, 16);
    write_section_header(
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

fn write_section_header(
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
    write_u32(bytes, offset, name);
    write_u32(bytes, offset + 4, sh_type);
    write_u64(bytes, offset + 8, flags);
    write_u64(bytes, offset + 16, 0);
    write_u64(bytes, offset + 24, data_offset);
    write_u64(bytes, offset + 32, size);
    write_u32(bytes, offset + 40, link);
    write_u32(bytes, offset + 44, info);
    write_u64(bytes, offset + 48, addralign);
    write_u64(bytes, offset + 56, entsize);
}

fn write_u16(bytes: &mut [u8], offset: usize, value: u16) {
    bytes[offset..offset + 2].copy_from_slice(&value.to_le_bytes());
}

fn write_u32(bytes: &mut [u8], offset: usize, value: u32) {
    bytes[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

fn write_u64(bytes: &mut [u8], offset: usize, value: u64) {
    bytes[offset..offset + 8].copy_from_slice(&value.to_le_bytes());
}
