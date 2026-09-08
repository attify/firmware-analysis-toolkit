#![allow(dead_code)]

use std::io::Write;

use flate2::write::ZlibEncoder;
use flate2::Compression;

#[derive(Debug, Clone, Copy)]
pub enum FixtureEndian {
    Little,
    Big,
}

pub fn named_gzip_member() -> Vec<u8> {
    vec![
        0x1f, 0x8b, 0x08, 0x08, 0x43, 0x77, 0xb8, 0x61, 0x02, 0x03, 0x76, 0x6d, 0x6c, 0x69, 0x6e,
        0x75, 0x78, 0x2e, 0x36, 0x34, 0x00, 0xcb, 0x4e, 0x2d, 0xca, 0x4b, 0xcd, 0xd1, 0x2d, 0x48,
        0xac, 0xcc, 0xc9, 0x4f, 0x4c, 0xd1, 0x4d, 0xcb, 0x2f, 0xd2, 0x4d, 0x4b, 0x2c, 0x01, 0x00,
        0xbe, 0x7b, 0x95, 0xbb, 0x16, 0x00, 0x00, 0x00,
    ]
}

pub fn gzip_elf_fixture(class_64: bool, little_endian: bool) -> Vec<u8> {
    let mut elf = vec![0u8; 64];
    elf[0..4].copy_from_slice(b"\x7fELF");
    elf[4] = if class_64 { 2 } else { 1 };
    elf[5] = if little_endian { 1 } else { 2 };
    elf[6] = 1;
    let elf_type = if little_endian {
        2u16.to_le_bytes()
    } else {
        2u16.to_be_bytes()
    };
    let machine = if little_endian {
        8u16.to_le_bytes()
    } else {
        8u16.to_be_bytes()
    };
    elf[16..18].copy_from_slice(&elf_type);
    elf[18..20].copy_from_slice(&machine);
    gzip_payload(&elf, "vmlinux")
}

pub fn gzip_payload(payload: &[u8], name: &str) -> Vec<u8> {
    let mut encoder = flate2::GzBuilder::new()
        .filename(name)
        .write(Vec::new(), Compression::default());
    encoder.write_all(payload).expect("gzip payload");
    encoder.finish().expect("gzip finish")
}

pub fn cpio_newc_fixture() -> Vec<u8> {
    let mut archive = Vec::new();
    push_cpio_newc_entry(&mut archive, "init", 0o100755, b"#!/bin/sh\n", 1, false);
    push_cpio_newc_entry(&mut archive, "TRAILER!!!", 0, &[], 2, false);
    archive
}

pub fn cpio_crc_fixture() -> Vec<u8> {
    let mut archive = Vec::new();
    push_cpio_newc_entry(&mut archive, "init", 0o100755, b"#!/bin/sh\n", 1, true);
    push_cpio_newc_entry(&mut archive, "TRAILER!!!", 0, &[], 2, true);
    archive
}

#[derive(Debug, Clone, Copy)]
pub enum ExtFixtureKind {
    Ext2,
    Ext3,
    Ext4,
}

pub fn ext_filesystem_fixture(kind: ExtFixtureKind) -> Vec<u8> {
    let block_size = 1_024usize;
    let block_count = 64u32;
    let mut image = vec![0u8; block_size * block_count as usize];
    let superblock = 1_024usize;
    write_u32_le(&mut image, superblock, 32);
    write_u32_le(&mut image, superblock + 4, block_count);
    write_u32_le(&mut image, superblock + 12, 16);
    write_u32_le(&mut image, superblock + 16, 16);
    write_u32_le(&mut image, superblock + 20, 1);
    write_u32_le(&mut image, superblock + 24, 0);
    write_u32_le(&mut image, superblock + 32, 64);
    write_u32_le(&mut image, superblock + 40, 32);
    image[superblock + 56..superblock + 58].copy_from_slice(&0xef53u16.to_le_bytes());
    image[superblock + 58..superblock + 60].copy_from_slice(&1u16.to_le_bytes());
    image[superblock + 60..superblock + 62].copy_from_slice(&1u16.to_le_bytes());
    write_u32_le(&mut image, superblock + 76, 1);
    image[superblock + 88..superblock + 90].copy_from_slice(
        &(if matches!(kind, ExtFixtureKind::Ext4) {
            256u16
        } else {
            128u16
        })
        .to_le_bytes(),
    );
    image[superblock + 104..superblock + 120].copy_from_slice(&[0x5a; 16]);

    match kind {
        ExtFixtureKind::Ext2 => {}
        ExtFixtureKind::Ext3 => write_u32_le(&mut image, superblock + 92, 0x4),
        ExtFixtureKind::Ext4 => {
            write_u32_le(&mut image, superblock + 96, 0x40 | 0x80 | 0x200);
            image[superblock + 254..superblock + 256].copy_from_slice(&64u16.to_le_bytes());
        }
    }
    image
}

pub fn set_ext_log_block_size(image: &mut [u8], value: u32) {
    write_u32_le(image, 1_024 + 24, value);
}

pub fn set_ext_inode_count(image: &mut [u8], value: u32) {
    write_u32_le(image, 1_024, value);
}

pub fn set_ext_block_count(image: &mut [u8], value: u32) {
    write_u32_le(image, 1_024 + 4, value);
}

pub fn set_ext_incompat_features(image: &mut [u8], value: u32) {
    write_u32_le(image, 1_024 + 96, value);
}

fn write_u32_le(image: &mut [u8], offset: usize, value: u32) {
    image[offset..offset + 4].copy_from_slice(&value.to_le_bytes());
}

pub struct FdtFixture {
    pub image: Vec<u8>,
    pub structure_offset: usize,
    pub strings_offset: usize,
}

impl FdtFixture {
    pub fn set_total_size(&mut self, size: u32) {
        self.image[4..8].copy_from_slice(&size.to_be_bytes());
    }

    pub fn set_structure_offset(&mut self, offset: u32) {
        self.image[8..12].copy_from_slice(&offset.to_be_bytes());
    }

    pub fn set_version(&mut self, version: u32, last_compatible: u32) {
        self.image[20..24].copy_from_slice(&version.to_be_bytes());
        self.image[24..28].copy_from_slice(&last_compatible.to_be_bytes());
    }

    pub fn remove_reserve_terminator(&mut self) {
        self.image[40..48].copy_from_slice(&1u64.to_be_bytes());
        self.image[48..56].copy_from_slice(&1u64.to_be_bytes());
    }

    pub fn set_first_structure_token(&mut self, token: u32) {
        self.image[self.structure_offset..self.structure_offset + 4]
            .copy_from_slice(&token.to_be_bytes());
    }

    pub fn set_property_name_offset(&mut self, offset: u32) {
        let property = self.structure_offset + 8;
        self.image[property + 8..property + 12].copy_from_slice(&offset.to_be_bytes());
    }

    pub fn remove_root_name_terminator(&mut self) {
        self.image[self.structure_offset + 4..self.structure_offset + 8].fill(b'A');
    }
}

pub fn fdt_fixture(fit: bool) -> FdtFixture {
    const BEGIN_NODE: u32 = 1;
    const END_NODE: u32 = 2;
    const PROP: u32 = 3;
    const END: u32 = 9;

    let reserve_offset = 40usize;
    let structure_offset = 56usize;
    let mut structure = Vec::new();
    push_fdt_token(&mut structure, BEGIN_NODE);
    structure.extend_from_slice(&[0, 0, 0, 0]);
    push_fdt_token(&mut structure, PROP);
    push_fdt_token(&mut structure, 4);
    push_fdt_token(&mut structure, 0);
    structure.extend_from_slice(b"test");
    if fit {
        push_fdt_node(&mut structure, "images");
        push_fdt_token(&mut structure, END_NODE);
        push_fdt_node(&mut structure, "configurations");
        push_fdt_token(&mut structure, END_NODE);
    } else {
        push_fdt_node(&mut structure, "soc");
        push_fdt_token(&mut structure, END_NODE);
    }
    push_fdt_token(&mut structure, END_NODE);
    push_fdt_token(&mut structure, END);

    let strings = b"compatible\0";
    let strings_offset = structure_offset + structure.len();
    let total_size = strings_offset + strings.len();
    let mut image = vec![0u8; total_size];
    image[0..4].copy_from_slice(&0xd00d_feedu32.to_be_bytes());
    image[4..8].copy_from_slice(&(total_size as u32).to_be_bytes());
    image[8..12].copy_from_slice(&(structure_offset as u32).to_be_bytes());
    image[12..16].copy_from_slice(&(strings_offset as u32).to_be_bytes());
    image[16..20].copy_from_slice(&(reserve_offset as u32).to_be_bytes());
    image[20..24].copy_from_slice(&17u32.to_be_bytes());
    image[24..28].copy_from_slice(&16u32.to_be_bytes());
    image[32..36].copy_from_slice(&(strings.len() as u32).to_be_bytes());
    image[36..40].copy_from_slice(&(structure.len() as u32).to_be_bytes());
    image[structure_offset..strings_offset].copy_from_slice(&structure);
    image[strings_offset..].copy_from_slice(strings);

    FdtFixture {
        image,
        structure_offset,
        strings_offset,
    }
}

fn push_fdt_token(bytes: &mut Vec<u8>, token: u32) {
    bytes.extend_from_slice(&token.to_be_bytes());
}

fn push_fdt_node(bytes: &mut Vec<u8>, name: &str) {
    push_fdt_token(bytes, 1);
    bytes.extend_from_slice(name.as_bytes());
    bytes.push(0);
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}

pub struct TrxFixture {
    pub image: Vec<u8>,
}

impl TrxFixture {
    pub fn corrupt_crc(&mut self) {
        self.image[8] ^= 0xff;
    }

    pub fn set_length(&mut self, length: u32) {
        self.image[4..8].copy_from_slice(&length.to_le_bytes());
        if let Ok(end) = usize::try_from(length) {
            if end >= 12 && end <= self.image.len() {
                self.refresh_crc(end);
            }
        }
    }

    pub fn set_partition_offsets(&mut self, offsets: [u32; 3]) {
        for (index, offset) in offsets.into_iter().enumerate() {
            let start = 16 + index * 4;
            self.image[start..start + 4].copy_from_slice(&offset.to_le_bytes());
        }
        self.refresh_crc(self.image.len());
    }

    fn refresh_crc(&mut self, end: usize) {
        let version =
            u32::from_le_bytes(self.image[12..16].try_into().expect("flags/version")) >> 16;
        let crc = if version == 2 {
            let fourth = u32::from_le_bytes(self.image[28..32].try_into().expect("v2 offset"));
            let stable = fourth as usize + 22;
            let mut covered = self.image[12..end].to_vec();
            covered[stable - 12..stable - 12 + 8].fill(0xff);
            crc32fast::hash(&covered)
        } else {
            crc32fast::hash(&self.image[12..end])
        };
        self.image[8..12].copy_from_slice(&crc.to_le_bytes());
    }
}

pub fn trx_fixture() -> TrxFixture {
    let mut image = vec![0x5a; 0x100];
    let image_len = image.len() as u32;
    image[0..4].copy_from_slice(b"HDR0");
    image[4..8].copy_from_slice(&image_len.to_le_bytes());
    image[12..16].copy_from_slice(&0x0001_0001u32.to_le_bytes());
    image[16..20].copy_from_slice(&28u32.to_le_bytes());
    image[20..24].copy_from_slice(&0x80u32.to_le_bytes());
    image[24..28].copy_from_slice(&0u32.to_le_bytes());
    let mut fixture = TrxFixture { image };
    fixture.refresh_crc(fixture.image.len());
    fixture
}

pub fn trx_v2_fixture() -> TrxFixture {
    let mut image = vec![0x5a; 0x100];
    let image_len = image.len() as u32;
    image[0..4].copy_from_slice(b"HDR0");
    image[4..8].copy_from_slice(&image_len.to_le_bytes());
    image[12..16].copy_from_slice(&0x0002_0000u32.to_le_bytes());
    for (index, offset) in [32u32, 0x60, 0xa0, 0xc0].into_iter().enumerate() {
        let start = 16 + index * 4;
        image[start..start + 4].copy_from_slice(&offset.to_le_bytes());
    }
    let mut fixture = TrxFixture { image };
    fixture.refresh_crc(fixture.image.len());
    fixture
}

fn push_cpio_newc_entry(
    archive: &mut Vec<u8>,
    name: &str,
    mode: u32,
    data: &[u8],
    inode: u32,
    checksum: bool,
) {
    let name_size = name.len() + 1;
    let fields = [
        inode,
        mode,
        0,
        0,
        1,
        0,
        data.len() as u32,
        0,
        0,
        0,
        0,
        name_size as u32,
        if checksum {
            data.iter()
                .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
        } else {
            0
        },
    ];
    archive.extend_from_slice(if checksum { b"070702" } else { b"070701" });
    for field in fields {
        archive.extend_from_slice(format!("{field:08x}").as_bytes());
    }
    archive.extend_from_slice(name.as_bytes());
    archive.push(0);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
    archive.extend_from_slice(data);
    while !archive.len().is_multiple_of(4) {
        archive.push(0);
    }
}

pub fn jffs2_fixture(endian: FixtureEndian) -> Vec<u8> {
    let mut image = Vec::new();
    push_jffs2_node(&mut image, endian, 0x2003, 12);
    push_jffs2_node(&mut image, endian, 0xe002, 68);
    image
}

pub fn corrupt_jffs2_header_crc(image: &mut [u8]) {
    image[20] ^= 0xff;
}

pub fn set_jffs2_second_totlen(image: &mut [u8], endian: FixtureEndian, total: u32) {
    write_u32(image, 16, total, endian);
    refresh_jffs2_header_crc(image, endian, 12);
}

pub fn set_jffs2_second_node_type(image: &mut [u8], endian: FixtureEndian, node_type: u16) {
    write_u16(image, 14, node_type, endian);
    refresh_jffs2_header_crc(image, endian, 12);
}

fn push_jffs2_node(image: &mut Vec<u8>, endian: FixtureEndian, node_type: u16, total: u32) {
    let start = image.len();
    image.resize(start + total as usize, 0);
    write_u16(image, start, 0x1985, endian);
    write_u16(image, start + 2, node_type, endian);
    write_u32(image, start + 4, total, endian);
    refresh_jffs2_header_crc(image, endian, start);
}

fn refresh_jffs2_header_crc(image: &mut [u8], endian: FixtureEndian, start: usize) {
    let crc = linux_crc32(0, &image[start..start + 8]);
    write_u32(image, start + 8, crc, endian);
}

pub struct UbiFixture {
    pub image: Vec<u8>,
    pub peb_size: usize,
    pub ubifs_offset: usize,
}

impl UbiFixture {
    pub fn corrupt_first_ec_crc(&mut self) {
        self.image[60] ^= 0xff;
    }

    pub fn set_first_version(&mut self, version: u8) {
        self.image[4] = version;
        refresh_ubi_ec_crc(&mut self.image, 0);
    }

    pub fn set_first_data_offset(&mut self, offset: u32) {
        self.image[20..24].copy_from_slice(&offset.to_be_bytes());
        refresh_ubi_ec_crc(&mut self.image, 0);
    }

    pub fn corrupt_ubifs_crc(&mut self) {
        self.image[self.ubifs_offset + 4] ^= 0xff;
    }

    pub fn set_ubifs_length(&mut self, length: u32) {
        self.image[self.ubifs_offset + 16..self.ubifs_offset + 20]
            .copy_from_slice(&length.to_le_bytes());
    }
}

pub fn ubi_ubifs_fixture() -> UbiFixture {
    let peb_size = 0x4000usize;
    let data_offset = 0x80usize;
    let mut image = vec![0xff; peb_size * 2];
    for peb in 0..2 {
        let start = peb * peb_size;
        image[start..start + 4].copy_from_slice(b"UBI#");
        image[start + 4] = 1;
        image[start + 5..start + 8].fill(0);
        image[start + 8..start + 16].copy_from_slice(&(peb as u64).to_be_bytes());
        image[start + 16..start + 20].copy_from_slice(&0x40u32.to_be_bytes());
        image[start + 20..start + 24].copy_from_slice(&(data_offset as u32).to_be_bytes());
        image[start + 24..start + 28].copy_from_slice(&0x1234_5678u32.to_be_bytes());
        image[start + 28..start + 60].fill(0);
        refresh_ubi_ec_crc(&mut image, start);
    }

    let ubifs_offset = data_offset;
    image[ubifs_offset..ubifs_offset + 4].copy_from_slice(&0x0610_1831u32.to_le_bytes());
    image[ubifs_offset + 8..ubifs_offset + 16].copy_from_slice(&1u64.to_le_bytes());
    image[ubifs_offset + 16..ubifs_offset + 20].copy_from_slice(&24u32.to_le_bytes());
    image[ubifs_offset + 20] = 6;
    image[ubifs_offset + 21] = 0;
    image[ubifs_offset + 22..ubifs_offset + 24].fill(0);
    let crc = linux_crc32(0xffff_ffff, &image[ubifs_offset + 8..ubifs_offset + 24]);
    image[ubifs_offset + 4..ubifs_offset + 8].copy_from_slice(&crc.to_le_bytes());

    UbiFixture {
        image,
        peb_size,
        ubifs_offset,
    }
}

fn refresh_ubi_ec_crc(image: &mut [u8], start: usize) {
    let crc = linux_crc32(0xffff_ffff, &image[start..start + 60]);
    image[start + 60..start + 64].copy_from_slice(&crc.to_be_bytes());
}

fn linux_crc32(mut crc: u32, bytes: &[u8]) -> u32 {
    for &byte in bytes {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xedb8_8320 & mask);
        }
    }
    crc
}

fn write_u16(image: &mut [u8], offset: usize, value: u16, endian: FixtureEndian) {
    let bytes = match endian {
        FixtureEndian::Little => value.to_le_bytes(),
        FixtureEndian::Big => value.to_be_bytes(),
    };
    image[offset..offset + 2].copy_from_slice(&bytes);
}

pub struct CramfsFixture {
    pub image: Vec<u8>,
    pub large_file: Vec<u8>,
    pub endian: FixtureEndian,
    pub root_start: usize,
    pub init_inode: usize,
    pub bin_inode: usize,
    pub empty_inode: usize,
    pub large_inode: usize,
    pub busybox_data: usize,
    pub large_data: usize,
}

impl CramfsFixture {
    pub fn set_flags(&mut self, flags: u32) {
        write_u32(&mut self.image, 8, flags, self.endian);
        self.refresh_crc();
    }

    pub fn set_declared_inode_count(&mut self, count: u32) {
        write_u32(&mut self.image, 44, count, self.endian);
        self.refresh_crc();
    }

    pub fn replace_init_name(&mut self, bytes: [u8; 4]) {
        self.image[self.init_inode + 12..self.init_inode + 16].copy_from_slice(&bytes);
        self.refresh_crc();
    }

    pub fn set_bin_directory_offset(&mut self, offset: usize) {
        set_inode_offset(&mut self.image, self.bin_inode, self.endian, offset);
        self.refresh_crc();
    }

    pub fn set_empty_mode(&mut self, mode: u16) {
        set_inode_mode(&mut self.image, self.empty_inode, self.endian, mode);
        self.refresh_crc();
    }

    pub fn set_large_size(&mut self, size: u32) {
        set_inode_size(&mut self.image, self.large_inode, self.endian, size);
        self.refresh_crc();
    }

    pub fn large_block_pointer(&self, index: usize) -> u32 {
        read_u32(&self.image, self.large_data + index * 4, self.endian)
    }

    pub fn set_large_block_pointer(&mut self, index: usize, pointer: u32) {
        write_u32(
            &mut self.image,
            self.large_data + index * 4,
            pointer,
            self.endian,
        );
        self.refresh_crc();
    }

    pub fn make_busybox_an_undeclared_hole(&mut self) {
        let table_end = self.busybox_data as u32 + 4;
        write_u32(&mut self.image, self.busybox_data, table_end, self.endian);
        self.refresh_crc();
    }

    pub fn corrupt_crc(&mut self) {
        self.image[32] ^= 0xff;
    }

    fn refresh_crc(&mut self) {
        refresh_crc(&mut self.image, self.endian);
    }
}

pub fn cramfs_fixture(endian: FixtureEndian) -> CramfsFixture {
    const SUPER_SIZE: usize = 76;
    const MODE_DIR: u16 = 0o040755;
    const MODE_FILE: u16 = 0o100644;
    const MODE_EXEC: u16 = 0o100755;
    const MODE_SYMLINK: u16 = 0o120777;

    let mut image = vec![0u8; SUPER_SIZE];
    let root_start = image.len();
    let init_inode = push_dir_entry(&mut image, "init");
    let bin_inode = push_dir_entry(&mut image, "bin");
    let etc_inode = push_dir_entry(&mut image, "etc");
    let empty_inode = push_dir_entry(&mut image, "empty");
    let large_inode = push_dir_entry(&mut image, "large.bin");
    let root_size = image.len() - root_start;

    let bin_start = image.len();
    let busybox_inode = push_dir_entry(&mut image, "busybox");
    let bin_size = image.len() - bin_start;

    let etc_start = image.len();
    let inittab_inode = push_dir_entry(&mut image, "inittab");
    let etc_size = image.len() - etc_start;
    align_four(&mut image);

    let init_target = b"bin/busybox";
    let init_data = append_file_data(&mut image, init_target, endian);
    let busybox = b"#!/bin/sh\necho busybox\n";
    let busybox_data = append_file_data(&mut image, busybox, endian);
    let inittab = b"::sysinit:/etc/init.d/rcS\n";
    let inittab_data = append_file_data(&mut image, inittab, endian);
    let large_file = (0..5_137)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let large_data = append_file_data(&mut image, &large_file, endian);

    write_inode(
        &mut image,
        64,
        endian,
        MODE_DIR,
        root_size as u32,
        0,
        root_start,
    );
    write_inode(
        &mut image,
        init_inode,
        endian,
        MODE_SYMLINK,
        init_target.len() as u32,
        padded_name_words("init"),
        init_data,
    );
    write_inode(
        &mut image,
        bin_inode,
        endian,
        MODE_DIR,
        bin_size as u32,
        padded_name_words("bin"),
        bin_start,
    );
    write_inode(
        &mut image,
        etc_inode,
        endian,
        MODE_DIR,
        etc_size as u32,
        padded_name_words("etc"),
        etc_start,
    );
    write_inode(
        &mut image,
        empty_inode,
        endian,
        MODE_FILE,
        0,
        padded_name_words("empty"),
        0,
    );
    write_inode(
        &mut image,
        large_inode,
        endian,
        MODE_FILE,
        large_file.len() as u32,
        padded_name_words("large.bin"),
        large_data,
    );
    write_inode(
        &mut image,
        busybox_inode,
        endian,
        MODE_EXEC,
        busybox.len() as u32,
        padded_name_words("busybox"),
        busybox_data,
    );
    write_inode(
        &mut image,
        inittab_inode,
        endian,
        MODE_FILE,
        inittab.len() as u32,
        padded_name_words("inittab"),
        inittab_data,
    );

    let image_size = image.len() as u32;
    write_u32(&mut image, 0, 0x28cd_3d45, endian);
    write_u32(&mut image, 4, image_size, endian);
    image[16..32].copy_from_slice(b"Compressed ROMFS");
    write_u32(&mut image, 8, 1, endian);
    write_u32(&mut image, 40, 1, endian);
    write_u32(&mut image, 44, 8, endian);
    image[48..56].copy_from_slice(b"fat-test");
    refresh_crc(&mut image, endian);

    CramfsFixture {
        image,
        large_file,
        endian,
        root_start,
        init_inode,
        bin_inode,
        empty_inode,
        large_inode,
        busybox_data,
        large_data,
    }
}

fn push_dir_entry(image: &mut Vec<u8>, name: &str) -> usize {
    let inode_offset = image.len();
    image.resize(image.len() + 12, 0);
    image.extend_from_slice(name.as_bytes());
    align_four(image);
    inode_offset
}

fn append_file_data(image: &mut Vec<u8>, data: &[u8], endian: FixtureEndian) -> usize {
    align_four(image);
    let table_offset = image.len();
    let block_count = data.len().div_ceil(4_096);
    image.resize(image.len() + block_count * 4, 0);

    for (index, block) in data.chunks(4_096).enumerate() {
        let mut encoder = ZlibEncoder::new(Vec::new(), Compression::default());
        encoder.write_all(block).expect("compress fixture block");
        let compressed = encoder.finish().expect("finish fixture block");
        image.extend_from_slice(&compressed);
        let block_end = image.len() as u32;
        write_u32(image, table_offset + index * 4, block_end, endian);
    }
    table_offset
}

fn write_inode(
    image: &mut [u8],
    offset: usize,
    endian: FixtureEndian,
    mode: u16,
    size: u32,
    name_words: u8,
    data_offset: usize,
) {
    assert_eq!(data_offset % 4, 0);
    let offset_words = (data_offset / 4) as u32;
    let (mode_uid, size_gid, name_offset) = match endian {
        FixtureEndian::Little => (
            u32::from(mode),
            size & 0x00ff_ffff,
            u32::from(name_words) | (offset_words << 6),
        ),
        FixtureEndian::Big => (
            u32::from(mode) << 16,
            (size & 0x00ff_ffff) << 8,
            (u32::from(name_words) << 26) | offset_words,
        ),
    };
    write_u32(image, offset, mode_uid, endian);
    write_u32(image, offset + 4, size_gid, endian);
    write_u32(image, offset + 8, name_offset, endian);
}

fn write_u32(image: &mut [u8], offset: usize, value: u32, endian: FixtureEndian) {
    let bytes = match endian {
        FixtureEndian::Little => value.to_le_bytes(),
        FixtureEndian::Big => value.to_be_bytes(),
    };
    image[offset..offset + 4].copy_from_slice(&bytes);
}

fn read_u32(image: &[u8], offset: usize, endian: FixtureEndian) -> u32 {
    let bytes: [u8; 4] = image[offset..offset + 4].try_into().expect("fixture u32");
    match endian {
        FixtureEndian::Little => u32::from_le_bytes(bytes),
        FixtureEndian::Big => u32::from_be_bytes(bytes),
    }
}

fn set_inode_mode(image: &mut [u8], offset: usize, endian: FixtureEndian, mode: u16) {
    let current = read_u32(image, offset, endian);
    let updated = match endian {
        FixtureEndian::Little => (current & 0xffff_0000) | u32::from(mode),
        FixtureEndian::Big => (current & 0x0000_ffff) | (u32::from(mode) << 16),
    };
    write_u32(image, offset, updated, endian);
}

fn set_inode_size(image: &mut [u8], offset: usize, endian: FixtureEndian, size: u32) {
    let current = read_u32(image, offset + 4, endian);
    let updated = match endian {
        FixtureEndian::Little => (current & 0xff00_0000) | (size & 0x00ff_ffff),
        FixtureEndian::Big => (current & 0x0000_00ff) | ((size & 0x00ff_ffff) << 8),
    };
    write_u32(image, offset + 4, updated, endian);
}

fn set_inode_offset(image: &mut [u8], offset: usize, endian: FixtureEndian, data_offset: usize) {
    assert_eq!(data_offset % 4, 0);
    let current = read_u32(image, offset + 8, endian);
    let offset_words = (data_offset / 4) as u32;
    let updated = match endian {
        FixtureEndian::Little => (current & 0x3f) | (offset_words << 6),
        FixtureEndian::Big => (current & 0xfc00_0000) | offset_words,
    };
    write_u32(image, offset + 8, updated, endian);
}

fn refresh_crc(image: &mut [u8], endian: FixtureEndian) {
    write_u32(image, 32, 0, endian);
    let crc = crc32fast::hash(image);
    write_u32(image, 32, crc, endian);
}

fn padded_name_words(name: &str) -> u8 {
    name.len().div_ceil(4) as u8
}

fn align_four(bytes: &mut Vec<u8>) {
    while !bytes.len().is_multiple_of(4) {
        bytes.push(0);
    }
}
