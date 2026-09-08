use serde::Serialize;
use std::error::Error;
use std::fs;
use std::path::Path;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Serialize)]
pub struct ElfInspectReport {
    pub header: ElfHeaderSummary,
    pub sections: Vec<ElfSectionSummary>,
    pub program_headers: Vec<ElfProgramHeaderSummary>,
    pub dynamic: Option<ElfDynamicSummary>,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfHeaderSummary {
    pub class: String,
    pub endianness: String,
    pub file_type: String,
    pub machine: String,
    pub entry_point: u64,
    pub program_header_count: u16,
    pub section_header_count: u16,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfSectionSummary {
    pub name: String,
    pub offset: u64,
    pub virtual_address: u64,
    pub size: u64,
    pub section_type: String,
    pub flags: String,
    pub role: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfProgramHeaderSummary {
    pub segment_type: String,
    pub offset: u64,
    pub virtual_address: u64,
    pub file_size: u64,
    pub memory_size: u64,
    pub flags: String,
    pub align: u64,
}

#[derive(Debug, Clone, Serialize)]
pub struct ElfDynamicSummary {
    pub soname: Option<String>,
    pub needed: Vec<String>,
    pub rpath: Option<String>,
    pub runpath: Option<String>,
    pub unknown_flags: Vec<String>,
}

#[derive(Debug, Clone, Copy)]
enum ElfClass {
    Elf32,
    Elf64,
}

#[derive(Debug, Clone, Copy)]
enum Endianness {
    Little,
    Big,
}

#[derive(Debug, Clone)]
struct SectionHeader {
    name_offset: u32,
    section_type: u32,
    flags: u64,
    address: u64,
    offset: u64,
    size: u64,
    link: u32,
    _info: u32,
}

#[derive(Debug, Clone, Copy)]
struct ProgramHeader {
    segment_type: u32,
    flags: u64,
    offset: u64,
    virtual_address: u64,
    file_size: u64,
    memory_size: u64,
    align: u64,
}

pub fn parse_elf_file(path: &Path) -> DynResult<ElfInspectReport> {
    let bytes = fs::read(path)?;
    parse_elf_bytes(&bytes).map_err(Into::into)
}

pub fn parse_elf_bytes(bytes: &[u8]) -> Result<ElfInspectReport, String> {
    if bytes.len() < 64 || &bytes[..4] != b"\x7fELF" {
        return Err("not an ELF file".into());
    }

    let class = match bytes[4] {
        1 => ElfClass::Elf32,
        2 => ElfClass::Elf64,
        other => return Err(format!("unsupported ELF class: {other}")),
    };

    let endianness = match bytes[5] {
        1 => Endianness::Little,
        2 => Endianness::Big,
        other => return Err(format!("unsupported ELF endianness: {other}")),
    };

    let (
        file_type,
        machine,
        entry_point,
        program_header_count,
        section_header_count,
        section_headers,
        shstrndx,
        program_headers,
    ) = match class {
        ElfClass::Elf32 => parse_elf32(bytes, endianness)?,
        ElfClass::Elf64 => parse_elf64(bytes, endianness)?,
    };

    let section_names = resolve_section_names(bytes, &section_headers, shstrndx as usize)?;
    let dynamic = extract_dynamic_info(bytes, &section_headers, endianness, class);
    let sections = section_headers
        .into_iter()
        .zip(section_names)
        .filter(|(_, name)| !name.is_empty())
        .map(|(section, name)| ElfSectionSummary {
            role: classify_section_role(&name),
            flags: render_flags(section.flags),
            section_type: render_section_type(section.section_type),
            name,
            offset: section.offset,
            virtual_address: section.address,
            size: section.size,
        })
        .collect();

    Ok(ElfInspectReport {
        header: ElfHeaderSummary {
            class: match class {
                ElfClass::Elf32 => "ELF32".into(),
                ElfClass::Elf64 => "ELF64".into(),
            },
            endianness: match endianness {
                Endianness::Little => "little-endian".into(),
                Endianness::Big => "big-endian".into(),
            },
            file_type: render_file_type(file_type),
            machine: render_machine(machine),
            entry_point,
            program_header_count,
            section_header_count,
        },
        sections,
        program_headers,
        dynamic,
    })
}

pub fn render_headers(report: &ElfInspectReport) -> String {
    let header = &report.header;
    let mut output = String::new();
    output.push_str("ELF header\n");
    output.push_str(&format!("- File type: {}\n", header.file_type));
    output.push_str(&format!("- Class: {}\n", header.class));
    output.push_str(&format!("- Endianness: {}\n", header.endianness));
    output.push_str(&format!("- Machine: {}\n", header.machine));
    output.push_str(&format!("- Entry point: 0x{:016X}\n", header.entry_point));
    output.push_str(&format!(
        "- Program headers: {}\n",
        header.program_header_count
    ));
    output.push_str(&format!(
        "- Section headers: {}\n",
        header.section_header_count
    ));

    if let Some(dynamic) = &report.dynamic {
        if let Some(soname) = &dynamic.soname {
            output.push_str(&format!("- SONAME: {soname}\n"));
        }
        if !dynamic.needed.is_empty() {
            output.push_str(&format!(
                "- Needed libraries: {}\n",
                dynamic.needed.join(", ")
            ));
        }
        if let Some(rpath) = &dynamic.rpath {
            output.push_str(&format!("- RPATH: {rpath}\n"));
        }
        if let Some(runpath) = &dynamic.runpath {
            output.push_str(&format!("- RUNPATH: {runpath}\n"));
        }
    }
    output
}

pub fn render_layout(report: &ElfInspectReport) -> String {
    let mut output = String::new();
    let code_sections = report
        .sections
        .iter()
        .filter(|section| matches!(section.role.as_str(), "code" | "linkage"))
        .count();
    let writable_sections = report
        .sections
        .iter()
        .filter(|section| section.flags.contains('W'))
        .count();

    output.push_str("ELF layout summary\n");
    output.push_str(&format!("- Sections: {}\n", report.sections.len()));
    output.push_str(&format!("- Code/linkage sections: {code_sections}\n"));
    output.push_str(&format!("- Writable sections: {writable_sections}\n\n"));
    output.push_str("ELF sections\n");
    output.push_str("| Offset | VAddr | Section | Type | Size | Flags | Role |\n");
    output.push_str("| --- | --- | --- | --- | --- | --- | --- |\n");
    for section in &report.sections {
        output.push_str(&format!(
            "| 0x{:08X} | 0x{:08X} | {} | {} | {} bytes | {} | {} |\n",
            section.offset,
            section.virtual_address,
            section.name,
            section.section_type,
            section.size,
            if section.flags.is_empty() {
                "-".to_string()
            } else {
                section.flags.clone()
            },
            section.role
        ));
    }

    if !report.program_headers.is_empty() {
        output.push_str("\nELF program headers\n");
        output.push_str("| Offset | VAddr | Filesz | Memsz | Flags | Type |\n");
        output.push_str("| --- | --- | --- | --- | --- | --- |\n");
        for program_header in &report.program_headers {
            output.push_str(&format!(
                "| 0x{:08X} | 0x{:08X} | {} | {} | {} | {} |\n",
                program_header.offset,
                program_header.virtual_address,
                program_header.file_size,
                program_header.memory_size,
                program_header.flags,
                program_header.segment_type
            ));
        }
    }
    output
}

fn parse_elf32(
    bytes: &[u8],
    endianness: Endianness,
) -> Result<
    (
        u16,
        u16,
        u64,
        u16,
        u16,
        Vec<SectionHeader>,
        u16,
        Vec<ElfProgramHeaderSummary>,
    ),
    String,
> {
    let file_type = read_u16(bytes, 16, endianness)?;
    let machine = read_u16(bytes, 18, endianness)?;
    let entry_point = read_u32(bytes, 24, endianness)? as u64;
    let section_headers_offset = read_u32(bytes, 32, endianness)? as usize;
    let program_header_count = read_u16(bytes, 44, endianness)?;
    let section_header_size = read_u16(bytes, 46, endianness)? as usize;
    let section_header_count = read_u16(bytes, 48, endianness)?;
    let shstrndx = read_u16(bytes, 50, endianness)?;

    let sections = parse_section_headers_32(
        bytes,
        section_headers_offset,
        section_header_size,
        section_header_count as usize,
        endianness,
    )?;
    let program_headers = parse_program_headers_32(
        bytes,
        read_u32(bytes, 28, endianness)? as usize,
        read_u16(bytes, 42, endianness)? as usize,
        read_u16(bytes, 44, endianness)? as usize,
        endianness,
    )?;

    Ok((
        file_type,
        machine,
        entry_point,
        program_header_count,
        section_header_count,
        sections,
        shstrndx,
        program_headers,
    ))
}

fn parse_elf64(
    bytes: &[u8],
    endianness: Endianness,
) -> Result<
    (
        u16,
        u16,
        u64,
        u16,
        u16,
        Vec<SectionHeader>,
        u16,
        Vec<ElfProgramHeaderSummary>,
    ),
    String,
> {
    let file_type = read_u16(bytes, 16, endianness)?;
    let machine = read_u16(bytes, 18, endianness)?;
    let entry_point = read_u64(bytes, 24, endianness)?;
    let section_headers_offset = read_u64(bytes, 40, endianness)? as usize;
    let program_header_count = read_u16(bytes, 56, endianness)?;
    let section_header_size = read_u16(bytes, 58, endianness)? as usize;
    let section_header_count = read_u16(bytes, 60, endianness)?;
    let shstrndx = read_u16(bytes, 62, endianness)?;

    let sections = parse_section_headers_64(
        bytes,
        section_headers_offset,
        section_header_size,
        section_header_count as usize,
        endianness,
    )?;
    let program_headers = parse_program_headers_64(
        bytes,
        read_u64(bytes, 32, endianness)? as usize,
        read_u16(bytes, 54, endianness)? as usize,
        read_u16(bytes, 56, endianness)? as usize,
        endianness,
    )?;

    Ok((
        file_type,
        machine,
        entry_point,
        program_header_count,
        section_header_count,
        sections,
        shstrndx,
        program_headers,
    ))
}

fn parse_section_headers_32(
    bytes: &[u8],
    offset: usize,
    entry_size: usize,
    count: usize,
    endianness: Endianness,
) -> Result<Vec<SectionHeader>, String> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let base = offset + index * entry_size;
        sections.push(SectionHeader {
            name_offset: read_u32(bytes, base, endianness)?,
            section_type: read_u32(bytes, base + 4, endianness)?,
            flags: read_u32(bytes, base + 8, endianness)? as u64,
            address: read_u32(bytes, base + 12, endianness)? as u64,
            offset: read_u32(bytes, base + 16, endianness)? as u64,
            size: read_u32(bytes, base + 20, endianness)? as u64,
            link: read_u32(bytes, base + 24, endianness)?,
            _info: read_u32(bytes, base + 28, endianness)?,
        });
    }
    Ok(sections)
}

fn parse_section_headers_64(
    bytes: &[u8],
    offset: usize,
    entry_size: usize,
    count: usize,
    endianness: Endianness,
) -> Result<Vec<SectionHeader>, String> {
    let mut sections = Vec::with_capacity(count);
    for index in 0..count {
        let base = offset + index * entry_size;
        sections.push(SectionHeader {
            name_offset: read_u32(bytes, base, endianness)?,
            section_type: read_u32(bytes, base + 4, endianness)?,
            flags: read_u64(bytes, base + 8, endianness)?,
            address: read_u64(bytes, base + 16, endianness)?,
            offset: read_u64(bytes, base + 24, endianness)?,
            size: read_u64(bytes, base + 32, endianness)?,
            link: read_u32(bytes, base + 40, endianness)?,
            _info: read_u32(bytes, base + 44, endianness)?,
        });
    }
    Ok(sections)
}

fn parse_program_headers_32(
    bytes: &[u8],
    offset: usize,
    entry_size: usize,
    count: usize,
    endianness: Endianness,
) -> Result<Vec<ElfProgramHeaderSummary>, String> {
    if entry_size == 0 {
        return Err("invalid ELF32 program header entry size".into());
    }

    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let base = offset + index * entry_size;
        if base + 32 > bytes.len() {
            return Err(format!("ELF program header out of range at {base:#x}"));
        }
        let segment_type = read_u32(bytes, base, endianness)?;
        let flags = read_u32(bytes, base + 24, endianness)? as u64;
        let ph = ProgramHeader {
            segment_type,
            flags,
            offset: read_u32(bytes, base + 4, endianness)? as u64,
            virtual_address: read_u32(bytes, base + 8, endianness)? as u64,
            file_size: read_u32(bytes, base + 16, endianness)? as u64,
            memory_size: read_u32(bytes, base + 20, endianness)? as u64,
            align: read_u32(bytes, base + 28, endianness)? as u64,
        };
        headers.push(render_program_header(&ph));
    }
    Ok(headers)
}

fn parse_program_headers_64(
    bytes: &[u8],
    offset: usize,
    entry_size: usize,
    count: usize,
    endianness: Endianness,
) -> Result<Vec<ElfProgramHeaderSummary>, String> {
    if entry_size == 0 {
        return Err("invalid ELF64 program header entry size".into());
    }

    let mut headers = Vec::with_capacity(count);
    for index in 0..count {
        let base = offset + index * entry_size;
        if base + 56 > bytes.len() {
            return Err(format!("ELF program header out of range at {base:#x}"));
        }
        let segment_type = read_u32(bytes, base, endianness)?;
        let ph = ProgramHeader {
            segment_type,
            flags: read_u32(bytes, base + 4, endianness)? as u64,
            offset: read_u64(bytes, base + 8, endianness)?,
            virtual_address: read_u64(bytes, base + 16, endianness)?,
            file_size: read_u64(bytes, base + 32, endianness)?,
            memory_size: read_u64(bytes, base + 40, endianness)?,
            align: read_u64(bytes, base + 48, endianness)?,
        };
        headers.push(render_program_header(&ph));
    }
    Ok(headers)
}

fn render_program_header(header: &ProgramHeader) -> ElfProgramHeaderSummary {
    ElfProgramHeaderSummary {
        segment_type: render_program_header_type(header.segment_type),
        offset: header.offset,
        virtual_address: header.virtual_address,
        file_size: header.file_size,
        memory_size: header.memory_size,
        flags: render_program_flags(header.flags),
        align: header.align,
    }
}

fn extract_dynamic_info(
    bytes: &[u8],
    sections: &[SectionHeader],
    endianness: Endianness,
    class: ElfClass,
) -> Option<ElfDynamicSummary> {
    let dynamic_section = sections.iter().find(|section| section.section_type == 6)?;
    if dynamic_section.size == 0 {
        return Some(ElfDynamicSummary {
            soname: None,
            needed: Vec::new(),
            rpath: None,
            runpath: None,
            unknown_flags: Vec::new(),
        });
    }

    let dynstr = sections
        .get(dynamic_section.link as usize)
        .filter(|s| s.section_type == 3)
        .and_then(|s| {
            let start = s.offset as usize;
            let end = start.checked_add(s.size as usize)?;
            bytes.get(start..end)
        });
    let dyn_data = {
        let start = dynamic_section.offset as usize;
        let end = start.checked_add(dynamic_section.size as usize)?;
        bytes.get(start..end).unwrap_or(&[])
    };

    let entry_size = match class {
        ElfClass::Elf32 => 8,
        ElfClass::Elf64 => 16,
    };

    let mut needed = Vec::new();
    let mut soname = None;
    let mut rpath = None;
    let mut runpath = None;
    let mut unknown_flags = Vec::new();

    let entries = dyn_data.len() / entry_size;
    for index in 0..entries {
        let base = index * entry_size;
        let (tag, value) = match class {
            ElfClass::Elf32 => {
                let tag = i64::from(
                    read_i32(bytes, dynamic_section.offset as usize + base, endianness).ok()?,
                );
                let value = i64::from(
                    read_u32(
                        bytes,
                        dynamic_section.offset as usize + base + 4,
                        endianness,
                    )
                    .ok()?,
                );
                (tag, value)
            }
            ElfClass::Elf64 => (
                read_i64(bytes, dynamic_section.offset as usize + base, endianness).ok()?,
                read_i64(
                    bytes,
                    dynamic_section.offset as usize + base + 8,
                    endianness,
                )
                .ok()?,
            ),
        };

        match tag {
            1 => {
                if let Some(string) = dynstr {
                    if let Some(name) = read_dyn_string(string, value as usize) {
                        needed.push(name);
                    }
                }
            }
            14 => {
                if let Some(string) = dynstr {
                    soname = read_dyn_string(string, value as usize);
                }
            }
            15 => {
                if let Some(string) = dynstr {
                    rpath = read_dyn_string(string, value as usize);
                }
            }
            29 => {
                if let Some(string) = dynstr {
                    runpath = read_dyn_string(string, value as usize);
                }
            }
            0 => {}
            _ => {
                if unknown_flags.len() < 32 {
                    unknown_flags.push(render_dynamic_tag_name(tag));
                }
            }
        }
    }

    Some(ElfDynamicSummary {
        soname,
        needed,
        rpath,
        runpath,
        unknown_flags,
    })
}

fn render_dynamic_tag_name(tag: i64) -> String {
    match tag {
        0 => "DT_NULL".into(),
        1 => "DT_NEEDED".into(),
        2 => "DT_PLTRELSZ".into(),
        3 => "DT_PLTGOT".into(),
        4 => "DT_HASH".into(),
        5 => "DT_STRTAB".into(),
        6 => "DT_SYMTAB".into(),
        7 => "DT_RELA".into(),
        8 => "DT_RELASZ".into(),
        9 => "DT_RELAENT".into(),
        10 => "DT_STRSZ".into(),
        11 => "DT_SYMENT".into(),
        12 => "DT_INIT".into(),
        13 => "DT_FINI".into(),
        14 => "DT_SONAME".into(),
        15 => "DT_RPATH".into(),
        16 => "DT_SYMBOLIC".into(),
        17 => "DT_REL".into(),
        18 => "DT_RELSZ".into(),
        19 => "DT_RELENT".into(),
        20 => "DT_PLTREL".into(),
        21 => "DT_DEBUG".into(),
        22 => "DT_TEXTREL".into(),
        23 => "DT_JMPREL".into(),
        29 => "DT_RUNPATH".into(),
        30 => "DT_FLAGS".into(),
        32 => "DT_PREINIT_ARRAY".into(),
        33 => "DT_PREINIT_ARRAYSZ".into(),
        34 => "DT_SYMTAB_SHNDX".into(),
        0x6ffffef5 => "DT_FLAGS_1".into(),
        0x6ffffffb => "DT_RELACOUNT".into(),
        0x6ffffffc => "DT_RELCOUNT".into(),
        0x6ffffffd => "DT_FLAGS_1".into(),
        0x6ffffffe => "DT_VERNEED".into(),
        0x6fffffff => "DT_VERNEEDNUM".into(),
        0x7ffffff0 => "DT_VERSYM".into(),
        other => format!("DT_UNKNOWN_{other}"),
    }
}

fn render_program_header_type(segment_type: u32) -> String {
    match segment_type {
        0 => "NULL".into(),
        1 => "LOAD".into(),
        2 => "DYNAMIC".into(),
        3 => "INTERP".into(),
        4 => "NOTE".into(),
        5 => "SHLIB".into(),
        6 => "PHDR".into(),
        7 => "TLS".into(),
        0x70000000 => "LOPROC".into(),
        0x7fffffff => "HIPROC".into(),
        other => format!("PT_{other}"),
    }
}

fn render_program_flags(flags: u64) -> String {
    let mut rendered = String::new();
    if flags & 0x1 != 0 {
        rendered.push('X');
    }
    if flags & 0x2 != 0 {
        rendered.push('W');
    }
    if flags & 0x4 != 0 {
        rendered.push('R');
    }
    rendered
}

fn read_dyn_string(dynstr: &[u8], offset: usize) -> Option<String> {
    if offset >= dynstr.len() {
        return None;
    }
    let tail = dynstr.get(offset..)?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    if end == 0 {
        return None;
    }
    Some(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn resolve_section_names(
    bytes: &[u8],
    sections: &[SectionHeader],
    shstrndx: usize,
) -> Result<Vec<String>, String> {
    let Some(name_table_header) = sections.get(shstrndx) else {
        return Err("ELF section header string table index is out of range".into());
    };
    let start = name_table_header.offset as usize;
    let end = start + name_table_header.size as usize;
    let table = bytes
        .get(start..end)
        .ok_or("ELF section header string table is out of range")?;

    sections
        .iter()
        .map(|section| read_c_string(table, section.name_offset as usize))
        .collect()
}

fn read_c_string(bytes: &[u8], offset: usize) -> Result<String, String> {
    let tail = bytes
        .get(offset..)
        .ok_or_else(|| format!("string table offset out of range: {offset}"))?;
    let end = tail
        .iter()
        .position(|byte| *byte == 0)
        .unwrap_or(tail.len());
    Ok(String::from_utf8_lossy(&tail[..end]).into_owned())
}

fn render_file_type(value: u16) -> String {
    match value {
        1 => "relocatable".into(),
        2 => "executable".into(),
        3 => "shared object".into(),
        4 => "core".into(),
        other => format!("unknown ({other})"),
    }
}

fn render_machine(value: u16) -> String {
    match value {
        3 => "x86".into(),
        8 => "mips".into(),
        40 => "arm".into(),
        62 => "x86-64".into(),
        183 => "aarch64".into(),
        other => format!("machine-{other}"),
    }
}

fn render_section_type(value: u32) -> String {
    match value {
        0 => "NULL".into(),
        1 => "PROGBITS".into(),
        3 => "STRTAB".into(),
        6 => "DYNAMIC".into(),
        8 => "NOBITS".into(),
        9 => "REL".into(),
        11 => "DYNSYM".into(),
        4 => "RELA".into(),
        other => format!("TYPE-{other}"),
    }
}

fn render_flags(flags: u64) -> String {
    let mut rendered = String::new();
    if flags & 0x1 != 0 {
        rendered.push('W');
    }
    if flags & 0x2 != 0 {
        rendered.push('A');
    }
    if flags & 0x4 != 0 {
        rendered.push('X');
    }
    rendered
}

fn classify_section_role(name: &str) -> String {
    match name {
        ".text" | ".init" | ".fini" => "code".into(),
        ".plt" | ".got" | ".got.plt" => "linkage".into(),
        ".dynamic" => "dynamic-link".into(),
        ".rodata" => "readonly-data".into(),
        ".data" | ".bss" => "writable-data".into(),
        ".dynsym" | ".dynstr" | ".shstrtab" | ".strtab" | ".symtab" => "metadata".into(),
        _ => "section".into(),
    }
}

fn read_u16(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u16, String> {
    let slice = bytes
        .get(offset..offset + 2)
        .ok_or_else(|| format!("ELF read out of range at {offset:#x}"))?;
    let raw = [slice[0], slice[1]];
    Ok(match endianness {
        Endianness::Little => u16::from_le_bytes(raw),
        Endianness::Big => u16::from_be_bytes(raw),
    })
}

fn read_u32(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u32, String> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("ELF read out of range at {offset:#x}"))?;
    let raw = [slice[0], slice[1], slice[2], slice[3]];
    Ok(match endianness {
        Endianness::Little => u32::from_le_bytes(raw),
        Endianness::Big => u32::from_be_bytes(raw),
    })
}

fn read_i32(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<i32, String> {
    let slice = bytes
        .get(offset..offset + 4)
        .ok_or_else(|| format!("ELF read out of range at {offset:#x}"))?;
    let raw = [slice[0], slice[1], slice[2], slice[3]];
    Ok(match endianness {
        Endianness::Little => i32::from_le_bytes(raw),
        Endianness::Big => i32::from_be_bytes(raw),
    })
}

fn read_i64(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<i64, String> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| format!("ELF read out of range at {offset:#x}"))?;
    let raw = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Ok(match endianness {
        Endianness::Little => i64::from_le_bytes(raw),
        Endianness::Big => i64::from_be_bytes(raw),
    })
}

fn read_u64(bytes: &[u8], offset: usize, endianness: Endianness) -> Result<u64, String> {
    let slice = bytes
        .get(offset..offset + 8)
        .ok_or_else(|| format!("ELF read out of range at {offset:#x}"))?;
    let raw = [
        slice[0], slice[1], slice[2], slice[3], slice[4], slice[5], slice[6], slice[7],
    ];
    Ok(match endianness {
        Endianness::Little => u64::from_le_bytes(raw),
        Endianness::Big => u64::from_be_bytes(raw),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_section_role_recognizes_common_elf_regions() {
        assert_eq!(classify_section_role(".text"), "code");
        assert_eq!(classify_section_role(".plt"), "linkage");
        assert_eq!(classify_section_role(".dynamic"), "dynamic-link");
        assert_eq!(classify_section_role(".shstrtab"), "metadata");
    }

    #[test]
    fn parse_elf32_section_headers_preserves_virtual_address() {
        let mut bytes = vec![0u8; 0x400];
        bytes[0..4].copy_from_slice(b"\x7fELF");
        bytes[4] = 1; // ELF32
        bytes[5] = 1; // little-endian
        bytes[16..18].copy_from_slice(&2u16.to_le_bytes()); // executable
        bytes[18..20].copy_from_slice(&8u16.to_le_bytes()); // mips
        bytes[24..28].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[28..32].copy_from_slice(&0x34u32.to_le_bytes()); // phoff
        bytes[32..36].copy_from_slice(&0x100u32.to_le_bytes()); // shoff
        bytes[42..44].copy_from_slice(&32u16.to_le_bytes()); // phentsize
        bytes[44..46].copy_from_slice(&1u16.to_le_bytes()); // phnum
        bytes[46..48].copy_from_slice(&40u16.to_le_bytes()); // shentsize
        bytes[48..50].copy_from_slice(&3u16.to_le_bytes()); // shnum
        bytes[50..52].copy_from_slice(&2u16.to_le_bytes()); // shstrndx

        // LOAD0 program header.
        bytes[0x34..0x38].copy_from_slice(&1u32.to_le_bytes());
        bytes[0x38..0x3c].copy_from_slice(&0u32.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&0x400000u32.to_le_bytes());
        bytes[0x44..0x48].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x48..0x4c].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[0x4c..0x50].copy_from_slice(&5u32.to_le_bytes()); // PF_R | PF_X
        bytes[0x50..0x54].copy_from_slice(&0x1000u32.to_le_bytes());

        // .text section.
        let text = 0x100 + 40;
        bytes[text..text + 4].copy_from_slice(&1u32.to_le_bytes()); // name offset
        bytes[text + 4..text + 8].copy_from_slice(&1u32.to_le_bytes()); // PROGBITS
        bytes[text + 8..text + 12].copy_from_slice(&6u32.to_le_bytes()); // SHF_ALLOC | SHF_EXECINSTR
        bytes[text + 12..text + 16].copy_from_slice(&0x401000u32.to_le_bytes()); // sh_addr
        bytes[text + 16..text + 20].copy_from_slice(&0x200u32.to_le_bytes());
        bytes[text + 20..text + 24].copy_from_slice(&0x20u32.to_le_bytes());

        // .shstrtab section.
        let shstr = 0x100 + 80;
        bytes[shstr..shstr + 4].copy_from_slice(&7u32.to_le_bytes()); // name offset
        bytes[shstr + 4..shstr + 8].copy_from_slice(&3u32.to_le_bytes()); // STRTAB
        bytes[shstr + 16..shstr + 20].copy_from_slice(&0x300u32.to_le_bytes());
        bytes[shstr + 20..shstr + 24].copy_from_slice(&17u32.to_le_bytes());
        bytes[0x300..0x311].copy_from_slice(b"\0.text\0.shstrtab\0");

        let report = parse_elf_bytes(&bytes).expect("synthetic ELF parses");
        let text_section = report
            .sections
            .iter()
            .find(|section| section.name == ".text")
            .expect(".text section present");

        assert_eq!(text_section.virtual_address, 0x401000);
    }
}
