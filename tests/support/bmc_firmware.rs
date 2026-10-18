#![allow(dead_code)]

/// Small synthetic FIT with explicit bytes, independent of FAT's parser.
pub fn fit(signed_configuration: bool) -> Vec<u8> {
    let mut builder = Fdt::default();
    builder.node("");
    builder.property("description", b"OpenBMC synthetic test image\0");
    builder.node("images");
    builder.node("kernel-1");
    builder.property("data", b"kernel payload");
    builder.node("hash-1");
    builder.property("algo", b"sha256\0");
    builder.property("value", &[0x42; 32]);
    builder.end();
    builder.end();
    builder.end();
    builder.node("configurations");
    builder.property("default", b"conf-1\0");
    builder.node("conf-1");
    builder.property("kernel", b"kernel-1\0");
    // Real OpenBMC FITs retain this algorithm declaration without a digest.
    builder.node("hash@1");
    builder.property("algo", b"sha256\0");
    builder.end();
    if signed_configuration {
        builder.node("signature-1");
        builder.property("algo", b"sha256,rsa2048\0");
        builder.property("key-name-hint", b"test-key\0");
        builder.property("value", &[0x55; 256]);
        builder.end();
    }
    builder.end();
    builder.end();
    builder.end();
    builder.finish()
}

#[derive(Default)]
struct Fdt {
    structure: Vec<u8>,
    strings: Vec<u8>,
}
impl Fdt {
    fn word(&mut self, value: u32) {
        self.structure.extend(value.to_be_bytes());
    }
    fn align(&mut self) {
        while !self.structure.len().is_multiple_of(4) {
            self.structure.push(0);
        }
    }
    fn node(&mut self, name: &str) {
        self.word(1);
        self.structure.extend(name.as_bytes());
        self.structure.push(0);
        self.align();
    }
    fn end(&mut self) {
        self.word(2);
    }
    fn property(&mut self, name: &str, value: &[u8]) {
        self.word(3);
        self.word(value.len() as u32);
        self.word(self.strings.len() as u32);
        self.strings.extend(name.as_bytes());
        self.strings.push(0);
        self.structure.extend(value);
        self.align();
    }
    fn finish(mut self) -> Vec<u8> {
        self.word(9);
        let strings_offset = 56 + self.structure.len();
        let total = strings_offset + self.strings.len();
        let mut bytes = Vec::new();
        for value in [
            0xd00dfeed,
            total as u32,
            56,
            strings_offset as u32,
            40,
            17,
            16,
            0,
            self.strings.len() as u32,
            self.structure.len() as u32,
        ] {
            bytes.extend(value.to_be_bytes());
        }
        bytes.extend([0; 16]);
        bytes.extend(self.structure);
        bytes.extend(self.strings);
        bytes
    }
}

pub fn environment() -> Vec<u8> {
    let mut bytes = vec![0xff; 4096];
    let vars = b"verify=no\0bootcmd=bootm 0x80000\0\0";
    bytes[4..4 + vars.len()].copy_from_slice(vars);
    let crc = crc32fast::hash(&bytes[4..]);
    bytes[..4].copy_from_slice(&crc.to_le_bytes());
    bytes
}
