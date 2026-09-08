//! Decompiled C cleanup — strip Ghidra intrinsics so CDT/c2cpg can parse the output.
//!
//! Ghidra's decompiled C contains non-standard constructs that Eclipse CDT chokes on:
//! - SUB84(), CONCAT44(), ZEXT816() type-casting intrinsics
//! - Undefined types (undefined4, undefined8, etc.)
//! - Non-standard pointer cast syntax
//!
//! This module rewrites decompiled .c files into parseable C.

use regex::Regex;
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum CleanError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

/// Clean a single decompiled C file in-place.
pub fn clean_decompiled_c(path: &Path) -> Result<(), CleanError> {
    let content = std::fs::read_to_string(path)?;
    let cleaned = clean_source(&content);
    std::fs::write(path, cleaned)?;
    Ok(())
}

/// Clean decompiled C source string.
pub fn clean_source(source: &str) -> String {
    let mut out = source.to_string();

    // 1. Replace Ghidra undefined types with standard C types
    out = out.replace("undefined8", "uint64_t");
    out = out.replace("undefined4", "uint32_t");
    out = out.replace("undefined2", "uint16_t");
    out = out.replace("undefined1", "uint8_t");
    out = out.replace("undefined", "uint8_t");

    // 2. Replace SUBxy() intrinsics — SUB84(x) extracts lower bytes
    //    SUB84(x) → (uint32_t)(x)
    //    SUB42(x) → (uint16_t)(x)
    //    SUB81(x) → (uint8_t)(x)
    let sub_re = Regex::new(r"SUB(\d)(\d)\(([^)]+)\)").unwrap();
    out = sub_re
        .replace_all(&out, |caps: &regex::Captures| {
            let target_size: u32 = caps[2].parse().unwrap_or(4);
            let expr = &caps[3];
            let type_name = match target_size {
                1 => "uint8_t",
                2 => "uint16_t",
                4 => "uint32_t",
                8 => "uint64_t",
                _ => "uint32_t",
            };
            format!("({type_name})({expr})")
        })
        .into_owned();

    // 3. Replace CONCAT intrinsics — CONCAT44(hi, lo) concatenates values
    //    CONCAT44(a, b) → ((uint64_t)(a) << 32 | (uint32_t)(b))
    let concat_re = Regex::new(r"CONCAT(\d)(\d)\(([^,]+),\s*([^)]+)\)").unwrap();
    out = concat_re
        .replace_all(&out, |caps: &regex::Captures| {
            let hi_size: u32 = caps[1].parse().unwrap_or(4);
            let hi = caps[3].trim();
            let lo = caps[4].trim();
            let shift = hi_size * 8;
            format!("((uint64_t)({hi}) << {shift} | (uint32_t)({lo}))")
        })
        .into_owned();

    // 4. Replace ZEXT intrinsics — ZEXT816(x) zero-extends
    //    ZEXT816(x) → (uint64_t)(uint16_t)(x)
    let zext_re = Regex::new(r"ZEXT(\d)(\d+)\(([^)]+)\)").unwrap();
    out = zext_re
        .replace_all(&out, |caps: &regex::Captures| {
            let target_size: u32 = caps[2].parse().unwrap_or(8);
            let expr = &caps[3];
            let type_name = match target_size {
                16 | 8 => "uint64_t",
                4 => "uint32_t",
                2 => "uint16_t",
                _ => "uint64_t",
            };
            format!("({type_name})({expr})")
        })
        .into_owned();

    // 5. Replace SEXT intrinsics — sign extension
    let sext_re = Regex::new(r"SEXT(\d)(\d+)\(([^)]+)\)").unwrap();
    out = sext_re
        .replace_all(&out, |caps: &regex::Captures| {
            let target_size: u32 = caps[2].parse().unwrap_or(8);
            let expr = &caps[3];
            let type_name = match target_size {
                16 | 8 => "int64_t",
                4 => "int32_t",
                2 => "int16_t",
                _ => "int64_t",
            };
            format!("({type_name})({expr})")
        })
        .into_owned();

    // 6. Add standard headers if not present
    if !out.contains("#include <stdint.h>") {
        out = format!("#include <stdint.h>\n#include <stdlib.h>\n#include <string.h>\n\n{out}");
    }

    out
}

/// Clean all .c files in a directory.
pub fn clean_all(dir: &Path) -> Result<usize, CleanError> {
    let mut count = 0;
    for entry in walkdir::WalkDir::new(dir)
        .into_iter()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().extension().map(|ext| ext == "c").unwrap_or(false))
    {
        clean_decompiled_c(entry.path())?;
        count += 1;
    }
    Ok(count)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_replace_undefined_types() {
        let input = "undefined4 local_10; undefined8 param_1;";
        let output = clean_source(input);
        assert!(output.contains("uint32_t local_10"));
        assert!(output.contains("uint64_t param_1"));
    }

    #[test]
    fn test_replace_sub_intrinsic() {
        let input = "uVar1 = SUB84(lVar2);";
        let output = clean_source(input);
        assert!(output.contains("(uint32_t)(lVar2)"));
        assert!(!output.contains("SUB84"));
    }

    #[test]
    fn test_replace_concat_intrinsic() {
        let input = "x = CONCAT44(hi, lo);";
        let output = clean_source(input);
        assert!(output.contains("(uint64_t)(hi) << 32"));
        assert!(!output.contains("CONCAT44"));
    }

    #[test]
    fn test_replace_zext_intrinsic() {
        let input = "y = ZEXT816(val);";
        let output = clean_source(input);
        assert!(output.contains("(uint64_t)(val)"));
        assert!(!output.contains("ZEXT816"));
    }

    #[test]
    fn test_adds_stdint_header() {
        let input = "uint32_t x = 0;";
        let output = clean_source(input);
        assert!(output.contains("#include <stdint.h>"));
    }

    #[test]
    fn test_does_not_double_add_header() {
        let input = "#include <stdint.h>\nuint32_t x = 0;";
        let output = clean_source(input);
        assert_eq!(output.matches("#include <stdint.h>").count(), 1);
    }
}
