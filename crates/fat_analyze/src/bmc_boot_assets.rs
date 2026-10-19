//! Bounded, explicit boot asset preparation; independent of FIT metadata findings.
use crate::firmware_formats::FdtScanBudget;
use sha2::{Digest, Sha256};

/// Extract an inline, uncompressed FIT payload only after checking its SHA-256.
/// This checks data integrity, not signature authenticity or boot enforcement.
pub fn fit_payload(fit: &[u8], name: &str, kind: &str) -> Result<Vec<u8>, String> {
    let tree = FdtScanBudget::default()
        .parse(fit, 0)
        .map_err(|e| e.message)?;
    let images = tree.child(0, "images").ok_or("FIT has no images node")?;
    let index = tree
        .child(images, name)
        .ok_or_else(|| format!("missing FIT image {name}"))?;
    let node = &tree.nodes[index];
    if node.property("type").map(|p| p.value) != Some(format!("{kind}\0").as_bytes()) {
        return Err(format!("FIT image {name} is not type {kind}"));
    }
    if node.property("compression").map(|p| p.value) != Some(b"none\0".as_slice()) {
        return Err("BMC direct boot supports explicitly uncompressed FIT payloads".into());
    }
    let data = node
        .property("data")
        .ok_or("BMC direct boot requires inline FIT data")?
        .value;
    if data.is_empty() || data.len() > 64 * 1024 * 1024 {
        return Err("FIT payload is empty or exceeds 64 MiB".into());
    }
    let digest = Sha256::digest(data);
    let mut verified = false;
    for &child in &node.children {
        let hash = &tree.nodes[child];
        if hash.name.starts_with("hash")
            && hash.property("algo").map(|p| p.value) == Some(b"sha256\0".as_slice())
        {
            if hash.property("value").map(|p| p.value) != Some(digest.as_slice()) {
                return Err(format!("SHA-256 mismatch in FIT image {name}"));
            }
            verified = true;
        }
    }
    if !verified {
        return Err(format!("FIT image {name} lacks a SHA-256 digest"));
    }
    Ok(data.to_vec())
}

/// Replace only an existing enabled node's status. Preserve the reserve map,
/// all other properties and nodes; revalidate the complete resulting FDT.
pub fn disable_dtb_node(dtb: &[u8], path: &str) -> Result<Vec<u8>, String> {
    if !path.starts_with('/')
        || path
            .split('/')
            .skip(1)
            .any(|p| matches!(p, "" | "." | ".."))
    {
        return Err("DTB node must be an absolute normalized path".into());
    }
    let tree = FdtScanBudget::default()
        .parse(dtb, 0)
        .map_err(|e| e.message)?;
    let mut index = 0;
    for name in path.split('/').skip(1) {
        index = tree
            .child(index, name)
            .ok_or_else(|| format!("missing DTB node {path}"))?;
    }
    let status = tree.nodes[index]
        .property("status")
        .ok_or("DTB node lacks explicit status")?;
    if !matches!(status.value, b"okay\0" | b"ok\0") {
        return Err(format!("DTB node {path} does not have enabled status"));
    }
    let start = status.offset + 12;
    let old_padded = (status.value.len() + 3) & !3;
    let replacement = b"disabled\0\0\0\0";
    let growth = replacement.len() - old_padded;
    let mut result = dtb[..tree.total_size].to_vec();
    result.splice(start..start + old_padded, replacement.iter().copied());
    result[status.offset + 4..status.offset + 8].copy_from_slice(&9u32.to_be_bytes());
    for header in [4usize, 8, 12, 16, 36] {
        let old = u32::from_be_bytes(dtb[header..header + 4].try_into().unwrap());
        // Total size, structure size and blocks following the replaced property move.
        if header == 4 || header == 36 || old as usize >= start + old_padded {
            result[header..header + 4].copy_from_slice(&(old + growth as u32).to_be_bytes());
        }
    }
    FdtScanBudget::default()
        .parse(&result, 0)
        .map_err(|e| e.message)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn word(out: &mut Vec<u8>, value: u32) {
        out.extend(value.to_be_bytes());
    }
    fn padded(out: &mut Vec<u8>, value: &[u8]) {
        out.extend(value);
        while !out.len().is_multiple_of(4) {
            out.push(0);
        }
    }
    fn node(out: &mut Vec<u8>, name: &str) {
        word(out, 1);
        padded(out, format!("{name}\0").as_bytes());
    }
    fn prop(out: &mut Vec<u8>, strings: &mut Vec<u8>, name: &str, value: &[u8]) {
        word(out, 3);
        word(out, value.len() as u32);
        word(out, strings.len() as u32);
        strings.extend(name.as_bytes());
        strings.push(0);
        padded(out, value);
    }
    fn finish(mut structure: Vec<u8>, strings: Vec<u8>) -> Vec<u8> {
        word(&mut structure, 9);
        let mut out = Vec::new();
        for v in [
            0xd00dfeed,
            (56 + structure.len() + strings.len()) as u32,
            56,
            (56 + structure.len()) as u32,
            40,
            17,
            16,
            0,
            strings.len() as u32,
            structure.len() as u32,
        ] {
            word(&mut out, v);
        }
        out.extend([0; 16]);
        out.extend(structure);
        out.extend(strings);
        out
    }
    fn fit() -> Vec<u8> {
        let (mut s, mut names) = (vec![], vec![]);
        node(&mut s, "");
        node(&mut s, "images");
        node(&mut s, "kernel@1");
        prop(&mut s, &mut names, "type", b"kernel\0");
        prop(&mut s, &mut names, "compression", b"none\0");
        prop(&mut s, &mut names, "data", b"firmware");
        node(&mut s, "hash@1");
        prop(&mut s, &mut names, "algo", b"sha256\0");
        prop(&mut s, &mut names, "value", &Sha256::digest(b"firmware"));
        for _ in 0..4 {
            word(&mut s, 2);
        }
        finish(s, names)
    }
    #[test]
    fn bmc_payload_requires_matching_digest_and_kind() {
        let data = fit();
        assert_eq!(
            fit_payload(&data, "kernel@1", "kernel").unwrap(),
            b"firmware"
        );
        assert!(fit_payload(&data, "kernel@1", "flat_dt").is_err());
        assert!(fit_payload(&data, "missing", "kernel").is_err());
        let mut bad = data;
        let i = bad.windows(8).position(|v| v == b"firmware").unwrap();
        bad[i] ^= 1;
        assert!(fit_payload(&bad, "kernel@1", "kernel").is_err());
    }
    #[test]
    fn bmc_dtb_changes_only_requested_status() {
        let (mut s, mut names) = (vec![], vec![]);
        node(&mut s, "");
        node(&mut s, "ahb");
        node(&mut s, "hace@1e6d0000");
        prop(&mut s, &mut names, "status", b"okay\0");
        prop(&mut s, &mut names, "reg", &[1, 2, 3, 4]);
        for _ in 0..3 {
            word(&mut s, 2);
        }
        let original = finish(s, names);
        let changed = disable_dtb_node(&original, "/ahb/hace@1e6d0000").unwrap();
        let tree = FdtScanBudget::default().parse(&changed, 0).unwrap();
        assert_eq!(
            tree.nodes[2].property("status").unwrap().value,
            b"disabled\0"
        );
        assert_eq!(tree.nodes[2].property("reg").unwrap().value, &[1, 2, 3, 4]);
        assert!(disable_dtb_node(&original, "/absent").is_err());
        assert!(disable_dtb_node(&original[..30], "/ahb").is_err());
        assert!(fit_payload(&original[..30], "x", "kernel").is_err());
    }
}
