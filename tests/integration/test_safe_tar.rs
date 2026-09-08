use fat_extract::safe_tar::safe_untar;
use tempfile::tempdir;

fn build_tar(entries: &[(&str, &[u8])]) -> Vec<u8> {
    let mut bytes = Vec::new();
    {
        let mut builder = tar::Builder::new(&mut bytes);
        for (path, data) in entries {
            let mut header = tar::Header::new_gnu();
            header.set_size(data.len() as u64);
            header.set_mode(0o644);
            builder
                .append_data(&mut header, *path, *data)
                .expect("append tar entry");
        }
        builder.finish().expect("finish tar");
    }
    bytes
}

fn build_traversal_tar() -> Vec<u8> {
    let mut bytes = build_tar(&[("safe.txt", b"safe"), ("second.txt", b"must not escape")]);
    let header = &mut bytes[1024..1536];
    header[..100].fill(0);
    header[..13].copy_from_slice(b"../escape.txt");
    header[148..156].fill(b' ');
    let checksum: u32 = header.iter().map(|byte| u32::from(*byte)).sum();
    header[148..156].copy_from_slice(format!("{checksum:06o}\0 ").as_bytes());
    bytes
}

#[test]
fn safe_untar_extracts_regular_files() {
    let workspace = tempdir().expect("workspace");
    let destination = workspace.path().join("unpacked");
    std::fs::create_dir(&destination).expect("destination");
    let tar = build_tar(&[("etc/device.conf", b"mode=secure\n")]);

    let written = safe_untar(&tar, &destination).expect("safe archive extracts");

    assert_eq!(written, 1);
    assert_eq!(
        std::fs::read(destination.join("etc/device.conf")).expect("extracted file"),
        b"mode=secure\n"
    );
}

#[test]
fn safe_untar_rejects_path_traversal() {
    let workspace = tempdir().expect("workspace");
    let destination = workspace.path().join("unpacked");
    std::fs::create_dir(&destination).expect("destination");

    let error =
        safe_untar(&build_traversal_tar(), &destination).expect_err("traversal archive must fail");

    assert!(
        error.to_string().contains("unsafe tar entry path"),
        "{error}"
    );
    assert!(!workspace.path().join("escape.txt").exists());
}
