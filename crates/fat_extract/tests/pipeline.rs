use std::io::{Cursor, Write};

use fat_extract::pipeline::{extract, ArtifactStatus, PipelineOptions};

fn tar_file(name: &str, bytes: &[u8]) -> Vec<u8> {
    let mut archive = tar::Builder::new(Vec::new());
    let mut header = tar::Header::new_gnu();
    header.set_size(bytes.len() as u64);
    header.set_mode(0o644);
    header.set_cksum();
    archive.append_data(&mut header, name, bytes).unwrap();
    archive.into_inner().unwrap()
}

#[test]
fn follows_zip_tar_gzip_without_filename_hints() {
    let temp = tempfile::tempdir().unwrap();
    let mut gzip = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
    gzip.write_all(&tar_file("etc/inittab", b"::sysinit:/etc/init.d/rcS\n"))
        .unwrap();
    let nested = tar_file("opaque", &gzip.finish().unwrap());
    let mut zip = zip::ZipWriter::new(Cursor::new(Vec::new()));
    zip.start_file("payload", zip::write::SimpleFileOptions::default())
        .unwrap();
    zip.write_all(&nested).unwrap();
    let input = temp.path().join("input");
    std::fs::write(&input, zip.finish().unwrap().into_inner()).unwrap();
    let report = extract(
        &input,
        &temp.path().join("output"),
        PipelineOptions::default(),
    )
    .unwrap();
    assert_eq!(
        report
            .artifacts
            .iter()
            .map(|a| a.format.as_str())
            .collect::<Vec<_>>(),
        ["zip", "tar", "gzip", "tar"]
    );
    assert!(report
        .artifacts
        .iter()
        .all(|a| a.status == ArtifactStatus::Recovered));
    for (id, artifact) in report.artifacts.iter().enumerate() {
        assert_eq!(artifact.parent, id.checked_sub(1));
    }
    assert!(report
        .artifacts
        .last()
        .unwrap()
        .output
        .as_ref()
        .unwrap()
        .join("etc/inittab")
        .is_file());
}

#[test]
fn malformed_child_does_not_erase_recovered_container() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    std::fs::write(&input, tar_file("broken", b"hsqs")).unwrap();
    let report = extract(
        &input,
        &temp.path().join("output"),
        PipelineOptions::default(),
    )
    .unwrap();
    assert_eq!(report.artifacts.len(), 2);
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Recovered);
    assert_eq!(report.artifacts[1].status, ArtifactStatus::Failed);
    assert!(report.has_unresolved());
    assert!(report.artifacts[1].output.is_none());
}

#[test]
fn output_budget_is_shared_across_nested_containers() {
    let temp = tempfile::tempdir().unwrap();
    let nested = tar_file("large", &[1; 512]);
    let input = temp.path().join("input");
    std::fs::write(&input, tar_file("nested", &nested)).unwrap();
    let mut options = PipelineOptions::default();
    options.limits.max_output_bytes = nested.len() as u64 + 511;
    let report = extract(&input, &temp.path().join("output"), options).unwrap();
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Recovered);
    assert_eq!(report.artifacts[1].status, ArtifactStatus::Limited);
    assert!(report.artifacts[1].output.is_none());
}

#[test]
fn depth_limit_is_a_reported_outcome() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    std::fs::write(&input, tar_file("nested", &tar_file("leaf", b"hello"))).unwrap();
    let options = PipelineOptions {
        max_container_depth: 0,
        ..Default::default()
    };
    let report = extract(&input, &temp.path().join("output"), options).unwrap();
    assert_eq!(report.artifacts[1].status, ArtifactStatus::Limited);
}

#[test]
fn embedded_magic_strings_without_plausible_headers_are_not_artifacts() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    let mut bytes = vec![0x41; 256];
    bytes[16..20].copy_from_slice(b"hsqs");
    bytes[64..68].copy_from_slice(b"sqlz");
    bytes[128..131].copy_from_slice(b"\x1f\x8b\x08");
    bytes[131] = 0xff;
    std::fs::write(&input, bytes).unwrap();
    let report = extract(
        &input,
        &temp.path().join("output"),
        PipelineOptions::default(),
    )
    .unwrap();
    assert!(report.artifacts.is_empty());
}

#[test]
fn artifact_limit_also_bounds_uninspected_children() {
    let temp = tempfile::tempdir().unwrap();
    let input = temp.path().join("input");
    std::fs::write(&input, tar_file("nested", &tar_file("leaf", b"hello"))).unwrap();
    let options = PipelineOptions {
        max_container_depth: 0,
        max_artifacts: 1,
        ..Default::default()
    };
    let report = extract(&input, &temp.path().join("output"), options).unwrap();
    assert_eq!(report.artifacts.len(), 1);
    assert!(report.truncated);
    assert!(report.has_unresolved());
}

#[cfg(unix)]
#[test]
fn unreadable_child_is_reported_and_readable_sibling_continues() {
    let temp = tempfile::tempdir().unwrap();
    let mut archive = tar::Builder::new(Vec::new());
    for (name, mode) in [("a-unreadable", 0), ("b-readable", 0o644)] {
        let bytes = tar_file("leaf", b"hello");
        let mut header = tar::Header::new_gnu();
        header.set_size(bytes.len() as u64);
        header.set_mode(mode);
        header.set_cksum();
        archive
            .append_data(&mut header, name, bytes.as_slice())
            .unwrap();
    }
    let input = temp.path().join("input");
    std::fs::write(&input, archive.into_inner().unwrap()).unwrap();
    let report = extract(
        &input,
        &temp.path().join("output"),
        PipelineOptions::default(),
    )
    .unwrap();
    assert_eq!(report.artifacts.len(), 3);
    assert_eq!(report.artifacts[0].status, ArtifactStatus::Recovered);
    assert_eq!(report.artifacts[2].status, ArtifactStatus::Recovered);
    if std::fs::File::open(
        report.artifacts[0]
            .output
            .as_ref()
            .unwrap()
            .join("a-unreadable"),
    )
    .is_err()
    {
        assert_eq!(report.artifacts[1].status, ArtifactStatus::Failed);
        assert!(report.has_unresolved());
    }
}
