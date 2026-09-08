use fat_core::runtime_store::RuntimeStore;
use fat_core::staging::{StagingManifest, StagingStrategy};
use tempfile::tempdir;

#[test]
fn staging_manifest_round_trips_through_runtime_store() {
    let tempdir = tempdir().expect("tempdir");
    let store = RuntimeStore::open(tempdir.path()).expect("runtime store");
    let manifest = StagingManifest::new(
        "demo",
        "target-demo",
        "sess-1",
        "run-1",
        "system",
        StagingStrategy::CopyOnWriteImage,
        "/inputs/rootfs.squashfs",
        "/work/staging/run-1",
    )
    .with_generated_artifacts(vec!["disk.qcow2".to_string(), "serial.sock".to_string()]);

    store
        .write_staging_manifest(&manifest)
        .expect("write staging");
    let restored = store
        .read_staging_manifest("sess-1", "run-1", &manifest.staging_manifest_id)
        .expect("read staging");

    assert_eq!(restored, manifest);
}
