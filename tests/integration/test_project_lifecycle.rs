use fat_core::{
    database::ProjectDb,
    fingerprint::FirmwareFingerprint,
    project::{Project, ProjectStatus},
};

#[test]
fn project_can_be_created_and_loaded() {
    let dir = tempfile::tempdir().unwrap();
    let db = ProjectDb::open(dir.path()).unwrap();
    let mut project = Project::new("demo".into(), "firmware.bin".into());
    project.status = ProjectStatus::Analyzed;
    project.fingerprint = Some(FirmwareFingerprint::new("a".repeat(64), 1234));

    db.save(&project).unwrap();

    let loaded = db.get("demo").unwrap().expect("project exists");
    assert_eq!(loaded.name, "demo");
    assert_eq!(loaded.firmware_name, "firmware.bin");
    assert_eq!(loaded.status, ProjectStatus::Analyzed);
    assert_eq!(loaded.fingerprint, project.fingerprint);
}

#[test]
fn project_get_rejects_unknown_status() {
    let dir = tempfile::tempdir().unwrap();
    let db = ProjectDb::open(dir.path()).unwrap();

    db.save(&Project::new("demo".into(), "firmware.bin".into()))
        .unwrap();

    let sqlite = rusqlite::Connection::open(dir.path().join(".fat.db")).unwrap();
    sqlite
        .execute(
            "UPDATE projects SET status = 'corrupted' WHERE name = 'demo'",
            [],
        )
        .unwrap();

    let err = db.get("demo").unwrap_err().to_string();
    assert!(
        err.contains("status"),
        "expected unknown status to be surfaced, got: {err}"
    );
}
