use fat_core::readiness::{ConfidenceLevel, ConfidenceReport};
use fat_core::rehosting_policy::SubstrateKind;
use fat_core::runtime_store::RuntimeStore;
use tempfile::tempdir;

#[test]
fn confidence_report_round_trips_through_runtime_store() {
    let tempdir = tempdir().expect("tempdir");
    let store = RuntimeStore::open(tempdir.path()).expect("runtime store");
    let report = ConfidenceReport::new(
        "demo",
        "target-demo",
        "sess-1",
        "run-1",
        Some(SubstrateKind::Reference),
        ConfidenceLevel::Low,
        24,
    )
    .with_summary("reference foothold available; target service fidelity unknown")
    .with_blockers(vec!["target service absent in reference image".to_string()]);

    store
        .write_confidence_report(&report)
        .expect("write confidence");
    let restored = store
        .read_confidence_report("sess-1", "run-1", &report.confidence_report_id)
        .expect("read confidence");

    assert_eq!(restored, report);
}
