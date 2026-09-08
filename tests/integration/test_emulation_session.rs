use fat_core::runs::RunStatus;

#[test]
fn test_emulation_session_records_backend_and_ports() {
    let session = fat_emulate::EmulationPlan::new("sess-1", "firmae", vec![443, 502])
        .expect("supported backend")
        .launch();

    assert_eq!(session.requested_session_id(), "sess-1");
    assert_eq!(session.backend_id(), "firmae");
    assert_eq!(session.mapped_ports(), vec![443, 502]);
    assert_eq!(session.run_record().status, RunStatus::Queued);
}
