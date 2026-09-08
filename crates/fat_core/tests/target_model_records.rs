use fat_core::target_model::{
    ModelServiceCandidate, ServiceExecutionClass, TargetModel, TargetModelInitCandidate,
    TargetModelNetworkHypothesis, TargetModelNvramFact,
};

#[test]
fn target_model_ids_are_stable_for_identical_input() {
    let left = TargetModel::new(
        "project-a",
        "target-a",
        Some("mipsel"),
        Some("linux-router-mips"),
        vec!["arch:mipsel".to_string(), "web:httpd".to_string()],
    )
    .with_service_candidates(vec![ModelServiceCandidate::new(
        "/bin/httpd",
        ServiceExecutionClass::Standalone,
    )])
    .with_init_candidates(vec![TargetModelInitCandidate::new("/etc/init.d/rcS", 100)])
    .with_network_hypotheses(vec![TargetModelNetworkHypothesis::new("br0", "bridge")])
    .with_nvram_facts(vec![TargetModelNvramFact::new("lan_ipaddr", "missing")]);

    let right = TargetModel::new(
        "project-a",
        "target-a",
        Some("mipsel"),
        Some("linux-router-mips"),
        vec!["web:httpd".to_string(), "arch:mipsel".to_string()],
    )
    .with_service_candidates(vec![ModelServiceCandidate::new(
        "/bin/httpd",
        ServiceExecutionClass::Standalone,
    )])
    .with_init_candidates(vec![TargetModelInitCandidate::new("/etc/init.d/rcS", 100)])
    .with_network_hypotheses(vec![TargetModelNetworkHypothesis::new("br0", "bridge")])
    .with_nvram_facts(vec![TargetModelNvramFact::new("lan_ipaddr", "missing")]);

    assert_eq!(left.model_id, right.model_id);
}

#[test]
fn target_model_distinguishes_distinct_evidence() {
    let left = TargetModel::new(
        "project-a",
        "target-a",
        Some("mipsel"),
        Some("linux-router-mips"),
        vec!["arch:mipsel".to_string()],
    );
    let right = TargetModel::new(
        "project-a",
        "target-a",
        Some("mipsel"),
        Some("linux-router-mips"),
        vec!["arch:mipsel".to_string(), "web:httpd".to_string()],
    );

    assert_ne!(left.model_id, right.model_id);
}
