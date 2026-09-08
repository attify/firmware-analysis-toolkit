use fat_core::rehosting::RehostingMode;
use fat_emulate::target_profile::{
    build_target_model, build_target_profile, readiness_goals_for_profile, TargetProfileRequest,
};

#[test]
fn target_profile_builder_derives_family_modes_and_hints() {
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
            "nvram:lan_ifname".to_string(),
            "iface:br0".to_string(),
        ],
    });
    let profile = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:busybox".to_string(),
            "web:cgi".to_string(),
            "nvram:lan_ifname".to_string(),
            "iface:br0".to_string(),
        ],
    });

    assert_eq!(profile.project_id, "demo");
    assert_eq!(profile.target_id, "target-demo");
    assert_eq!(profile.architecture.as_deref(), Some("armel"));
    assert_eq!(profile.family_id.as_deref(), Some("linux-router-arm"));
    assert!(profile.candidate_modes.contains(&RehostingMode::Service));
    assert!(profile.candidate_modes.contains(&RehostingMode::System));
    assert_eq!(profile.nvram_hints, vec!["lan_ifname".to_string()]);
    assert_eq!(profile.network_hints, vec!["br0".to_string()]);
    assert_eq!(profile.init_hints, vec!["busybox".to_string()]);
    assert_eq!(model.project_id, profile.project_id);
    assert_eq!(model.target_id, profile.target_id);
    assert_eq!(model.family_id, profile.family_id);
    assert_eq!(model.architecture, profile.architecture);
    assert_eq!(model.to_execution_profile(), profile);
}

#[test]
fn target_profile_ids_are_stable_for_identical_input() {
    let request = TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec!["arch:armel".to_string(), "web:cgi".to_string()],
    };

    let alpha = build_target_profile(&request);
    let beta = build_target_profile(&request);

    assert_eq!(alpha.profile_id, beta.profile_id);
    assert_eq!(alpha.candidate_modes, beta.candidate_modes);
}

#[test]
fn target_profile_builder_dedupes_modes_and_preserves_stable_order() {
    let profile = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "generated:reference-rootfs".to_string(),
            "web:uhttpd".to_string(),
            "init:/etc/init.d/rcS".to_string(),
            "arch:armel".to_string(),
            "web:httpd".to_string(),
            "reference:image".to_string(),
            "web:cgi".to_string(),
        ],
    });

    assert_eq!(
        profile.candidate_modes,
        vec![
            RehostingMode::Service,
            RehostingMode::System,
            RehostingMode::Reference,
        ]
    );
}

#[test]
fn target_profile_builder_only_marks_system_for_router_init_evidence() {
    let non_router = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-non-router".to_string(),
        evidence: vec![
            "arch:x86_64".to_string(),
            "init:/sbin/init".to_string(),
            "fs:ext4".to_string(),
        ],
    });
    let router = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-router".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:/etc/init.d/rcS".to_string(),
        ],
    });

    assert!(!non_router.candidate_modes.contains(&RehostingMode::System));
    assert_eq!(router.family_id.as_deref(), Some("linux-router-arm"));
    assert!(router.candidate_modes.contains(&RehostingMode::System));
}

#[test]
fn target_profile_builder_does_not_infer_reference_from_noisy_tokens() {
    let profile = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-noise".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "referrer:content".to_string(),
            "emuxhelper:available".to_string(),
            "generated:report".to_string(),
        ],
    });

    assert!(!profile.candidate_modes.contains(&RehostingMode::Reference));
}

#[test]
fn readiness_goals_are_deduped_and_follow_mode_priority() {
    let profile = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:/etc/init.d/rcS".to_string(),
            "web:uhttpd".to_string(),
            "generated:reference-rootfs".to_string(),
        ],
    });

    assert_eq!(
        readiness_goals_for_profile(&profile),
        vec![
            "shell-access".to_string(),
            "listener-bind".to_string(),
            "http-validation".to_string(),
            "process-chain".to_string(),
            "init-complete".to_string(),
            "reference-bootstrap".to_string(),
        ]
    );
}

#[test]
fn target_profile_builder_is_stable_for_permuted_evidence_order() {
    let alpha = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "fs:squashfs".to_string(),
            "init:/etc/init.d/rcS".to_string(),
            "web:uhttpd".to_string(),
            "nvram:lan_ifname".to_string(),
            "nvram:wan_ifname".to_string(),
            "iface:br0".to_string(),
            "bridge:br-lan".to_string(),
        ],
    });
    let beta = build_target_profile(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-demo".to_string(),
        evidence: vec![
            "bridge:br-lan".to_string(),
            "iface:br0".to_string(),
            "nvram:wan_ifname".to_string(),
            "web:uhttpd".to_string(),
            "init:/etc/init.d/rcS".to_string(),
            "fs:squashfs".to_string(),
            "nvram:lan_ifname".to_string(),
            "arch:armel".to_string(),
        ],
    });

    assert_eq!(alpha.profile_id, beta.profile_id);
    assert_eq!(alpha.candidate_modes, beta.candidate_modes);
    assert_eq!(alpha.nvram_hints, beta.nvram_hints);
    assert_eq!(alpha.network_hints, beta.network_hints);
    assert_eq!(alpha.init_hints, beta.init_hints);
}

#[test]
fn target_model_builder_normalizes_service_candidates_to_executable_paths() {
    let model = build_target_model(&TargetProfileRequest {
        project_id: "demo".to_string(),
        target_id: "target-service".to_string(),
        evidence: vec![
            "arch:armel".to_string(),
            "service:/usr/sbin/uhttpd".to_string(),
            "web:uhttpd".to_string(),
            "web:httpd".to_string(),
        ],
    });

    assert_eq!(
        model
            .service_candidates
            .iter()
            .map(|candidate| candidate.path.as_str())
            .collect::<Vec<_>>(),
        vec!["/usr/sbin/uhttpd", "/usr/sbin/httpd"]
    );
}
