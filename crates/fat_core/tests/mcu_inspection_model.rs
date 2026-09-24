use fat_core::mcu_inspection::*;

#[test]
fn mcu_inspection_report_round_trips() {
    let report = McuInspectionReport {
        schema_version: "mcu-inspection/v1".into(),
        artifact_path: "fw.bin".into(),
        artifact_identity: Some(ArtifactIdentity {
            path: "fw.bin".into(),
            sha256: "00".repeat(32),
            total_bytes: 8192,
        }),
        byte_measurements: Some(ByteMeasurements {
            total_bytes: 8192,
            content_prefix_bytes: 4096,
            trailing_uniform_byte: Some(0xff),
            trailing_uniform_offset: Some(4096),
            trailing_uniform_bytes: 4096,
            trailing_uniform_percent: 50.0,
            whole_entropy_bits_per_byte: 4.2,
            content_entropy_bits_per_byte: Some(7.8),
            repetition: Default::default(),
        }),
        analysis_provenance: AnalysisProvenance {
            backend: "native-mcu-inspect".into(),
            backend_version: Some("0.1".into()),
            user_base: Some(0x0800_0000),
            user_family: None,
            family_selection_mode: "auto".into(),
            notes: vec!["unit test".into()],
        },
        identification: None,
        code_analysis: None,
        register_annotations: None,
        fast_profile: Some(McuProfile {
            architecture: "ARM Cortex-M".into(),
            chip_family: "STM32H7".into(),
            chip_family_confidence: 95,
            initial_sp: 0x2401_A058,
            reset_vector: 0x0800_02AD,
            flash_base: 0x0800_0000,
            active_interrupt_count: 2,
            total_interrupt_slots: 2,
            code_size: Some(4096),
            total_size: 8192,
            padding_percent: Some(50),
            is_power_of_two_size: true,
            detected_sdk: Some("STM32CubeMX".into()),
            detected_rtos: None,
            detected_stacks: vec!["LwIP".into()],
            peripheral_hints: vec!["UART".into()],
        }),
        degradations: Some(vec![InspectionDegradation::WeakSignal]),
        image_layout: Some(ImageLayoutReport {
            kind: Interpretation {
                value: ImageLayoutKind::Unknown,
                confidence: 0.2,
                rationale: vec!["no layout proof".into()],
                evidence_ids: vec!["ev-1".into()],
            },
            candidate_offsets: vec![0x1000],
            vector_address: None,
            rationale: vec!["layout unknown".into()],
            evidence_ids: vec!["ev-1".into()],
        }),
        address_hypotheses: Some(vec![AddressHypothesis {
            base: 0x0800_0000,
            confidence: 0.9,
            rationale: vec!["vector table at flash base".into()],
            evidence_ids: vec!["ev-2".into()],
            is_primary: true,
        }]),
        memory_map: Some(vec![MemoryRegion {
            start: 0x0800_0000,
            end: Some(0x0800_FFFF),
            kind: MemoryRegionKind::Flash,
            label: Some("flash".into()),
            confidence: 0.95,
            evidence_ids: vec!["ev-3".into()],
        }]),
        vector_table: Some(InterruptVectorReport {
            entry_count: 2,
            active_count: 2,
            default_handler_count: 0,
            core_exception_count: 1,
            external_irq_count: 0,
            reserved_entry_count: 0,
            unpopulated_entry_count: 0,
            scanned_word_count: 2,
            handler_candidate_count: 1,
            unique_aligned_target_count: 1,
            repeated_targets: vec![RepeatedVectorTarget {
                aligned_address: 0x0800_0200,
                reference_count: 2,
            }],
            scan_boundary: "available-bytes".into(),
            scan_boundary_rationale: vec!["synthetic boundary".into()],
            entries: vec![InterruptVectorEntry {
                index: 0,
                address: 0x2401_A058,
                handler_kind: InterruptHandlerKind::InitialStackPointer,
                family_label: None,
                core_exception: None,
                external_irq_number: None,
                evidence_ids: vec!["ev-4".into()],
            }],
            provenance: Some(SectionProvenance {
                extractor: "vector-table".into(),
                backend: Some("native".into()),
                family_pack: Some("cortex-m".into()),
                notes: vec![],
            }),
        }),
        init_table: None,
        sram_partitions: None,
        system_init_effects: None,
        startup_chain: Some(StartupChainReport {
            steps: vec![StartupStep {
                ordinal: 1,
                address: 0x0800_02AD,
                role: StartupRole::ResetStub,
                evidence_ids: vec!["ev-5".into()],
            }],
            confidence: 0.8,
            provenance: None,
        }),
        main_entry: Some(MainEntryReport {
            entrypoint: Interpretation {
                value: 0x0800_F780,
                confidence: 0.7,
                rationale: vec!["direct branch target".into()],
                evidence_ids: vec!["ev-6".into()],
            },
            provenance: None,
        }),
        execution_model: Some(ExecutionModelReport {
            model: Interpretation {
                value: ExecutionModelKind::Superloop,
                confidence: 0.82,
                rationale: vec!["recurrent loop body".into()],
                evidence_ids: vec!["ev-7".into()],
            },
            loop_heads: vec![0x0800_F8A4],
            scheduler_candidates: vec![],
            task_spawn_sites: vec![],
            isr_shared_state_edges: vec![SharedStateEdge {
                irq_handler: 0x0800_1234,
                consumer: 0x0800_5678,
                variable: Some("flag".into()),
                producer_label: Some("USART1".into()),
                consumer_label: Some("main_loop".into()),
                access_pattern: SharedAccessPattern::PollingFlag,
                touches_flash_or_update: false,
                touches_actuation: true,
                touches_comms: false,
                touches_watchdog: false,
                touches_dma: false,
                touches_safety: false,
                confidence: 0.6,
                rationale: vec!["synthetic shared flag".into()],
                evidence_ids: vec!["ev-8".into()],
            }],
            evidence_ids: vec!["ev-7".into()],
            provenance: None,
            ..Default::default()
        }),
        peripheral_map: Some(PeripheralMapReport {
            uses: vec![PeripheralUse {
                family: Some("STM32H7".into()),
                peripheral_name: "I2C4".into(),
                base: 0x5800_1C00,
                roles: vec![PeripheralRole::HostSidecarLink],
                source: PeripheralEvidenceSource::Mmio,
                confidence: 0.94,
                evidence_ids: vec!["ev-9".into()],
            }],
            provenance: None,
        }),
        peripheral_surface: Some(PeripheralSurfaceReport {
            register_blocks: vec![RegisterBlockObservation {
                family: Some("STM32H7".into()),
                peripheral_name: "USART1".into(),
                base: 0x4001_1000,
                observed_registers: vec!["BRR".into(), "CR1".into()],
                sample_offsets: vec![0x180, 0x188],
                confidence: 0.8,
                evidence_ids: vec!["ev-9a".into()],
            }],
            recovered_configs: vec![RecoveredPeripheralConfig {
                peripheral_name: "USART1".into(),
                kind: PeripheralConfigKind::Uart,
                summary: "UART config registers observed".into(),
                fields: vec![RecoveredConfigField {
                    name: "brr_raw".into(),
                    value: "0x00000138".into(),
                    normalized: None,
                    confidence: 0.72,
                    evidence_ids: vec!["ev-9b".into()],
                }],
                confidence: 0.72,
                evidence_ids: vec!["ev-9b".into()],
                provenance: None,
            }],
            provenance: None,
        }),
        security_surface: Some(SecuritySurfaceSummary {
            update_surface: vec!["tftp".into()],
            flash_surface: vec!["flash-write".into()],
            actuation_surface: vec!["motor-control".into()],
            comms_surface: vec!["uart".into()],
            debug_surface: vec!["swd".into()],
            crypto_surface: vec!["crc".into()],
            confidence: 0.88,
            evidence_ids: vec!["ev-10".into()],
        }),
        integrity_checks: Some(vec![IntegrityCheckReport {
            description: "crc present".into(),
            confidence: 0.9,
            evidence_ids: vec!["ev-10".into()],
            provenance: None,
        }]),
        authenticity_checks: Some(vec![AuthenticityMechanismReport {
            description: "no signature evidence".into(),
            confidence: 0.1,
            evidence_ids: vec![],
            provenance: None,
        }]),
        rollback_checks: Some(vec![RollbackResistanceReport {
            description: "no anti-rollback evidence".into(),
            confidence: 0.1,
            evidence_ids: vec![],
            provenance: None,
        }]),
        write_authority: Some(vec![WriteAuthorityReport {
            description: "flash erase/program path present".into(),
            confidence: 0.85,
            evidence_ids: vec!["ev-11".into()],
            provenance: None,
        }]),
        shared_state_risk: Some(SharedStateRiskReport {
            edges: vec![SharedStateEdge {
                irq_handler: 0x0800_1234,
                consumer: 0x0800_5678,
                variable: Some("flag".into()),
                producer_label: Some("USART1".into()),
                consumer_label: Some("main_loop".into()),
                access_pattern: SharedAccessPattern::PollingFlag,
                touches_flash_or_update: false,
                touches_actuation: true,
                touches_comms: true,
                touches_watchdog: false,
                touches_dma: false,
                touches_safety: false,
                confidence: 0.6,
                rationale: vec!["synthetic risk edge".into()],
                evidence_ids: vec!["ev-13".into()],
            }],
            ranked_findings: vec![SharedStateFinding {
                title: "USART1 IRQ shared state reaches actuation loop".into(),
                tags: vec![SharedStateRiskTag::HostComms, SharedStateRiskTag::Actuation],
                confidence: 0.64,
                rationale: vec!["synthetic risk".into()],
                evidence_ids: vec!["ev-13".into()],
            }],
            degradation_notes: vec![],
            provenance: None,
        }),
        update_paths: Some(vec![UpdatePathReport {
            path_id: "path-1".into(),
            source_artifact: "updater.py".into(),
            target_artifact: "fw.bin".into(),
            transport: "tftp".into(),
            mechanism: "push".into(),
            confidence: 0.8,
            evidence_ids: vec!["ev-12".into()],
        }]),
        trust_chain: Some(vec![TrustChainReport {
            source_artifact: "updater.py".into(),
            source_role: "updater".into(),
            target_artifact: "fw.bin".into(),
            operation: "program".into(),
            trust_check: Some("crc".into()),
            rollback_check: None,
            confidence: 0.75,
            evidence_ids: vec!["ev-12".into()],
        }]),
        claims: Some(vec![ClaimRecord {
            claim_id: "claim-1".into(),
            title: "example claim".into(),
            kind: ClaimKind::Derived,
            confidence: 0.6,
            evidence_ids: vec!["ev-1".into()],
            notes: vec!["round-trip".into()],
        }]),
        evidence: Some(vec![EvidenceRecord {
            evidence_id: "ev-1".into(),
            kind: EvidenceKind::ToolOutput,
            summary: "synthetic evidence".into(),
            location: Some(EvidenceLocation {
                offset: Some(0),
                address: Some(0x0800_0000),
                symbol: None,
                note: Some("test".into()),
            }),
            raw: Some("tool output".into()),
        }]),
    };

    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json.get("next_steps").is_none(),
        "unexpected next_steps: {json}"
    );
    for key in [
        "artifact_identity",
        "byte_measurements",
        "fast_profile",
        "analysis_provenance",
        "degradations",
        "image_layout",
        "address_hypotheses",
        "vector_table",
        "execution_model",
        "security_surface",
        "peripheral_surface",
        "integrity_checks",
        "authenticity_checks",
        "rollback_checks",
        "write_authority",
        "shared_state_risk",
        "trust_chain",
    ] {
        assert!(json.get(key).is_some(), "missing key {key}");
    }

    let mut legacy = json.clone();
    let vectors = legacy["vector_table"].as_object_mut().unwrap();
    for key in [
        "core_exception_count",
        "external_irq_count",
        "reserved_entry_count",
        "unpopulated_entry_count",
    ] {
        vectors.remove(key);
    }
    let legacy_report: McuInspectionReport = serde_json::from_value(legacy).unwrap();
    assert!(legacy_report.code_analysis.is_none());
    assert!(legacy_report.register_annotations.is_none());
    assert_eq!(
        legacy_report.vector_table.unwrap().unpopulated_entry_count,
        0
    );
    let round_trip: McuInspectionReport = serde_json::from_value(json).unwrap();
    assert_eq!(round_trip, report);
}

#[test]
fn mcu_inspection_report_omits_unset_sections() {
    let report = McuInspectionReport {
        schema_version: "mcu-inspection/v1".into(),
        artifact_path: "fw.bin".into(),
        artifact_identity: None,
        byte_measurements: None,
        analysis_provenance: AnalysisProvenance::default(),
        identification: None,
        code_analysis: None,
        register_annotations: None,
        fast_profile: None,
        degradations: None,
        image_layout: None,
        address_hypotheses: None,
        memory_map: None,
        vector_table: None,
        startup_chain: None,
        init_table: None,
        sram_partitions: None,
        system_init_effects: None,
        main_entry: None,
        execution_model: None,
        peripheral_map: None,
        peripheral_surface: None,
        security_surface: None,
        integrity_checks: None,
        authenticity_checks: None,
        rollback_checks: None,
        write_authority: None,
        shared_state_risk: None,
        update_paths: None,
        trust_chain: None,
        claims: None,
        evidence: None,
    };

    let json = serde_json::to_value(&report).unwrap();
    assert!(
        json.get("next_steps").is_none(),
        "unexpected next_steps: {json}"
    );
    for key in [
        "code_analysis",
        "register_annotations",
        "artifact_identity",
        "byte_measurements",
        "fast_profile",
        "degradations",
        "image_layout",
        "address_hypotheses",
        "memory_map",
        "vector_table",
        "startup_chain",
        "init_table",
        "main_entry",
        "execution_model",
        "peripheral_map",
        "peripheral_surface",
        "security_surface",
        "integrity_checks",
        "authenticity_checks",
        "rollback_checks",
        "write_authority",
        "shared_state_risk",
        "update_paths",
        "trust_chain",
        "claims",
        "evidence",
    ] {
        assert!(json.get(key).is_none(), "unexpected key {key}");
    }
}
