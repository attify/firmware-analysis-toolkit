use std::collections::HashMap;
use std::path::PathBuf;

use fat_core::diagnostics::{
    DiagnosticActionability, DiagnosticClass, DiagnosticConfidence, DiagnosticOwner,
    DiagnosticPhase, DiagnosticSeverity,
};
use fat_emulate::preflight::PreflightReport;

struct FakeCommandProbe {
    commands: HashMap<String, PathBuf>,
}

impl FakeCommandProbe {
    fn with_commands(entries: &[(&str, &str)]) -> Self {
        Self {
            commands: entries
                .iter()
                .map(|(command, path)| ((*command).to_string(), PathBuf::from(path)))
                .collect(),
        }
    }
}

impl fat_backend::CommandProbe for FakeCommandProbe {
    fn command_path(&self, command: &str) -> Option<PathBuf> {
        self.commands.get(command).cloned()
    }
}

#[test]
fn preflight_report_structured_host_capabilities_include_backend_summaries_and_diagnostics() {
    let managed_bundle = std::env::var_os("FAT_MANAGED_LINUX_VM_BUNDLE_DIR");
    let firmae_upstream = std::env::var_os("FAT_FIRMAE_UPSTREAM_DIR");
    let firmae_python = std::env::var_os("FAT_FIRMAE_HOST_PYTHON");
    unsafe {
        std::env::remove_var("FAT_MANAGED_LINUX_VM_BUNDLE_DIR");
        std::env::remove_var("FAT_FIRMAE_UPSTREAM_DIR");
        std::env::remove_var("FAT_FIRMAE_HOST_PYTHON");
    }

    let probe = FakeCommandProbe::with_commands(&[("qemu-system-arm", "/usr/bin/qemu-system-arm")]);
    let report = PreflightReport::from_signals_with_probe(
        [
            "arch:armel",
            "fs:squashfs",
            "init:busybox",
            "web:cgi",
            "nvram:present",
        ],
        &probe,
    );

    assert_eq!(report.primary_family.family_id, "linux-router-arm");
    assert_eq!(
        report.host_capabilities.primary_family.family_id,
        report.primary_family.family_id
    );
    assert_eq!(
        report.host_capabilities.backend_summaries.len(),
        report.backends.len()
    );

    let firmae_summary = report
        .host_capabilities
        .backend_summaries
        .iter()
        .find(|summary| summary.backend_id == "firmae")
        .expect("firmae summary");
    assert!(!firmae_summary.is_available);
    assert!(firmae_summary
        .stable_summary
        .contains("missing FAT_MANAGED_LINUX_VM_BUNDLE_DIR"));

    let qemu_summary = report
        .host_capabilities
        .backend_summaries
        .iter()
        .find(|summary| summary.backend_id == "qemu-direct")
        .expect("qemu summary");
    assert!(qemu_summary.is_available);
    assert!(qemu_summary.stable_summary.contains("available via"));

    let diagnostic = report
        .host_capabilities
        .diagnostics
        .iter()
        .find(|diagnostic| diagnostic.class == DiagnosticClass::BackendUnavailable)
        .expect("backend unavailable diagnostic");
    assert_eq!(diagnostic.phase, DiagnosticPhase::BackendProvisioning);
    assert_eq!(diagnostic.owner, DiagnosticOwner::BackendTool);
    assert_eq!(diagnostic.severity, DiagnosticSeverity::Medium);
    assert_eq!(diagnostic.confidence, DiagnosticConfidence::High);
    assert_eq!(
        diagnostic.actionability,
        DiagnosticActionability::FallbackRecommended
    );

    match managed_bundle {
        Some(value) => unsafe { std::env::set_var("FAT_MANAGED_LINUX_VM_BUNDLE_DIR", value) },
        None => unsafe { std::env::remove_var("FAT_MANAGED_LINUX_VM_BUNDLE_DIR") },
    }
    match firmae_upstream {
        Some(value) => unsafe { std::env::set_var("FAT_FIRMAE_UPSTREAM_DIR", value) },
        None => unsafe { std::env::remove_var("FAT_FIRMAE_UPSTREAM_DIR") },
    }
    match firmae_python {
        Some(value) => unsafe { std::env::set_var("FAT_FIRMAE_HOST_PYTHON", value) },
        None => unsafe { std::env::remove_var("FAT_FIRMAE_HOST_PYTHON") },
    }
}

#[test]
fn preflight_report_backend_availability_summary_is_stable_for_available_backends() {
    let probe = FakeCommandProbe::with_commands(&[("qemu-system-arm", "/usr/bin/qemu-system-arm")]);
    let scores = fat_backend::model::BackendRegistry::with_test_backends()
        .rank_family_with_probe("linux-router-arm", &probe);

    let qemu_score = scores
        .iter()
        .find(|score| score.backend_id == "qemu-direct")
        .expect("qemu-direct score");
    let summary = qemu_score.availability_summary();

    assert_eq!(summary.backend_id, "qemu-direct");
    assert_eq!(summary.display_name, "QEMU Direct");
    assert_eq!(summary.matched_family_id, "linux-router-arm");
    assert!(summary.is_available);
    assert!(summary.stable_summary.contains("available via"));
}
