use crate::result::{DerivedAnalysis, DerivedFact, EvidenceBasis, FamilyPack, FusedSourceEvidence};
use std::collections::BTreeMap;

pub fn derive_from_fused_source(fused: &FusedSourceEvidence) -> DerivedAnalysis {
    let mut analysis = DerivedAnalysis::default();

    for method in &fused.methods {
        let _fact_start = analysis.facts.len();
        let lower = method.qualified_name.to_ascii_lowercase();
        // GPU protocol lifecycle: require GPU-specific context, not generic map/destroy
        if is_gpu_lifecycle_method(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::GpuProtocolLifecycle,
                "gpu_protocol_lifecycle_method",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests GPU protocol ordering or lifecycle control",
            );
        }
        if lower.contains("guard") {
            push_fact(
                &mut analysis,
                FamilyPack::GpuProtocolLifecycle,
                "explicit_state_guard",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests an explicit state guard",
            );
        }
        if lower.contains("override") || lower.contains("permission") {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "override_permission_site",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests permission-sensitive override site",
            );
        }
        if lower.contains("validate")
            || lower.contains("permission")
            || lower.contains("origin")
            || lower.contains("remote")
            || lower.contains("dispatch")
            || lower.contains("message")
            || lower.contains("ipc")
            || lower.contains("verify")
            || lower.contains("authorize")
            || lower.contains("sanitize")
            || lower.contains("untrusted")
            || lower.contains("boundary")
            || (lower.contains("check")
                && (lower.contains("access")
                    || lower.contains("bound")
                    || lower.contains("type")
                    || lower.contains("auth")
                    || lower.contains("perm")))
        {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "validation_or_permission_method",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests validation or trust-boundary handling",
            );
        }
        // permission_gate_present is deliberately narrower than
        // validation_or_permission_method so a single method name cannot
        // satisfy both primary facts by itself.
        if lower.contains("validate") || lower.contains("permission") || lower.contains("origin") {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "permission_gate_present",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests a validation or permission gate",
            );
        }
        if lower.contains("release")
            || lower.contains("destroy")
            || lower.contains("callback")
            || lower.contains("invalidate")
            || lower.contains("pending")
        {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "lifetime_sensitive_method",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests teardown/callback lifetime pattern",
            );
        }
        if lower.contains("cleanup") {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "cleanup_only_teardown",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests cleanup-only teardown flow",
            );
        }
        if is_deferred_or_pending_term(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "deferred_or_pending_state_present",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests deferred, queued, or pending object state",
            );
        }
        if is_post_handoff_observer_term(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "post_handoff_observer_present",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests reporting, tracing, or notification after a state transition",
            );
        }
        if lower.contains("shutdown") {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "explicit_shutdown_path",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests an explicit shutdown path",
            );
        }
        if lower.contains("single") && lower.contains("callback") {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "single_shot_callback",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests a one-shot callback path",
            );
        }
        if lower.contains("cancel") {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "explicit_cancellation_guard",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests an explicit cancellation path",
            );
        }
        if lower.contains("subimage") || lower.contains("buffer") {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "buffer_or_subimage_method",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests copy/allocation size handling",
            );
        }
        if lower.contains("guarded")
            && (lower.contains("subimage")
                || lower.contains("upload")
                || lower.contains("copy")
                || lower.contains("buffer"))
        {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "dominating_size_guard",
                &method.qualified_name,
                EvidenceBasis::ObservedFromAstFacts,
                "method name suggests a guard-dominated size path",
            );
        }
        // Tag all facts produced during this method iteration with the source file
        for fact in &mut analysis.facts[_fact_start..] {
            if fact.source_file.is_none() {
                fact.source_file = Some(method.file.clone());
            }
        }
    }

    for call in &fused.calls {
        let _call_fact_start = analysis.facts.len();
        let lower = call.callee_name.to_ascii_lowercase();
        if lower.contains("map")
            || lower.contains("unmap")
            || lower.contains("submit")
            || lower.contains("destroy")
        {
            push_fact(
                &mut analysis,
                FamilyPack::GpuProtocolLifecycle,
                "gpu_ordering_call_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("protocol-ordering call {}", call.callee_name),
            );
        }
        if lower.contains("callback")
            || lower.contains("lost")
            || lower.contains("async")
            || lower.contains("complete")
        {
            push_fact(
                &mut analysis,
                FamilyPack::GpuProtocolLifecycle,
                "gpu_async_callback_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("async lifecycle call {}", call.callee_name),
            );
        }
        if lower.contains("guard") {
            push_fact(
                &mut analysis,
                FamilyPack::GpuProtocolLifecycle,
                "explicit_state_guard",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("explicit state guard {}", call.callee_name),
            );
        }
        if lower.contains("makebuffer") || lower.contains("alloc") {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "allocation_call_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("allocation-like call {}", call.callee_name),
            );
        }
        if lower.contains("copy") || lower.contains("memcpy") {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "copy_call_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("copy-like call {}", call.callee_name),
            );
        }
        if lower.contains("check") || lower.contains("validate") {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "bounds_checked_copy",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("bounds-check-like call {}", call.callee_name),
            );
        }
        if lower.contains("depth") || lower.contains("pitch") || lower.contains("stride") {
            push_fact(
                &mut analysis,
                FamilyPack::BoundsSizeArithmetic,
                "stride_pitch_depth_role",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("size-role call {}", call.callee_name),
            );
        }
        if lower.contains("permission") || lower.contains("haspermission") {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "permission_gate_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("validation-like call {}", call.callee_name),
            );
        }
        if lower.contains("validate")
            || lower.contains("dispatch")
            || lower.contains("remote")
            || lower.contains("enforce")
            || lower.contains("message")
            || lower.contains("ipc")
        {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "trust_boundary_action_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("trust-boundary action {}", call.callee_name),
            );
        }
        if lower.contains("badmessage") || lower.contains("denied") || lower.contains("reject") {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "bad_message_path_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("bad-message or rejection path {}", call.callee_name),
            );
        }
        if lower.contains("guard") {
            push_fact(
                &mut analysis,
                FamilyPack::ValidationPolicy,
                "dominating_validation_guard",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("validation guard {}", call.callee_name),
            );
        }
        if is_ownership_transfer_term(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "ownership_transfer_call_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("handoff-like call {}", call.callee_name),
            );
        }
        if is_deferred_or_pending_term(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "deferred_or_pending_state_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("deferred or pending state call {}", call.callee_name),
            );
        }
        if is_post_handoff_observer_term(&lower) {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "post_handoff_observer_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("post-handoff observer call {}", call.callee_name),
            );
        }
        if lower.contains("callback")
            || lower.contains("destroy")
            || lower.contains("release")
            || lower.contains("posttask")
            || lower.contains("bindonce")
            || lower.contains("bindrepeating")
            || lower.contains("schedule")
            || lower.contains("cancel")
            || lower.contains("invalidate")
            || lower.contains("complete")
        {
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "callback_or_teardown_call_present",
                &call.enclosing_symbol,
                call.basis.clone(),
                format!("lifetime-like call {}", call.callee_name),
            );
        }
        // Tag all facts produced during this call iteration with the source file
        for fact in &mut analysis.facts[_call_fact_start..] {
            if fact.source_file.is_none() {
                fact.source_file = Some(call.file.clone());
            }
        }
    }

    let grouped = group_facts_by_subject(&analysis);
    for (_key, facts) in grouped {
        let has_transfer = facts
            .iter()
            .any(|fact| fact.kind == "ownership_transfer_call_present");
        let has_deferred = facts
            .iter()
            .any(|fact| fact.kind == "deferred_or_pending_state_present");
        let has_observer = facts
            .iter()
            .any(|fact| fact.kind == "post_handoff_observer_present");
        let has_lifetime_context = facts.iter().any(|fact| {
            matches!(
                fact.kind.as_str(),
                "lifetime_sensitive_method"
                    | "callback_or_teardown_call_present"
                    | "cleanup_only_teardown"
            )
        });
        if has_transfer && has_observer && (has_deferred || has_lifetime_context) {
            // Use the bare subject name from the first fact, not the
            // file-qualified grouping key.
            let bare_subject = facts.first().map(|f| f.subject.as_str()).unwrap_or(&_key);
            push_fact(
                &mut analysis,
                FamilyPack::LifetimeOwnership,
                "stale_subject_reuse_risk",
                bare_subject,
                EvidenceBasis::ObservedFromAstFacts,
                "subject is observed after a handoff/deferred boundary",
            );
        }
    }

    analysis.observed = fused.observed.clone();
    if analysis.facts.is_empty() {
        analysis
            .inferred
            .push("no family-pack facts were derived from fused source evidence".into());
    } else {
        analysis
            .inferred
            .push("family-pack facts derived from fused source evidence".into());
    }
    analysis
}

fn is_gpu_lifecycle_method(lower: &str) -> bool {
    // Strong GPU context: terms that are unambiguously GPU/graphics-related
    let strong_gpu = lower.contains("gpu")
        || lower.contains("vulkan")
        || lower.contains("opengl")
        || lower.contains("webgpu")
        || lower.contains("wgpu")
        || lower.contains("dawn")
        || lower.contains("angle")
        || lower.contains("metal")
        || lower.contains("shader")
        || lower.contains("texture")
        || lower.contains("rendertarget")
        || lower.contains("renderpass")
        || lower.contains("framebuffer")
        || lower.contains("swapchain");

    // Only strong GPU terms establish context. Generic terms like "device",
    // "buffer", "render" appear in non-GPU code (Linux device drivers, I/O
    // buffers, UI rendering) and cause false positives even in combination.
    let has_gpu_context = strong_gpu;
    if !has_gpu_context {
        return false;
    }
    lower.contains("map")
        || lower.contains("unmap")
        || lower.contains("destroy")
        || lower.contains("submit")
        || lower.contains("lost")
}

fn push_fact(
    analysis: &mut DerivedAnalysis,
    family_pack: FamilyPack,
    kind: &str,
    subject: &str,
    evidence_basis: EvidenceBasis,
    detail: impl Into<String>,
) {
    *analysis
        .family_scores
        .entry(family_pack.as_str().to_string())
        .or_insert(0) += 1;
    analysis.facts.push(DerivedFact {
        family_pack,
        kind: kind.to_string(),
        subject: subject.to_string(),
        source_file: None,
        evidence_basis,
        detail: detail.into(),
    });
}

/// Group derived facts by (subject, source_file) so that same-named functions
/// in different files get separate fact buckets.
pub fn group_facts_by_subject(analysis: &DerivedAnalysis) -> BTreeMap<String, Vec<DerivedFact>> {
    let mut grouped = BTreeMap::new();
    for fact in &analysis.facts {
        let key = fact_grouping_key(&fact.subject, fact.source_file.as_deref());
        grouped
            .entry(key)
            .or_insert_with(Vec::new)
            .push(fact.clone());
    }
    grouped
}

/// Produce a grouping key that includes the source file when available,
/// so same-named functions in different files get distinct fact buckets.
pub fn fact_grouping_key(subject: &str, source_file: Option<&std::path::Path>) -> String {
    match source_file {
        Some(file) => format!("{}@{}", subject, file.display()),
        None => subject.to_string(),
    }
}

fn is_ownership_transfer_term(lower: &str) -> bool {
    lower.contains("enqueue")
        || lower.contains("queue")
        || lower.contains("submit")
        || lower.contains("dispatch")
        || lower.contains("handoff")
        || lower.contains("transfer")
        || lower.contains("deliver")
        || lower.contains("consume")
        || lower.contains("proc_transaction")
}

fn is_deferred_or_pending_term(lower: &str) -> bool {
    lower.contains("pending")
        || lower.contains("deferred")
        || lower.contains("frozen")
        || lower.contains("queued")
}

fn is_post_handoff_observer_term(lower: &str) -> bool {
    lower.contains("report")
        || lower.contains("trace")
        || lower.contains("notify")
        || lower.contains("dump")
        || lower.contains("metrics")
        || lower.contains("log")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::result::{FusedSourceEvidence, SourceMethodFact};
    use std::path::PathBuf;

    fn make_method(name: &str) -> SourceMethodFact {
        SourceMethodFact {
            qualified_name: name.to_string(),
            signature_hash: String::new(),
            file: PathBuf::from("test.c"),
            line: 1,
            begin_line: 1,
            end_line: 10,
        }
    }

    fn make_fused_with_methods(names: &[&str]) -> FusedSourceEvidence {
        let mut fused = FusedSourceEvidence::default();
        for name in names {
            fused.methods.push(make_method(name));
        }
        fused
    }

    #[test]
    fn generic_map_destroy_should_not_trigger_gpu_classification() {
        let fused = make_fused_with_methods(&[
            "hashTableDestroy",
            "hamt_node_bitmap_assoc",
            "mmap",
            "mapReduce",
            "UnmapViewOfFile",
            // Reviewer repro: single weak term "device" + lifecycle verb "map"
            // should NOT match without strong GPU context
            "device_map_memory",
            "buffer_destroy",
            "submit_request",
        ]);
        let derived = derive_from_fused_source(&fused);
        let gpu_facts: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "gpu_protocol_lifecycle_method")
            .collect();
        assert!(
            gpu_facts.is_empty(),
            "generic map/destroy functions should NOT be classified as GPU protocol. Got: {:?}",
            gpu_facts.iter().map(|f| &f.subject).collect::<Vec<_>>()
        );
    }

    #[test]
    fn actual_gpu_methods_should_trigger_gpu_classification() {
        let fused = make_fused_with_methods(&[
            "gpu_buffer_destroy",
            "wgpuDeviceCreateBuffer",
            "dawn_texture_unmap",
        ]);
        let derived = derive_from_fused_source(&fused);
        let gpu_facts: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "gpu_protocol_lifecycle_method")
            .collect();
        assert!(
            !gpu_facts.is_empty(),
            "actual GPU methods should be classified as GPU protocol"
        );
    }

    #[test]
    fn validation_matches_broader_terms() {
        let fused = make_fused_with_methods(&[
            "verify_signature",
            "authorize_request",
            "sanitize_input",
            "check_access_permission",
        ]);
        let derived = derive_from_fused_source(&fused);
        let validation_facts: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "validation_or_permission_method")
            .collect();
        assert!(
            validation_facts.len() >= 3,
            "verify/authorize/sanitize/check_access should match validation family. Got {} matches: {:?}",
            validation_facts.len(),
            validation_facts.iter().map(|f| &f.subject).collect::<Vec<_>>()
        );
    }

    #[test]
    fn two_weak_gpu_terms_should_not_trigger_gpu_classification() {
        // Reviewer repro: device_buffer_destroy has "device" + "buffer" (2 weak terms)
        // + "destroy" (lifecycle verb). Should NOT match without strong GPU context.
        let fused = make_fused_with_methods(&["device_buffer_destroy"]);
        let derived = derive_from_fused_source(&fused);
        let gpu_facts: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "gpu_protocol_lifecycle_method")
            .collect();
        assert!(
            gpu_facts.is_empty(),
            "device_buffer_destroy should NOT be GPU — 'device' and 'buffer' are generic systems terms. Got: {:?}",
            gpu_facts.iter().map(|f| &f.subject).collect::<Vec<_>>()
        );
    }

    #[test]
    fn generic_helper_should_not_produce_validation_lead() {
        // Reviewer repro: check_type_auth() is a generic helper, not a trust-boundary.
        // It should NOT satisfy both validation primary facts from a single method name.
        let fused = make_fused_with_methods(&["check_type_auth"]);
        let derived = derive_from_fused_source(&fused);
        let validation_method: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "validation_or_permission_method")
            .collect();
        let permission_gate: Vec<_> = derived
            .facts
            .iter()
            .filter(|f| f.kind == "permission_gate_present")
            .collect();
        // At most one of the two primary facts should fire from a single method name
        assert!(
            validation_method.is_empty() || permission_gate.is_empty(),
            "a single generic helper should not satisfy both validation primary facts. \
             validation_or_permission_method={}, permission_gate_present={}",
            validation_method.len(),
            permission_gate.len()
        );
    }
}
