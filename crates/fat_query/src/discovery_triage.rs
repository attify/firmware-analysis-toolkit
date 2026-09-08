use fat_core::discovery::{DiscoveryLifecycleStatus, DiscoveryOutcomeClass, TriageRecord};

use fat_core::discovery::HarnessAttemptRecord;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TriageInput {
    CapturedOutput {
        stdout: String,
        stderr: String,
        exit_code: Option<i32>,
    },
    BlockedByLocality {
        reason: String,
    },
}

pub fn normalize_triage(attempt: &HarnessAttemptRecord, input: TriageInput) -> TriageRecord {
    let (outcome, summary) = match input {
        TriageInput::BlockedByLocality { reason } => (
            DiscoveryOutcomeClass::BlockedByLocality,
            format!("blocked by locality: {reason}"),
        ),
        TriageInput::CapturedOutput {
            stdout,
            stderr,
            exit_code,
        } => {
            let outcome = classify_captured_output(&stdout, &stderr, exit_code);
            let summary = build_captured_output_summary(outcome, &stdout, &stderr, exit_code);
            (outcome, summary)
        }
    };

    let lifecycle = if outcome.requires_review() {
        DiscoveryLifecycleStatus::NeedsReview
    } else {
        DiscoveryLifecycleStatus::Completed
    };

    TriageRecord {
        triage_id: format!("triage::{}", attempt.harness_attempt_id),
        harness_attempt_id: attempt.harness_attempt_id.clone(),
        lifecycle,
        outcome: Some(outcome),
        attempt_plan_hash: attempt.attempt_plan_hash.clone(),
        artifact_root: attempt.artifact_root.clone(),
        retry_count: attempt.retry_count,
        state_hypothesis_id: attempt.state_hypothesis_id.clone(),
        forbidden_transition_id: attempt.forbidden_transition_id.clone(),
        attempted_transition_summary: attempt.attempted_transition_summary.clone(),
        summary,
    }
}

fn build_captured_output_summary(
    outcome: DiscoveryOutcomeClass,
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> String {
    let mut details = vec![format!(
        "exit_code={}",
        exit_code
            .map(|code| code.to_string())
            .unwrap_or_else(|| "none".into())
    )];
    if let Some(lifetime_detail) = extract_lifetime_detail(stdout, stderr) {
        details.push(lifetime_detail);
    }
    format!("{} ({})", outcome.as_str(), details.join("; "))
}

fn classify_captured_output(
    stdout: &str,
    stderr: &str,
    exit_code: Option<i32>,
) -> DiscoveryOutcomeClass {
    let combined = format!("{stdout}\n{stderr}").to_ascii_lowercase();
    if combined.contains("addresssanitizer") && combined.contains("use-after-free") {
        return DiscoveryOutcomeClass::AsanUseAfterFree;
    }
    if combined.contains("addresssanitizer") && combined.contains("heap-buffer-overflow") {
        return DiscoveryOutcomeClass::AsanHeapBufferOverflow;
    }
    if combined.contains("runtime error:") && combined.contains("integer overflow") {
        return DiscoveryOutcomeClass::UbsanIntegerOverflow;
    }
    if combined.contains("received bad user message") || combined.contains("bad message") {
        return DiscoveryOutcomeClass::BadMessage;
    }
    if combined.contains("ktap version") && combined.contains("not ok") {
        return DiscoveryOutcomeClass::GuardTrip;
    }
    if combined.contains("check failed:")
        || combined.contains("dcheck")
        || combined.contains("guard trip")
    {
        return DiscoveryOutcomeClass::GuardTrip;
    }
    if exit_code == Some(0) {
        return DiscoveryOutcomeClass::NoSignal;
    }
    DiscoveryOutcomeClass::Flaky
}

fn extract_lifetime_detail(stdout: &str, stderr: &str) -> Option<String> {
    let combined = format!("{stdout}\n{stderr}");
    let normalized = combined.to_ascii_lowercase();
    if !normalized.contains("lifetime markers:") {
        return None;
    }

    let markers = combined
        .lines()
        .find_map(|line| {
            let trimmed = line.trim();
            let (_, markers) = trimmed.split_once("lifetime markers:")?;
            Some(markers.trim().to_ascii_lowercase())
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "none".into());

    let stale_access_observed =
        normalized.contains("lifetime stale access observed without native proof");
    let sequence_observed = stale_access_observed
        || normalized.contains("lifetime sequence observed without native proof")
        || normalized.contains("guard trip: observed lifetime sequence before timeout");

    if stale_access_observed {
        return Some(format!("lifetime-stale-access-observed; markers={markers}"));
    }

    if sequence_observed {
        return Some(format!("lifetime-sequence-observed; markers={markers}"));
    }

    Some(format!("markers={markers}"))
}
