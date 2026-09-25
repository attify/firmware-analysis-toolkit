use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::Duration;

use fat_extract::evidence::CarvedEvidence;
use fat_extract::extractors::{
    run_extraction_strategy, ExtractStatus, ExtractionOutcome, ExtractionRequest, Extractor,
    ExtractorRegistry, ExtractorSelection, StrategyContext, Sufficiency,
};
use tempfile::tempdir;

/// An extractor that records whether it ran and reports canned evidence, so the
/// strategy can be exercised without binwalk or unblob installed.
struct StubExtractor {
    id: &'static str,
    status: ExtractStatus,
    evidence: CarvedEvidence,
    sufficiency: Sufficiency,
    runs: Arc<AtomicUsize>,
    incomplete: bool,
}

impl StubExtractor {
    fn new(id: &'static str, evidence: CarvedEvidence) -> Self {
        Self {
            id,
            status: ExtractStatus::Succeeded,
            evidence,
            sufficiency: Sufficiency::AnyCarvedEvidence,
            runs: Arc::new(AtomicUsize::new(0)),
            incomplete: false,
        }
    }

    fn with_sufficiency(mut self, sufficiency: Sufficiency) -> Self {
        self.sufficiency = sufficiency;
        self
    }

    fn with_status(mut self, status: ExtractStatus) -> Self {
        self.status = status;
        self
    }

    fn runs(&self) -> Arc<AtomicUsize> {
        Arc::clone(&self.runs)
    }
}

impl Extractor for StubExtractor {
    fn id(&self) -> &str {
        self.id
    }

    fn available(&self) -> bool {
        true
    }

    fn sufficiency(&self) -> Sufficiency {
        self.sufficiency
    }

    fn extract(
        &self,
        _request: &ExtractionRequest,
        _on_tick: &mut dyn FnMut(Duration),
    ) -> ExtractionOutcome {
        self.runs.fetch_add(1, Ordering::SeqCst);
        let mut outcome = ExtractionOutcome::new(self.id, self.status)
            .with_detail(self.evidence.summary())
            .with_evidence(self.evidence.clone());
        outcome.incomplete = self.incomplete;
        outcome
    }
}

fn rootfs_evidence() -> CarvedEvidence {
    CarvedEvidence {
        rootfs: Some(PathBuf::from("/carved/squashfs-root")),
        file_count: 12,
        ..CarvedEvidence::default()
    }
}

#[test]
fn a_recovered_tree_with_an_unresolved_sibling_does_not_stop_fallback() {
    let mut first = StubExtractor::new("first", rootfs_evidence());
    first.incomplete = true;
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(first);
    registry.register(second);
    run(&registry, &ExtractorSelection::Auto, &harness());
    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
}

fn image_evidence() -> CarvedEvidence {
    CarvedEvidence {
        filesystem_images: 1,
        file_count: 1,
        ..CarvedEvidence::default()
    }
}

fn nothing_evidence() -> CarvedEvidence {
    CarvedEvidence::default()
}

struct Harness {
    _dir: tempfile::TempDir,
    context: StrategyContext,
}

fn harness() -> Harness {
    let dir = tempdir().expect("work dir");
    let context = StrategyContext {
        firmware: dir.path().join("firmware.bin"),
        extraction_root: dir.path().join("extractions"),
        log_root: dir.path().to_path_buf(),
        timeout: None,
    };
    Harness { _dir: dir, context }
}

fn run(
    registry: &ExtractorRegistry,
    selection: &ExtractorSelection,
    harness: &Harness,
) -> Vec<ExtractionOutcome> {
    run_extraction_strategy(registry, selection, &harness.context, &mut |_, _| {})
}

#[test]
fn auto_stops_after_an_extractor_recovers_enough() {
    let first = StubExtractor::new("first", rootfs_evidence());
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(first);
    registry.register(second);

    let harness = harness();
    let outcomes = run(&registry, &ExtractorSelection::Auto, &harness);

    assert_eq!(second_runs.load(Ordering::SeqCst), 0, "second must not run");
    assert_eq!(outcomes[1].status, ExtractStatus::Skipped);
    assert_eq!(
        outcomes[1].detail.as_deref(),
        Some("first already recovered a rootfs")
    );
}

#[test]
fn a_skipped_extractor_records_why_in_its_own_log() {
    let mut registry = ExtractorRegistry::new();
    registry.register(StubExtractor::new("first", rootfs_evidence()));
    registry.register(StubExtractor::new("second", rootfs_evidence()));

    let harness = harness();
    run(&registry, &ExtractorSelection::Auto, &harness);

    let log = std::fs::read_to_string(harness.context.log_root.join("second.log")).expect("log");
    assert_eq!(
        log,
        "skipped second because first already recovered a rootfs\n"
    );
}

#[test]
fn auto_continues_when_an_extractor_recovers_nothing() {
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(StubExtractor::new("first", nothing_evidence()));
    registry.register(second);

    let harness = harness();
    let outcomes = run(&registry, &ExtractorSelection::Auto, &harness);

    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
    assert!(outcomes.iter().all(|outcome| outcome.status.attempted()));
}

#[test]
fn rootfs_only_sufficiency_does_not_preempt_on_carved_images() {
    // Native carving that finds a kernel but no rootfs must leave the external
    // engines their turn.
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(
        StubExtractor::new("first", image_evidence()).with_sufficiency(Sufficiency::RootfsOnly),
    );
    registry.register(second);

    let harness = harness();
    run(&registry, &ExtractorSelection::Auto, &harness);

    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
}

#[test]
fn a_failed_extractor_never_preempts_the_next_one() {
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(
        StubExtractor::new("first", rootfs_evidence()).with_status(ExtractStatus::Failed),
    );
    registry.register(second);

    let harness = harness();
    run(&registry, &ExtractorSelection::Auto, &harness);

    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
}

#[test]
fn all_runs_every_extractor_regardless_of_earlier_evidence() {
    let second = StubExtractor::new("second", rootfs_evidence());
    let second_runs = second.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(StubExtractor::new("first", rootfs_evidence()));
    registry.register(second);

    let harness = harness();
    let outcomes = run(&registry, &ExtractorSelection::All, &harness);

    assert_eq!(second_runs.load(Ordering::SeqCst), 1);
    assert!(outcomes
        .iter()
        .all(|outcome| outcome.status == ExtractStatus::Succeeded));
}

#[test]
fn only_runs_the_named_extractor_and_says_so() {
    let first = StubExtractor::new("first", rootfs_evidence());
    let first_runs = first.runs();
    let mut registry = ExtractorRegistry::new();
    registry.register(first);
    registry.register(StubExtractor::new("second", rootfs_evidence()));

    let harness = harness();
    let outcomes = run(
        &registry,
        &ExtractorSelection::Only("second".to_string()),
        &harness,
    );

    assert_eq!(first_runs.load(Ordering::SeqCst), 0);
    assert_eq!(outcomes[0].status, ExtractStatus::Skipped);
    assert_eq!(
        outcomes[0].detail.as_deref(),
        Some("--extractor second selected instead")
    );
    assert_eq!(outcomes[1].status, ExtractStatus::Succeeded);
}

#[test]
fn selection_parsing_accepts_known_engines_and_rejects_the_rest() {
    let known = vec!["native".to_string(), "binwalk".to_string()];
    assert_eq!(
        ExtractorSelection::parse("auto", &known),
        Ok(ExtractorSelection::Auto)
    );
    assert_eq!(
        ExtractorSelection::parse("BINWALK", &known),
        Ok(ExtractorSelection::Only("binwalk".to_string()))
    );
    // `both` is the spelling the suppression problem is usually described with.
    assert_eq!(
        ExtractorSelection::parse("both", &known),
        Ok(ExtractorSelection::All)
    );
    assert_eq!(
        ExtractorSelection::parse("all", &known),
        Ok(ExtractorSelection::All)
    );
    assert!(ExtractorSelection::parse("unblob", &known).is_err());
}
