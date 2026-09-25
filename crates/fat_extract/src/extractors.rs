use std::ffi::OsString;
use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::command::{command_available, run_logged_command, CommandOutcome};
use crate::evidence::CarvedEvidence;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractStatus {
    Succeeded,
    Failed,
    Skipped,
    TimedOut,
}

impl ExtractStatus {
    pub fn succeeded(self) -> bool {
        matches!(self, Self::Succeeded)
    }

    pub fn attempted(self) -> bool {
        !matches!(self, Self::Skipped)
    }
}

/// One extractor's contribution to a run.
#[derive(Debug, Clone)]
pub struct ExtractionOutcome {
    pub extractor: String,
    pub status: ExtractStatus,
    /// Why it was skipped, or what it recovered. Reported verbatim.
    pub detail: Option<String>,
    pub evidence: CarvedEvidence,
    pub duration: Duration,
    /// Whether this extractor shells out to a tool the host must provide.
    pub requires_external_tool: bool,
    /// Exact arguments the extractor was invoked with, for reproducibility.
    pub args: Vec<String>,
    pub artifacts: Vec<crate::pipeline::ArtifactRecord>,
    pub incomplete: bool,
}

impl ExtractionOutcome {
    pub fn new(extractor: impl Into<String>, status: ExtractStatus) -> Self {
        Self {
            extractor: extractor.into(),
            status,
            detail: None,
            evidence: CarvedEvidence::default(),
            duration: Duration::ZERO,
            requires_external_tool: true,
            args: Vec::new(),
            artifacts: Vec::new(),
            incomplete: false,
        }
    }

    pub fn with_detail(mut self, detail: impl Into<String>) -> Self {
        self.detail = Some(detail.into());
        self
    }

    pub fn with_evidence(mut self, evidence: CarvedEvidence) -> Self {
        self.evidence = evidence;
        self
    }

    pub fn with_duration(mut self, duration: Duration) -> Self {
        self.duration = duration;
        self
    }

    pub fn with_args(mut self, args: Vec<String>) -> Self {
        self.args = args;
        self
    }
}

/// What an extractor has to produce before the chain stops asking others.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Sufficiency {
    /// Only a mounted-and-walkable rootfs preempts later extractors.
    RootfsOnly,
    /// Any carved candidate — rootfs, boot artifacts, filesystem images.
    AnyCarvedEvidence,
}

impl Sufficiency {
    pub fn is_met(self, evidence: &CarvedEvidence) -> bool {
        match self {
            Self::RootfsOnly => evidence.has_rootfs(),
            Self::AnyCarvedEvidence => evidence.has_carved_candidates(),
        }
    }
}

pub struct ExtractionRequest {
    pub firmware: PathBuf,
    pub work_dir: PathBuf,
    pub log_path: PathBuf,
    pub timeout: Option<Duration>,
}

pub trait Extractor: Send + Sync {
    fn id(&self) -> &str;

    /// Whether the tool this extractor drives is present on the host.
    fn available(&self) -> bool {
        command_available(self.id())
    }

    /// False for extractors implemented inside FAT, which cannot be "missing".
    fn requires_external_tool(&self) -> bool {
        true
    }

    fn work_dir(&self, extraction_root: &Path) -> PathBuf {
        extraction_root.join(self.id())
    }

    fn log_path(&self, log_root: &Path) -> PathBuf {
        log_root.join(format!("{}.log", self.id()))
    }

    fn sufficiency(&self) -> Sufficiency {
        Sufficiency::AnyCarvedEvidence
    }

    /// How this extractor is named when it preempts a later one, as the
    /// "because" clause of `skipped <other> because <this>`.
    fn precedence_reason(&self, evidence: &CarvedEvidence) -> Option<String> {
        evidence
            .precedence_phrase()
            .map(|phrase| format!("{} already {phrase}", self.id()))
    }

    fn extract(
        &self,
        request: &ExtractionRequest,
        on_tick: &mut dyn FnMut(Duration),
    ) -> ExtractionOutcome;
}

#[derive(Default)]
pub struct ExtractorRegistry {
    extractors: Vec<Box<dyn Extractor>>,
}

impl ExtractorRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register<E>(&mut self, extractor: E)
    where
        E: Extractor + 'static,
    {
        self.extractors.push(Box::new(extractor));
    }

    pub fn iter(&self) -> impl Iterator<Item = &dyn Extractor> {
        self.extractors.iter().map(|extractor| extractor.as_ref())
    }

    pub fn ids(&self) -> Vec<String> {
        self.extractors
            .iter()
            .map(|extractor| extractor.id().to_string())
            .collect()
    }

    pub fn is_empty(&self) -> bool {
        self.extractors.is_empty()
    }
}

/// Which extractors a run is allowed to use.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExtractorSelection {
    /// Priority chain with preemption — the default.
    Auto,
    /// One named extractor; everything else is skipped.
    Only(String),
    /// Every extractor runs, whatever the earlier ones recovered.
    All,
}

impl ExtractorSelection {
    /// Parse `--extractor`. `both` is accepted as a spelling of `all`.
    pub fn parse(value: &str, known_ids: &[String]) -> Result<Self, String> {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            "auto" => Ok(Self::Auto),
            "all" | "both" => Ok(Self::All),
            id if known_ids.iter().any(|known| known == id) => Ok(Self::Only(id.to_string())),
            other => Err(format!(
                "unsupported extractor: {other} (expected auto, all, or one of {})",
                known_ids.join(", ")
            )),
        }
    }

    pub fn includes(&self, id: &str) -> bool {
        match self {
            Self::Auto | Self::All => true,
            Self::Only(selected) => selected == id,
        }
    }

    pub fn preempts(&self) -> bool {
        matches!(self, Self::Auto)
    }
}

pub struct StrategyContext {
    pub firmware: PathBuf,
    pub extraction_root: PathBuf,
    /// Directory holding the per-extractor logs (`work/`).
    pub log_root: PathBuf,
    pub timeout: Option<Duration>,
}

/// Run the extraction chain and report what every extractor did.
///
/// In `Auto` the first extractor whose evidence meets its own sufficiency bar
/// preempts the rest, and each skipped extractor's log records why — the
/// decision is never invisible. `All` disables preemption so a false positive in
/// an earlier engine cannot suppress a later one.
pub fn run_extraction_strategy(
    registry: &ExtractorRegistry,
    selection: &ExtractorSelection,
    context: &StrategyContext,
    on_tick: &mut dyn FnMut(&str, Duration),
) -> Vec<ExtractionOutcome> {
    let mut outcomes = Vec::new();
    let mut preempted_by: Option<String> = None;

    for extractor in registry.iter() {
        let id = extractor.id().to_string();

        if !selection.includes(&id) {
            let reason = match selection {
                ExtractorSelection::Only(selected) => {
                    format!("--extractor {selected} selected instead")
                }
                _ => "not selected".to_string(),
            };
            outcomes.push(skip(extractor, &reason, &context.log_root));
            continue;
        }

        if let Some(reason) = &preempted_by {
            outcomes.push(skip(extractor, reason, &context.log_root));
            continue;
        }

        let request = ExtractionRequest {
            firmware: context.firmware.clone(),
            work_dir: extractor.work_dir(&context.extraction_root),
            log_path: extractor.log_path(&context.log_root),
            timeout: context.timeout,
        };
        let mut tick = |elapsed: Duration| on_tick(&id, elapsed);
        let mut outcome = extractor.extract(&request, &mut tick);
        // The registry, not the implementation, is the authority on whether a
        // failure here means "install a tool".
        outcome.requires_external_tool = extractor.requires_external_tool();

        if selection.preempts()
            && outcome.status.succeeded()
            && !outcome.incomplete
            && extractor.sufficiency().is_met(&outcome.evidence)
        {
            preempted_by = extractor.precedence_reason(&outcome.evidence);
        }
        outcomes.push(outcome);
    }

    outcomes
}

/// Record a skip in the skipped extractor's own log, so the reason is where a
/// reader looking for that engine's output would go first.
fn skip(extractor: &dyn Extractor, reason: &str, log_root: &Path) -> ExtractionOutcome {
    let log_path = extractor.log_path(log_root);
    if let Some(parent) = log_path.parent() {
        let _ = fs::create_dir_all(parent);
    }
    let _ = fs::write(
        &log_path,
        format!("skipped {} because {reason}\n", extractor.id()),
    );
    ExtractionOutcome {
        requires_external_tool: extractor.requires_external_tool(),
        ..ExtractionOutcome::new(extractor.id(), ExtractStatus::Skipped).with_detail(reason)
    }
}

/// Tuning a caller can hand to an external extractor. Options are forwarded
/// only when set, so the default invocation stays exactly what the tool would
/// do on its own.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ExternalExtractorOptions {
    /// Worker processes, for hosts where the tool's own default over- or
    /// under-subscribes.
    pub processes: Option<u32>,
    /// How deep to recurse into nested containers.
    pub max_depth: Option<u32>,
}

impl ExternalExtractorOptions {
    pub fn is_empty(&self) -> bool {
        self.processes.is_none() && self.max_depth.is_none()
    }
}

/// An extractor that shells out to a carving tool with `-e`.
pub struct ExternalExtractor {
    id: &'static str,
    args: fn(firmware: &Path, work_dir: &Path) -> Vec<OsString>,
    tuning: fn(options: &ExternalExtractorOptions) -> Vec<OsString>,
    options: ExternalExtractorOptions,
}

impl ExternalExtractor {
    pub fn binwalk() -> Self {
        Self {
            id: "binwalk",
            args: |firmware, _work_dir| {
                vec![OsString::from("-e"), firmware.as_os_str().to_os_string()]
            },
            // binwalk exposes no equivalent knobs, so tuning is ignored for it.
            tuning: |_options| Vec::new(),
            options: ExternalExtractorOptions::default(),
        }
    }

    pub fn unblob() -> Self {
        Self {
            id: "unblob",
            args: |firmware, work_dir| {
                vec![
                    OsString::from("-e"),
                    work_dir.as_os_str().to_os_string(),
                    firmware.as_os_str().to_os_string(),
                ]
            },
            tuning: |options| {
                let mut args = Vec::new();
                if let Some(processes) = options.processes {
                    args.push(OsString::from("--processes"));
                    args.push(OsString::from(processes.to_string()));
                }
                if let Some(depth) = options.max_depth {
                    args.push(OsString::from("--depth"));
                    args.push(OsString::from(depth.to_string()));
                }
                args
            },
            options: ExternalExtractorOptions::default(),
        }
    }

    pub fn with_options(mut self, options: ExternalExtractorOptions) -> Self {
        self.options = options;
        self
    }

    fn invocation(&self, firmware: &Path, work_dir: &Path) -> Vec<OsString> {
        let mut args = (self.tuning)(&self.options);
        args.extend((self.args)(firmware, work_dir));
        args
    }
}

impl Extractor for ExternalExtractor {
    fn id(&self) -> &str {
        self.id
    }

    fn sufficiency(&self) -> Sufficiency {
        Sufficiency::RootfsOnly
    }

    fn extract(
        &self,
        request: &ExtractionRequest,
        on_tick: &mut dyn FnMut(Duration),
    ) -> ExtractionOutcome {
        let started = Instant::now();
        if let Err(err) = fs::create_dir_all(&request.work_dir) {
            return ExtractionOutcome::new(self.id, ExtractStatus::Failed)
                .with_detail(format!(
                    "could not prepare {}: {err}",
                    request.work_dir.display()
                ))
                .with_duration(started.elapsed());
        }

        // Every extractor runs with its own extraction dir as cwd, so stray
        // relative output stays inside work/extractions.
        let invocation = self.invocation(&request.firmware, &request.work_dir);
        let rendered_args: Vec<String> = invocation
            .iter()
            .map(|arg| arg.to_string_lossy().into_owned())
            .collect();
        let mut attempts = 0;
        let outcome = loop {
            let elapsed = started.elapsed();
            let remaining = request.timeout.map(|limit| limit.saturating_sub(elapsed));
            if remaining == Some(Duration::ZERO) {
                break Ok(CommandOutcome::TimedOut);
            }
            attempts += 1;
            let outcome = run_logged_command(
                self.id,
                invocation.clone(),
                &request.work_dir,
                &request.log_path,
                remaining,
                &mut |tick| on_tick(elapsed + tick),
            );
            // Binwalk 3 can exit successfully before its queued worker starts.
            // Its explicit zero-file summary means the input was never scanned;
            // a completed scan with no signatures is a different, valid result.
            if self.id != "binwalk"
                || !matches!(outcome, Ok(CommandOutcome::Succeeded))
                || !binwalk_analyzed_zero_files(&request.log_path)
            {
                break outcome;
            }
            // A fresh cwd avoids the input-symlink collision in Binwalk 3.1.0.
            // Keep incomplete output outside the extraction tree so it cannot
            // be mistaken for evidence from the completed scan.
            if let Err(err) = preserve_binwalk_attempt(request, attempts) {
                break Err(err);
            }
            if attempts == 3 {
                return ExtractionOutcome::new(self.id, ExtractStatus::Failed)
                    .with_detail("Binwalk analyzed zero files in all 3 attempts")
                    .with_duration(started.elapsed())
                    .with_args(rendered_args);
            }
        };
        let duration = started.elapsed();

        match outcome {
            Ok(CommandOutcome::Succeeded) => {
                let evidence = CarvedEvidence::survey(&request.work_dir);
                ExtractionOutcome::new(self.id, ExtractStatus::Succeeded)
                    .with_detail(if attempts > 1 {
                        format!("{} after retry ({} attempts)", evidence.summary(), attempts)
                    } else {
                        evidence.summary().to_owned()
                    })
                    .with_evidence(evidence)
                    .with_duration(duration)
                    .with_args(rendered_args)
            }
            Ok(CommandOutcome::TimedOut) => {
                ExtractionOutcome::new(self.id, ExtractStatus::TimedOut)
                    .with_duration(duration)
                    .with_args(rendered_args)
            }
            Ok(CommandOutcome::Failed) => {
                let mut outcome = ExtractionOutcome::new(self.id, ExtractStatus::Failed)
                    .with_duration(duration)
                    .with_args(rendered_args);
                if !self.available() {
                    outcome = outcome.with_detail("not installed");
                }
                outcome
            }
            Err(err) => ExtractionOutcome::new(self.id, ExtractStatus::Failed)
                .with_detail(err.to_string())
                .with_duration(duration),
        }
    }
}

/// Read only the log tail: extractor output can be much larger than the input.
fn binwalk_analyzed_zero_files(log_path: &Path) -> bool {
    let read_tail = || -> io::Result<Vec<u8>> {
        let mut log = fs::File::open(log_path)?;
        let start = log.metadata()?.len().saturating_sub(4096);
        log.seek(SeekFrom::Start(start))?;
        let mut tail = Vec::new();
        log.take(4096).read_to_end(&mut tail)?;
        Ok(tail)
    };
    read_tail().is_ok_and(|tail| {
        String::from_utf8_lossy(&tail)
            .lines()
            .any(|line| line.trim().starts_with("Analyzed 0 files for "))
    })
}

fn preserve_binwalk_attempt(request: &ExtractionRequest, attempt: usize) -> io::Result<()> {
    let nested_log = request.log_path.strip_prefix(&request.work_dir).ok();
    let archive_base = if nested_log.is_some() {
        &request.work_dir
    } else {
        &request.log_path
    };
    let mut sequence = attempt;
    let (output, log) = loop {
        let output = archive_base.with_extension(format!("attempt-{sequence}"));
        let log = archive_base.with_extension(format!("attempt-{sequence}.log"));
        if !output.try_exists()? && !log.try_exists()? {
            break (output, log);
        }
        sequence += 1;
    };
    fs::rename(&request.work_dir, &output)?;
    let moved_log = nested_log.map(|relative| output.join(relative));
    fs::rename(moved_log.as_deref().unwrap_or(&request.log_path), &log)?;
    fs::create_dir_all(&request.work_dir)?;
    if let Some(parent) = request.log_path.parent() {
        fs::create_dir_all(parent)?;
    }
    // Keep the primary log useful even when the final attempt was incomplete.
    fs::write(
        &request.log_path,
        format!(
            "Binwalk analyzed zero files; incomplete output and log preserved at {}\n",
            log.display()
        ),
    )
}
