use std::error::Error;
use std::fs;
use std::io::Read;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clap::Subcommand;
use fat_core::artifacts::{ArtifactHashes, ArtifactKind, ArtifactRecord, ArtifactRetentionPolicy};
use fat_core::database::ProjectDb;
use fat_core::experiment::{
    validate_experiment_bundle, validate_started_bundle, ExperimentBundle,
    ExperimentValidationError,
};
use fat_core::experiment_selector::{select_compatibility, SelectionRequest};
use fat_core::external_campaign::{
    validate_external_campaign, ExternalCampaignManifest, ExternalCampaignValidationError,
    ExternalReplayCase,
};
use fat_core::project::Project;
use fat_core::runs::{GoalProgressDelta, RunOrigin, RunRecord, RunStatus, SubstrateKind};
use fat_core::runtime_store::{ExperimentCatalogEntry, RuntimeStore};
use fat_core::sessions::{GoalProgress, SessionOrigin, SessionRecord, SessionStatus};
use fat_core::targets::derive_target_id;
use serde::Serialize;
use sha2::{Digest, Sha256};
use wait_timeout::ChildExt;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Subcommand)]
pub enum ExperimentCommand {
    /// Validate or run a pinned campaign owned by an external engine.
    External {
        #[command(subcommand)]
        command: ExternalCampaignCommand,
    },
    /// Validate a standalone experiment bundle without writing project state.
    Validate {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Import an already-finalized experiment bundle into a FAT project.
    Import {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Persist the immutable launch state before execution begins.
    Start {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Finalize an experiment against its stored immutable launch.
    Finalize {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show a finalized experiment record, or its started launch when no final exists.
    Show {
        #[arg(long)]
        project: PathBuf,
        #[arg(long = "id")]
        experiment_id: String,
        #[arg(long = "record-digest")]
        record_digest: Option<String>,
        #[arg(long)]
        json: bool,
    },
    /// List immutable experiment launches and finalized record digests in a project.
    List {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Select and explain compatible machine, kernel, and guest candidates.
    Select {
        #[arg(long)]
        request: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Subcommand)]
pub enum ExternalCampaignCommand {
    /// Validate setup artifacts, replay inputs, evidence, and cleanup declarations.
    Validate {
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Run one pinned replay case and persist its input, logs, evidence, and cleanup result.
    Run {
        #[arg(long)]
        project: PathBuf,
        #[arg(long)]
        file: PathBuf,
        #[arg(long)]
        root: PathBuf,
        #[arg(long = "case")]
        case_id: String,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct ValidationReport<'a> {
    schema_version: &'static str,
    operation: &'static str,
    valid: bool,
    experiment_id: Option<&'a str>,
    record_digest: Option<&'a str>,
    verdict: &'a str,
    errors: &'a [ExperimentValidationError],
}

#[derive(Debug, Serialize)]
struct PersistReport<'a> {
    schema_version: &'static str,
    operation: &'static str,
    experiment_id: &'a str,
    record_digest: Option<&'a str>,
    path: String,
}

#[derive(Debug, Serialize)]
struct ListReport {
    schema_version: &'static str,
    operation: &'static str,
    experiments: Vec<ExperimentCatalogEntry>,
}

#[derive(Debug, Serialize)]
struct ExternalValidationReport<'a> {
    schema_version: &'static str,
    operation: &'static str,
    valid: bool,
    campaign_id: &'a str,
    checked_artifacts: usize,
    errors: &'a [ExternalCampaignValidationError],
}

#[derive(Debug, Serialize)]
struct ExternalRunReport {
    schema_version: &'static str,
    operation: &'static str,
    campaign_id: String,
    case_id: String,
    session_id: String,
    run_id: String,
    command: Vec<String>,
    input_sha256: String,
    exit_code: Option<i32>,
    timed_out: bool,
    error: Option<String>,
    expected_outcome: bool,
    cleanup: ExternalCleanupReport,
}

#[derive(Debug, Serialize)]
struct ExternalCleanupReport {
    command: Vec<String>,
    status: &'static str,
    exit_code: Option<i32>,
    timed_out: bool,
    error: Option<String>,
}

#[derive(Debug)]
struct CapturedCommand {
    stdout: Vec<u8>,
    stderr: Vec<u8>,
    exit_code: Option<i32>,
    success: bool,
    timed_out: bool,
    error: Option<String>,
}

pub fn run(command: ExperimentCommand) -> DynResult<()> {
    match command {
        ExperimentCommand::External { command } => run_external(command),
        ExperimentCommand::Validate { file, json } => validate(&file, json),
        ExperimentCommand::Import {
            project,
            file,
            json,
        } => import(&project, &file, json),
        ExperimentCommand::Start {
            project,
            file,
            json,
        } => start(&project, &file, json),
        ExperimentCommand::Finalize {
            project,
            file,
            json,
        } => finalize(&project, &file, json),
        ExperimentCommand::Show {
            project,
            experiment_id,
            record_digest,
            json,
        } => show(&project, &experiment_id, record_digest.as_deref(), json),
        ExperimentCommand::List { project, json } => list(&project, json),
        ExperimentCommand::Select { request, json } => select(&request, json),
    }
}

fn run_external(command: ExternalCampaignCommand) -> DynResult<()> {
    match command {
        ExternalCampaignCommand::Validate { file, root, json } => {
            validate_external(&file, &root, json)
        }
        ExternalCampaignCommand::Run {
            project,
            file,
            root,
            case_id,
            json,
        } => run_external_case(&project, &file, &root, &case_id, json),
    }
}

fn validate_external(path: &Path, root: &Path, json: bool) -> DynResult<()> {
    let manifest = load_external_manifest(path)?;
    let validation = validate_external_campaign(&manifest, root);
    let checked_artifacts = validation.as_ref().copied().unwrap_or_default();
    let errors = validation.err().unwrap_or_default();
    let report = ExternalValidationReport {
        schema_version: "external-campaign-command/v1",
        operation: "validate",
        valid: errors.is_empty(),
        campaign_id: &manifest.campaign_id,
        checked_artifacts,
        errors: &errors,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if errors.is_empty() {
        println!("valid external campaign: {}", manifest.campaign_id);
        println!("checked artifacts: {checked_artifacts}");
    } else {
        println!("invalid external campaign: {}", path.display());
        for error in &errors {
            println!("  [{}] {}: {}", error.code, error.path, error.message);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "external campaign validation failed with {} error(s)",
            errors.len()
        )
        .into())
    }
}

fn load_external_manifest(path: &Path) -> DynResult<ExternalCampaignManifest> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read external campaign manifest {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes).map_err(|error| {
        format!("invalid external campaign JSON {}: {error}", path.display()).into()
    })
}

fn run_external_case(
    project_dir: &Path,
    manifest_path: &Path,
    root: &Path,
    case_id: &str,
    json: bool,
) -> DynResult<()> {
    let manifest = load_external_manifest(manifest_path)?;
    validate_external_campaign(&manifest, root).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| format!("[{}] {}: {}", error.code, error.path, error.message))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    let replay_case = manifest
        .cases
        .iter()
        .find(|candidate| candidate.id == case_id)
        .ok_or_else(|| format!("external campaign case {case_id} was not found"))?;

    let db = ProjectDb::open(project_dir)?;
    let project = load_project(&db, project_dir)?;
    let store = RuntimeStore::open(project_dir)?;
    let target_id = derive_target_id(&project.name, &project.firmware_name);
    let started_at = current_timestamp_string();
    let substrate_kind = substrate_kind(&manifest.engine.substrate_kind)?;
    let goal = format!(
        "external campaign {} case {} at {}",
        manifest.campaign_id, case_id, started_at
    );
    let mut session = SessionRecord::new(
        project.name.clone(),
        target_id,
        goal,
        "external-campaign",
        SessionOrigin::Imported,
        started_at.clone(),
    )
    .with_status(SessionStatus::Active);
    let mut run = RunRecord::new(
        session.session_id.clone(),
        format!("external:{}:{}", manifest.campaign_id, case_id),
        format!("external:{}", manifest.engine.name),
        substrate_kind,
        1,
        RunOrigin::Replay,
    )
    .with_status(RunStatus::Running)
    .with_started_at(Some(started_at.clone()));
    session = session.with_run_ids(vec![run.run_id.clone()]);
    store.write_session(&session)?;
    store.write_run(&run)?;

    let command = materialize_replay_command(replay_case, root);
    let replay_output = execute_command(&command, root, replay_case.timeout_seconds);
    let cleanup_command = materialize_command(&manifest.cleanup.command, root);
    let cleanup_output = execute_command(&cleanup_command, root, manifest.cleanup.timeout_seconds);
    let cleanup = cleanup_report(&cleanup_command, &cleanup_output);
    let exit_code = replay_output.exit_code;
    let expected_outcome = !replay_output.timed_out
        && replay_output.error.is_none()
        && exit_code.is_some_and(|code| replay_case.expected_exit_codes.contains(&code));

    let outputs_dir = store
        .run_path(&session.session_id, &run.run_id)
        .parent()
        .map(|path| path.join("outputs"))
        .ok_or("run path missing parent")?;
    fs::create_dir_all(&outputs_dir)?;
    let stdout_path = outputs_dir.join("external-replay.stdout");
    let stderr_path = outputs_dir.join("external-replay.stderr");
    let stdout = replay_output.stdout.as_slice();
    let stderr = replay_output.stderr.as_slice();
    fs::write(&stdout_path, stdout)?;
    fs::write(&stderr_path, stderr)?;

    let report = ExternalRunReport {
        schema_version: "external-campaign-command/v1",
        operation: "run",
        campaign_id: manifest.campaign_id.clone(),
        case_id: replay_case.id.clone(),
        session_id: session.session_id.clone(),
        run_id: run.run_id.clone(),
        command: command.clone(),
        input_sha256: replay_case.input.sha256.clone(),
        exit_code,
        timed_out: replay_output.timed_out,
        error: replay_output.error.clone(),
        expected_outcome,
        cleanup,
    };
    let report_path = outputs_dir.join("external-replay-result.json");
    let report_json = serde_json::to_vec_pretty(&report)?;
    fs::write(&report_path, &report_json)?;

    persist_external_run_artifacts(
        &store,
        &project,
        &session,
        &run,
        &manifest,
        manifest_path,
        root,
        replay_case,
        &stdout_path,
        stdout,
        &stderr_path,
        stderr,
        &report_path,
        &report_json,
    )?;

    let cleanup_passed = report.cleanup.status == "passed";
    let finished_at = current_timestamp_string();
    run = run
        .with_status(if !cleanup_passed {
            RunStatus::CleanupFailed
        } else if expected_outcome {
            RunStatus::Completed
        } else {
            RunStatus::Failed
        })
        .with_finished_at(Some(finished_at.clone()))
        .with_goal_progress_delta(GoalProgressDelta::new(
            GoalProgress::NotStarted,
            if expected_outcome && cleanup_passed {
                GoalProgress::Achieved
            } else {
                GoalProgress::Partial
            },
        ));
    session = session
        .with_status(if expected_outcome && cleanup_passed {
            SessionStatus::Completed
        } else {
            SessionStatus::Degraded
        })
        .with_progress(if expected_outcome && cleanup_passed {
            GoalProgress::Achieved
        } else {
            GoalProgress::Partial
        })
        .with_updated_at(finished_at);
    store.write_run(&run)?;
    store.write_session(&session)?;

    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("external campaign: {}", report.campaign_id);
        println!("case: {}", report.case_id);
        println!("exit code: {:?}", report.exit_code);
        println!("expected outcome: {}", report.expected_outcome);
        println!("cleanup: {}", report.cleanup.status);
        println!("session: {}", report.session_id);
        println!("run: {}", report.run_id);
    }
    if expected_outcome && cleanup_passed {
        Ok(())
    } else {
        Err("external campaign replay or cleanup did not match the manifest".into())
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_external_run_artifacts(
    store: &RuntimeStore,
    project: &Project,
    session: &SessionRecord,
    run: &RunRecord,
    manifest: &ExternalCampaignManifest,
    manifest_path: &Path,
    root: &Path,
    replay_case: &ExternalReplayCase,
    stdout_path: &Path,
    stdout: &[u8],
    stderr_path: &Path,
    stderr: &[u8],
    report_path: &Path,
    report_json: &[u8],
) -> DynResult<()> {
    let producer_id = format!("external-campaign:{}", manifest.campaign_id);
    persist_artifact(
        store,
        project,
        session,
        run,
        ArtifactKind::RuntimeInput,
        "external-replay-input",
        &root.join(&replay_case.input.path),
        "application/octet-stream",
        Some(replay_case.input.sha256.clone()),
        &producer_id,
        "exact replay input pinned by the external campaign manifest",
    )?;
    persist_artifact(
        store,
        project,
        session,
        run,
        ArtifactKind::RuntimeLog,
        "external-replay-stdout",
        stdout_path,
        "text/plain",
        Some(sha256_digest(stdout)),
        &producer_id,
        "stdout captured from the external replay process",
    )?;
    persist_artifact(
        store,
        project,
        session,
        run,
        ArtifactKind::RuntimeLog,
        "external-replay-stderr",
        stderr_path,
        "text/plain",
        Some(sha256_digest(stderr)),
        &producer_id,
        "stderr or spawn error captured from the external replay process",
    )?;
    persist_artifact(
        store,
        project,
        session,
        run,
        ArtifactKind::RuntimeCapture,
        "external-replay-result",
        report_path,
        "application/json",
        Some(sha256_digest(report_json)),
        &producer_id,
        "FAT replay outcome, exact argv, and cleanup result",
    )?;
    persist_artifact(
        store,
        project,
        session,
        run,
        ArtifactKind::Strategy,
        "external-campaign-manifest",
        manifest_path,
        "application/json",
        Some(sha256_digest(&fs::read(manifest_path)?)),
        &producer_id,
        "validated external campaign manifest",
    )?;
    for evidence in &manifest.evidence {
        persist_artifact(
            store,
            project,
            session,
            run,
            ArtifactKind::RuntimeCapture,
            "external-campaign-evidence",
            &root.join(&evidence.path),
            "application/octet-stream",
            Some(evidence.sha256.clone()),
            &producer_id,
            &format!("pinned external campaign evidence: {}", evidence.role),
        )?;
    }
    Ok(())
}

fn materialize_replay_command(replay_case: &ExternalReplayCase, root: &Path) -> Vec<String> {
    let input = root
        .join(&replay_case.input.path)
        .to_string_lossy()
        .into_owned();
    let command = replay_case
        .command
        .iter()
        .map(|argument| {
            if argument == "{input}" {
                input.clone()
            } else {
                argument.clone()
            }
        })
        .collect::<Vec<_>>();
    materialize_command(&command, root)
}

fn materialize_command(command: &[String], root: &Path) -> Vec<String> {
    let mut command = command.to_vec();
    if let Some(program) = command.first_mut() {
        let path = Path::new(program);
        if path.is_relative() && path.components().count() > 1 {
            *program = root.join(path).to_string_lossy().into_owned();
        }
    }
    command
}

fn execute_command(command: &[String], root: &Path, timeout_seconds: u64) -> CapturedCommand {
    let Some(program) = command.first() else {
        return CapturedCommand {
            stdout: Vec::new(),
            stderr: Vec::new(),
            exit_code: None,
            success: false,
            timed_out: false,
            error: Some("command is empty".to_string()),
        };
    };
    let mut process = Command::new(program);
    process
        .args(&command[1..])
        .current_dir(root)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    #[cfg(unix)]
    process.process_group(0);
    let mut child = match process.spawn() {
        Ok(child) => child,
        Err(error) => {
            return CapturedCommand {
                stdout: Vec::new(),
                stderr: format!("failed to execute {program}: {error}").into_bytes(),
                exit_code: None,
                success: false,
                timed_out: false,
                error: Some(format!("failed to execute {program}: {error}")),
            };
        }
    };
    let stdout = child.stdout.take();
    let stderr = child.stderr.take();
    let stdout_reader = std::thread::spawn(move || read_pipe(stdout));
    let stderr_reader = std::thread::spawn(move || read_pipe(stderr));
    let wait = child.wait_timeout(Duration::from_secs(timeout_seconds));
    let (status, timed_out, error) = match wait {
        Ok(Some(status)) => (Some(status), false, None),
        Ok(None) => {
            let kill_error = terminate_process_tree(&mut child);
            let status = child.wait().ok();
            (status, true, kill_error)
        }
        Err(wait_error) => {
            let _ = terminate_process_tree(&mut child);
            let status = child.wait().ok();
            (
                status,
                false,
                Some(format!("failed to wait for {program}: {wait_error}")),
            )
        }
    };
    let stdout = stdout_reader.join().unwrap_or_default();
    let stderr = stderr_reader.join().unwrap_or_default();
    CapturedCommand {
        stdout,
        stderr,
        exit_code: if timed_out {
            None
        } else {
            status.as_ref().and_then(|status| status.code())
        },
        success: !timed_out && status.is_some_and(|status| status.success()),
        timed_out,
        error,
    }
}

fn terminate_process_tree(child: &mut std::process::Child) -> Option<String> {
    #[cfg(unix)]
    {
        let result = unsafe { libc::kill(-(child.id() as i32), libc::SIGKILL) };
        if result == 0 {
            return None;
        }
    }
    child.kill().err().map(|error| error.to_string())
}

fn read_pipe(mut pipe: Option<impl Read>) -> Vec<u8> {
    let mut bytes = Vec::new();
    if let Some(pipe) = pipe.as_mut() {
        let _ = pipe.read_to_end(&mut bytes);
    }
    bytes
}

fn cleanup_report(command: &[String], result: &CapturedCommand) -> ExternalCleanupReport {
    ExternalCleanupReport {
        command: command.to_vec(),
        status: if result.success { "passed" } else { "failed" },
        exit_code: result.exit_code,
        timed_out: result.timed_out,
        error: result.error.clone(),
    }
}

#[allow(clippy::too_many_arguments)]
fn persist_artifact(
    store: &RuntimeStore,
    project: &Project,
    session: &SessionRecord,
    run: &RunRecord,
    kind: ArtifactKind,
    subkind: &str,
    path: &Path,
    content_type: &str,
    digest: Option<String>,
    producer_id: &str,
    provenance: &str,
) -> DynResult<()> {
    let metadata = fs::metadata(path)?;
    let hashes = digest.map(|digest| ArtifactHashes {
        sha256: digest.strip_prefix("sha256:").map(ToOwned::to_owned),
        ..ArtifactHashes::default()
    });
    let artifact = ArtifactRecord::new(
        project.name.clone(),
        session.target_id.clone(),
        session.session_id.clone(),
        run.run_id.clone(),
        kind,
        subkind,
        "fat",
        producer_id,
        current_timestamp_string(),
        path.to_string_lossy().into_owned(),
        content_type,
        metadata.len(),
        hashes,
        provenance,
        ArtifactRetentionPolicy::Session,
    )
    .with_phase("external-replay")
    .with_backend_driver(run.backend_driver.clone())
    .with_substrate_kind(run.substrate_kind)
    .with_tool_version(env!("CARGO_PKG_VERSION"));
    store.write_artifact(&artifact)?;
    store.append_artifact_index(&artifact)?;
    Ok(())
}

fn substrate_kind(value: &str) -> DynResult<SubstrateKind> {
    match value {
        "native-host" => Ok(SubstrateKind::NativeHost),
        "docker-engine" => Ok(SubstrateKind::DockerEngine),
        "managed-linux-vm" => Ok(SubstrateKind::ManagedLinuxVm),
        _ => Err(format!("unsupported external campaign substrate {value}").into()),
    }
}

fn load_project(db: &ProjectDb, project_dir: &Path) -> DynResult<Project> {
    let name = project_dir
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| format!("invalid project directory name: {}", project_dir.display()))?;
    db.get(name)?
        .ok_or_else(|| format!("project metadata not found for {}", project_dir.display()).into())
}

fn current_timestamp_string() -> String {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis();
    format!("unix-ms:{millis}")
}

fn sha256_digest(bytes: &[u8]) -> String {
    format!("sha256:{:x}", Sha256::digest(bytes))
}

fn validate(path: &Path, json: bool) -> DynResult<()> {
    let bundle = load_bundle(path)?;
    let errors = validate_by_status(&bundle).err().unwrap_or_default();
    let report = ValidationReport {
        schema_version: "experiment-command/v1",
        operation: "validate",
        valid: errors.is_empty(),
        experiment_id: bundle.experiment.id.as_deref(),
        record_digest: bundle.experiment.record_digest.as_deref(),
        verdict: &bundle.experiment.verdict.compatibility,
        errors: &errors,
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else if errors.is_empty() {
        println!(
            "valid experiment: {}",
            report.experiment_id.unwrap_or("<missing-id>")
        );
        println!("verdict: {}", report.verdict);
        if let Some(digest) = report.record_digest {
            println!("record digest: {digest}");
        }
    } else {
        println!("invalid experiment: {}", path.display());
        for error in &errors {
            println!("  [{}] {}: {}", error.code, error.path, error.message);
        }
    }
    if errors.is_empty() {
        Ok(())
    } else {
        Err(format!(
            "experiment validation failed with {} error(s)",
            errors.len()
        )
        .into())
    }
}

fn import(project: &Path, path: &Path, json: bool) -> DynResult<()> {
    let bundle = load_bundle(path)?;
    let store = RuntimeStore::open(project)?;
    let persisted = store.import_finalized_experiment(&bundle)?;
    let report = PersistReport {
        schema_version: "experiment-command/v1",
        operation: "import",
        experiment_id: bundle
            .experiment
            .id
            .as_deref()
            .ok_or("missing experiment id")?,
        record_digest: bundle.experiment.record_digest.as_deref(),
        path: persisted.display().to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("imported experiment: {}", report.experiment_id);
        if let Some(digest) = report.record_digest {
            println!("record digest: {digest}");
        }
        println!("path: {}", report.path);
    }
    Ok(())
}

fn start(project: &Path, path: &Path, json: bool) -> DynResult<()> {
    let bundle = load_bundle(path)?;
    let store = RuntimeStore::open(project)?;
    let persisted = store.write_experiment_launch(&bundle)?;
    render_persist("start", &bundle, &persisted, json)
}

fn finalize(project: &Path, path: &Path, json: bool) -> DynResult<()> {
    let bundle = load_bundle(path)?;
    let store = RuntimeStore::open(project)?;
    let persisted = store.finalize_experiment(&bundle)?;
    render_persist("finalize", &bundle, &persisted, json)
}

fn render_persist(
    operation: &'static str,
    bundle: &ExperimentBundle,
    path: &Path,
    json: bool,
) -> DynResult<()> {
    let report = PersistReport {
        schema_version: "experiment-command/v1",
        operation,
        experiment_id: bundle
            .experiment
            .id
            .as_deref()
            .ok_or("missing experiment id")?,
        record_digest: bundle.experiment.record_digest.as_deref(),
        path: path.display().to_string(),
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("{operation} experiment: {}", report.experiment_id);
        if let Some(digest) = report.record_digest {
            println!("record digest: {digest}");
        }
        println!("path: {}", report.path);
    }
    Ok(())
}

fn show(
    project: &Path,
    experiment_id: &str,
    record_digest: Option<&str>,
    json: bool,
) -> DynResult<()> {
    let store = RuntimeStore::open(project)?;
    let bundle = if let Some(record_digest) = record_digest {
        store.read_experiment_record(experiment_id, record_digest)?
    } else {
        store
            .read_latest_experiment_record(experiment_id)?
            .map(Ok)
            .unwrap_or_else(|| store.read_experiment_launch(experiment_id))?
    };
    if json {
        println!("{}", serde_json::to_string_pretty(&bundle)?);
    } else {
        println!(
            "experiment: {}",
            bundle.experiment.id.as_deref().unwrap_or("<missing-id>")
        );
        println!(
            "status: {}",
            bundle
                .experiment
                .record_status
                .as_deref()
                .unwrap_or("unknown")
        );
        println!("verdict: {}", bundle.experiment.verdict.compatibility);
        println!(
            "reached: {}",
            bundle.experiment.proof_ladder.reached_predicates.join(", ")
        );
    }
    Ok(())
}

fn list(project: &Path, json: bool) -> DynResult<()> {
    let store = RuntimeStore::open(project)?;
    let experiments = store.list_experiments()?;
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&ListReport {
                schema_version: "experiment-command/v1",
                operation: "list",
                experiments,
            })?
        );
    } else if experiments.is_empty() {
        println!("no experiments recorded");
    } else {
        for entry in experiments {
            println!(
                "{} launch={} final_records={}",
                entry.experiment_id,
                entry.has_launch,
                entry.record_digests.len()
            );
        }
    }
    Ok(())
}

fn select(path: &Path, json: bool) -> DynResult<()> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read selection request {}: {error}",
            path.display()
        )
    })?;
    let request: SelectionRequest = serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid selection request JSON {}: {error}", path.display()))?;
    let result = select_compatibility(&request).map_err(|errors| {
        errors
            .into_iter()
            .map(|error| format!("[{}] {}: {}", error.code, error.path, error.message))
            .collect::<Vec<_>>()
            .join("\n")
    })?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        println!("selection: {:?}", result.status);
        if let Some(selected) = &result.selected_candidate_id {
            println!("candidate: {selected}");
        }
        for candidate in &result.candidates {
            println!(
                "{} {:?} score={}",
                candidate.candidate_id, candidate.disposition, candidate.score
            );
            for reason in &candidate.reasons {
                println!("  [{}] {}", reason.code, reason.message);
            }
        }
    }
    Ok(())
}

fn load_bundle(path: &Path) -> DynResult<ExperimentBundle> {
    let bytes = fs::read(path).map_err(|error| {
        format!(
            "failed to read experiment bundle {}: {error}",
            path.display()
        )
    })?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid experiment JSON {}: {error}", path.display()).into())
}

fn validate_by_status(bundle: &ExperimentBundle) -> Result<(), Vec<ExperimentValidationError>> {
    if bundle.experiment.record_status.as_deref() == Some("started") {
        validate_started_bundle(bundle)
    } else {
        validate_experiment_bundle(bundle)
    }
}
