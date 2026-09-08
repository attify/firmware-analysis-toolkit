use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use serde::de::DeserializeOwned;
use serde::Serialize;

use crate::artifacts::ArtifactRecord;
use crate::benchmark::{BenchmarkOutcomeRecord, BenchmarkRunRecord, BenchmarkTarget};
use crate::decompile::{
    DecompileBinaryRecord, DecompileContextRecord, DecompileFunctionRecord, DecompileSyncRecord,
};
use crate::diagnostics::{DiagnosticRecord, TargetDiagnosticRecord};
use crate::discovery::{
    DiscoveryLeadRecord, HarnessAttemptRecord, HarvesterExpansionRecord, TriageRecord,
};
use crate::experiment::{
    validate_experiment_bundle, validate_experiment_supersession, validate_finalization,
    validate_started_bundle, ExperimentBundle, ExperimentValidationError,
};
use crate::finding::Finding;
use crate::ids::stable_prefixed_id;
use crate::project::{ProjectLayoutMarker, PROJECT_LAYOUT_VERSION};
use crate::readiness::{BlockerRecord, ConfidenceReport};
use crate::recipes::RecipeRecord;
use crate::rehosting::{
    AttemptRecord, ReadinessReport, RepairMaterializationRecord, RepairRecord,
    TargetExecutionProfile,
};
use crate::rehosting_policy::SelectionTrace;
use crate::rehosting_recipe::RehostingRecipe;
use crate::runs::RunRecord;
use crate::sessions::SessionRecord;
use crate::staging::StagingManifest;
use crate::target_model::TargetModel;
use crate::targets::{TargetArtifactRecord, TargetRecord};

pub struct RuntimeStore {
    project_dir: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, serde::Deserialize)]
pub struct ExperimentCatalogEntry {
    pub experiment_id: String,
    pub has_launch: bool,
    pub record_digests: Vec<String>,
}

const MAX_PATH_COMPONENT_LEN: usize = 160;

pub fn initialize_project_layout(dir: impl AsRef<Path>) -> io::Result<()> {
    let dir = dir.as_ref();
    fs::create_dir_all(dir)?;
    fs::create_dir_all(dir.join("targets"))?;
    fs::create_dir_all(dir.join("sessions"))?;
    fs::create_dir_all(dir.join("index"))?;
    fs::create_dir_all(dir.join("discovery").join("leads"))?;
    fs::create_dir_all(dir.join("discovery").join("harvester_expansions"))?;
    fs::create_dir_all(dir.join("discovery").join("harness_attempts"))?;
    fs::create_dir_all(dir.join("discovery").join("triage"))?;
    fs::create_dir_all(dir.join("benchmark").join("targets"))?;
    fs::create_dir_all(dir.join("benchmark").join("runs"))?;
    fs::create_dir_all(dir.join("benchmark").join("outcomes"))?;
    fs::create_dir_all(dir.join("decompile"))?;
    fs::create_dir_all(dir.join("experiments"))?;

    let marker_path = dir.join("project.json");
    if marker_path.exists() {
        let marker = read_json_record::<ProjectLayoutMarker>(&marker_path)?;
        if marker.layout_version != PROJECT_LAYOUT_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!(
                    "unsupported project layout version {}",
                    marker.layout_version
                ),
            ));
        }
        return Ok(());
    }

    write_json_record(&marker_path, &ProjectLayoutMarker::new())
}

impl RuntimeStore {
    pub fn open(dir: impl AsRef<Path>) -> io::Result<Self> {
        let project_dir = dir.as_ref().to_path_buf();
        initialize_project_layout(&project_dir)?;
        Ok(Self { project_dir })
    }

    /// Open a project for reading without creating the project layout.
    ///
    /// [`RuntimeStore::open`] initializes the directory tree as a side effect,
    /// which is wrong for read-only commands: pointing one at a mistyped path
    /// would silently materialize a project there. Read paths tolerate missing
    /// directories and report them as empty.
    pub fn open_read_only(dir: impl AsRef<Path>) -> io::Result<Self> {
        Ok(Self {
            project_dir: dir.as_ref().to_path_buf(),
        })
    }

    pub fn project_dir(&self) -> &Path {
        &self.project_dir
    }

    pub fn experiment_launch_path(&self, experiment_id: &str) -> io::Result<PathBuf> {
        validate_experiment_id(experiment_id)?;
        Ok(self.experiment_dir(experiment_id).join("launch.json"))
    }

    pub fn experiment_record_path(
        &self,
        experiment_id: &str,
        record_digest: &str,
    ) -> io::Result<PathBuf> {
        validate_experiment_id(experiment_id)?;
        validate_experiment_record_digest(record_digest)?;
        Ok(self
            .experiment_dir(experiment_id)
            .join("records")
            .join(format!("{record_digest}.json")))
    }

    pub fn write_experiment_launch(&self, bundle: &ExperimentBundle) -> io::Result<PathBuf> {
        validate_started_bundle(bundle).map_err(experiment_validation_error)?;
        let experiment_id = required_experiment_id(bundle)?;
        let path = self.experiment_launch_path(experiment_id)?;
        write_immutable_json_record(&path, bundle)?;
        Ok(path)
    }

    pub fn read_experiment_launch(&self, experiment_id: &str) -> io::Result<ExperimentBundle> {
        read_json_record(&self.experiment_launch_path(experiment_id)?)
    }

    pub fn finalize_experiment(&self, bundle: &ExperimentBundle) -> io::Result<PathBuf> {
        let experiment_id = required_experiment_id(bundle)?;
        let started = self.read_experiment_launch(experiment_id)?;
        validate_finalization(&started, bundle).map_err(experiment_validation_error)?;
        self.write_final_experiment_record(bundle)
    }

    pub fn import_finalized_experiment(&self, bundle: &ExperimentBundle) -> io::Result<PathBuf> {
        validate_experiment_bundle(bundle).map_err(experiment_validation_error)?;
        if bundle.experiment.record_status.as_deref() != Some("finalized") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "only finalized experiment bundles can be imported",
            ));
        }
        let experiment_id = required_experiment_id(bundle)?;
        let record_digest = required_experiment_record_digest(bundle)?;
        let path = self.experiment_record_path(experiment_id, record_digest)?;
        if path.exists() {
            write_immutable_json_record(&path, bundle)?;
            return Ok(path);
        }

        let existing = self.read_experiment_records(experiment_id)?;
        let supersedes = bundle
            .experiment
            .extra
            .get("supersedes_record_digest")
            .and_then(serde_json::Value::as_str);
        if let Some(supersedes) = supersedes {
            let previous = existing
                .iter()
                .find(|record| record.experiment.record_digest.as_deref() == Some(supersedes))
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::NotFound,
                        format!("superseded experiment record {supersedes} was not found"),
                    )
                })?;
            let current_head = self
                .read_latest_experiment_record(experiment_id)?
                .and_then(|record| record.experiment.record_digest);
            if current_head.as_deref() != Some(supersedes) {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    format!(
                        "superseding record must extend current head {:?}, not {supersedes}",
                        current_head
                    ),
                ));
            }
            validate_experiment_supersession(previous, bundle)
                .map_err(experiment_validation_error)?;
        } else if !existing.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "new final record for an existing experiment must supersede a prior digest",
            ));
        }
        self.write_final_experiment_record(bundle)
    }

    pub fn read_experiment_record(
        &self,
        experiment_id: &str,
        record_digest: &str,
    ) -> io::Result<ExperimentBundle> {
        read_json_record(&self.experiment_record_path(experiment_id, record_digest)?)
    }

    pub fn read_experiment_records(
        &self,
        experiment_id: &str,
    ) -> io::Result<Vec<ExperimentBundle>> {
        validate_experiment_id(experiment_id)?;
        let records_dir = self.experiment_dir(experiment_id).join("records");
        let mut records = self.read_json_file_records(&records_dir)?;
        records.sort_by(|left: &ExperimentBundle, right| {
            left.experiment
                .record_digest
                .cmp(&right.experiment.record_digest)
        });
        Ok(records)
    }

    pub fn read_latest_experiment_record(
        &self,
        experiment_id: &str,
    ) -> io::Result<Option<ExperimentBundle>> {
        let records = self.read_experiment_records(experiment_id)?;
        let superseded = records
            .iter()
            .filter_map(|record| {
                record
                    .experiment
                    .extra
                    .get("supersedes_record_digest")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_string)
            })
            .collect::<std::collections::BTreeSet<_>>();
        let mut heads = records
            .into_iter()
            .filter(|record| {
                record
                    .experiment
                    .record_digest
                    .as_deref()
                    .is_some_and(|digest| !superseded.contains(digest))
            })
            .collect::<Vec<_>>();
        match heads.len() {
            0 => Ok(None),
            1 => Ok(heads.pop()),
            count => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("experiment {experiment_id} has {count} unsuperseded final records"),
            )),
        }
    }

    pub fn list_experiments(&self) -> io::Result<Vec<ExperimentCatalogEntry>> {
        let root = self.project_dir.join("experiments");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => return Err(error),
        };
        let mut catalog = Vec::new();
        for entry in entries {
            let entry = entry?;
            if !entry.file_type()?.is_dir() {
                continue;
            }
            let experiment_id = entry.file_name().to_string_lossy().into_owned();
            validate_experiment_id(&experiment_id).map_err(|error| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("invalid experiment catalog directory {experiment_id}: {error}"),
                )
            })?;
            let records = self.read_experiment_records(&experiment_id)?;
            let mut record_digests = records
                .into_iter()
                .filter_map(|record| record.experiment.record_digest)
                .collect::<Vec<_>>();
            record_digests.sort();
            catalog.push(ExperimentCatalogEntry {
                has_launch: self.experiment_launch_path(&experiment_id)?.is_file(),
                experiment_id,
                record_digests,
            });
        }
        catalog.sort_by(|left, right| left.experiment_id.cmp(&right.experiment_id));
        Ok(catalog)
    }

    fn experiment_dir(&self, experiment_id: &str) -> PathBuf {
        self.project_dir
            .join("experiments")
            .join(path_key(experiment_id))
    }

    fn write_final_experiment_record(&self, bundle: &ExperimentBundle) -> io::Result<PathBuf> {
        let experiment_id = required_experiment_id(bundle)?;
        let record_digest = required_experiment_record_digest(bundle)?;
        let path = self.experiment_record_path(experiment_id, record_digest)?;
        write_immutable_json_record(&path, bundle)?;
        Ok(path)
    }

    pub fn project_marker_path(&self) -> PathBuf {
        self.project_dir.join("project.json")
    }

    pub fn session_path(&self, session_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("session.json")
    }

    pub fn target_path(&self, target_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("target.json")
    }

    pub fn target_profile_path(&self, target_id: &str, profile_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("rehosting")
            .join("profiles")
            .join(format!("{}.json", path_key(profile_id)))
    }

    pub fn target_model_path(&self, target_id: &str, model_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("rehosting")
            .join("models")
            .join(format!("{}.json", path_key(model_id)))
    }

    pub fn run_path(&self, session_id: &str, run_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("run.json")
    }

    pub fn recipe_path(&self, session_id: &str, recipe_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("recipes")
            .join(path_key(recipe_id))
            .join("recipe.json")
    }

    pub fn artifact_path(&self, session_id: &str, run_id: &str, artifact_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("artifacts")
            .join(format!("{}.json", path_key(artifact_id)))
    }

    pub fn target_artifact_path(&self, target_id: &str, artifact_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("artifacts")
            .join(format!("{}.json", path_key(artifact_id)))
    }

    pub fn diagnostic_path(&self, session_id: &str, run_id: &str, diagnostic_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("diagnostics")
            .join(format!("{}.json", path_key(diagnostic_id)))
    }

    pub fn readiness_report_path(
        &self,
        session_id: &str,
        run_id: &str,
        readiness_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("readiness")
            .join(format!("{}.json", path_key(readiness_id)))
    }

    pub fn attempt_record_path(&self, session_id: &str, run_id: &str, attempt_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("attempts")
            .join(format!("{}.json", path_key(attempt_id)))
    }

    pub fn repair_record_path(&self, session_id: &str, run_id: &str, repair_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("repairs")
            .join(format!("{}.json", path_key(repair_id)))
    }

    pub fn repair_materialization_path(
        &self,
        session_id: &str,
        run_id: &str,
        repair_materialization_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("repairs")
            .join("materializations")
            .join(format!("{}.json", path_key(repair_materialization_id)))
    }

    pub fn rehosting_recipe_path(
        &self,
        session_id: &str,
        run_id: &str,
        rehosting_recipe_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("recipes")
            .join(format!("{}.json", path_key(rehosting_recipe_id)))
    }

    pub fn selection_trace_path(
        &self,
        session_id: &str,
        run_id: &str,
        selection_trace_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("selection")
            .join(format!("{}.json", path_key(selection_trace_id)))
    }

    pub fn staging_manifest_path(
        &self,
        session_id: &str,
        run_id: &str,
        staging_manifest_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("staging")
            .join(format!("{}.json", path_key(staging_manifest_id)))
    }

    pub fn confidence_report_path(
        &self,
        session_id: &str,
        run_id: &str,
        confidence_report_id: &str,
    ) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("confidence")
            .join(format!("{}.json", path_key(confidence_report_id)))
    }

    pub fn blocker_record_path(&self, session_id: &str, run_id: &str, blocker_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("rehosting")
            .join("blockers")
            .join(format!("{}.json", path_key(blocker_id)))
    }

    pub fn target_diagnostic_path(&self, target_id: &str, diagnostic_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("diagnostics")
            .join(format!("{}.json", path_key(diagnostic_id)))
    }

    pub fn run_finding_path(&self, session_id: &str, run_id: &str, finding_id: &str) -> PathBuf {
        self.project_dir
            .join("sessions")
            .join(path_key(session_id))
            .join("runs")
            .join(path_key(run_id))
            .join("findings")
            .join(format!("{}.json", path_key(finding_id)))
    }

    pub fn target_finding_path(&self, target_id: &str, finding_id: &str) -> PathBuf {
        self.project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("findings")
            .join(format!("{}.json", path_key(finding_id)))
    }

    pub fn benchmark_target_path(&self, target_id: &str) -> PathBuf {
        self.project_dir
            .join("benchmark")
            .join("targets")
            .join(format!("{}.json", path_key(target_id)))
    }

    pub fn benchmark_run_path(&self, benchmark_run_id: &str) -> PathBuf {
        self.project_dir
            .join("benchmark")
            .join("runs")
            .join(format!("{}.json", path_key(benchmark_run_id)))
    }

    pub fn benchmark_outcome_path(&self, benchmark_run_id: &str) -> PathBuf {
        self.project_dir
            .join("benchmark")
            .join("outcomes")
            .join(format!("{}.json", path_key(benchmark_run_id)))
    }

    pub fn discovery_lead_path(&self, discovery_lead_id: &str) -> PathBuf {
        self.project_dir
            .join("discovery")
            .join("leads")
            .join(format!("{}.json", path_key(discovery_lead_id)))
    }

    pub fn harvester_expansion_path(&self, harvester_expansion_id: &str) -> PathBuf {
        self.project_dir
            .join("discovery")
            .join("harvester_expansions")
            .join(format!("{}.json", path_key(harvester_expansion_id)))
    }

    pub fn harness_attempt_path(&self, harness_attempt_id: &str) -> PathBuf {
        self.project_dir
            .join("discovery")
            .join("harness_attempts")
            .join(format!("{}.json", path_key(harness_attempt_id)))
    }

    pub fn triage_path(&self, triage_id: &str) -> PathBuf {
        self.project_dir
            .join("discovery")
            .join("triage")
            .join(format!("{}.json", path_key(triage_id)))
    }

    pub fn artifact_index_path(&self) -> PathBuf {
        self.project_dir.join("index").join("artifacts.jsonl")
    }

    pub fn diagnostic_index_path(&self) -> PathBuf {
        self.project_dir.join("index").join("diagnostics.jsonl")
    }

    pub fn write_session(&self, session: &SessionRecord) -> io::Result<()> {
        write_json_record(&self.session_path(&session.session_id), session)
    }

    pub fn write_target(&self, target: &TargetRecord) -> io::Result<()> {
        write_json_record(&self.target_path(&target.target_id), target)
    }

    pub fn write_target_profile(&self, record: &TargetExecutionProfile) -> io::Result<()> {
        write_json_record(
            &self.target_profile_path(&record.target_id, &record.profile_id),
            record,
        )
    }

    pub fn write_target_model(&self, record: &TargetModel) -> io::Result<()> {
        write_json_record(
            &self.target_model_path(&record.target_id, &record.model_id),
            record,
        )
    }

    pub fn write_benchmark_target(&self, target: &BenchmarkTarget) -> io::Result<()> {
        write_json_record(&self.benchmark_target_path(&target.target_id), target)
    }

    pub fn write_benchmark_run(&self, run: &BenchmarkRunRecord) -> io::Result<()> {
        validate_benchmark_run_record(run)?;
        write_json_record(&self.benchmark_run_path(&run.benchmark_run_id), run)
    }

    pub fn write_benchmark_outcome(&self, outcome: &BenchmarkOutcomeRecord) -> io::Result<()> {
        validate_benchmark_outcome_record(self, outcome)?;
        write_json_record(
            &self.benchmark_outcome_path(&outcome.benchmark_run_id),
            outcome,
        )
    }

    pub fn write_discovery_lead(&self, record: &DiscoveryLeadRecord) -> io::Result<()> {
        write_json_record(&self.discovery_lead_path(&record.discovery_lead_id), record)
    }

    pub fn write_harvester_expansion(&self, record: &HarvesterExpansionRecord) -> io::Result<()> {
        write_json_record(
            &self.harvester_expansion_path(&record.harvester_expansion_id),
            record,
        )
    }

    pub fn write_harness_attempt(&self, record: &HarnessAttemptRecord) -> io::Result<()> {
        write_json_record(
            &self.harness_attempt_path(&record.harness_attempt_id),
            record,
        )
    }

    pub fn write_triage(&self, record: &TriageRecord) -> io::Result<()> {
        write_json_record(&self.triage_path(&record.triage_id), record)
    }

    pub fn read_session(&self, session_id: &str) -> io::Result<SessionRecord> {
        read_json_record(&self.session_path(session_id))
    }

    pub fn read_sessions(&self) -> io::Result<Vec<SessionRecord>> {
        self.read_records_in_dir(&self.project_dir.join("sessions"), "session.json")
    }

    pub fn read_target(&self, target_id: &str) -> io::Result<TargetRecord> {
        read_json_record(&self.target_path(target_id))
    }

    pub fn read_target_profile(
        &self,
        target_id: &str,
        profile_id: &str,
    ) -> io::Result<TargetExecutionProfile> {
        read_json_record(&self.target_profile_path(target_id, profile_id))
    }

    pub fn read_target_model(&self, target_id: &str, model_id: &str) -> io::Result<TargetModel> {
        read_json_record(&self.target_model_path(target_id, model_id))
    }

    pub fn read_benchmark_target(&self, target_id: &str) -> io::Result<BenchmarkTarget> {
        read_json_record(&self.benchmark_target_path(target_id))
    }

    pub fn read_benchmark_run(&self, benchmark_run_id: &str) -> io::Result<BenchmarkRunRecord> {
        let canonical_benchmark_run_id = self
            .resolve_benchmark_run_id(benchmark_run_id)?
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::NotFound,
                    format!("benchmark run not found: {benchmark_run_id}"),
                )
            })?;
        read_json_record(&self.benchmark_run_path(&canonical_benchmark_run_id))
    }

    pub fn read_benchmark_outcome(
        &self,
        benchmark_run_id: &str,
    ) -> io::Result<BenchmarkOutcomeRecord> {
        if let Some(canonical_benchmark_run_id) = self.resolve_benchmark_run_id(benchmark_run_id)? {
            let canonical_run: BenchmarkRunRecord =
                read_json_record(&self.benchmark_run_path(&canonical_benchmark_run_id))?;
            let canonical_outcome_path = self.benchmark_outcome_path(&canonical_benchmark_run_id);
            return match read_json_record(&canonical_outcome_path) {
                Ok(outcome) => Ok(outcome),
                Err(err)
                    if err.kind() == io::ErrorKind::NotFound
                        && canonical_run.execution_id
                            == legacy_benchmark_run_alias_id(&canonical_run) =>
                {
                    self.migrate_benchmark_outcome_record(
                        &canonical_run.execution_id,
                        &canonical_benchmark_run_id,
                    )?;
                    read_json_record(&canonical_outcome_path)
                }
                Err(err) => Err(err),
            };
        }

        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "benchmark outcome record references a nonexistent benchmark run: {benchmark_run_id}"
            ),
        ))
    }

    pub fn read_discovery_lead(&self, discovery_lead_id: &str) -> io::Result<DiscoveryLeadRecord> {
        read_json_record(&self.discovery_lead_path(discovery_lead_id))
    }

    pub fn read_harvester_expansion(
        &self,
        harvester_expansion_id: &str,
    ) -> io::Result<HarvesterExpansionRecord> {
        read_json_record(&self.harvester_expansion_path(harvester_expansion_id))
    }

    pub fn read_harness_attempt(
        &self,
        harness_attempt_id: &str,
    ) -> io::Result<HarnessAttemptRecord> {
        read_json_record(&self.harness_attempt_path(harness_attempt_id))
    }

    pub fn read_triage(&self, triage_id: &str) -> io::Result<TriageRecord> {
        read_json_record(&self.triage_path(triage_id))
    }

    pub fn read_benchmark_targets(&self) -> io::Result<Vec<BenchmarkTarget>> {
        let mut targets: Vec<BenchmarkTarget> =
            self.read_json_file_records(&self.project_dir.join("benchmark").join("targets"))?;
        targets.sort_by(|left, right| left.target_id.cmp(&right.target_id));
        Ok(targets)
    }

    pub fn read_benchmark_runs(&self) -> io::Result<Vec<BenchmarkRunRecord>> {
        self.migrate_legacy_benchmark_records()?;
        let mut runs: Vec<BenchmarkRunRecord> =
            self.read_json_file_records(&self.project_dir.join("benchmark").join("runs"))?;
        runs.sort_by(|left, right| left.benchmark_run_id.cmp(&right.benchmark_run_id));
        Ok(runs)
    }

    pub fn read_benchmark_outcomes(&self) -> io::Result<Vec<BenchmarkOutcomeRecord>> {
        self.migrate_legacy_benchmark_records()?;
        let mut canonical_outcomes: BTreeMap<String, BenchmarkOutcomeRecord> = BTreeMap::new();
        for outcome in self.read_json_file_records::<BenchmarkOutcomeRecord>(
            &self.project_dir.join("benchmark").join("outcomes"),
        )? {
            let canonical_outcome = self.read_benchmark_outcome(&outcome.benchmark_run_id)?;
            canonical_outcomes
                .entry(canonical_outcome.benchmark_run_id.clone())
                .or_insert(canonical_outcome);
        }

        Ok(canonical_outcomes.into_values().collect())
    }

    pub fn read_discovery_leads(&self) -> io::Result<Vec<DiscoveryLeadRecord>> {
        let mut records: Vec<DiscoveryLeadRecord> =
            self.read_json_file_records(&self.project_dir.join("discovery").join("leads"))?;
        records.sort_by(|left, right| left.discovery_lead_id.cmp(&right.discovery_lead_id));
        Ok(records)
    }

    pub fn read_harvester_expansions(&self) -> io::Result<Vec<HarvesterExpansionRecord>> {
        let mut records: Vec<HarvesterExpansionRecord> = self.read_json_file_records(
            &self
                .project_dir
                .join("discovery")
                .join("harvester_expansions"),
        )?;
        records.sort_by(|left, right| {
            left.harvester_expansion_id
                .cmp(&right.harvester_expansion_id)
        });
        Ok(records)
    }

    pub fn read_harness_attempts(&self) -> io::Result<Vec<HarnessAttemptRecord>> {
        let mut records: Vec<HarnessAttemptRecord> = self
            .read_json_file_records(&self.project_dir.join("discovery").join("harness_attempts"))?;
        records.sort_by(|left, right| left.harness_attempt_id.cmp(&right.harness_attempt_id));
        Ok(records)
    }

    pub fn read_triage_records(&self) -> io::Result<Vec<TriageRecord>> {
        let mut records: Vec<TriageRecord> =
            self.read_json_file_records(&self.project_dir.join("discovery").join("triage"))?;
        records.sort_by(|left, right| left.triage_id.cmp(&right.triage_id));
        Ok(records)
    }

    pub fn write_run(&self, run: &RunRecord) -> io::Result<()> {
        write_json_record(&self.run_path(&run.session_id, &run.run_id), run)
    }

    pub fn read_run(&self, session_id: &str, run_id: &str) -> io::Result<RunRecord> {
        read_json_record(&self.run_path(session_id, run_id))
    }

    pub fn write_readiness_report(&self, record: &ReadinessReport) -> io::Result<()> {
        write_json_record(
            &self.readiness_report_path(&record.session_id, &record.run_id, &record.readiness_id),
            record,
        )
    }

    pub fn read_readiness_report(
        &self,
        session_id: &str,
        run_id: &str,
        readiness_id: &str,
    ) -> io::Result<ReadinessReport> {
        read_json_record(&self.readiness_report_path(session_id, run_id, readiness_id))
    }

    pub fn write_attempt_record(&self, record: &AttemptRecord) -> io::Result<()> {
        write_json_record(
            &self.attempt_record_path(&record.session_id, &record.run_id, &record.attempt_id),
            record,
        )
    }

    pub fn read_attempt_record(
        &self,
        session_id: &str,
        run_id: &str,
        attempt_id: &str,
    ) -> io::Result<AttemptRecord> {
        read_json_record(&self.attempt_record_path(session_id, run_id, attempt_id))
    }

    pub fn write_repair_record(&self, record: &RepairRecord) -> io::Result<()> {
        write_json_record(
            &self.repair_record_path(&record.session_id, &record.run_id, &record.repair_id),
            record,
        )
    }

    pub fn write_repair_materialization_record(
        &self,
        record: &RepairMaterializationRecord,
    ) -> io::Result<()> {
        write_json_record(
            &self.repair_materialization_path(
                &record.session_id,
                &record.run_id,
                &record.repair_materialization_id,
            ),
            record,
        )
    }

    pub fn write_rehosting_recipe(
        &self,
        session_id: &str,
        run_id: &str,
        recipe: &RehostingRecipe,
    ) -> io::Result<()> {
        write_json_record(
            &self.rehosting_recipe_path(session_id, run_id, &recipe.rehosting_recipe_id),
            recipe,
        )
    }

    pub fn write_selection_trace(&self, trace: &SelectionTrace) -> io::Result<()> {
        write_json_record(
            &self.selection_trace_path(&trace.session_id, &trace.run_id, &trace.selection_trace_id),
            trace,
        )
    }

    pub fn write_staging_manifest(&self, record: &StagingManifest) -> io::Result<()> {
        write_json_record(
            &self.staging_manifest_path(
                &record.session_id,
                &record.run_id,
                &record.staging_manifest_id,
            ),
            record,
        )
    }

    pub fn write_confidence_report(&self, record: &ConfidenceReport) -> io::Result<()> {
        write_json_record(
            &self.confidence_report_path(
                &record.session_id,
                &record.run_id,
                &record.confidence_report_id,
            ),
            record,
        )
    }

    pub fn write_blocker_record(&self, record: &BlockerRecord) -> io::Result<()> {
        write_json_record(
            &self.blocker_record_path(&record.session_id, &record.run_id, &record.blocker_id),
            record,
        )
    }

    pub fn read_repair_record(
        &self,
        session_id: &str,
        run_id: &str,
        repair_id: &str,
    ) -> io::Result<RepairRecord> {
        read_json_record(&self.repair_record_path(session_id, run_id, repair_id))
    }

    pub fn read_repair_materialization_record(
        &self,
        session_id: &str,
        run_id: &str,
        repair_materialization_id: &str,
    ) -> io::Result<RepairMaterializationRecord> {
        read_json_record(&self.repair_materialization_path(
            session_id,
            run_id,
            repair_materialization_id,
        ))
    }

    pub fn read_rehosting_recipe(
        &self,
        session_id: &str,
        run_id: &str,
        rehosting_recipe_id: &str,
    ) -> io::Result<RehostingRecipe> {
        read_json_record(&self.rehosting_recipe_path(session_id, run_id, rehosting_recipe_id))
    }

    pub fn read_selection_trace(
        &self,
        session_id: &str,
        run_id: &str,
        selection_trace_id: &str,
    ) -> io::Result<SelectionTrace> {
        read_json_record(&self.selection_trace_path(session_id, run_id, selection_trace_id))
    }

    pub fn read_staging_manifest(
        &self,
        session_id: &str,
        run_id: &str,
        staging_manifest_id: &str,
    ) -> io::Result<StagingManifest> {
        read_json_record(&self.staging_manifest_path(session_id, run_id, staging_manifest_id))
    }

    pub fn read_confidence_report(
        &self,
        session_id: &str,
        run_id: &str,
        confidence_report_id: &str,
    ) -> io::Result<ConfidenceReport> {
        read_json_record(&self.confidence_report_path(session_id, run_id, confidence_report_id))
    }

    pub fn read_blocker_record(
        &self,
        session_id: &str,
        run_id: &str,
        blocker_id: &str,
    ) -> io::Result<BlockerRecord> {
        read_json_record(&self.blocker_record_path(session_id, run_id, blocker_id))
    }

    pub fn read_runs(&self, session_id: &str) -> io::Result<Vec<RunRecord>> {
        self.read_records_in_dir(
            &self
                .session_path(session_id)
                .parent()
                .map(|path| path.join("runs"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "session path missing parent")
                })?,
            "run.json",
        )
    }

    pub fn write_recipe(&self, session_id: &str, recipe: &RecipeRecord) -> io::Result<()> {
        write_json_record(&self.recipe_path(session_id, &recipe.recipe_id), recipe)
    }

    pub fn read_recipe(&self, session_id: &str, recipe_id: &str) -> io::Result<RecipeRecord> {
        read_json_record(&self.recipe_path(session_id, recipe_id))
    }

    pub fn write_artifact(&self, artifact: &ArtifactRecord) -> io::Result<()> {
        write_json_record(
            &self.artifact_path(
                &artifact.session_id,
                &artifact.run_id,
                &artifact.artifact_id,
            ),
            artifact,
        )
    }

    pub fn write_target_artifact(&self, artifact: &TargetArtifactRecord) -> io::Result<()> {
        write_json_record(
            &self.target_artifact_path(&artifact.target_id, &artifact.artifact_id),
            artifact,
        )
    }

    pub fn read_artifact(
        &self,
        session_id: &str,
        run_id: &str,
        artifact_id: &str,
    ) -> io::Result<ArtifactRecord> {
        read_json_record(&self.artifact_path(session_id, run_id, artifact_id))
    }

    pub fn read_target_artifact(
        &self,
        target_id: &str,
        artifact_id: &str,
    ) -> io::Result<TargetArtifactRecord> {
        read_json_record(&self.target_artifact_path(target_id, artifact_id))
    }

    pub fn read_target_artifacts(&self, target_id: &str) -> io::Result<Vec<TargetArtifactRecord>> {
        let dir = self
            .project_dir
            .join("targets")
            .join(path_key(target_id))
            .join("artifacts");

        match fs::read_dir(&dir) {
            Ok(entries) => {
                let mut artifacts: Vec<TargetArtifactRecord> = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    artifacts.push(read_json_record(&path)?);
                }
                artifacts.sort_by(|left, right| left.artifact_id.cmp(&right.artifact_id));
                Ok(artifacts)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    pub fn read_run_artifacts(
        &self,
        session_id: &str,
        run_id: &str,
    ) -> io::Result<Vec<ArtifactRecord>> {
        self.read_json_file_records(
            &self
                .run_path(session_id, run_id)
                .parent()
                .map(|path| path.join("artifacts"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "run path missing parent")
                })?,
        )
    }

    pub fn write_diagnostic(
        &self,
        session_id: &str,
        diagnostic: &DiagnosticRecord,
    ) -> io::Result<()> {
        self.write_diagnostic_for_session(session_id, diagnostic)
    }

    pub fn write_diagnostic_for_session(
        &self,
        session_id: &str,
        diagnostic: &DiagnosticRecord,
    ) -> io::Result<()> {
        write_json_record(
            &self.diagnostic_path(session_id, &diagnostic.run_id, &diagnostic.diagnostic_id),
            diagnostic,
        )
    }

    pub fn read_diagnostic(
        &self,
        session_id: &str,
        run_id: &str,
        diagnostic_id: &str,
    ) -> io::Result<DiagnosticRecord> {
        read_json_record(&self.diagnostic_path(session_id, run_id, diagnostic_id))
    }

    pub fn read_run_diagnostics(
        &self,
        session_id: &str,
        run_id: &str,
    ) -> io::Result<Vec<DiagnosticRecord>> {
        self.read_json_file_records(
            &self
                .run_path(session_id, run_id)
                .parent()
                .map(|path| path.join("diagnostics"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "run path missing parent")
                })?,
        )
    }

    pub fn write_target_diagnostic(&self, diagnostic: &TargetDiagnosticRecord) -> io::Result<()> {
        write_json_record(
            &self.target_diagnostic_path(&diagnostic.target_id, &diagnostic.diagnostic_id),
            diagnostic,
        )
    }

    pub fn read_target_diagnostic(
        &self,
        target_id: &str,
        diagnostic_id: &str,
    ) -> io::Result<TargetDiagnosticRecord> {
        read_json_record(&self.target_diagnostic_path(target_id, diagnostic_id))
    }

    pub fn read_target_diagnostics(
        &self,
        target_id: &str,
    ) -> io::Result<Vec<TargetDiagnosticRecord>> {
        self.read_json_file_records(
            &self
                .target_path(target_id)
                .parent()
                .map(|path| path.join("diagnostics"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "target path missing parent")
                })?,
        )
    }

    pub fn write_run_finding(
        &self,
        session_id: &str,
        run_id: &str,
        finding: &Finding,
    ) -> io::Result<()> {
        write_json_record(
            &self.run_finding_path(session_id, run_id, &finding.id),
            finding,
        )
    }

    pub fn write_target_finding(&self, target_id: &str, finding: &Finding) -> io::Result<()> {
        write_json_record(&self.target_finding_path(target_id, &finding.id), finding)
    }

    pub fn read_run_findings(&self, session_id: &str, run_id: &str) -> io::Result<Vec<Finding>> {
        self.read_json_file_records(
            &self
                .run_path(session_id, run_id)
                .parent()
                .map(|path| path.join("findings"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "run path missing parent")
                })?,
        )
    }

    pub fn read_target_findings(&self, target_id: &str) -> io::Result<Vec<Finding>> {
        self.read_json_file_records(
            &self
                .target_path(target_id)
                .parent()
                .map(|path| path.join("findings"))
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::NotFound, "target path missing parent")
                })?,
        )
    }

    pub fn append_artifact_index(&self, artifact: &ArtifactRecord) -> io::Result<()> {
        append_jsonl_record(&self.artifact_index_path(), artifact)
    }

    pub fn append_target_artifact_index(&self, artifact: &TargetArtifactRecord) -> io::Result<()> {
        append_jsonl_record(
            &self.artifact_index_path(),
            &ArtifactRecord {
                artifact_id: artifact.artifact_id.clone(),
                project_id: artifact.project_id.clone(),
                target_id: artifact.target_id.clone(),
                session_id: String::new(),
                run_id: String::new(),
                kind: artifact.kind,
                subkind: artifact.subkind.clone(),
                producer_type: artifact.producer_type.clone(),
                producer_id: artifact.producer_id.clone(),
                created_at: artifact.created_at.clone(),
                path: artifact.path.clone(),
                content_type: artifact.content_type.clone(),
                size_bytes: artifact.size_bytes,
                hashes: artifact.hashes.clone(),
                provenance: artifact.provenance.clone(),
                retention_policy: artifact.retention_policy,
                phase: artifact.phase.clone(),
                backend_driver: None,
                substrate_kind: None,
                tool_version: artifact.tool_version.clone(),
                labels: artifact.labels.clone(),
                related_artifact_ids: artifact.related_artifact_ids.clone(),
            },
        )
    }

    pub fn append_diagnostic_index(&self, diagnostic: &DiagnosticRecord) -> io::Result<()> {
        append_jsonl_record(&self.diagnostic_index_path(), diagnostic)
    }

    pub fn read_artifact_index(&self) -> io::Result<Vec<ArtifactRecord>> {
        read_jsonl_records(&self.artifact_index_path())
    }

    pub fn read_diagnostic_index(&self) -> io::Result<Vec<DiagnosticRecord>> {
        read_jsonl_records(&self.diagnostic_index_path())
    }

    fn read_records_in_dir<T: DeserializeOwned>(
        &self,
        dir: &Path,
        file_name: &str,
    ) -> io::Result<Vec<T>> {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut records = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path().join(file_name);
                    if !path.is_file() {
                        continue;
                    }
                    records.push(read_json_record(&path)?);
                }
                Ok(records)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    fn read_json_file_records<T: DeserializeOwned>(&self, dir: &Path) -> io::Result<Vec<T>> {
        match fs::read_dir(dir) {
            Ok(entries) => {
                let mut records = Vec::new();
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    records.push(read_json_record(&path)?);
                }
                Ok(records)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
            Err(err) => Err(err),
        }
    }

    fn migrate_legacy_benchmark_records(&self) -> io::Result<()> {
        let runs_dir = self.project_dir.join("benchmark").join("runs");
        match fs::read_dir(&runs_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }
                    self.read_and_migrate_benchmark_run_path(&path)?;
                }
                Ok(())
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(err) => Err(err),
        }
    }

    fn resolve_benchmark_run_id(&self, benchmark_run_id: &str) -> io::Result<Option<String>> {
        if let Some(run) =
            self.read_and_migrate_benchmark_run_path(&self.benchmark_run_path(benchmark_run_id))?
        {
            return Ok(Some(run.benchmark_run_id));
        }

        self.migrate_legacy_benchmark_records()?;
        self.find_benchmark_run_alias(benchmark_run_id)
    }

    fn find_benchmark_run_alias(&self, benchmark_run_id: &str) -> io::Result<Option<String>> {
        let runs_dir = self.project_dir.join("benchmark").join("runs");
        match fs::read_dir(&runs_dir) {
            Ok(entries) => {
                for entry in entries {
                    let entry = entry?;
                    let path = entry.path();
                    if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
                        continue;
                    }

                    let run: BenchmarkRunRecord = read_json_record(&path)?;
                    let is_legacy_alias = run.execution_id == legacy_benchmark_run_alias_id(&run);
                    if run.benchmark_run_id == benchmark_run_id
                        || (is_legacy_alias && run.execution_id == benchmark_run_id)
                    {
                        return Ok(Some(run.benchmark_run_id));
                    }
                }
                Ok(None)
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(err) => Err(err),
        }
    }

    fn read_and_migrate_benchmark_run_path(
        &self,
        path: &Path,
    ) -> io::Result<Option<BenchmarkRunRecord>> {
        let contents = match fs::read_to_string(path) {
            Ok(contents) => contents,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err),
        };
        #[derive(serde::Deserialize)]
        struct BenchmarkRunRecordIdWire {
            benchmark_run_id: String,
        }

        let source: BenchmarkRunRecordIdWire =
            serde_json::from_str(&contents).map_err(json_error)?;
        let run: BenchmarkRunRecord = serde_json::from_str(&contents).map_err(json_error)?;
        let canonical_path = self.benchmark_run_path(&run.benchmark_run_id);
        if source.benchmark_run_id == run.benchmark_run_id {
            return Ok(Some(run));
        }

        match read_json_record::<BenchmarkRunRecord>(&canonical_path) {
            Ok(existing_run) if existing_run == run => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "benchmark run migration conflicts with existing canonical record",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                write_json_record(&canonical_path, &run)?;
            }
            Err(err) => return Err(err),
        }
        self.migrate_benchmark_outcome_record(&source.benchmark_run_id, &run.benchmark_run_id)?;
        remove_file_if_exists(path)?;
        Ok(Some(run))
    }

    fn migrate_benchmark_outcome_record(
        &self,
        source_benchmark_run_id: &str,
        canonical_benchmark_run_id: &str,
    ) -> io::Result<()> {
        let source_path = self.benchmark_outcome_path(source_benchmark_run_id);
        let canonical_path = self.benchmark_outcome_path(canonical_benchmark_run_id);
        if source_path == canonical_path {
            return Ok(());
        }

        let mut outcome = match read_json_record::<BenchmarkOutcomeRecord>(&source_path) {
            Ok(outcome) => outcome,
            Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err),
        };
        if outcome.benchmark_run_id != source_benchmark_run_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "benchmark outcome alias migration source does not match alias path",
            ));
        }
        outcome.benchmark_run_id = canonical_benchmark_run_id.to_string();
        match read_json_record::<BenchmarkOutcomeRecord>(&canonical_path) {
            Ok(existing_outcome) if existing_outcome == outcome => {}
            Ok(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "benchmark outcome migration conflicts with existing canonical record",
                ));
            }
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                write_json_record(&canonical_path, &outcome)?;
            }
            Err(err) => return Err(err),
        }
        remove_file_if_exists(&source_path)
    }

    /// Root directory for a binary's decompile workspace
    pub fn decompile_binary_dir(&self, binary_id: &str) -> PathBuf {
        self.project_dir.join("decompile").join(path_key(binary_id))
    }

    /// Directory for a specific function's decompile artifacts
    pub fn decompile_function_dir(&self, binary_id: &str, function_addr: &str) -> PathBuf {
        self.decompile_binary_dir(binary_id).join(function_addr)
    }

    /// Latest artifacts for a function
    pub fn decompile_function_latest(&self, binary_id: &str, function_addr: &str) -> PathBuf {
        self.decompile_function_dir(binary_id, function_addr)
            .join("latest")
    }

    /// Run-specific artifacts for a function
    pub fn decompile_function_run(
        &self,
        binary_id: &str,
        function_addr: &str,
        run_id: &str,
    ) -> PathBuf {
        self.decompile_function_dir(binary_id, function_addr)
            .join("runs")
            .join(path_key(run_id))
    }

    pub fn decompile_binary_record_path(&self, binary_id: &str) -> PathBuf {
        self.decompile_binary_dir(binary_id).join("binary.json")
    }

    pub fn decompile_function_record_path(&self, binary_id: &str, function_addr: &str) -> PathBuf {
        self.decompile_function_dir(binary_id, function_addr)
            .join("function.json")
    }

    pub fn decompile_context_record_path(&self, binary_id: &str, function_addr: &str) -> PathBuf {
        self.decompile_function_latest(binary_id, function_addr)
            .join("context.json")
    }

    pub fn decompile_sync_record_path(&self, binary_id: &str, function_addr: &str) -> PathBuf {
        self.decompile_function_latest(binary_id, function_addr)
            .join("sync.json")
    }

    pub fn write_decompile_binary_record(&self, record: &DecompileBinaryRecord) -> io::Result<()> {
        write_json_record(
            &self.decompile_binary_record_path(&record.binary_id),
            record,
        )
    }

    pub fn read_decompile_binary_record(
        &self,
        binary_id: &str,
    ) -> io::Result<DecompileBinaryRecord> {
        read_json_record(&self.decompile_binary_record_path(binary_id))
    }

    pub fn write_decompile_function_record(
        &self,
        binary_id: &str,
        record: &DecompileFunctionRecord,
    ) -> io::Result<()> {
        write_json_record(
            &self.decompile_function_record_path(binary_id, &record.function_addr),
            record,
        )
    }

    pub fn read_decompile_function_record(
        &self,
        binary_id: &str,
        function_addr: &str,
    ) -> io::Result<DecompileFunctionRecord> {
        read_json_record(&self.decompile_function_record_path(binary_id, function_addr))
    }

    pub fn write_decompile_context_record(
        &self,
        binary_id: &str,
        function_addr: &str,
        record: &DecompileContextRecord,
    ) -> io::Result<()> {
        write_json_record(
            &self.decompile_context_record_path(binary_id, function_addr),
            record,
        )
    }

    pub fn read_decompile_context_record(
        &self,
        binary_id: &str,
        function_addr: &str,
    ) -> io::Result<DecompileContextRecord> {
        read_json_record(&self.decompile_context_record_path(binary_id, function_addr))
    }

    pub fn write_decompile_sync_record(
        &self,
        binary_id: &str,
        function_addr: &str,
        record: &DecompileSyncRecord,
    ) -> io::Result<()> {
        write_json_record(
            &self.decompile_sync_record_path(binary_id, function_addr),
            record,
        )
    }

    pub fn read_decompile_sync_record(
        &self,
        binary_id: &str,
        function_addr: &str,
    ) -> io::Result<DecompileSyncRecord> {
        read_json_record(&self.decompile_sync_record_path(binary_id, function_addr))
    }
}

/// Walk parent directories looking for a .fat.db file, indicating a FAT project.
pub fn find_project_dir(path: &Path) -> Option<PathBuf> {
    let canonical = path.canonicalize().ok()?;
    let mut current = canonical.parent()?;
    loop {
        if current.join(".fat.db").exists() {
            return Some(current.to_path_buf());
        }
        match current.parent() {
            Some(parent) if parent != current => current = parent,
            _ => return None,
        }
    }
}

fn required_experiment_id(bundle: &ExperimentBundle) -> io::Result<&str> {
    bundle.experiment.id.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "experiment bundle is missing experiment.id",
        )
    })
}

fn required_experiment_record_digest(bundle: &ExperimentBundle) -> io::Result<&str> {
    bundle.experiment.record_digest.as_deref().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "finalized experiment bundle is missing experiment.record_digest",
        )
    })
}

fn experiment_validation_error(errors: Vec<ExperimentValidationError>) -> io::Error {
    let message = errors
        .into_iter()
        .map(|error| format!("[{}] {}: {}", error.code, error.path, error.message))
        .collect::<Vec<_>>()
        .join("\n");
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn validate_experiment_id(value: &str) -> io::Result<()> {
    validate_lower_hex_component(value, "exp-", 16, "experiment id")
}

fn validate_experiment_record_digest(value: &str) -> io::Result<()> {
    validate_lower_hex_component(value, "sha256:", 64, "experiment record digest")
}

fn validate_lower_hex_component(
    value: &str,
    prefix: &str,
    hex_len: usize,
    label: &str,
) -> io::Result<()> {
    let valid = value.strip_prefix(prefix).is_some_and(|hex| {
        hex.len() == hex_len
            && hex
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    });
    if valid {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "invalid {label}: expected {prefix} followed by {hex_len} lowercase hex characters"
            ),
        ))
    }
}

fn write_immutable_json_record<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec_pretty(value).map_err(json_error)?;
    if path.exists() {
        return compare_immutable_record(path, &bytes);
    }

    let file_name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid record file name"))?;
    let nonce = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    let temp_path = path.with_file_name(format!(".{file_name}.tmp-{}-{nonce}", std::process::id()));
    let write_result = (|| {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temp_path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        match fs::hard_link(&temp_path, path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                compare_immutable_record(path, &bytes)
            }
            Err(error) => Err(error),
        }
    })();
    let cleanup_result = match fs::remove_file(&temp_path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
    };
    write_result.and(cleanup_result)
}

fn compare_immutable_record(path: &Path, expected: &[u8]) -> io::Result<()> {
    let existing = fs::read(path)?;
    if existing == expected {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!(
                "immutable record already exists with different content: {}",
                path.display()
            ),
        ))
    }
}

fn write_json_record<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let temp_path = path.with_extension(format!(
        "{}.tmp-{}-{}",
        path.extension()
            .and_then(|ext| ext.to_str())
            .unwrap_or("json"),
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("system clock before UNIX_EPOCH")
            .as_nanos()
    ));
    let file = fs::File::create(&temp_path)?;
    serde_json::to_writer_pretty(&file, value).map_err(json_error)?;
    file.sync_all()?;
    fs::rename(&temp_path, path)?;
    Ok(())
}

fn read_json_record<T: DeserializeOwned>(path: &Path) -> io::Result<T> {
    let file = fs::File::open(path)?;
    serde_json::from_reader(file).map_err(json_error)
}

fn append_jsonl_record<T: Serialize>(path: &Path, value: &T) -> io::Result<()> {
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent)?;
    }

    let mut file = OpenOptions::new().create(true).append(true).open(path)?;
    serde_json::to_writer(&mut file, value).map_err(json_error)?;
    file.write_all(b"\n")?;
    Ok(())
}

fn read_jsonl_records<T: DeserializeOwned>(path: &Path) -> io::Result<Vec<T>> {
    match fs::read_to_string(path) {
        Ok(contents) => contents
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| serde_json::from_str(line).map_err(json_error))
            .collect(),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

fn json_error(err: serde_json::Error) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, err)
}

fn remove_file_if_exists(path: &Path) -> io::Result<()> {
    match fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

fn validate_benchmark_run_record(run: &BenchmarkRunRecord) -> io::Result<()> {
    let expected_run = BenchmarkRunRecord::try_new(
        run.target_id.clone(),
        run.comparator.clone(),
        run.host_profile.clone(),
        run.execution_id.clone(),
    )
    .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;

    if expected_run == *run {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "benchmark run record does not match canonical benchmark run identity",
        ))
    }
}

fn validate_benchmark_outcome_record(
    store: &RuntimeStore,
    outcome: &BenchmarkOutcomeRecord,
) -> io::Result<()> {
    let run: BenchmarkRunRecord =
        match read_json_record(&store.benchmark_run_path(&outcome.benchmark_run_id)) {
            Ok(run) => run,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "benchmark outcome record references a nonexistent benchmark run",
                ));
            }
            Err(err) => return Err(err),
        };

    if run.benchmark_run_id == outcome.benchmark_run_id {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "benchmark outcome record does not reference the canonical benchmark run id",
        ))
    }
}

fn legacy_benchmark_run_alias_id(run: &BenchmarkRunRecord) -> String {
    stable_prefixed_id(
        "brun",
        [
            run.target_id.as_str(),
            run.comparator.comparator_id.as_str(),
            run.comparator.kind.as_str(),
            run.comparator.run_mode.as_str(),
            run.host_profile.as_str(),
        ],
    )
}

fn path_key(value: &str) -> String {
    if value.len() <= MAX_PATH_COMPONENT_LEN {
        return value.to_string();
    }

    let suffix_len = 16;
    let prefix_len = MAX_PATH_COMPONENT_LEN.saturating_sub(suffix_len + 1);
    let prefix_len = prefix_len.min(value.len().saturating_sub(suffix_len + 1));
    let prefix = &value[..prefix_len];
    let suffix = &value[value.len() - suffix_len..];

    format!("{prefix}~{suffix}")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::decompile::{
        ContextSource, DecompileBinaryRecord, DecompileContextRecord, DecompileFunctionRecord,
        DecompileStatus, DecompileSyncRecord,
    };
    use std::fs;

    #[test]
    fn test_initialize_project_layout_creates_decompile_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("project");

        initialize_project_layout(&project_dir).unwrap();

        assert!(
            project_dir.join("decompile").is_dir(),
            "decompile/ directory should be created by initialize_project_layout"
        );
    }

    #[test]
    fn test_initialize_project_layout_creates_all_expected_dirs() {
        let tmp = tempfile::tempdir().unwrap();
        let project_dir = tmp.path().join("project");

        initialize_project_layout(&project_dir).unwrap();

        let expected = vec![
            "targets",
            "sessions",
            "index",
            "discovery/leads",
            "discovery/harvester_expansions",
            "discovery/harness_attempts",
            "discovery/triage",
            "benchmark/targets",
            "benchmark/runs",
            "benchmark/outcomes",
            "decompile",
        ];
        for dir_name in expected {
            assert!(
                project_dir.join(dir_name).is_dir(),
                "{dir_name}/ should exist after initialization"
            );
        }
        assert!(project_dir.join("project.json").is_file());
    }

    #[test]
    fn test_decompile_binary_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        let dir = store.decompile_binary_dir("bin-abc123");
        assert_eq!(dir, tmp.path().join("decompile").join("bin-abc123"));
    }

    #[test]
    fn test_decompile_function_dir() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        let dir = store.decompile_function_dir("bin-abc123", "0x00401000");
        assert_eq!(
            dir,
            tmp.path()
                .join("decompile")
                .join("bin-abc123")
                .join("0x00401000")
        );
    }

    #[test]
    fn test_decompile_function_latest() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        let path = store.decompile_function_latest("bin-abc123", "0x00401000");
        assert_eq!(
            path,
            tmp.path()
                .join("decompile")
                .join("bin-abc123")
                .join("0x00401000")
                .join("latest")
        );
    }

    #[test]
    fn test_decompile_function_run() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        let path = store.decompile_function_run("bin-abc123", "0x00401000", "run-001");
        assert_eq!(
            path,
            tmp.path()
                .join("decompile")
                .join("bin-abc123")
                .join("0x00401000")
                .join("runs")
                .join("run-001")
        );
    }

    #[test]
    fn test_decompile_path_helpers_use_path_key_for_long_ids() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        // Create a binary_id longer than MAX_PATH_COMPONENT_LEN
        let long_id = "a".repeat(MAX_PATH_COMPONENT_LEN + 50);
        let dir = store.decompile_binary_dir(&long_id);

        // The path component should be truncated via path_key
        let component = dir.file_name().unwrap().to_str().unwrap();
        assert!(
            component.len() <= MAX_PATH_COMPONENT_LEN,
            "path component should be truncated for long binary IDs"
        );
        assert!(
            component.contains('~'),
            "truncated path should contain ~ separator"
        );
    }

    #[test]
    fn test_find_project_dir_finds_fat_db() {
        let tmp = tempfile::tempdir().unwrap();
        let project_root = tmp.path().join("my_project");
        fs::create_dir_all(&project_root).unwrap();

        // Create .fat.db marker
        fs::write(project_root.join(".fat.db"), b"").unwrap();

        // Create a nested directory to search from
        let nested = project_root.join("subdir").join("deep");
        fs::create_dir_all(&nested).unwrap();

        let found = find_project_dir(&nested);
        assert!(found.is_some(), "should find project dir");
        // Canonicalize both sides for comparison (macOS /private/var vs /var)
        assert_eq!(
            found.unwrap().canonicalize().unwrap(),
            project_root.canonicalize().unwrap()
        );
    }

    #[test]
    fn test_find_project_dir_returns_none_when_no_fat_db() {
        let tmp = tempfile::tempdir().unwrap();
        let nested = tmp.path().join("a").join("b").join("c");
        fs::create_dir_all(&nested).unwrap();

        let found = find_project_dir(&nested);
        assert!(found.is_none(), "should return None when no .fat.db exists");
    }

    #[test]
    fn test_find_project_dir_finds_closest_ancestor() {
        let tmp = tempfile::tempdir().unwrap();

        // Create two levels with .fat.db
        let outer = tmp.path().join("outer");
        let inner = outer.join("inner");
        fs::create_dir_all(&inner).unwrap();
        fs::write(outer.join(".fat.db"), b"").unwrap();
        fs::write(inner.join(".fat.db"), b"").unwrap();

        let search_from = inner.join("deep");
        fs::create_dir_all(&search_from).unwrap();

        let found = find_project_dir(&search_from);
        assert!(found.is_some());
        assert_eq!(
            found.unwrap().canonicalize().unwrap(),
            inner.canonicalize().unwrap(),
            "should find the closest ancestor with .fat.db"
        );
    }

    #[test]
    fn test_decompile_record_round_trip() {
        let tmp = tempfile::tempdir().unwrap();
        let store = RuntimeStore::open(tmp.path()).unwrap();

        let binary = DecompileBinaryRecord {
            binary_id: "bin-httpd".into(),
            binary_name: "httpd".into(),
            original_path: "/fw/usr/sbin/httpd".into(),
            binary_hash: "sha256:1234".into(),
            arch: "mips".into(),
            endianness: "little".into(),
            decompiler_backend: "r2ghidra".into(),
            created_at: "2026-04-06T00:00:00Z".into(),
            updated_at: "2026-04-06T00:00:00Z".into(),
        };
        let function = DecompileFunctionRecord {
            function_addr: "0x00440b3c".into(),
            symbol_name: Some("handle_cmd".into()),
            status: DecompileStatus::Verified,
            latest_run_id: Some("run-001".into()),
            raw_lines: Some(40),
            refined_lines: Some(32),
            transform_count: Some(8),
            confirmed_count: Some(3),
            security_finding_count: Some(1),
            created_at: "2026-04-06T00:00:00Z".into(),
            updated_at: "2026-04-06T00:05:00Z".into(),
        };
        let context = DecompileContextRecord {
            sources: vec![ContextSource {
                source_type: "crypto".into(),
                source_path: Some("/tmp/crypto.json".into()),
                summary: "crypto summary".into(),
                relevance_score: 0.7,
                injected: true,
            }],
            total_tokens_estimate: 128,
        };
        let sync = DecompileSyncRecord {
            function_addr: "0x00440b3c".into(),
            pushed: true,
            functions_renamed: 2,
            variables_renamed: 3,
            comments_added: 1,
            pushed_at: Some("2026-04-06T00:06:00Z".into()),
            cutter_url: Some("http://127.0.0.1:8000".into()),
            errors: vec![],
        };

        store.write_decompile_binary_record(&binary).unwrap();
        store
            .write_decompile_function_record(&binary.binary_id, &function)
            .unwrap();
        store
            .write_decompile_context_record(&binary.binary_id, &function.function_addr, &context)
            .unwrap();
        store
            .write_decompile_sync_record(&binary.binary_id, &function.function_addr, &sync)
            .unwrap();

        assert_eq!(
            store
                .read_decompile_binary_record(&binary.binary_id)
                .unwrap(),
            binary
        );
        assert_eq!(
            store
                .read_decompile_function_record(&binary.binary_id, &function.function_addr)
                .unwrap(),
            function
        );
        assert_eq!(
            store
                .read_decompile_context_record(&binary.binary_id, &function.function_addr)
                .unwrap(),
            context
        );
        assert_eq!(
            store
                .read_decompile_sync_record(&binary.binary_id, &function.function_addr)
                .unwrap(),
            sync
        );
    }
}
