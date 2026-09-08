use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use fat_core::experiment::{
    validate_experiment_bundle, validate_started_bundle, ExperimentBundle,
    ExperimentValidationError,
};
use fat_core::experiment_selector::{select_compatibility, SelectionRequest};
use fat_core::runtime_store::{ExperimentCatalogEntry, RuntimeStore};
use serde::Serialize;

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Subcommand)]
pub enum ExperimentCommand {
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

pub fn run(command: ExperimentCommand) -> DynResult<()> {
    match command {
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
