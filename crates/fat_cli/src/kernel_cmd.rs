use std::error::Error;
use std::fs;
use std::path::{Path, PathBuf};

use clap::Subcommand;
use fat_core::data_dir::DataResolver;
use fat_core::kernel_system::{
    evaluate_kernel_promotion, verify_bundle_directory, KernelArtifactBundleManifest,
    KernelArtifactStore, KernelBuildRecipe, KernelPromotionEvidence, KernelPromotionPolicy,
    KernelRecordValidationError,
};
use serde::{Deserialize, Serialize};

type DynResult<T> = Result<T, Box<dyn Error>>;

#[derive(Debug, Clone, Subcommand)]
pub enum KernelCommand {
    /// List and validate checked-in maintained-kernel build recipes.
    Recipes {
        /// Kernel profile root; defaults to the active FAT runtime-data tree.
        #[arg(long)]
        profiles: Option<PathBuf>,
        #[arg(long)]
        json: bool,
    },
    /// Verify an artifact bundle against its content-addressed manifest.
    Verify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Verify, immutably publish, and activate an artifact bundle.
    Install {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long, default_value = ".fat-kernels")]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// List installed artifact bundles.
    List {
        #[arg(long, default_value = ".fat-kernels")]
        store: PathBuf,
        #[arg(long)]
        json: bool,
    },
    /// Show one installed immutable bundle manifest.
    Show {
        #[arg(long, default_value = ".fat-kernels")]
        store: PathBuf,
        #[arg(long = "id")]
        bundle_id: String,
        #[arg(long)]
        json: bool,
    },
    /// Evaluate immutable fixture and corpus evidence against a promotion policy.
    EvaluatePromotion {
        #[arg(long)]
        request: PathBuf,
        /// Verified artifact bundle bound by the promotion evidence.
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Serialize)]
struct RecipeList {
    schema_version: &'static str,
    recipes: Vec<KernelBuildRecipe>,
}

#[derive(Debug, Serialize)]
struct VerificationOutput<'a> {
    schema_version: &'static str,
    operation: &'static str,
    valid: bool,
    bundle_id: Option<&'a str>,
    verified_files: usize,
    errors: &'a [KernelRecordValidationError],
}

#[derive(Debug, Serialize)]
struct InstalledBundle {
    id: String,
    class: fat_core::kernel_system::KernelClass,
    support_tier: fat_core::kernel_system::SupportTier,
    kernel_digest: String,
    valid: bool,
}

#[derive(Debug, Serialize)]
struct BundleList {
    schema_version: &'static str,
    bundles: Vec<InstalledBundle>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PromotionEvaluationRequest {
    policy: KernelPromotionPolicy,
    evidence: KernelPromotionEvidence,
}

pub fn run(command: KernelCommand) -> DynResult<()> {
    match command {
        KernelCommand::Recipes { profiles, json } => recipes(profiles.as_deref(), json),
        KernelCommand::Verify { bundle, json } => verify(&bundle, json),
        KernelCommand::Install {
            bundle,
            store,
            json,
        } => install(&bundle, &store, json),
        KernelCommand::List { store, json } => list(&store, json),
        KernelCommand::Show {
            store,
            bundle_id,
            json,
        } => show(&store, &bundle_id, json),
        KernelCommand::EvaluatePromotion {
            request,
            bundle,
            json,
        } => evaluate_promotion(&request, &bundle, json),
    }
}

fn evaluate_promotion(request: &Path, bundle: &Path, json: bool) -> DynResult<()> {
    let request: PromotionEvaluationRequest = read_json(request)?;
    let manifest = read_manifest(bundle)?;
    verify_bundle_directory(bundle, &manifest).map_err(render_errors)?;
    if !request.evidence.artifact_verified {
        return Err("promotion evidence must declare artifact_verified=true".into());
    }
    if request.evidence.bundle_id != manifest.id || request.evidence.class != manifest.class {
        return Err(format!(
            "promotion evidence binding does not match verified bundle {} ({})",
            manifest.id,
            manifest.class.as_str()
        )
        .into());
    }
    let record =
        evaluate_kernel_promotion(&request.policy, &request.evidence).map_err(render_errors)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&record)?);
    } else {
        println!("promotion: {:?}", record.decision);
        println!("record: {}", record.id);
        for predicate in &record.missing_predicates {
            println!("missing: {predicate}");
        }
    }
    Ok(())
}

fn recipes(profiles: Option<&Path>, json: bool) -> DynResult<()> {
    let resolved_profiles;
    let profiles = match profiles {
        Some(profiles) => profiles,
        None => {
            resolved_profiles = DataResolver::for_current_process(None)
                .resolve_required("profiles/kernels")?
                .path;
            &resolved_profiles
        }
    };
    let recipe_dir = profiles.join("recipes");
    let mut paths = fs::read_dir(&recipe_dir)
        .map_err(|error| format!("failed to read {}: {error}", recipe_dir.display()))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.extension()
                .is_some_and(|extension| extension == "json")
        })
        .collect::<Vec<_>>();
    paths.sort();
    let mut records = Vec::new();
    for path in paths {
        let record: KernelBuildRecipe = read_json(&path)?;
        record.validate().map_err(render_errors)?;
        records.push(record);
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&RecipeList {
                schema_version: "kernel-command/v1",
                recipes: records,
            })?
        );
    } else {
        for recipe in records {
            println!(
                "{} {} {:?}",
                recipe.id,
                recipe.class.as_str(),
                recipe.support_tier
            );
        }
    }
    Ok(())
}

fn verify(bundle: &Path, json: bool) -> DynResult<()> {
    let manifest = read_manifest(bundle)?;
    match verify_bundle_directory(bundle, &manifest) {
        Ok(report) => {
            let errors = Vec::new();
            let output = VerificationOutput {
                schema_version: "kernel-command/v1",
                operation: "verify",
                valid: true,
                bundle_id: Some(&report.bundle_id),
                verified_files: report.verified_files,
                errors: &errors,
            };
            if json {
                println!("{}", serde_json::to_string_pretty(&output)?);
            } else {
                println!(
                    "valid kernel bundle: {} ({} files)",
                    report.bundle_id, report.verified_files
                );
            }
            Ok(())
        }
        Err(errors) => {
            if json {
                println!(
                    "{}",
                    serde_json::to_string_pretty(&VerificationOutput {
                        schema_version: "kernel-command/v1",
                        operation: "verify",
                        valid: false,
                        bundle_id: Some(&manifest.id),
                        verified_files: 0,
                        errors: &errors,
                    })?
                );
            } else {
                for error in &errors {
                    println!("[{}] {}: {}", error.code, error.path, error.message);
                }
            }
            Err(format!(
                "kernel bundle validation failed with {} error(s)",
                errors.len()
            )
            .into())
        }
    }
}

fn install(bundle: &Path, store_root: &Path, json: bool) -> DynResult<()> {
    let manifest = read_manifest(bundle)?;
    let result = KernelArtifactStore::new(store_root)
        .install(bundle, &manifest)
        .map_err(render_errors)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else {
        let verb = if result.installed {
            "installed"
        } else {
            "already installed"
        };
        println!("{verb}: {}", result.bundle_id);
        println!("path: {}", result.bundle_dir.display());
    }
    Ok(())
}

fn list(store: &Path, json: bool) -> DynResult<()> {
    let bundle_root = store.join("bundles");
    let mut bundles = Vec::new();
    if bundle_root.is_dir() {
        let mut paths = fs::read_dir(&bundle_root)?
            .filter_map(Result::ok)
            .map(|entry| entry.path())
            .filter(|path| path.is_dir())
            .collect::<Vec<_>>();
        paths.sort();
        for path in paths {
            let Ok(manifest) = read_manifest(&path) else {
                continue;
            };
            let valid = verify_bundle_directory(&path, &manifest).is_ok();
            bundles.push(InstalledBundle {
                id: manifest.id,
                class: manifest.class,
                support_tier: manifest.support_tier,
                kernel_digest: manifest.kernel_image.digest,
                valid,
            });
        }
    }
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&BundleList {
                schema_version: "kernel-command/v1",
                bundles,
            })?
        );
    } else if bundles.is_empty() {
        println!("no installed kernel bundles");
    } else {
        for bundle in bundles {
            println!(
                "{} {} {:?} valid={}",
                bundle.id,
                bundle.class.as_str(),
                bundle.support_tier,
                bundle.valid
            );
        }
    }
    Ok(())
}

fn show(store: &Path, bundle_id: &str, json: bool) -> DynResult<()> {
    if !bundle_id.starts_with("kab-")
        || bundle_id
            .chars()
            .any(|character| !character.is_ascii_alphanumeric() && character != '-')
    {
        return Err("invalid kernel bundle id".into());
    }
    let bundle_dir = store.join("bundles").join(bundle_id);
    let manifest = read_manifest(&bundle_dir)?;
    verify_bundle_directory(&bundle_dir, &manifest).map_err(render_errors)?;
    if json {
        println!("{}", serde_json::to_string_pretty(&manifest)?);
    } else {
        println!("bundle: {}", manifest.id);
        println!("class: {}", manifest.class.as_str());
        println!("support: {:?}", manifest.support_tier);
        println!("kernel: {}", manifest.kernel_image.digest);
    }
    Ok(())
}

fn read_manifest(bundle: &Path) -> DynResult<KernelArtifactBundleManifest> {
    read_json(&bundle.join("manifest.json"))
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> DynResult<T> {
    let bytes =
        fs::read(path).map_err(|error| format!("failed to read {}: {error}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("invalid JSON in {}: {error}", path.display()).into())
}

fn render_errors(errors: Vec<KernelRecordValidationError>) -> String {
    errors
        .into_iter()
        .map(|error| format!("[{}] {}: {}", error.code, error.path, error.message))
        .collect::<Vec<_>>()
        .join("\n")
}
