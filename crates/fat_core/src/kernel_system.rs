use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;
use std::path::{Component, Path};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

const SCHEMA_VERSION: &str = "1.0";

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelRecordValidationError {
    pub code: &'static str,
    pub path: String,
    pub message: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelClass {
    Mips32O32LeR1Page4k,
    Mips32O32BeR1Page4k,
    Arm32EabiLeV7Page4k,
}

impl KernelClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Mips32O32LeR1Page4k => "mips32-o32-le-r1-page4k",
            Self::Mips32O32BeR1Page4k => "mips32-o32-be-r1-page4k",
            Self::Arm32EabiLeV7Page4k => "arm32-eabi-le-v7-page4k",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SupportTier {
    External,
    Experimental,
    Supported,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FixtureOutcome {
    BootFailed,
    KernelBooted,
    UserspaceReached,
    ServiceReached,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KernelPromotionDecision {
    NotPromoted,
    Promoted,
    Indeterminate,
    Deprecated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelSourceLock {
    pub schema_version: String,
    pub id: String,
    pub project: String,
    pub release: String,
    pub archive_url: String,
    pub archive_digest: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub signature_url: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksums_url: Option<String>,
    pub license: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LockedBuilderPackage {
    pub name: String,
    pub version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelBuilderIdentity {
    pub schema_version: String,
    pub id: String,
    pub image: String,
    pub manifest_digest: String,
    pub base_image: String,
    pub base_manifest_digest: String,
    pub build_timestamp: u64,
    pub packages: Vec<LockedBuilderPackage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArchitectureContract {
    pub isa_family: String,
    pub endianness: String,
    pub userspace_abi: String,
    pub isa_floor: String,
    pub page_size: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelBuildRecipe {
    pub schema_version: String,
    pub id: String,
    pub class: KernelClass,
    pub source_lock_id: String,
    pub builder_id: String,
    pub architecture: ArchitectureContract,
    pub cross_compile: String,
    pub base_defconfig: String,
    pub ordered_fragments: Vec<String>,
    pub output_image: String,
    pub machine_profile_ids: Vec<String>,
    pub support_tier: SupportTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactFile {
    pub path: String,
    pub digest: String,
    pub role: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AttributionEntry {
    pub project: String,
    pub source_url: String,
    pub license: String,
    pub role: String,
    pub redistributed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelArtifactBundleManifest {
    pub schema_version: String,
    pub id: String,
    pub recipe_id: String,
    pub class: KernelClass,
    pub support_tier: SupportTier,
    pub source_lock_id: String,
    pub builder_id: String,
    pub kernel_image: ArtifactFile,
    pub final_config: ArtifactFile,
    pub build_log: ArtifactFile,
    #[serde(default)]
    pub declared_files: Vec<ArtifactFile>,
    #[serde(default)]
    pub attribution: Vec<AttributionEntry>,
    pub recipe_reproducible: bool,
    pub bit_reproducible: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelFixtureResult {
    pub schema_version: String,
    pub id: String,
    pub bundle_id: String,
    pub kernel_digest: String,
    pub machine_profile_id: String,
    pub qemu_binary_digest: String,
    pub cpu: String,
    pub process_id: u32,
    pub predicted_outcome: FixtureOutcome,
    pub observed_outcome: FixtureOutcome,
    pub serial_log_digest: String,
    pub cleanup_passed: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPromotionRecord {
    pub schema_version: String,
    pub id: String,
    pub class: KernelClass,
    pub bundle_id: String,
    pub decision: KernelPromotionDecision,
    pub policy_id: String,
    #[serde(default)]
    pub fixture_result_ids: Vec<String>,
    #[serde(default)]
    pub counted_experiment_ids: Vec<String>,
    #[serde(default)]
    pub satisfied_predicates: Vec<String>,
    #[serde(default)]
    pub missing_predicates: Vec<String>,
    #[serde(default)]
    pub reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPromotionPolicy {
    pub schema_version: String,
    pub id: String,
    pub minimum_distinct_vendors: usize,
    pub minimum_distinct_targets: usize,
    pub minimum_distinct_families: usize,
    pub minimum_fixture_machines: usize,
    pub require_holdout: bool,
    pub maximum_semantic_risk: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PromotionExperimentEvidence {
    pub experiment_id: String,
    pub record_digest: String,
    pub target_id: String,
    pub vendor: String,
    pub family_id: String,
    pub corpus_role: String,
    pub finalized: bool,
    pub available: bool,
    pub bindings_match: bool,
    pub cleanup_passed: bool,
    pub proof_stage: u8,
    pub baseline_proof_stage: u8,
    pub highest_semantic_risk: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KernelPromotionEvidence {
    pub class: KernelClass,
    pub bundle_id: String,
    pub artifact_verified: bool,
    #[serde(default)]
    pub fixtures: Vec<KernelFixtureResult>,
    #[serde(default)]
    pub experiments: Vec<PromotionExperimentEvidence>,
}

pub fn evaluate_kernel_promotion(
    policy: &KernelPromotionPolicy,
    evidence: &KernelPromotionEvidence,
) -> Result<KernelPromotionRecord, Vec<KernelRecordValidationError>> {
    let mut errors = Vec::new();
    if policy.schema_version != SCHEMA_VERSION {
        push_error(
            &mut errors,
            "schema-version-unsupported",
            "policy.schema_version",
            "promotion policy schema must be 1.0",
        );
    }
    require_nonempty("policy.id", &policy.id, &mut errors);
    if policy.minimum_distinct_vendors == 0 {
        push_error(
            &mut errors,
            "promotion-threshold-invalid",
            "policy.minimum_distinct_vendors",
            "promotion must require at least one distinct vendor",
        );
    }
    if policy.minimum_fixture_machines == 0 {
        push_error(
            &mut errors,
            "promotion-threshold-invalid",
            "policy.minimum_fixture_machines",
            "promotion must require at least one fixture machine",
        );
    }
    if policy.minimum_distinct_targets == 0 {
        push_error(
            &mut errors,
            "promotion-threshold-invalid",
            "policy.minimum_distinct_targets",
            "promotion must require at least one distinct target",
        );
    }
    if policy.minimum_distinct_families == 0 {
        push_error(
            &mut errors,
            "promotion-threshold-invalid",
            "policy.minimum_distinct_families",
            "promotion must require at least one distinct target family",
        );
    }
    if !matches!(
        policy.maximum_semantic_risk.as_str(),
        "none" | "low" | "medium"
    ) {
        push_error(
            &mut errors,
            "semantic-risk-policy-invalid",
            "policy.maximum_semantic_risk",
            "maximum semantic risk must be none, low, or medium",
        );
    }
    require_prefixed_id(
        "evidence.bundle_id",
        &evidence.bundle_id,
        "kab-",
        &mut errors,
    );
    for (index, fixture) in evidence.fixtures.iter().enumerate() {
        if let Err(fixture_errors) = fixture.validate() {
            errors.extend(fixture_errors.into_iter().map(|mut error| {
                error.path = format!("evidence.fixtures.{index}.{}", error.path);
                error
            }));
        }
        if fixture.bundle_id != evidence.bundle_id {
            push_error(
                &mut errors,
                "fixture-binding-mismatch",
                &format!("evidence.fixtures.{index}.bundle_id"),
                "fixture result must bind the bundle under evaluation",
            );
        }
    }
    for (index, experiment) in evidence.experiments.iter().enumerate() {
        require_nonempty(
            &format!("evidence.experiments.{index}.experiment_id"),
            &experiment.experiment_id,
            &mut errors,
        );
        require_digest(
            &format!("evidence.experiments.{index}.record_digest"),
            &experiment.record_digest,
            &mut errors,
        );
        require_nonempty(
            &format!("evidence.experiments.{index}.target_id"),
            &experiment.target_id,
            &mut errors,
        );
        require_nonempty(
            &format!("evidence.experiments.{index}.vendor"),
            &experiment.vendor,
            &mut errors,
        );
        require_nonempty(
            &format!("evidence.experiments.{index}.family_id"),
            &experiment.family_id,
            &mut errors,
        );
    }
    errors = finish_vec(errors);
    if !errors.is_empty() {
        return Err(errors);
    }

    let mut missing = Vec::new();
    if !evidence.artifact_verified {
        missing.push("artifact-integrity".to_string());
    }
    let fixture_machines = evidence
        .fixtures
        .iter()
        .filter(|fixture| {
            fixture.bundle_id == evidence.bundle_id
                && fixture.cleanup_passed
                && matches!(
                    fixture.observed_outcome,
                    FixtureOutcome::UserspaceReached | FixtureOutcome::ServiceReached
                )
        })
        .map(|fixture| fixture.machine_profile_id.as_str())
        .collect::<BTreeSet<_>>();
    if fixture_machines.len() < policy.minimum_fixture_machines {
        missing.push("deterministic-fixture".to_string());
    }
    if evidence
        .fixtures
        .iter()
        .any(|fixture| !fixture.cleanup_passed)
        || evidence
            .experiments
            .iter()
            .any(|experiment| experiment.available && !experiment.cleanup_passed)
    {
        missing.push("cleanup".to_string());
    }
    if evidence
        .experiments
        .iter()
        .any(|experiment| !experiment.finalized)
    {
        missing.push("finalized-evidence".to_string());
    }
    if evidence
        .experiments
        .iter()
        .any(|experiment| !experiment.bindings_match)
    {
        missing.push("binding-integrity".to_string());
    }
    let maximum_risk = semantic_risk_rank(&policy.maximum_semantic_risk);
    let eligible_experiment = |experiment: &&PromotionExperimentEvidence| {
        experiment.available
            && experiment.finalized
            && experiment.bindings_match
            && experiment.cleanup_passed
            && experiment.proof_stage >= experiment.baseline_proof_stage
            && semantic_risk_rank(&experiment.highest_semantic_risk) <= maximum_risk
    };
    let vendors = evidence
        .experiments
        .iter()
        .filter(eligible_experiment)
        .map(|experiment| experiment.vendor.as_str())
        .collect::<BTreeSet<_>>();
    if vendors.len() < policy.minimum_distinct_vendors {
        missing.push("vendor-breadth".to_string());
    }
    let targets = evidence
        .experiments
        .iter()
        .filter(eligible_experiment)
        .map(|experiment| experiment.target_id.as_str())
        .collect::<BTreeSet<_>>();
    if targets.len() < policy.minimum_distinct_targets {
        missing.push("target-breadth".to_string());
    }
    let families = evidence
        .experiments
        .iter()
        .filter(eligible_experiment)
        .map(|experiment| experiment.family_id.as_str())
        .collect::<BTreeSet<_>>();
    if families.len() < policy.minimum_distinct_families {
        missing.push("family-breadth".to_string());
    }
    if policy.require_holdout
        && !evidence
            .experiments
            .iter()
            .filter(eligible_experiment)
            .any(|experiment| experiment.corpus_role == "holdout")
    {
        missing.push("holdout".to_string());
    }
    if evidence
        .experiments
        .iter()
        .filter(|experiment| experiment.available)
        .any(|experiment| experiment.proof_stage < experiment.baseline_proof_stage)
    {
        missing.push("baseline-proof-depth".to_string());
    }
    if evidence
        .experiments
        .iter()
        .filter(|experiment| experiment.available)
        .any(|experiment| semantic_risk_rank(&experiment.highest_semantic_risk) > maximum_risk)
    {
        missing.push("semantic-risk".to_string());
    }
    missing.sort();
    missing.dedup();

    let unavailable = evidence
        .experiments
        .iter()
        .any(|experiment| !experiment.available);
    if unavailable {
        missing.push("corpus-availability".to_string());
        missing.sort();
        missing.dedup();
    }
    let decision = if unavailable {
        KernelPromotionDecision::Indeterminate
    } else if missing.is_empty() {
        KernelPromotionDecision::Promoted
    } else {
        KernelPromotionDecision::NotPromoted
    };
    let predicates = [
        "artifact-integrity",
        "baseline-proof-depth",
        "binding-integrity",
        "cleanup",
        "corpus-availability",
        "deterministic-fixture",
        "finalized-evidence",
        "family-breadth",
        "holdout",
        "semantic-risk",
        "target-breadth",
        "vendor-breadth",
    ];
    let satisfied = predicates
        .iter()
        .filter(|predicate| !missing.iter().any(|missing| missing == **predicate))
        .map(|predicate| (*predicate).to_string())
        .collect::<Vec<_>>();
    let reasons = missing
        .iter()
        .map(|predicate| format!("promotion predicate not satisfied: {predicate}"))
        .collect();
    KernelPromotionRecord {
        schema_version: SCHEMA_VERSION.to_string(),
        id: String::new(),
        class: evidence.class,
        bundle_id: evidence.bundle_id.clone(),
        decision,
        policy_id: policy.id.clone(),
        fixture_result_ids: evidence
            .fixtures
            .iter()
            .map(|fixture| fixture.id.clone())
            .collect(),
        counted_experiment_ids: evidence
            .experiments
            .iter()
            .filter(eligible_experiment)
            .map(|experiment| experiment.experiment_id.clone())
            .collect(),
        satisfied_predicates: satisfied,
        missing_predicates: missing,
        reasons,
    }
    .seal()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelBundleVerification {
    pub bundle_id: String,
    pub verified_files: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KernelInstallResult {
    pub bundle_id: String,
    pub bundle_dir: PathBuf,
    pub installed: bool,
}

#[derive(Debug, Clone)]
pub struct KernelArtifactStore {
    root: PathBuf,
}

impl KernelArtifactStore {
    pub fn new(root: impl Into<PathBuf>) -> Self {
        Self { root: root.into() }
    }

    pub fn install(
        &self,
        source: &Path,
        manifest: &KernelArtifactBundleManifest,
    ) -> Result<KernelInstallResult, Vec<KernelRecordValidationError>> {
        verify_bundle_directory(source, manifest)?;

        let bundles = self.root.join("bundles");
        let destination = bundles.join(&manifest.id);
        create_dir(&bundles, "bundles")?;
        create_dir(&self.root.join("active"), "active")?;

        if destination.exists() {
            let valid_existing = read_manifest(&destination.join("manifest.json"))
                .is_ok_and(|existing| existing == *manifest)
                && verify_bundle_directory(&destination, manifest).is_ok();
            if !valid_existing {
                return Err(vec![KernelRecordValidationError {
                    code: "immutable-bundle-conflict",
                    path: destination.display().to_string(),
                    message: "an existing bundle directory does not match the immutable manifest"
                        .to_string(),
                }]);
            }
            self.activate(manifest)?;
            return Ok(KernelInstallResult {
                bundle_id: manifest.id.clone(),
                bundle_dir: destination,
                installed: false,
            });
        }

        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos();
        let staging = self.root.join(format!(".staging-{}-{nonce}", manifest.id));
        create_dir(&staging, "staging")?;

        let publish = (|| {
            for file in manifest_files(manifest) {
                let target = staging.join(&file.path);
                if let Some(parent) = target.parent() {
                    create_dir(parent, &file.path)?;
                }
                fs::copy(source.join(&file.path), &target)
                    .map_err(|error| io_error("artifact-copy-failed", &file.path, error))?;
                sync_file(&target)?;
            }
            let manifest_path = staging.join("manifest.json");
            let bytes = serde_json::to_vec_pretty(manifest).map_err(|error| {
                vec![KernelRecordValidationError {
                    code: "manifest-serialization-failed",
                    path: "manifest.json".to_string(),
                    message: error.to_string(),
                }]
            })?;
            write_synced(&manifest_path, &bytes)?;
            verify_bundle_directory(&staging, manifest)?;
            sync_directory(&staging)?;
            fs::rename(&staging, &destination)
                .map_err(|error| io_error("bundle-publish-failed", &manifest.id, error))?;
            sync_directory(&bundles)?;
            self.activate(manifest)
        })();

        if publish.is_err() && staging.exists() {
            let _ = fs::remove_dir_all(&staging);
        }
        publish?;

        Ok(KernelInstallResult {
            bundle_id: manifest.id.clone(),
            bundle_dir: destination,
            installed: true,
        })
    }

    pub fn active_bundle(
        &self,
        class: KernelClass,
    ) -> Result<Option<String>, Vec<KernelRecordValidationError>> {
        let path = self
            .root
            .join("active")
            .join(format!("{}.json", class.as_str()));
        if !path.exists() {
            return Ok(None);
        }
        let value: Value = serde_json::from_slice(&fs::read(&path).map_err(|error| {
            io_error("activation-read-failed", &path.display().to_string(), error)
        })?)
        .map_err(|error| {
            vec![KernelRecordValidationError {
                code: "activation-parse-failed",
                path: path.display().to_string(),
                message: error.to_string(),
            }]
        })?;
        Ok(value
            .get("bundle_id")
            .and_then(Value::as_str)
            .map(ToOwned::to_owned))
    }

    fn activate(
        &self,
        manifest: &KernelArtifactBundleManifest,
    ) -> Result<(), Vec<KernelRecordValidationError>> {
        let active = self.root.join("active");
        create_dir(&active, "active")?;
        let destination = active.join(format!("{}.json", manifest.class.as_str()));
        let temporary = active.join(format!(".{}.tmp", manifest.class.as_str()));
        let bytes = serde_json::to_vec_pretty(&serde_json::json!({
            "schema_version": "1.0",
            "class": manifest.class,
            "bundle_id": manifest.id,
            "kernel_digest": manifest.kernel_image.digest,
        }))
        .expect("activation record serialization cannot fail");
        write_synced(&temporary, &bytes)?;
        fs::rename(&temporary, &destination).map_err(|error| {
            io_error(
                "activation-publish-failed",
                &destination.display().to_string(),
                error,
            )
        })?;
        sync_directory(&active)
    }
}

pub fn verify_bundle_directory(
    root: &Path,
    manifest: &KernelArtifactBundleManifest,
) -> Result<KernelBundleVerification, Vec<KernelRecordValidationError>> {
    let mut errors = manifest.validate().err().unwrap_or_default();
    let files = manifest_files(manifest);
    let mut expected = BTreeMap::new();
    for file in &files {
        if expected.insert(file.path.as_str(), file).is_some() {
            push_error(
                &mut errors,
                "duplicate-artifact-path",
                &file.path,
                "artifact path is declared more than once",
            );
            continue;
        }
        let path = root.join(&file.path);
        match fs::read(&path) {
            Ok(bytes) => {
                let actual = format!("sha256:{:x}", Sha256::digest(bytes));
                if actual != file.digest {
                    push_error(
                        &mut errors,
                        "artifact-digest-mismatch",
                        &file.path,
                        &format!("expected {}, observed {actual}", file.digest),
                    );
                }
            }
            Err(error) => push_error(
                &mut errors,
                "artifact-read-failed",
                &file.path,
                &error.to_string(),
            ),
        }
    }

    let declared = expected.keys().copied().collect::<BTreeSet<_>>();
    if root.is_dir() {
        for entry in WalkDir::new(root).follow_links(false).into_iter() {
            let Ok(entry) = entry else {
                continue;
            };
            if entry.path() == root || entry.file_type().is_dir() {
                continue;
            }
            let relative = entry
                .path()
                .strip_prefix(root)
                .expect("walked entry is below root")
                .to_string_lossy()
                .replace('\\', "/");
            if relative == "manifest.json" {
                continue;
            }
            if entry.file_type().is_symlink() {
                push_error(
                    &mut errors,
                    "artifact-symlink-refused",
                    &relative,
                    "bundle artifacts must be regular files",
                );
            } else if !declared.contains(relative.as_str()) {
                push_error(
                    &mut errors,
                    "undeclared-file",
                    &relative,
                    "bundle contains a file not declared by the manifest",
                );
            }
        }
    } else {
        push_error(
            &mut errors,
            "bundle-root-invalid",
            &root.display().to_string(),
            "bundle root must be a directory",
        );
    }

    errors = finish_vec(errors);
    if errors.is_empty() {
        Ok(KernelBundleVerification {
            bundle_id: manifest.id.clone(),
            verified_files: files.len(),
        })
    } else {
        Err(errors)
    }
}

macro_rules! impl_sealed_record {
    ($record:ty, $prefix:literal, $validator:ident) => {
        impl $record {
            pub fn seal(mut self) -> Result<Self, Vec<KernelRecordValidationError>> {
                self.id.clear();
                let errors = $validator(&self);
                if !errors.is_empty() {
                    return Err(errors);
                }
                self.id = content_id($prefix, &self);
                Ok(self)
            }

            pub fn validate(&self) -> Result<(), Vec<KernelRecordValidationError>> {
                let mut errors = $validator(self);
                validate_id($prefix, self, &self.id, &mut errors);
                finish(errors)
            }
        }
    };
}

impl_sealed_record!(KernelSourceLock, "ksl", validate_source_lock);
impl_sealed_record!(KernelBuilderIdentity, "kbi", validate_builder);
impl_sealed_record!(KernelBuildRecipe, "krc", validate_recipe);
impl_sealed_record!(KernelArtifactBundleManifest, "kab", validate_bundle);
impl_sealed_record!(KernelFixtureResult, "kfr", validate_fixture);
impl_sealed_record!(KernelPromotionRecord, "kpr", validate_promotion);

fn validate_source_lock(record: &KernelSourceLock) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_nonempty("project", &record.project, &mut errors);
    require_nonempty("release", &record.release, &mut errors);
    require_https("archive_url", &record.archive_url, &mut errors);
    require_digest("archive_digest", &record.archive_digest, &mut errors);
    if let Some(url) = &record.signature_url {
        require_https("signature_url", url, &mut errors);
    }
    if let Some(url) = &record.checksums_url {
        require_https("checksums_url", url, &mut errors);
    }
    require_nonempty("license", &record.license, &mut errors);
    finish_vec(errors)
}

fn validate_builder(record: &KernelBuilderIdentity) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_nonempty("image", &record.image, &mut errors);
    require_digest("manifest_digest", &record.manifest_digest, &mut errors);
    require_nonempty("base_image", &record.base_image, &mut errors);
    require_digest(
        "base_manifest_digest",
        &record.base_manifest_digest,
        &mut errors,
    );
    if record.build_timestamp == 0 {
        push_error(
            &mut errors,
            "build-timestamp-invalid",
            "build_timestamp",
            "builder image must declare a nonzero reproducible OCI timestamp",
        );
    }
    if record.packages.is_empty() {
        push_error(
            &mut errors,
            "builder-packages-empty",
            "packages",
            "builder identity must pin at least one package",
        );
    }
    for (index, package) in record.packages.iter().enumerate() {
        require_nonempty(
            &format!("packages.{index}.name"),
            &package.name,
            &mut errors,
        );
        require_nonempty(
            &format!("packages.{index}.version"),
            &package.version,
            &mut errors,
        );
    }
    finish_vec(errors)
}

fn validate_recipe(record: &KernelBuildRecipe) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_prefixed_id(
        "source_lock_id",
        &record.source_lock_id,
        "ksl-",
        &mut errors,
    );
    require_prefixed_id("builder_id", &record.builder_id, "kbi-", &mut errors);
    require_nonempty("cross_compile", &record.cross_compile, &mut errors);
    require_relative_path("base_defconfig", &record.base_defconfig, &mut errors);
    require_relative_path("output_image", &record.output_image, &mut errors);
    for (index, fragment) in record.ordered_fragments.iter().enumerate() {
        require_relative_path(&format!("ordered_fragments.{index}"), fragment, &mut errors);
    }
    if record.machine_profile_ids.is_empty() {
        push_error(
            &mut errors,
            "machine-profile-missing",
            "machine_profile_ids",
            "recipe must name at least one compatible machine profile",
        );
    }
    validate_class_contract(record.class, &record.architecture, &mut errors);
    finish_vec(errors)
}

fn validate_bundle(record: &KernelArtifactBundleManifest) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_prefixed_id("recipe_id", &record.recipe_id, "krc-", &mut errors);
    require_prefixed_id(
        "source_lock_id",
        &record.source_lock_id,
        "ksl-",
        &mut errors,
    );
    require_prefixed_id("builder_id", &record.builder_id, "kbi-", &mut errors);
    for (path, file) in [
        ("kernel_image", &record.kernel_image),
        ("final_config", &record.final_config),
        ("build_log", &record.build_log),
    ] {
        validate_artifact(path, file, &mut errors);
    }
    for (index, file) in record.declared_files.iter().enumerate() {
        validate_artifact(&format!("declared_files.{index}"), file, &mut errors);
    }
    if record
        .declared_files
        .iter()
        .any(|file| file.role == "third-party-input")
        && record.attribution.is_empty()
    {
        push_error(
            &mut errors,
            "attribution-required",
            "attribution",
            "third-party inputs require a provenance and license entry",
        );
    }
    for (index, attribution) in record.attribution.iter().enumerate() {
        require_nonempty(
            &format!("attribution.{index}.project"),
            &attribution.project,
            &mut errors,
        );
        require_https(
            &format!("attribution.{index}.source_url"),
            &attribution.source_url,
            &mut errors,
        );
        require_nonempty(
            &format!("attribution.{index}.license"),
            &attribution.license,
            &mut errors,
        );
    }
    if !record.recipe_reproducible {
        push_error(
            &mut errors,
            "recipe-not-reproducible",
            "recipe_reproducible",
            "maintained artifact bundle must be reproducible from its declared recipe",
        );
    }
    finish_vec(errors)
}

fn validate_fixture(record: &KernelFixtureResult) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_prefixed_id("bundle_id", &record.bundle_id, "kab-", &mut errors);
    require_digest("kernel_digest", &record.kernel_digest, &mut errors);
    require_nonempty(
        "machine_profile_id",
        &record.machine_profile_id,
        &mut errors,
    );
    require_digest(
        "qemu_binary_digest",
        &record.qemu_binary_digest,
        &mut errors,
    );
    require_nonempty("cpu", &record.cpu, &mut errors);
    require_digest("serial_log_digest", &record.serial_log_digest, &mut errors);
    finish_vec(errors)
}

fn validate_promotion(record: &KernelPromotionRecord) -> Vec<KernelRecordValidationError> {
    let mut errors = common_errors(&record.schema_version);
    require_prefixed_id("bundle_id", &record.bundle_id, "kab-", &mut errors);
    require_nonempty("policy_id", &record.policy_id, &mut errors);
    if record.decision == KernelPromotionDecision::Promoted
        && (!record.missing_predicates.is_empty()
            || record.fixture_result_ids.is_empty()
            || record.counted_experiment_ids.is_empty())
    {
        push_error(
            &mut errors,
            "promotion-evidence-incomplete",
            "decision",
            "promotion requires no missing predicates plus fixture and corpus experiment evidence",
        );
    }
    if matches!(
        record.decision,
        KernelPromotionDecision::NotPromoted | KernelPromotionDecision::Indeterminate
    ) && record.missing_predicates.is_empty()
    {
        push_error(
            &mut errors,
            "missing-predicates-required",
            "missing_predicates",
            "not-promoted records must identify the evidence still required",
        );
    }
    finish_vec(errors)
}

fn semantic_risk_rank(value: &str) -> u8 {
    match value {
        "none" => 0,
        "low" => 1,
        "medium" => 2,
        "high" => 3,
        _ => u8::MAX,
    }
}

fn validate_class_contract(
    class: KernelClass,
    contract: &ArchitectureContract,
    errors: &mut Vec<KernelRecordValidationError>,
) {
    let expected = match class {
        KernelClass::Mips32O32LeR1Page4k => ("mips32", "little", "o32", "mips32r1", 4096),
        KernelClass::Mips32O32BeR1Page4k => ("mips32", "big", "o32", "mips32r1", 4096),
        KernelClass::Arm32EabiLeV7Page4k => ("arm32", "little", "eabi", "armv7", 4096),
    };
    let actual = (
        contract.isa_family.as_str(),
        contract.endianness.as_str(),
        contract.userspace_abi.as_str(),
        contract.isa_floor.as_str(),
        contract.page_size,
    );
    if actual != expected {
        push_error(
            errors,
            "class-contract-mismatch",
            "architecture",
            "architecture contract does not match the declared compatibility class",
        );
    }
}

fn validate_artifact(
    field: &str,
    file: &ArtifactFile,
    errors: &mut Vec<KernelRecordValidationError>,
) {
    require_relative_path(&format!("{field}.path"), &file.path, errors);
    require_digest(&format!("{field}.digest"), &file.digest, errors);
    require_nonempty(&format!("{field}.role"), &file.role, errors);
}

fn common_errors(version: &str) -> Vec<KernelRecordValidationError> {
    let mut errors = Vec::new();
    if version != SCHEMA_VERSION {
        push_error(
            &mut errors,
            "schema-version-unsupported",
            "schema_version",
            "kernel record schema must be 1.0",
        );
    }
    errors
}

fn require_nonempty(path: &str, value: &str, errors: &mut Vec<KernelRecordValidationError>) {
    if value.trim().is_empty() {
        push_error(errors, "required", path, "value must not be empty");
    }
}

fn require_https(path: &str, value: &str, errors: &mut Vec<KernelRecordValidationError>) {
    if !value.starts_with("https://") {
        push_error(errors, "https-required", path, "URL must use HTTPS");
    }
}

fn require_digest(path: &str, value: &str, errors: &mut Vec<KernelRecordValidationError>) {
    if !is_sha256_digest(value) {
        push_error(
            errors,
            "digest-invalid",
            path,
            "digest must use sha256:<64 lowercase hex characters>",
        );
    }
}

fn require_prefixed_id(
    path: &str,
    value: &str,
    prefix: &str,
    errors: &mut Vec<KernelRecordValidationError>,
) {
    if !value.starts_with(prefix) || value.len() <= prefix.len() {
        push_error(
            errors,
            "record-id-invalid",
            path,
            &format!("record ID must start with {prefix}"),
        );
    }
}

fn require_relative_path(path: &str, value: &str, errors: &mut Vec<KernelRecordValidationError>) {
    let candidate = Path::new(value);
    let safe = !value.trim().is_empty()
        && !candidate.is_absolute()
        && candidate
            .components()
            .all(|component| matches!(component, Component::Normal(_) | Component::CurDir));
    if !safe {
        push_error(
            errors,
            "unsafe-path",
            path,
            "path must be relative and must not contain parent traversal",
        );
    }
}

fn validate_id<T: Serialize>(
    prefix: &str,
    record: &T,
    id: &str,
    errors: &mut Vec<KernelRecordValidationError>,
) {
    let expected = content_id(prefix, record);
    if id != expected {
        push_error(
            errors,
            "content-id-mismatch",
            "id",
            &format!("record ID must be {expected}"),
        );
    }
}

fn content_id<T: Serialize>(prefix: &str, record: &T) -> String {
    let mut value = serde_json::to_value(record).expect("kernel record serialization cannot fail");
    if let Value::Object(object) = &mut value {
        object.remove("id");
    }
    let bytes = serde_json::to_vec(&canonicalize(value))
        .expect("canonical kernel record serialization cannot fail");
    let digest = format!("{:x}", Sha256::digest(bytes));
    format!("{prefix}-{}", &digest[..16])
}

fn canonicalize(value: Value) -> Value {
    match value {
        Value::Object(object) => {
            let sorted = object
                .into_iter()
                .map(|(key, value)| (key, canonicalize(value)))
                .collect::<BTreeMap<_, _>>();
            Value::Object(sorted.into_iter().collect())
        }
        Value::Array(values) => Value::Array(values.into_iter().map(canonicalize).collect()),
        other => other,
    }
}

fn is_sha256_digest(value: &str) -> bool {
    let Some(hex) = value.strip_prefix("sha256:") else {
        return false;
    };
    hex.len() == 64
        && hex
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn push_error(
    errors: &mut Vec<KernelRecordValidationError>,
    code: &'static str,
    path: &str,
    message: &str,
) {
    errors.push(KernelRecordValidationError {
        code,
        path: path.to_string(),
        message: message.to_string(),
    });
}

fn finish(
    mut errors: Vec<KernelRecordValidationError>,
) -> Result<(), Vec<KernelRecordValidationError>> {
    errors = finish_vec(errors);
    if errors.is_empty() {
        Ok(())
    } else {
        Err(errors)
    }
}

fn finish_vec(mut errors: Vec<KernelRecordValidationError>) -> Vec<KernelRecordValidationError> {
    errors.sort_by(|left, right| {
        left.path
            .cmp(&right.path)
            .then_with(|| left.code.cmp(right.code))
            .then_with(|| left.message.cmp(&right.message))
    });
    errors.dedup();
    errors
}

fn manifest_files(manifest: &KernelArtifactBundleManifest) -> Vec<&ArtifactFile> {
    let mut files = vec![
        &manifest.kernel_image,
        &manifest.final_config,
        &manifest.build_log,
    ];
    files.extend(&manifest.declared_files);
    files
}

fn read_manifest(
    path: &Path,
) -> Result<KernelArtifactBundleManifest, Vec<KernelRecordValidationError>> {
    let bytes = fs::read(path)
        .map_err(|error| io_error("manifest-read-failed", &path.display().to_string(), error))?;
    serde_json::from_slice(&bytes).map_err(|error| {
        vec![KernelRecordValidationError {
            code: "manifest-parse-failed",
            path: path.display().to_string(),
            message: error.to_string(),
        }]
    })
}

fn create_dir(path: &Path, field: &str) -> Result<(), Vec<KernelRecordValidationError>> {
    fs::create_dir_all(path).map_err(|error| io_error("directory-create-failed", field, error))
}

fn write_synced(path: &Path, bytes: &[u8]) -> Result<(), Vec<KernelRecordValidationError>> {
    let mut file = File::create(path)
        .map_err(|error| io_error("file-create-failed", &path.display().to_string(), error))?;
    file.write_all(bytes)
        .map_err(|error| io_error("file-write-failed", &path.display().to_string(), error))?;
    file.sync_all()
        .map_err(|error| io_error("file-sync-failed", &path.display().to_string(), error))
}

fn sync_file(path: &Path) -> Result<(), Vec<KernelRecordValidationError>> {
    File::open(path)
        .and_then(|file| file.sync_all())
        .map_err(|error| io_error("file-sync-failed", &path.display().to_string(), error))
}

fn sync_directory(path: &Path) -> Result<(), Vec<KernelRecordValidationError>> {
    File::open(path)
        .and_then(|directory| directory.sync_all())
        .map_err(|error| io_error("directory-sync-failed", &path.display().to_string(), error))
}

fn io_error(
    code: &'static str,
    path: &str,
    error: std::io::Error,
) -> Vec<KernelRecordValidationError> {
    vec![KernelRecordValidationError {
        code,
        path: path.to_string(),
        message: error.to_string(),
    }]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn digest_format_is_strict() {
        assert!(is_sha256_digest(&format!("sha256:{}", "a".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha256:{}", "A".repeat(64))));
        assert!(!is_sha256_digest(&format!("sha512:{}", "a".repeat(64))));
    }
}
