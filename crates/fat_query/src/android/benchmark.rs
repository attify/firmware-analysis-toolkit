use crate::android::discovery::build_discover_report;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;
use zip::write::SimpleFileOptions;
use zip::ZipWriter;

#[derive(Debug, Clone, Deserialize)]
pub struct AndroidDiscoveryBenchmarkManifest {
    pub suite: String,
    pub top_k: usize,
    pub cases: Vec<AndroidDiscoveryBenchmarkCaseManifest>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct AndroidDiscoveryBenchmarkCaseManifest {
    pub id: String,
    pub package_name: String,
    pub semantic_bundle: String,
    #[serde(default)]
    pub family: Option<String>,
    pub expect_min_leads: usize,
    #[serde(default)]
    pub expect_top_family: Option<String>,
    #[serde(default)]
    pub expect_symbol_contains: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidDiscoveryBenchmarkCaseResult {
    pub id: String,
    pub family: Option<String>,
    pub lead_count: usize,
    #[serde(default)]
    pub top_family: Option<String>,
    pub expected_min_leads: usize,
    pub family_match: bool,
    pub symbol_match: bool,
    pub passed: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AndroidDiscoveryBenchmarkSummary {
    pub suite: String,
    pub top_k: usize,
    pub pass_count: usize,
    pub family_hit_rate: f64,
    pub positive_precision: f64,
    pub cases: Vec<AndroidDiscoveryBenchmarkCaseResult>,
}

pub fn run_android_discovery_benchmark(
    manifest_path: &Path,
) -> Result<AndroidDiscoveryBenchmarkSummary, String> {
    let manifest = load_manifest(manifest_path)?;
    let manifest_dir = manifest_path
        .parent()
        .ok_or_else(|| format!("manifest has no parent: {}", manifest_path.display()))?;
    let mut results = Vec::new();
    for case in &manifest.cases {
        results.push(run_case(case, manifest_dir, manifest.top_k)?);
    }

    let pass_count = results.iter().filter(|case| case.passed).count();
    let positive_cases = results
        .iter()
        .filter(|case| case.expected_min_leads > 0)
        .collect::<Vec<_>>();
    let family_hit_rate = if positive_cases.is_empty() {
        0.0
    } else {
        positive_cases
            .iter()
            .filter(|case| case.family_match)
            .count() as f64
            / positive_cases.len() as f64
    };
    let positive_precision = if positive_cases.is_empty() {
        0.0
    } else {
        positive_cases.iter().filter(|case| case.passed).count() as f64
            / positive_cases.len() as f64
    };

    Ok(AndroidDiscoveryBenchmarkSummary {
        suite: manifest.suite,
        top_k: manifest.top_k,
        pass_count,
        family_hit_rate,
        positive_precision,
        cases: results,
    })
}

fn run_case(
    case: &AndroidDiscoveryBenchmarkCaseManifest,
    manifest_dir: &Path,
    top_k: usize,
) -> Result<AndroidDiscoveryBenchmarkCaseResult, String> {
    let temp = tempfile::tempdir().map_err(|e| format!("tempdir failed: {e}"))?;
    let apk_path = temp.path().join(format!("{}.apk", case.id));
    write_minimal_apk(&apk_path, &case.package_name)?;
    let semantic_bundle = manifest_dir.join(&case.semantic_bundle);
    let report = build_discover_report(
        &apk_path,
        &[],
        Some(&semantic_bundle),
        case.family.as_deref(),
        top_k,
        "benchmark",
    )?;
    let top_family = report.leads.first().map(|lead| lead.family.clone());
    let family_match = case
        .expect_top_family
        .as_ref()
        .map(|expected| top_family.as_deref() == Some(expected.as_str()))
        .unwrap_or(report.lead_count >= case.expect_min_leads);
    let symbol_match = case
        .expect_symbol_contains
        .as_ref()
        .map(|needle| report.leads.iter().any(|lead| lead.symbol.contains(needle)))
        .unwrap_or(true);
    let passed = report.lead_count >= case.expect_min_leads && family_match && symbol_match;

    Ok(AndroidDiscoveryBenchmarkCaseResult {
        id: case.id.clone(),
        family: case.family.clone(),
        lead_count: report.lead_count,
        top_family,
        expected_min_leads: case.expect_min_leads,
        family_match,
        symbol_match,
        passed,
    })
}

fn load_manifest(path: &Path) -> Result<AndroidDiscoveryBenchmarkManifest, String> {
    let bytes = fs::read(path)
        .map_err(|e| format!("failed to read benchmark manifest {}: {e}", path.display()))?;
    serde_json::from_slice(&bytes)
        .map_err(|e| format!("failed to parse benchmark manifest {}: {e}", path.display()))
}

fn write_minimal_apk(path: &Path, package_name: &str) -> Result<(), String> {
    let file = std::fs::File::create(path)
        .map_err(|e| format!("create {} failed: {e}", path.display()))?;
    let mut zip = ZipWriter::new(file);
    let opts = SimpleFileOptions::default();
    let manifest = format!(r#"<manifest package="{package_name}"><application /></manifest>"#);

    zip.start_file("AndroidManifest.xml", opts)
        .map_err(|e| format!("manifest entry failed: {e}"))?;
    use std::io::Write as _;
    zip.write_all(manifest.as_bytes())
        .map_err(|e| format!("manifest write failed: {e}"))?;
    zip.start_file("classes.dex", opts)
        .map_err(|e| format!("classes.dex entry failed: {e}"))?;
    zip.write_all(b"dex")
        .map_err(|e| format!("classes.dex write failed: {e}"))?;
    zip.finish()
        .map_err(|e| format!("finish zip failed: {e}"))?;
    Ok(())
}
