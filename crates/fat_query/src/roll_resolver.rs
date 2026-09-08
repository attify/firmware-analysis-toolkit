use crate::result::{LocalityStatus, RollResolution};
use serde::Deserialize;
use std::path::{Path, PathBuf};

#[derive(Debug, Deserialize)]
struct RollMetadata {
    #[serde(default)]
    likely_upstream_repo: Option<String>,
    #[serde(default)]
    vendored_nearby_path: Option<PathBuf>,
    #[serde(default)]
    local_patch_touching_vendored_code: bool,
    #[serde(default)]
    no_local_vulnerable_source_likely: bool,
}

pub fn resolve_roll_locality(root: &Path) -> Result<RollResolution, String> {
    if let Some(explicit) = load_explicit_roll_metadata(root)? {
        return Ok(explicit);
    }

    let patch_text = load_patch_if_present(root)?;
    let mentions_vendored = patch_text
        .as_deref()
        .map(|patch| patch.contains("third_party/") || patch.contains("vendor/"))
        .unwrap_or(false);
    let vendored_path = discover_vendored_path(root);

    let locality = if mentions_vendored || vendored_path.is_some() {
        LocalityStatus::VendoredLocal
    } else {
        LocalityStatus::RepoLocal
    };

    Ok(RollResolution {
        locality: locality.clone(),
        likely_upstream_repo: None,
        vendored_nearby_path: vendored_path.clone(),
        local_patch_touching_vendored_code: mentions_vendored,
        no_local_vulnerable_source_likely: false,
        allow_vendored_scan: matches!(locality, LocalityStatus::VendoredLocal)
            && vendored_path.is_some(),
        observed: vec![format!(
            "locality={}",
            match locality {
                LocalityStatus::RepoLocal => "RepoLocal",
                LocalityStatus::VendoredLocal => "VendoredLocal",
                LocalityStatus::Generated => "Generated",
                LocalityStatus::UpstreamReferenced => "UpstreamReferenced",
                LocalityStatus::UpstreamHidden => "UpstreamHidden",
                LocalityStatus::Unknown => "Unknown",
            }
        )],
        inferred: if mentions_vendored {
            vec!["patch or tree suggests vendored-local neighborhood".into()]
        } else {
            vec!["no vendored or upstream-hidden signal observed".into()]
        },
    })
}

fn load_explicit_roll_metadata(root: &Path) -> Result<Option<RollResolution>, String> {
    let metadata_path = root.join("fat-roll-metadata.json");
    if !metadata_path.is_file() {
        return Ok(None);
    }
    let text = std::fs::read_to_string(&metadata_path)
        .map_err(|e| format!("failed to read {}: {}", metadata_path.display(), e))?;
    let meta: RollMetadata =
        serde_json::from_str(&text).map_err(|e| format!("invalid roll metadata: {e}"))?;
    let locality = if meta.no_local_vulnerable_source_likely {
        LocalityStatus::UpstreamHidden
    } else if meta.vendored_nearby_path.is_some() {
        LocalityStatus::VendoredLocal
    } else if meta.likely_upstream_repo.is_some() {
        LocalityStatus::UpstreamReferenced
    } else {
        LocalityStatus::RepoLocal
    };
    Ok(Some(RollResolution {
        locality: locality.clone(),
        likely_upstream_repo: meta.likely_upstream_repo,
        vendored_nearby_path: meta.vendored_nearby_path.clone(),
        local_patch_touching_vendored_code: meta.local_patch_touching_vendored_code,
        no_local_vulnerable_source_likely: meta.no_local_vulnerable_source_likely,
        allow_vendored_scan: matches!(locality, LocalityStatus::VendoredLocal)
            && meta.vendored_nearby_path.is_some(),
        observed: vec!["explicit roll metadata loaded".into()],
        inferred: vec![],
    }))
}

fn load_patch_if_present(root: &Path) -> Result<Option<String>, String> {
    let patch = root.join("patch.diff");
    if patch.is_file() {
        return std::fs::read_to_string(&patch)
            .map(Some)
            .map_err(|e| format!("failed to read {}: {}", patch.display(), e));
    }
    Ok(None)
}

fn discover_vendored_path(root: &Path) -> Option<PathBuf> {
    ["third_party", "vendor", "external"]
        .into_iter()
        .map(|name| root.join(name))
        .find(|path| path.exists())
}
