use crate::android::discovery::{AndroidArtifactFact, AndroidArtifactKind, AndroidResourceFact};

pub fn collect_resource_facts(artifacts: &[AndroidArtifactFact]) -> AndroidResourceFact {
    let xml_files = artifacts
        .iter()
        .filter(|artifact| matches!(artifact.kind, AndroidArtifactKind::ResourceXml))
        .map(|artifact| artifact.path.clone())
        .collect();
    let html_assets = artifacts
        .iter()
        .filter(|artifact| {
            matches!(artifact.kind, AndroidArtifactKind::Asset)
                && (artifact.path.ends_with(".html") || artifact.path.ends_with(".htm"))
        })
        .map(|artifact| artifact.path.clone())
        .collect::<Vec<_>>();
    let route_like_assets = artifacts
        .iter()
        .filter(|artifact| {
            artifact.path.contains("route")
                || artifact.path.contains("router")
                || artifact.path.contains("deeplink")
                || artifact.path.contains("deep_link")
        })
        .map(|artifact| artifact.path.clone())
        .collect();

    AndroidResourceFact {
        xml_files,
        html_assets,
        route_like_assets,
    }
}
