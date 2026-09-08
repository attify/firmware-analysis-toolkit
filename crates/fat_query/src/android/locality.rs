use crate::android::discovery::{
    AndroidApkContainerInventory, AndroidArtifactFact, AndroidArtifactKind, AndroidContainerKind,
    AndroidLocalityClass, AndroidLocalityRecord, AndroidLocalitySummary,
};
use crate::android::native::classify_native_library_provenance;

pub fn build_locality_records(
    containers: &[AndroidApkContainerInventory],
) -> Vec<AndroidLocalityRecord> {
    let mut records = Vec::new();
    for container in containers {
        for artifact in &container.artifacts {
            if matches!(artifact.kind, AndroidArtifactKind::Other) {
                continue;
            }
            records.push(AndroidLocalityRecord {
                apk_path: container.apk_path.clone(),
                artifact_path: artifact.path.clone(),
                kind: artifact.kind.clone(),
                locality: classify_artifact(container.kind.clone(), artifact),
            });
        }
    }
    records
}

pub fn summarize_locality_records(records: &[AndroidLocalityRecord]) -> AndroidLocalitySummary {
    let mut summary = AndroidLocalitySummary {
        app_local: 0,
        split_feature_local: 0,
        bundled_sdk: 0,
        bundled_native_lib: 0,
        vendored_local: 0,
        likely_upstream: 0,
        unknown: 0,
    };
    for record in records {
        match record.locality {
            AndroidLocalityClass::AppLocal => summary.app_local += 1,
            AndroidLocalityClass::SplitFeatureLocal => summary.split_feature_local += 1,
            AndroidLocalityClass::BundledSdk => summary.bundled_sdk += 1,
            AndroidLocalityClass::BundledNativeLib => summary.bundled_native_lib += 1,
            AndroidLocalityClass::VendoredLocal => summary.vendored_local += 1,
            AndroidLocalityClass::LikelyUpstream => summary.likely_upstream += 1,
            AndroidLocalityClass::Unknown => summary.unknown += 1,
        }
    }
    summary
}

fn classify_artifact(
    kind: AndroidContainerKind,
    artifact: &AndroidArtifactFact,
) -> AndroidLocalityClass {
    if matches!(kind, AndroidContainerKind::SplitApk) {
        return AndroidLocalityClass::SplitFeatureLocal;
    }
    if matches!(artifact.kind, AndroidArtifactKind::NativeLib) {
        let library_name = artifact.path.rsplit('/').next().unwrap_or("unknown.so");
        return match classify_native_library_provenance(library_name) {
            "well-known-sdk" => AndroidLocalityClass::BundledSdk,
            _ => AndroidLocalityClass::Unknown,
        };
    }
    if artifact.path.contains("third_party")
        || artifact.path.contains("vendor/")
        || artifact.path.contains("sdk/")
    {
        return AndroidLocalityClass::VendoredLocal;
    }
    if artifact.path.contains("flutter_assets")
        || artifact.path.starts_with("assets/")
        || artifact.path.starts_with("res/")
        || artifact.path == "AndroidManifest.xml"
        || artifact.path.starts_with("classes")
    {
        return AndroidLocalityClass::AppLocal;
    }
    AndroidLocalityClass::Unknown
}

#[cfg(test)]
mod tests {
    use super::classify_artifact;
    use crate::android::discovery::{
        AndroidArtifactFact, AndroidArtifactKind, AndroidContainerKind, AndroidLocalityClass,
    };

    #[test]
    fn classify_artifact_distinguishes_native_sdk_and_unknown() {
        let sdk = AndroidArtifactFact {
            path: "lib/arm64-v8a/libmmkv.so".into(),
            kind: AndroidArtifactKind::NativeLib,
            size_bytes: 1,
        };
        let unknown = AndroidArtifactFact {
            path: "lib/arm64-v8a/libmystery.so".into(),
            kind: AndroidArtifactKind::NativeLib,
            size_bytes: 1,
        };

        assert_eq!(
            classify_artifact(AndroidContainerKind::BaseApk, &sdk),
            AndroidLocalityClass::BundledSdk
        );
        assert_eq!(
            classify_artifact(AndroidContainerKind::BaseApk, &unknown),
            AndroidLocalityClass::Unknown
        );
    }
}
