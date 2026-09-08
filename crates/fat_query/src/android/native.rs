use crate::android::discovery::{AndroidArtifactFact, AndroidArtifactKind, AndroidNativeLibFact};

pub fn collect_native_libs(artifacts: &[AndroidArtifactFact]) -> Vec<AndroidNativeLibFact> {
    artifacts
        .iter()
        .filter(|artifact| matches!(artifact.kind, AndroidArtifactKind::NativeLib))
        .map(|artifact| {
            let mut parts = artifact.path.split('/');
            let _lib = parts.next();
            let abi = parts.next().unwrap_or("unknown").to_string();
            let library_name = artifact
                .path
                .rsplit('/')
                .next()
                .unwrap_or("unknown.so")
                .to_string();
            AndroidNativeLibFact {
                path: artifact.path.clone(),
                abi,
                provenance_class: classify_native_library_provenance(&library_name).into(),
                library_name,
            }
        })
        .collect()
}

pub(crate) fn classify_native_library_provenance(library_name: &str) -> &'static str {
    let lower = library_name.to_ascii_lowercase();
    if matches!(
        lower.as_str(),
        "libmmkv.so"
            | "libmsc.so"
            | "libbugly.so"
            | "libc++_shared.so"
            | "libffmpeg.so"
            | "libagora-rtc-sdk-jni.so"
            | "libijkffmpeg.so"
            | "libyuv.so"
    ) || lower.contains("iflytek")
        || lower.contains("agora")
        || lower.contains("mmkv")
        || lower.contains("bugly")
        || lower.contains("ffmpeg")
    {
        return "well-known-sdk";
    }
    "unknown"
}

#[cfg(test)]
mod tests {
    use super::classify_native_library_provenance;

    #[test]
    fn classify_native_library_provenance_does_not_infer_first_party_from_target_name() {
        assert_eq!(
            classify_native_library_provenance("libunitree_native.so"),
            "unknown"
        );
        assert_eq!(
            classify_native_library_provenance("libmmkv.so"),
            "well-known-sdk"
        );
        assert_eq!(
            classify_native_library_provenance("libmystery.so"),
            "unknown"
        );
    }
}
