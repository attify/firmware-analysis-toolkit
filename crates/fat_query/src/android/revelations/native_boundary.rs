use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    native_ids_where, revelation,
};

pub(crate) fn derive_native_boundary_revelations(
    bundle: &AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    let load_library_fact_ids = fact_ids_where(bundle, |fact| {
        fact.kind == "source.load-library"
            && fact
                .subject
                .to_ascii_lowercase()
                .contains("weavedevicemanager")
    });
    let security_native_fact_ids = fact_ids_where(bundle, |fact| {
        matches!(
            fact.kind.as_str(),
            "protocol.weave-key-export" | "source.security-family"
        ) && matches!(
            fact.subject.as_str(),
            "key-export" | "pairing-code" | "certificate" | "access-token"
        )
    });
    let callback_surface_ids = control_surface_ids_where(bundle, |surface| {
        surface.kind == "device-management-callback"
    });
    let native_ids = native_ids_where(bundle, |native| {
        native.kind == "java-load-library"
            && (native
                .library_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("WeaveDeviceManager"))
                || native
                    .symbol_name
                    .to_ascii_lowercase()
                    .contains("weavedevicemanager"))
    });
    let security_native_ids =
        native_ids_where(bundle, |native| native.kind == "weave-key-export-native");
    let correlation_ids = correlation_ids_where(bundle, |correlation| {
        matches!(
            correlation.kind.as_str(),
            "java-native-bridge" | "weave-auth-fabric-key-export"
        )
    });

    if load_library_fact_ids.is_empty() && security_native_fact_ids.is_empty() {
        return empty_bundle();
    }
    if native_ids.is_empty() && security_native_ids.is_empty() {
        return empty_bundle();
    }
    if callback_surface_ids.is_empty() || correlation_ids.is_empty() {
        return empty_bundle();
    }
    let members = dedupe_strings(
        [
            load_library_fact_ids,
            security_native_fact_ids,
            native_ids,
            security_native_ids,
            callback_surface_ids,
            correlation_ids,
        ]
        .into_iter()
        .flatten()
        .collect(),
    );

    if members.is_empty() {
        return empty_bundle();
    }

    let mut derived = empty_bundle();
    derived.revelations.push(revelation(
        "rev-jni-security-boundary",
        "jni-security-boundary",
        members,
        "The Java loadLibrary bridge and device callback surface identify a JNI security boundary.",
    ));
    derived
}
