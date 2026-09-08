use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    native_ids_where, revelation,
};

pub(crate) fn derive_key_lifecycle_revelations(
    bundle: &AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    let weave_key_export_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "protocol.weave-key-export");
    let security_surface_ids =
        control_surface_ids_where(bundle, |surface| surface.kind == "weave-security-plane");
    let native_ids = native_ids_where(bundle, |native| native.kind == "weave-key-export-native");
    let key_export_correlation_ids = correlation_ids_where(bundle, |correlation| {
        correlation.kind == "weave-auth-fabric-key-export"
    });

    if weave_key_export_fact_ids.is_empty()
        || security_surface_ids.is_empty()
        || native_ids.is_empty()
        || key_export_correlation_ids.is_empty()
    {
        return empty_bundle();
    }

    let mut derived = empty_bundle();
    derived.revelations.push(revelation(
        "rev-key-export-risk-plane",
        "key-export-risk-plane",
        dedupe_strings(
            [
                weave_key_export_fact_ids,
                security_surface_ids,
                native_ids,
                key_export_correlation_ids,
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
        "The security plane, key-export bridge, and correlation compress into a key lifecycle risk plane.",
    ));
    derived
}
