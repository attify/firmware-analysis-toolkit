use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    native_ids_where, revelation,
};

pub(crate) fn derive_fabric_revelations(bundle: &AndroidSemanticBundle) -> AndroidSemanticBundle {
    let weave_fabric_fact_ids = fact_ids_where(bundle, |fact| fact.kind == "protocol.weave-fabric");
    let security_surface_ids =
        control_surface_ids_where(bundle, |surface| surface.kind == "weave-security-plane");
    let native_ids = native_ids_where(bundle, |native| native.kind == "weave-key-export-native");
    let weave_correlation_ids = correlation_ids_where(bundle, |correlation| {
        correlation.kind == "weave-auth-fabric-key-export"
    });

    if weave_fabric_fact_ids.is_empty()
        || security_surface_ids.is_empty()
        || native_ids.is_empty()
        || weave_correlation_ids.is_empty()
    {
        return empty_bundle();
    }

    let mut derived = empty_bundle();
    derived.revelations.push(revelation(
        "rev-fabric-authority-plane",
        "fabric-authority-plane",
        dedupe_strings(
            [
                weave_fabric_fact_ids,
                security_surface_ids,
                native_ids,
                weave_correlation_ids,
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
        "The weave security plane, fabric protocol, native bridge, and correlation compress into a fabric authority plane.",
    ));
    derived
}
