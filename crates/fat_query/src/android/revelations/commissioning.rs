use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    native_ids_where, revelation,
};

pub(crate) fn derive_commissioning_revelations(
    bundle: &AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    let security_facts = fact_ids_where(bundle, |fact| {
        fact.kind == "source.security-family"
            && matches!(fact.subject.as_str(), "commissioning" | "pairing-code")
    });
    let commissioning_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "protocol.matter-commissioning");
    let session_surface_ids = control_surface_ids_where(bundle, |surface| {
        matches!(
            surface.kind.as_str(),
            "device-commissioning-flow" | "matter-commissioning-session"
        )
    });
    let native_ids = native_ids_where(bundle, |native| native.kind == "weave-key-export-native");
    let session_correlation_ids = correlation_ids_where(bundle, |correlation| {
        correlation.kind == "matter-commissioning-session"
    });

    if commissioning_fact_ids.is_empty()
        || session_surface_ids.is_empty()
        || native_ids.is_empty()
        || session_correlation_ids.is_empty()
    {
        return empty_bundle();
    }

    let mut derived = empty_bundle();
    derived.revelations.push(revelation(
        "rev-commissioning-plane",
        "commissioning-plane",
        dedupe_strings(
            [
                security_facts,
                commissioning_fact_ids,
                session_surface_ids,
                native_ids,
                session_correlation_ids,
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
        "Commissioning, pairing-code, and Matter session markers align on a single setup plane.",
    ));
    derived
}
