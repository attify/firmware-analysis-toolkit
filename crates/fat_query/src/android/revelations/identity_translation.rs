use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    native_ids_where, revelation,
};

pub(crate) fn derive_identity_translation_revelations(
    bundle: &AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    let weave_facts = fact_ids_where(bundle, |fact| {
        fact.kind == "source.protocol-family" && fact.subject == "weave"
    });
    let matter_fact_ids = fact_ids_where(bundle, |fact| {
        (fact.kind == "source.protocol-family" && fact.subject == "matter")
            || fact.kind == "protocol.matter-commissioning"
    });
    let auth_fact_ids = fact_ids_where(bundle, |fact| fact.kind == "protocol.weave-auth");
    let security_surface_ids =
        control_surface_ids_where(bundle, |surface| surface.kind == "weave-security-plane");
    let matter_surface_ids = control_surface_ids_where(bundle, |surface| {
        matches!(
            surface.kind.as_str(),
            "matter-commissioning-session" | "device-commissioning-flow"
        )
    });
    let native_ids = native_ids_where(bundle, |native| {
        native.kind == "java-load-library"
            && native
                .library_name
                .as_deref()
                .is_some_and(|name| name.eq_ignore_ascii_case("WeaveDeviceManager"))
    });
    let correlation_ids = correlation_ids_where(bundle, |correlation| {
        matches!(
            correlation.kind.as_str(),
            "weave-auth-fabric-key-export"
                | "device-stack-protocol-composition"
                | "matter-commissioning-session"
        )
    });

    if weave_facts.is_empty() || matter_fact_ids.is_empty() {
        return empty_bundle();
    }
    if auth_fact_ids.is_empty()
        || security_surface_ids.is_empty()
        || matter_surface_ids.is_empty()
        || native_ids.is_empty()
        || correlation_ids.is_empty()
    {
        return empty_bundle();
    }

    let mut derived = empty_bundle();
    derived.revelations.push(revelation(
        "rev-weave-matter-bridge",
        "weave-matter-bridge",
        dedupe_strings(
            [
                weave_facts,
                matter_fact_ids,
                auth_fact_ids,
                security_surface_ids,
                matter_surface_ids,
                native_ids,
                correlation_ids,
            ]
            .into_iter()
            .flatten()
            .collect(),
        ),
        "Weave and Matter commissioning markers bridge through the security plane and native edge.",
    ));
    derived
}
