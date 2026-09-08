use crate::android::semantic::AndroidSemanticBundle;
use crate::android::{
    control_surface_ids_where, correlation_ids_where, dedupe_strings, empty_bundle, fact_ids_where,
    revelation,
};

pub(crate) fn derive_control_plane_revelations(
    bundle: &AndroidSemanticBundle,
) -> AndroidSemanticBundle {
    let mut derived = empty_bundle();

    let command_fact_ids = fact_ids_where(bundle, |fact| fact.kind == "role.command-envelope");
    let session_fact_ids = fact_ids_where(bundle, |fact| fact.kind == "role.session-offer");
    let local_control_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "role.local-device-control");
    let command_surface_ids = control_surface_ids_where(bundle, |surface| {
        matches!(
            surface.kind.as_str(),
            "web-command-bridge" | "remote-command-dispatch" | "local-device-control-surface"
        )
    });
    let command_corr_ids =
        correlation_ids_where(bundle, |corr| corr.kind == "web-command-local-control");

    if !command_fact_ids.is_empty()
        && !session_fact_ids.is_empty()
        && !local_control_fact_ids.is_empty()
        && !command_surface_ids.is_empty()
        && !command_corr_ids.is_empty()
    {
        derived.revelations.push(revelation(
            "rev-web-to-command-plane",
            "web-to-command-plane",
            dedupe_strings(
                [
                    command_fact_ids,
                    session_fact_ids,
                    local_control_fact_ids,
                    command_surface_ids,
                    command_corr_ids,
                ]
                .into_iter()
                .flatten()
                .collect(),
            ),
            "Web bridge, command envelope, session offer, and local device control evidence align into a web-to-command plane.",
        ));
    }

    let binding_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "role.account-device-binding");
    let binding_surface_ids =
        control_surface_ids_where(bundle, |surface| surface.kind == "account-device-bind-flow");
    let binding_corr_ids =
        correlation_ids_where(bundle, |corr| corr.kind == "account-device-binding");

    if !binding_fact_ids.is_empty()
        && !binding_surface_ids.is_empty()
        && !binding_corr_ids.is_empty()
    {
        derived.revelations.push(revelation(
            "rev-account-to-device-authority-plane",
            "account-to-device-authority-plane",
            dedupe_strings(
                [binding_fact_ids, binding_surface_ids, binding_corr_ids]
                    .into_iter()
                    .flatten()
                    .collect(),
            ),
            "Account auth token and device-binding evidence align into an account-to-device authority transition.",
        ));
    }

    let runtime_fact_ids = fact_ids_where(bundle, |fact| {
        fact.kind == "runtime.app-framework" && fact.subject == "flutter"
    });
    let runtime_asset_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "artifact.bundled-script");
    let runtime_local_control_fact_ids =
        fact_ids_where(bundle, |fact| fact.kind == "role.local-device-control");
    let runtime_local_control_surface_ids = control_surface_ids_where(bundle, |surface| {
        surface.kind == "local-device-control-surface"
    });
    if !runtime_fact_ids.is_empty()
        && !runtime_asset_fact_ids.is_empty()
        && !runtime_local_control_fact_ids.is_empty()
        && !runtime_local_control_surface_ids.is_empty()
    {
        derived.revelations.push(revelation(
            "rev-runtime-to-device-control-plane",
            "runtime-to-device-control-plane",
            dedupe_strings(
                [
                    runtime_fact_ids,
                    runtime_asset_fact_ids,
                    runtime_local_control_fact_ids,
                    runtime_local_control_surface_ids,
                ]
                .into_iter()
                .flatten()
                .collect(),
            ),
            "Flutter runtime assets, packaged scripts or firmware, and local device control evidence align into a runtime-to-device control plane.",
        ));
    }

    derived
}
