use crate::android::extractor::AndroidSemanticMode;
use crate::android::semantic::{AndroidProvenance, AndroidSemanticBundle};
use std::path::PathBuf;

pub mod ble;
pub mod ble_security;
pub mod command_catalog;
pub mod control_plane;
pub mod http_api;
pub mod matter;
pub mod security_constants;
pub mod security_posture;
pub mod weave;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub(crate) enum ProtocolSignalKind {
    WeaveAuth,
    WeaveFabric,
    WeaveKeyExport,
    WeaveNativeKeyExport,
    MatterCommissioning,
    MatterCommissioningField,
    BleImport,
    BleSymbol,
    BleCharacteristicUuid,
    BleCryptoMode,
    BleSessionKeyDerivation,
    WebBridgeEntry,
    CommandEnvelope,
    CommandCatalogEntry,
    CommandEnvelopeField,
    SessionOffer,
    LocalDeviceControl,
    AccountAuth,
    AccountDeviceBinding,
    HttpApiEndpoint,
    HttpAuthHeader,
    HttpDynamicPath,
    StaticSecret,
    PublicKey,
    SymmetricKeyMaterial,
    DefaultCredential,
    NetworkStaticEndpoint,
    HostnameVerificationDisabled,
    WeakTrustManager,
    PlaintextTokenStore,
    AvailableEncryptionUnused,
}

#[derive(Debug, Clone)]
pub(crate) struct ProtocolSignal {
    pub kind: ProtocolSignalKind,
    pub detail: Option<String>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProtocolFileView {
    pub path: PathBuf,
    pub provenance: AndroidProvenance,
    pub signals: Vec<ProtocolSignal>,
}

#[derive(Debug, Clone)]
pub(crate) struct ProtocolIndex {
    pub files: Vec<ProtocolFileView>,
}

pub(crate) fn derive_protocol_semantics(
    index: &ProtocolIndex,
    mode: AndroidSemanticMode,
) -> AndroidSemanticBundle {
    let mut bundle = empty_bundle();
    merge_semantics(&mut bundle, weave::derive_weave_semantics(index, mode));
    merge_semantics(&mut bundle, matter::derive_matter_semantics(index, mode));
    merge_semantics(&mut bundle, ble::derive_ble_semantics(index, mode));
    merge_semantics(
        &mut bundle,
        ble_security::derive_ble_security_semantics(index, mode),
    );
    merge_semantics(
        &mut bundle,
        command_catalog::derive_command_catalog_semantics(index, mode),
    );
    merge_semantics(
        &mut bundle,
        control_plane::derive_control_plane_semantics(index, mode),
    );
    merge_semantics(
        &mut bundle,
        http_api::derive_http_api_semantics(index, mode),
    );
    merge_semantics(
        &mut bundle,
        security_constants::derive_security_constant_semantics(index, mode),
    );
    merge_semantics(
        &mut bundle,
        security_posture::derive_security_posture_semantics(index, mode),
    );
    bundle
}

fn merge_semantics(into: &mut AndroidSemanticBundle, other: AndroidSemanticBundle) {
    into.facts.extend(other.facts);
    into.symbol_identities.extend(other.symbol_identities);
    into.control_surfaces.extend(other.control_surfaces);
    into.transport_surfaces.extend(other.transport_surfaces);
    into.trust_boundaries.extend(other.trust_boundaries);
    into.resources.extend(other.resources);
    into.native_semantics.extend(other.native_semantics);
    into.correlations.extend(other.correlations);
    into.warnings.extend(other.warnings);
}

fn empty_bundle() -> AndroidSemanticBundle {
    crate::android::semantic::AndroidSemanticBundle {
        bundle_version: String::new(),
        target: crate::android::semantic::AndroidSemanticTarget {
            application_id: None,
            package_name: String::new(),
            version_code: None,
            version_name: None,
            split_names: Vec::new(),
        },
        extractor: crate::android::semantic::AndroidExtractorMetadata {
            extractor_id: String::new(),
            extractor_version: String::new(),
            input_kind: String::new(),
            generated_at_utc: None,
            degraded: false,
            notes: Vec::new(),
        },
        facts: Vec::new(),
        symbol_identities: Vec::new(),
        control_surfaces: Vec::new(),
        transport_surfaces: Vec::new(),
        trust_boundaries: Vec::new(),
        resources: Vec::new(),
        native_semantics: Vec::new(),
        subsystems: Vec::new(),
        revelations: Vec::new(),
        correlations: Vec::new(),
        warnings: Vec::new(),
    }
}
