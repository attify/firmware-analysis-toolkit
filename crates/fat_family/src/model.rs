#[derive(Debug, Clone, PartialEq)]
pub struct FamilyEvidence {
    pub signal: String,
    pub weight: f32,
}

#[derive(Debug, Clone, PartialEq)]
pub struct FamilyGuess {
    pub family_id: String,
    pub confidence: f32,
    pub evidence: Vec<FamilyEvidence>,
}

#[derive(Debug, Clone, Copy)]
pub struct FamilyTraits {
    pub family_id: &'static str,
    pub labels: &'static [&'static str],
    pub signals: &'static [(&'static str, f32)],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProofClass {
    AsanUseAfterFree,
    AsanHeapBufferOverflow,
    UbsanIntegerOverflow,
    GuardTrip,
    BadMessage,
    NoSignal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LocalityPolicy {
    RepoLocalOnly,
    VendoredAllowed,
    BlockWhenUpstreamHidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RequiredRoleGroup {
    pub name: &'static str,
    pub roles: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suppressor {
    pub name: &'static str,
    pub signals: &'static [&'static str],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TriggerTemplate {
    pub name: &'static str,
    pub description: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TargetPreference {
    pub kind: &'static str,
    pub value: &'static str,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DiscoveryFamilySpec {
    pub family_id: &'static str,
    pub required_role_groups: &'static [RequiredRoleGroup],
    pub suppressors: &'static [Suppressor],
    pub trigger_templates: &'static [TriggerTemplate],
    pub expected_proof_classes: &'static [ProofClass],
    pub locality_policy: LocalityPolicy,
    pub target_preferences: &'static [TargetPreference],
}
