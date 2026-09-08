use crate::discovery::DiscoveryLead;
use crate::harnesses::HarnessPlan;
use crate::target_lanes::{LaneAdapterKind, TargetLaneRecord};

pub mod browser_lifetime_webtest;
pub mod direct_cli_size;
pub mod stderr_proof;

pub fn configure_lifetime_plan(
    plan: &mut HarnessPlan,
    lead: &DiscoveryLead,
    lane: &TargetLaneRecord,
) {
    if matches!(
        lane.adapter.as_ref().map(|adapter| adapter.kind()),
        Some(LaneAdapterKind::BrowserLifetimeWebtest)
    ) {
        browser_lifetime_webtest::configure(plan, lead, lane);
    }
}

pub fn configure_size_plan(plan: &mut HarnessPlan, lead: &DiscoveryLead, lane: &TargetLaneRecord) {
    if matches!(
        lane.adapter.as_ref().map(|adapter| adapter.kind()),
        Some(LaneAdapterKind::DirectCliSize)
    ) {
        direct_cli_size::configure(plan, lead, lane);
    }
}

pub fn configure_protocol_plan(plan: &mut HarnessPlan, lane: &TargetLaneRecord) {
    if matches!(
        lane.adapter.as_ref().map(|adapter| adapter.kind()),
        Some(LaneAdapterKind::StderrProofProtocol)
    ) {
        stderr_proof::configure_protocol(plan, lane);
    }
}

pub fn configure_validation_plan(plan: &mut HarnessPlan, lane: &TargetLaneRecord) {
    if matches!(
        lane.adapter.as_ref().map(|adapter| adapter.kind()),
        Some(LaneAdapterKind::StderrProofValidation)
    ) {
        stderr_proof::configure_validation(plan, lane);
    }
}
