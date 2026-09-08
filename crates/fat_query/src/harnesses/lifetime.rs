use crate::discovery::DiscoveryLead;
use crate::harnesses::{new_plan, target_adapters, HarnessKind, HarnessPlan};
use crate::target_lanes::TargetLaneRecord;

pub fn build_plan(lead: &DiscoveryLead, lane: &TargetLaneRecord) -> HarnessPlan {
    let expected = lead
        .expected_proof_signal
        .iter()
        .map(|signal| signal.kind.clone())
        .collect::<Vec<_>>();
    let mut plan = new_plan(lead, lane, HarnessKind::ReentrancyTeardown, expected);
    target_adapters::configure_lifetime_plan(&mut plan, lead, lane);
    plan
}
