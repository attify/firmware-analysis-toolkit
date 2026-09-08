use std::collections::BTreeMap;
use std::path::Path;

use crate::discovery::DiscoveryLead;
use crate::ir::{EdgeKind, EdgeRecord, NodeKind, NodeRecord, Provenance};

use super::sqlite::{init_snapshot, GraphWriter, SnapshotMeta};

pub fn materialize_state_leads_snapshot(
    path: &Path,
    project_id: &str,
    leads: &[DiscoveryLead],
) -> Result<(), String> {
    init_snapshot(path, &SnapshotMeta::new(project_id, "ssdb-state-leads"))?;
    let mut writer = GraphWriter::open(path)?;

    for lead in leads {
        let lead_id = writer.insert_node(&lead_node(lead))?;
        for hypothesis in &lead.state_hypotheses {
            let hypothesis_id = writer.insert_node(&hypothesis_node(hypothesis))?;
            let mut lead_edge = EdgeRecord::new(EdgeKind::ReadsChannel, lead_id, hypothesis_id);
            lead_edge
                .attrs
                .insert("relation".into(), "has-hypothesis".into());
            lead_edge.provenance = provenance();
            writer.insert_edge(&lead_edge)?;

            for transition in &hypothesis.forbidden_transitions {
                let transition_id = writer.insert_node(&transition_node(
                    &transition.transition_id,
                    &transition.expected_proof_class,
                ))?;
                let mut transition_edge =
                    EdgeRecord::new(EdgeKind::ViolatesInvariant, hypothesis_id, transition_id);
                transition_edge
                    .attrs
                    .insert("relation".into(), "targets-transition".into());
                transition_edge.provenance = provenance();
                writer.insert_edge(&transition_edge)?;
            }
        }
    }

    Ok(())
}

fn lead_node(lead: &DiscoveryLead) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("kind".into(), "discovery-lead".into());
    attrs.insert("lead_id".into(), lead.lead_id.clone());
    attrs.insert("family".into(), lead.family.as_str().into());
    NodeRecord {
        id: 0,
        kind: NodeKind::Observation,
        label: format!("lead:{}", lead.symbol),
        attrs,
        provenance: provenance(),
    }
}

fn hypothesis_node(hypothesis: &crate::discovery::StateHypothesis) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("kind".into(), "state-hypothesis".into());
    attrs.insert("hypothesis_id".into(), hypothesis.hypothesis_id.clone());
    attrs.insert("machine_id".into(), hypothesis.machine_id.clone());
    NodeRecord {
        id: 0,
        kind: NodeKind::StateChannel,
        label: format!("hypothesis:{}", hypothesis.hypothesis_id),
        attrs,
        provenance: provenance(),
    }
}

fn transition_node(transition_id: &str, expected_proof_class: &str) -> NodeRecord {
    let mut attrs = BTreeMap::new();
    attrs.insert("kind".into(), "forbidden-transition".into());
    attrs.insert("transition_id".into(), transition_id.into());
    attrs.insert("expected_proof_class".into(), expected_proof_class.into());
    NodeRecord {
        id: 0,
        kind: NodeKind::Invariant,
        label: format!("transition:{transition_id}"),
        attrs,
        provenance: provenance(),
    }
}

fn provenance() -> Provenance {
    Provenance {
        source: "ssdb-state-snapshot".into(),
        confidence_millis: 900,
    }
}
