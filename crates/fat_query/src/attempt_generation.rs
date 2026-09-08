use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use crate::harnesses::{HarnessKind, HarnessPlan, InputBinding};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ParamKind {
    Integer,
    Enum,
    Path,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ParamDomain {
    pub name: String,
    pub kind: ParamKind,
    pub seeds: Vec<String>,
    pub edge_cases: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "kebab-case")]
pub enum GenerationStrategy {
    #[default]
    SeedOnly,
    CartesianProduct,
    FocusedEdgeSweep,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedAttemptBinding {
    pub binding_id: String,
    pub inputs: Vec<InputBinding>,
}

pub fn plan_param_domains(plan: &HarnessPlan) -> Vec<ParamDomain> {
    plan.param_domains.clone()
}

pub fn generate_attempt_bindings(plan: &HarnessPlan) -> Vec<GeneratedAttemptBinding> {
    if plan.param_domains.is_empty() {
        return vec![GeneratedAttemptBinding {
            binding_id: format!("{}::g0", plan.harness_id),
            inputs: plan.input_bindings.clone(),
        }];
    }

    match plan.generation_strategy {
        GenerationStrategy::SeedOnly => {
            let inputs = plan
                .param_domains
                .iter()
                .filter_map(|domain| {
                    domain.seeds.first().map(|value| InputBinding {
                        key: domain.name.clone(),
                        value: value.clone(),
                    })
                })
                .collect::<Vec<_>>();
            vec![GeneratedAttemptBinding {
                binding_id: format!("{}::g0", plan.harness_id),
                inputs: finalize_inputs(plan, inputs),
            }]
        }
        GenerationStrategy::CartesianProduct => cartesian_product_bindings(plan),
        GenerationStrategy::FocusedEdgeSweep => focused_edge_sweep_bindings(plan),
    }
}

fn cartesian_product_bindings(plan: &HarnessPlan) -> Vec<GeneratedAttemptBinding> {
    let mut domain_values = Vec::new();
    for domain in &plan.param_domains {
        let mut values = Vec::new();
        let mut seen = BTreeSet::new();
        for value in domain.seeds.iter().chain(domain.edge_cases.iter()) {
            if seen.insert(value.clone()) {
                values.push(value.clone());
            }
        }
        if values.is_empty() {
            return vec![GeneratedAttemptBinding {
                binding_id: format!("{}::g0", plan.harness_id),
                inputs: plan.input_bindings.clone(),
            }];
        }
        domain_values.push((domain.name.clone(), values));
    }

    let mut rows = vec![BTreeMap::<String, String>::new()];
    for (name, values) in domain_values {
        let mut next = Vec::new();
        for row in &rows {
            for value in &values {
                let mut expanded = row.clone();
                expanded.insert(name.clone(), value.clone());
                next.push(expanded);
            }
        }
        rows = next;
    }

    rows.into_iter()
        .enumerate()
        .map(|(index, row)| GeneratedAttemptBinding {
            binding_id: format!("{}::g{}", plan.harness_id, index),
            inputs: finalize_inputs(
                plan,
                row.into_iter()
                    .map(|(key, value)| InputBinding { key, value })
                    .collect(),
            ),
        })
        .collect()
}

fn focused_edge_sweep_bindings(plan: &HarnessPlan) -> Vec<GeneratedAttemptBinding> {
    let base_inputs = base_seed_inputs(plan);
    let mut bindings = vec![GeneratedAttemptBinding {
        binding_id: format!("{}::g0", plan.harness_id),
        inputs: finalize_inputs(plan, base_inputs.clone()),
    }];

    let mut index = 1;
    for domain in &plan.param_domains {
        for edge in &domain.edge_cases {
            let mut inputs = base_inputs.clone();
            if let Some(binding) = inputs.iter_mut().find(|binding| binding.key == domain.name) {
                binding.value = edge.clone();
            } else {
                inputs.push(InputBinding {
                    key: domain.name.clone(),
                    value: edge.clone(),
                });
            }
            bindings.push(GeneratedAttemptBinding {
                binding_id: format!("{}::g{}", plan.harness_id, index),
                inputs: finalize_inputs(plan, inputs),
            });
            index += 1;
        }
    }

    bindings
}

fn base_seed_inputs(plan: &HarnessPlan) -> Vec<InputBinding> {
    let mut inputs = plan.input_bindings.clone();
    for domain in &plan.param_domains {
        if let Some(seed) = domain.seeds.first() {
            if let Some(binding) = inputs.iter_mut().find(|binding| binding.key == domain.name) {
                binding.value = seed.clone();
            } else {
                inputs.push(InputBinding {
                    key: domain.name.clone(),
                    value: seed.clone(),
                });
            }
        }
    }
    inputs
}

fn finalize_inputs(plan: &HarnessPlan, mut inputs: Vec<InputBinding>) -> Vec<InputBinding> {
    if matches!(plan.kind, HarnessKind::ShapeStride) && plan_requires_arg_size(plan) {
        let binding_map = inputs
            .iter()
            .map(|binding| (binding.key.as_str(), binding.value.as_str()))
            .collect::<BTreeMap<_, _>>();
        if !binding_map.contains_key("arg_size") {
            if let Some(arg_size) = derive_shape_stride_arg_size(plan, &binding_map) {
                inputs.push(InputBinding {
                    key: "arg_size".into(),
                    value: arg_size,
                });
            }
        }
    }
    inputs
}

fn plan_requires_arg_size(plan: &HarnessPlan) -> bool {
    plan.input_bindings.iter().any(|binding| binding.key == "arg_size")
        || plan
            .argv_template
            .iter()
            .any(|template| matches!(template, crate::harnesses::ArgTemplate::Binding { key } if key == "arg_size"))
}

fn derive_shape_stride_arg_size(
    plan: &HarnessPlan,
    binding_map: &BTreeMap<&str, &str>,
) -> Option<String> {
    let payload_bytes = parse_u64(binding_map.get("payload_bytes").copied()?)?;
    let row_pitch = parse_u64(binding_map.get("row_pitch").copied().unwrap_or("0")).unwrap_or(0);
    let depth_pitch =
        parse_u64(binding_map.get("depth_pitch").copied().unwrap_or("0")).unwrap_or(0);
    let height = parse_u64(binding_map.get("height").copied().unwrap_or("0")).unwrap_or(0);
    let base_row_pitch = domain_seed(plan, "row_pitch").and_then(parse_u64);
    let base_depth_pitch = domain_seed(plan, "depth_pitch").and_then(parse_u64);

    let arg_size = if base_row_pitch.is_some()
        && Some(row_pitch) != base_row_pitch
        && row_pitch > 0
        && height > 0
    {
        row_pitch.saturating_mul(height).saturating_sub(1)
    } else if base_depth_pitch.is_some() && Some(depth_pitch) != base_depth_pitch && depth_pitch > 0
    {
        depth_pitch.saturating_sub(1)
    } else {
        payload_bytes
    };
    Some(arg_size.to_string())
}

fn domain_seed<'a>(plan: &'a HarnessPlan, name: &str) -> Option<&'a str> {
    plan.param_domains
        .iter()
        .find(|domain| domain.name == name)
        .and_then(|domain| domain.seeds.first())
        .map(String::as_str)
}

fn parse_u64(value: &str) -> Option<u64> {
    value.parse().ok()
}
