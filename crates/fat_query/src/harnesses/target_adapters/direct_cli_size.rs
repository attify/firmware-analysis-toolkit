use std::collections::BTreeMap;
use std::path::Path;

use crate::attempt_generation::{GenerationStrategy, ParamDomain, ParamKind};
use crate::discovery::DiscoveryLead;
use crate::harnesses::{ArgTemplate, EnvTemplate, HarnessPlan, InputBinding};
use crate::target_lanes::TargetLaneRecord;

pub fn configure(plan: &mut HarnessPlan, lead: &DiscoveryLead, lane: &TargetLaneRecord) {
    if supports_direct_shape_stride_lane(lane) {
        plan.base_command = vec![lane.binary_or_driver.clone()];
        plan.argv_template = vec![
            ArgTemplate::Literal {
                value: "--width".into(),
            },
            ArgTemplate::Binding {
                key: "width".into(),
            },
            ArgTemplate::Literal {
                value: "--height".into(),
            },
            ArgTemplate::Binding {
                key: "height".into(),
            },
            ArgTemplate::Literal {
                value: "--row-pitch".into(),
            },
            ArgTemplate::Binding {
                key: "row_pitch".into(),
            },
            ArgTemplate::Literal {
                value: "--depth-pitch".into(),
            },
            ArgTemplate::Binding {
                key: "depth_pitch".into(),
            },
            ArgTemplate::Literal {
                value: "--payload-bytes".into(),
            },
            ArgTemplate::Binding {
                key: "payload_bytes".into(),
            },
        ];
        configure_shape_stride_bindings(plan, lead, lane);
    } else if supports_real_angle_argsize_lane(lane) {
        plan.base_command = vec![lane.binary_or_driver.clone()];
        plan.argv_template = vec![ArgTemplate::Binding {
            key: "arg_size".into(),
        }];
        configure_shape_stride_bindings(plan, lead, lane);
    }
}

fn configure_shape_stride_bindings(
    plan: &mut HarnessPlan,
    lead: &DiscoveryLead,
    lane: &TargetLaneRecord,
) {
    if lane.runtime_capabilities.requires_vk_icd {
        plan.env_template = BTreeMap::from([(
            "VK_ICD_FILENAMES".into(),
            EnvTemplate::Binding {
                key: "vk_icd_filenames".into(),
            },
        )]);
    }
    plan.input_bindings = vec![
        InputBinding {
            key: "width".into(),
            value: "4".into(),
        },
        InputBinding {
            key: "height".into(),
            value: "4".into(),
        },
        InputBinding {
            key: "row_pitch".into(),
            value: "16".into(),
        },
        InputBinding {
            key: "depth_pitch".into(),
            value: "64".into(),
        },
        InputBinding {
            key: "payload_bytes".into(),
            value: suggested_payload_bytes(lead),
        },
    ];
    if lane.runtime_capabilities.requires_vk_icd {
        plan.input_bindings.push(InputBinding {
            key: "vk_icd_filenames".into(),
            value: Path::new(&lane.build_dir)
                .join("vk_swiftshader_icd.json")
                .display()
                .to_string(),
        });
    }
    plan.param_domains = vec![
        ParamDomain {
            name: "width".into(),
            kind: ParamKind::Integer,
            seeds: vec!["4".into()],
            edge_cases: Vec::new(),
        },
        ParamDomain {
            name: "height".into(),
            kind: ParamKind::Integer,
            seeds: vec!["4".into()],
            edge_cases: Vec::new(),
        },
        ParamDomain {
            name: "row_pitch".into(),
            kind: ParamKind::Integer,
            seeds: vec!["16".into()],
            edge_cases: vec!["32".into()],
        },
        ParamDomain {
            name: "depth_pitch".into(),
            kind: ParamKind::Integer,
            seeds: vec!["64".into()],
            edge_cases: vec!["96".into()],
        },
        ParamDomain {
            name: "payload_bytes".into(),
            kind: ParamKind::Integer,
            seeds: vec![suggested_payload_bytes(lead)],
            edge_cases: vec!["63".into(), "32".into()],
        },
    ];
    if lane.runtime_capabilities.requires_vk_icd {
        plan.param_domains.push(ParamDomain {
            name: "vk_icd_filenames".into(),
            kind: ParamKind::Path,
            seeds: vec![Path::new(&lane.build_dir)
                .join("vk_swiftshader_icd.json")
                .display()
                .to_string()],
            edge_cases: Vec::new(),
        });
    }
    plan.generation_strategy = GenerationStrategy::FocusedEdgeSweep;
}

fn supports_real_angle_argsize_lane(lane: &TargetLaneRecord) -> bool {
    lane.binary_or_driver
        .contains("angle_cl_argsize_repro_manual")
        && lane.runtime_capabilities.accepts_arg_size
        && lane.runtime_capabilities.accepts_width
        && lane.runtime_capabilities.accepts_height
        && lane.runtime_capabilities.accepts_row_pitch
        && lane.runtime_capabilities.accepts_depth_pitch
        && lane.runtime_capabilities.accepts_payload_bytes
        && lane.runtime_capabilities.honors_arg_size
}

fn supports_direct_shape_stride_lane(lane: &TargetLaneRecord) -> bool {
    lane.runtime_capabilities.honors_width
        && lane.runtime_capabilities.honors_height
        && lane.runtime_capabilities.honors_row_pitch
        && lane.runtime_capabilities.honors_depth_pitch
        && lane.runtime_capabilities.honors_payload_bytes
}

fn suggested_payload_bytes(lead: &DiscoveryLead) -> String {
    if lead
        .suggested_trigger_recipe
        .iter()
        .any(|step| step.kind == "pitch-depth-mismatch")
    {
        "64".into()
    } else {
        "16".into()
    }
}
