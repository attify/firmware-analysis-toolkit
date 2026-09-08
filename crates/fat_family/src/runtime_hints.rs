#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RuntimeHintActionKind {
    Mount,
    Overlay,
    ConfigMaterialization,
    DeviceNode,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHintAction {
    pub kind: RuntimeHintActionKind,
    pub path: String,
    pub detail: String,
    pub required: bool,
}

impl RuntimeHintAction {
    pub fn required(
        kind: RuntimeHintActionKind,
        path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            detail: detail.into(),
            required: true,
        }
    }

    pub fn recommended(
        kind: RuntimeHintActionKind,
        path: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            kind,
            path: path.into(),
            detail: detail.into(),
            required: false,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuntimeHints {
    pub family_id: String,
    pub required_actions: Vec<RuntimeHintAction>,
    pub recommended_actions: Vec<RuntimeHintAction>,
}

impl RuntimeHints {
    pub fn new(
        family_id: impl Into<String>,
        required_actions: Vec<RuntimeHintAction>,
        recommended_actions: Vec<RuntimeHintAction>,
    ) -> Self {
        Self {
            family_id: family_id.into(),
            required_actions,
            recommended_actions,
        }
    }
}

pub fn runtime_hints_for_family(family_id: &str) -> RuntimeHints {
    match family_id {
        "lifetime-reentrancy" => discovery_family_runtime_hints(family_id),
        "size-stride-arithmetic" => discovery_family_runtime_hints(family_id),
        "gpu-protocol-order-lifecycle" => discovery_family_runtime_hints(family_id),
        "validation-trust-boundary" => discovery_family_runtime_hints(family_id),
        "linux-router-arm" => RuntimeHints::new(
            family_id,
            vec![
                RuntimeHintAction::required(
                    RuntimeHintActionKind::Mount,
                    "/system",
                    "mount the firmware application tree before launch",
                ),
                RuntimeHintAction::required(
                    RuntimeHintActionKind::ConfigMaterialization,
                    "/configs",
                    "materialize persistent configuration state for router startup",
                ),
                RuntimeHintAction::required(
                    RuntimeHintActionKind::DeviceNode,
                    "/dev/urandom",
                    "provide entropy and basic runtime device access",
                ),
            ],
            vec![RuntimeHintAction::recommended(
                RuntimeHintActionKind::Overlay,
                "/var/run",
                "overlay runtime scratch space and IPC directories",
            )],
        ),
        "linux-router-mips" => RuntimeHints::new(
            family_id,
            vec![
                RuntimeHintAction::required(
                    RuntimeHintActionKind::Mount,
                    "/system",
                    "mount the firmware application tree before launch",
                ),
                RuntimeHintAction::required(
                    RuntimeHintActionKind::ConfigMaterialization,
                    "/configs",
                    "materialize persistent configuration state for router startup",
                ),
            ],
            vec![RuntimeHintAction::recommended(
                RuntimeHintActionKind::Overlay,
                "/var/run",
                "overlay runtime scratch space and IPC directories",
            )],
        ),
        "linux-camera-mips" => RuntimeHints::new(
            family_id,
            vec![
                RuntimeHintAction::required(
                    RuntimeHintActionKind::Mount,
                    "/system",
                    "mount the camera firmware application tree before launch",
                ),
                RuntimeHintAction::required(
                    RuntimeHintActionKind::ConfigMaterialization,
                    "/configs",
                    "materialize camera configuration state before services start",
                ),
            ],
            vec![RuntimeHintAction::recommended(
                RuntimeHintActionKind::Overlay,
                "/var/run",
                "overlay runtime scratch space and service IPC directories",
            )],
        ),
        _ => RuntimeHints::new(
            family_id,
            vec![RuntimeHintAction::required(
                RuntimeHintActionKind::Mount,
                "/system",
                "mount the firmware application tree before launch",
            )],
            vec![RuntimeHintAction::recommended(
                RuntimeHintActionKind::Overlay,
                "/var/run",
                "overlay runtime scratch space and IPC directories",
            )],
        ),
    }
}

fn discovery_family_runtime_hints(family_id: &str) -> RuntimeHints {
    RuntimeHints::new(
        family_id,
        vec![RuntimeHintAction::required(
            RuntimeHintActionKind::Mount,
            "/analysis",
            "mount the discovery workspace before launch",
        )],
        vec![RuntimeHintAction::recommended(
            RuntimeHintActionKind::Overlay,
            "/analysis/tmp",
            "overlay scratch space for discovery runs",
        )],
    )
}
