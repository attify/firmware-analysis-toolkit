use std::path::Path;

use crate::qemu_direct::{
    build_endpoints, common_launch_args, QemuDirectPlacementSpec, QemuDirectRequest,
};
use crate::substrate::{BackendSubstrateContract, BackendSubstrateKind};

pub fn build_placement(request: &QemuDirectRequest, working_dir: &Path) -> QemuDirectPlacementSpec {
    let mut launch_command = vec![request.qemu_binary.clone()];
    launch_command.extend(common_launch_args(request, working_dir));
    launch_command.push("--placement".into());
    launch_command.push("native-host".into());
    launch_command.push("--monitor".into());
    launch_command.push("tcp:127.0.0.1:10024".into());

    QemuDirectPlacementSpec {
        substrate: BackendSubstrateKind::NativeHost,
        substrate_contract: substrate_contract(),
        launch_command,
        endpoints: build_endpoints(10022, 10023, 10024),
        working_dir: working_dir.to_path_buf(),
    }
}

pub fn substrate_contract() -> BackendSubstrateContract {
    BackendSubstrateContract::healthy(
        BackendSubstrateKind::NativeHost,
        "native-host",
        "qemu-direct runs against the host runtime substrate",
    )
}
