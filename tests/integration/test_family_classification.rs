#[test]
fn test_family_classification_prefers_linux_router_arm_for_busybox_web_ui_arm_firmware() {
    let guess = fat_family::classifier::classify_for_test(vec![
        "arch:armel",
        "fs:squashfs",
        "init:busybox",
        "web:cgi",
        "nvram:present",
    ]);
    assert_eq!(guess.family_id, "linux-router-arm");
    assert!(guess.confidence > 0.5);
}

#[test]
fn test_family_classification_prefers_linux_router_mips_for_busybox_web_ui_mips_firmware() {
    let guess = fat_family::classifier::classify_for_test(vec![
        "arch:mipsel",
        "fs:squashfs",
        "init:busybox",
        "web:cgi",
        "nvram:present",
    ]);
    assert_eq!(guess.family_id, "linux-router-mips");
    assert!(guess.confidence > 0.5);
}

#[test]
fn test_family_classification_prefers_linux_edge_ai_onnx_for_onnx_runtime_signals() {
    let guess = fat_family::classifier::classify_for_test(vec![
        "arch:arm64",
        "fs:squashfs",
        "ai_format:onnx",
        "ai_lib:onnxruntime",
        "ai_lib:openvino",
    ]);
    assert_eq!(guess.family_id, "linux-edge-ai-onnx");
    assert!(guess.confidence > 0.5);
}

#[test]
fn test_family_classification_prefers_qualcomm_edge_ai_dlc_for_qnn_signals() {
    let guess = fat_family::classifier::classify_for_test(vec![
        "arch:arm64",
        "ai_format:dlc",
        "ai_lib:snpe",
        "ai_lib:qnn",
        "ai_lib:hexagon",
    ]);
    assert_eq!(guess.family_id, "qualcomm-edge-ai-dlc");
    assert!(guess.confidence > 0.5);
}
