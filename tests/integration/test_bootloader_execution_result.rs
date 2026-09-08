#[test]
fn execution_result_detects_kernel_banner_and_timeout() {
    let banner = fat_bootloader::classify_serial_output(
        "Linux version 5.10.0\nBooting Linux on physical CPU 0x0\n",
    );
    assert_eq!(banner.stage, "kernel_banner_seen");

    let timeout = fat_bootloader::classify_serial_output("U-Boot 2024.01\nBK-IoT => ");
    assert_eq!(timeout.stage, "timed_out");
}

#[test]
fn execution_result_detects_failed_kernel_handoff() {
    let failed = fat_bootloader::classify_serial_output(
        "=> bootm ${loadaddr}\nWrong Image Type for bootm command\nERROR -91: can't get kernel image!\n",
    );

    assert_eq!(failed.stage, "kernel_handoff_failed");
    assert_eq!(failed.result, "failed");
}

#[test]
fn execution_result_does_not_treat_u_boot_boot_banner_as_shell() {
    let failed = fat_bootloader::classify_serial_output(
        "=> bootm ${loadaddr}\n## Booting kernel from Legacy Image at 40200000 ...\nFDT and ATAGS support not compiled in\nresetting ...\n=> ",
    );

    assert_eq!(failed.stage, "kernel_handoff_failed");
    assert_eq!(failed.result, "failed");
}

#[test]
fn execution_result_keeps_waiting_during_u_boot_boot_banner_without_shell_prompt() {
    let partial = fat_bootloader::classify_serial_output(
        "=> bootm ${loadaddr}\n## Booting kernel from Legacy Image at 40200000 ...\n",
    );

    assert_eq!(partial.stage, "timed_out");
    assert_eq!(partial.result, "unknown");
}

#[test]
fn execution_result_recognizes_kernel_handoff_attempt_with_fdt() {
    let partial = fat_bootloader::classify_serial_output(
        "=> bootm ${loadaddr} - ${fdt_addr_r}\n## Booting kernel from Legacy Image at 40200000 ...\n## Flattened Device Tree blob at 43000000\n   Booting using the fdt blob at 0x43000000\nWorking FDT set to 43000000\n   Loading Kernel Image\nStarting kernel ...\n",
    );

    assert_eq!(partial.stage, "kernel_handoff_attempted");
    assert_eq!(partial.result, "unknown");
}
