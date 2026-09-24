use std::process::Command;

#[test]
fn doctor_supports_forced_color_output() {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_COLOR", "always")
        .args(["doctor"])
        .output()
        .expect("fat doctor runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{1b}["));
    assert!(stdout.contains("fat doctor"));
}

#[test]
fn taint_query_supports_forced_color_output() {
    let fixture = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/fixtures/query/binary/genie-constant-arg"
    );
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_COLOR", "always")
        .args([
            "taint-query",
            "--fixture",
            fixture,
            "--from",
            "call[name=\"getenv\" and arg0=\"QUERY_STRING\"].ret",
            "--to",
            "call[name=\"popen\"].arg0",
        ])
        .output()
        .expect("fat taint-query runs");

    assert!(output.status.success(), "{output:?}");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("\u{1b}["));
    assert!(stdout.contains("ConstantSinkArg"));
}

#[derive(Debug, Clone, Copy)]
enum McuCommand {
    Inspect,
    Identify,
}

fn synthetic_mcu_rom() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x400];
    for (index, value) in [0x1000_1000u32, 0x1fff_0105, 0x1fff_0121, 0x1fff_0121]
        .into_iter()
        .enumerate()
    {
        bytes[index * 4..index * 4 + 4].copy_from_slice(&value.to_le_bytes());
    }
    for (offset, instruction) in [
        (0x104, 0x4801u16), // LDR r0, [pc, #4]: word at file offset 0x10c.
        (0x106, 0x6801),    // LDR r1, [r0]: separate evidence of a read.
        (0x108, 0x4770),    // BX LR.
        (0x120, 0x4770),
    ] {
        bytes[offset..offset + 2].copy_from_slice(&instruction.to_le_bytes());
    }
    bytes[0x10c..0x110].copy_from_slice(&0xe000_e010u32.to_le_bytes());
    let identity = b"NXP LPC134X IFLASH";
    bytes[0x300..0x300 + identity.len()].copy_from_slice(identity);
    bytes
}

fn run_mcu_command(
    directory: &std::path::Path,
    kind: McuCommand,
    color: &str,
    no_color: bool,
    columns: usize,
    json: bool,
    details: bool,
) -> String {
    let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
    command
        .current_dir(directory)
        .env("FAT_COLOR", color)
        .env("COLUMNS", columns.to_string())
        .env("TERM", "xterm-256color")
        .env_remove("NO_COLOR")
        .env_remove("CLICOLOR_FORCE")
        .env_remove("COLORTERM");
    if no_color {
        command.env("NO_COLOR", "1");
    }
    match kind {
        McuCommand::Inspect => {
            command.args(["inspect", "mcu", "--file", "sample.bin"]);
        }
        McuCommand::Identify => {
            command.args(["identify", "sample.bin"]);
        }
    }
    if json {
        command.arg("--json");
    }
    if details {
        command.arg("--details");
    }
    let output = command.output().expect("MCU command runs");
    assert!(
        output.status.success(),
        "{kind:?}, FAT_COLOR={color}, NO_COLOR={no_color}, COLUMNS={columns}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8(output.stdout).expect("MCU output is UTF-8")
}

fn without_ansi(text: &str) -> String {
    let mut plain = String::new();
    let mut characters = text.chars().peekable();
    while let Some(character) = characters.next() {
        if character == '\u{1b}' && characters.peek() == Some(&'[') {
            characters.next();
            for sequence in characters.by_ref() {
                if ('@'..='~').contains(&sequence) {
                    break;
                }
            }
        } else {
            plain.push(character);
        }
    }
    plain
}

fn assert_mcu_values(kind: McuCommand, text: &str, details: bool) {
    let plain = without_ansi(text);
    // Wrapping may split a value over multiple lines without changing its bytes.
    let compact: String = plain
        .chars()
        .filter(|character| !character.is_whitespace())
        .flat_map(char::to_lowercase)
        .collect();
    for expected in ["Cortex-M", "NXP LPC134x", "sample.bin"] {
        let expected_compact = expected.to_lowercase().replace(' ', "");
        assert!(
            compact.contains(&expected_compact),
            "{kind:?} lost {expected:?}: {plain}"
        );
    }
    if matches!(kind, McuCommand::Identify) {
        assert!(
            compact.contains("sample.bin"),
            "input identity missing: {plain}"
        );
    }
    if matches!(kind, McuCommand::Inspect) {
        for expected in ["0xE000E010", "SysTick.CTRL"] {
            assert!(
                compact.contains(&expected.to_lowercase()),
                "{kind:?} lost {expected:?}: {plain}"
            );
        }
        if details {
            for address in ["0x1FFF0105", "0x1FFF0106"] {
                assert!(
                    compact.contains(&address.to_lowercase()),
                    "lost {address}: {plain}"
                );
            }
        } else {
            assert!(
                compact.contains("0x1fff0104"),
                "missing aligned reset handler: {plain}"
            );
        }
        for section in ["Image", "Startup", "Interrupts", "Hardware"] {
            assert!(plain.contains(section), "missing {section}: {plain}");
        }
        for absent in [
            "Evidence notes & limits",
            "Degradations",
            "Init descriptor table",
            "SystemInit effects",
        ] {
            assert!(
                !plain.contains(absent),
                "unexpected diagnostic section {absent}: {plain}"
            );
        }
    }
}

#[test]
fn mcu_reports_support_forced_color_without_changing_report_values() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("sample.bin"), synthetic_mcu_rom()).unwrap();
    for (kind, details) in [McuCommand::Inspect, McuCommand::Identify]
        .into_iter()
        .flat_map(|kind| [false, true].map(|details| (kind, details)))
    {
        let colored = run_mcu_command(directory.path(), kind, "always", false, 80, false, details);
        let plain = run_mcu_command(directory.path(), kind, "never", false, 80, false, details);
        assert!(
            colored.contains("\u{1b}["),
            "{kind:?} has no forced styling"
        );
        assert!(
            !plain.contains('\u{1b}'),
            "{kind:?} ignored FAT_COLOR=never"
        );
        assert_mcu_values(kind, &colored, details);
        assert_mcu_values(kind, &plain, details);
    }
}

#[test]
fn mcu_reports_respect_no_color_and_redirected_auto_output() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("sample.bin"), synthetic_mcu_rom()).unwrap();
    for (kind, details) in [McuCommand::Inspect, McuCommand::Identify]
        .into_iter()
        .flat_map(|kind| [false, true].map(|details| (kind, details)))
    {
        for (color, no_color) in [("never", false), ("auto", true), ("auto", false)] {
            // Command::output redirects stdout: auto must stay plain even with TERM set.
            let text = run_mcu_command(directory.path(), kind, color, no_color, 80, false, details);
            assert!(
                !text.contains('\u{1b}'),
                "{kind:?} emitted ANSI in plain mode"
            );
            assert_mcu_values(kind, &text, details);
        }
    }
}

#[test]
fn mcu_json_is_invariant_under_color_and_terminal_width() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("sample.bin"), synthetic_mcu_rom()).unwrap();
    for (kind, details) in [McuCommand::Inspect, McuCommand::Identify]
        .into_iter()
        .flat_map(|kind| [false, true].map(|details| (kind, details)))
    {
        let baseline_text =
            run_mcu_command(directory.path(), kind, "never", false, 80, true, false);
        let baseline: serde_json::Value = serde_json::from_str(&baseline_text).unwrap();
        for columns in [40, 80, 120] {
            for (color, no_color) in [("always", false), ("never", false), ("auto", true)] {
                let text = run_mcu_command(
                    directory.path(),
                    kind,
                    color,
                    no_color,
                    columns,
                    true,
                    details,
                );
                assert!(!text.contains('\u{1b}'), "{kind:?} JSON contains ANSI");
                let report: serde_json::Value = serde_json::from_str(&text)
                    .unwrap_or_else(|error| panic!("{kind:?} invalid JSON: {error}: {text}"));
                assert_eq!(
                    report, baseline,
                    "{kind:?} JSON changed with color={color}, columns={columns}"
                );
            }
        }
    }
}

#[test]
fn mcu_human_reports_preserve_values_within_requested_width() {
    let directory = tempfile::tempdir().unwrap();
    std::fs::write(directory.path().join("sample.bin"), synthetic_mcu_rom()).unwrap();
    for (kind, details) in [McuCommand::Inspect, McuCommand::Identify]
        .into_iter()
        .flat_map(|kind| [false, true].map(|details| (kind, details)))
    {
        for columns in [40, 80, 120] {
            let mut previous_layout = None;
            for color in ["always", "never"] {
                let text = run_mcu_command(
                    directory.path(),
                    kind,
                    color,
                    false,
                    columns,
                    false,
                    details,
                );
                assert_mcu_values(kind, &text, details);
                let plain = without_ansi(&text);
                if let Some(previous) = previous_layout.replace(plain.clone()) {
                    assert_eq!(
                        plain, previous,
                        "{kind:?} color changed the layout at {columns} columns"
                    );
                }
                for (index, line) in plain.lines().enumerate() {
                    assert!(
                        line.chars().count() <= columns,
                        "{kind:?} line {} exceeds {columns} columns ({}): {line:?}",
                        index + 1,
                        line.chars().count()
                    );
                }
            }
        }
    }
}
