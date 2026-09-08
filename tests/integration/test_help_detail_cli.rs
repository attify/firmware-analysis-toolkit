use std::process::Command;

fn run_help(args: &[&str]) -> String {
    let output = Command::new(env!("CARGO_BIN_EXE_fat"))
        .env("FAT_COLOR", "never")
        .args(args)
        .output()
        .expect("help command runs");

    assert!(output.status.success(), "{output:?}");
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn root_help_groups_commands_by_task_in_both_modes() {
    for flag in ["-h", "--help"] {
        let stdout = run_help(&[flag]);
        let groups = [
            ("Start here:", "identify"),
            ("Projects & extraction:", "new"),
            ("Firmware structure:", "inspect"),
            ("Filesystem & code:", "search"),
            ("Security analysis:", "taint"),
            ("Emulation & runtime:", "emulate"),
            ("Queries & evidence:", "invariant"),
        ];
        let mut remainder = stdout.as_str();
        for (heading, command) in groups {
            remainder = remainder.split_once(heading).expect(heading).1;
            let section = remainder.split("\n\n").next().unwrap();
            assert!(section.contains(&format!("\n  {command} ")), "{section}");
        }
        assert!(!stdout.contains("\nCommands:"));
        assert!(stdout.contains("Options:"));
        assert!(!stdout.contains('\u{1b}'));
    }
    assert_eq!(run_help(&["help"]), run_help(&["--help"]));
}

#[test]
fn grouped_help_respects_color_controls_without_changing_content() {
    let ansi = regex::Regex::new(r"\x1b\[[0-9;]*m").unwrap();
    for flag in ["-h", "--help"] {
        let plain = run_help(&[flag]);
        for (color, no_color, expect_color) in [
            ("always", false, true),
            ("always", true, true),
            ("auto", true, false),
            ("auto", false, false), // Captured stdout is a pipe.
        ] {
            let mut command = Command::new(env!("CARGO_BIN_EXE_fat"));
            command
                .arg(flag)
                .env("FAT_COLOR", color)
                .env_remove("NO_COLOR")
                .env_remove("CLICOLOR_FORCE")
                .env_remove("CLICOLOR")
                .env_remove("FORCE_COLOR");
            if no_color {
                command.env("NO_COLOR", "1");
            }
            let output = command.output().expect("help runs");
            assert!(output.status.success(), "{output:?}");
            let stdout = String::from_utf8(output.stdout).unwrap();
            assert_eq!(
                stdout.contains('\u{1b}'),
                expect_color,
                "{color}, NO_COLOR={no_color}"
            );
            assert_eq!(ansi.replace_all(&stdout, ""), plain);
            if expect_color {
                assert!(stdout.contains("\u{1b}[34mStart here:"), "{stdout}");
                assert!(stdout.contains("\u{1b}[36midentify"), "{stdout}");
            }
        }
    }
}

/// The shell mode's own help must not describe the writable-mount promotion the
/// base profile no longer makes.
#[test]
fn shell_taint_help_states_that_a_path_prefix_needs_an_overlay() {
    let stdout = run_help(&["taint", "--help"]);
    assert!(
        stdout.contains("never establishes attacker control on its own"),
        "{stdout}"
    );
    assert!(stdout.contains("--source-profile"), "{stdout}");
}

/// `fat taint-cross --help` must say the catalog is supplied, and show the shape.
#[test]
fn taint_cross_help_documents_the_supplied_shared_state_catalog() {
    let stdout = run_help(&["taint-cross", "--help"]);
    assert!(stdout.contains("FAT ships no such catalog"), "{stdout}");
    assert!(stdout.contains("--state-profile"), "{stdout}");
    assert!(stdout.contains("families:"), "{stdout}");
    assert!(
        stdout.contains("JSON mode returns an empty array"),
        "{stdout}"
    );
}
