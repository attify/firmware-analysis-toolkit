//! Run environment-sensitive tests in a child with its own environment and cwd.

use std::ffi::OsStr;
use std::process::Command;

const CHILD_TEST: &str = "FAT_ISOLATED_TEST";

/// Returns a command in the parent, or `None` when this exact test is the child.
pub fn isolated_test(test_name: &str) -> Option<Command> {
    if std::env::var_os(CHILD_TEST).as_deref() == Some(OsStr::new(test_name)) {
        return None;
    }
    let mut command = Command::new(std::env::current_exe().expect("test executable"));
    command
        .args(["--exact", test_name, "--nocapture", "--test-threads=1"])
        .env(CHILD_TEST, test_name);
    Some(command)
}

pub fn assert_success(command: &mut Command) {
    let output = command.output().expect("run isolated test");
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success() && stdout.contains("test result: ok. 1 passed;"),
        "isolated test must run exactly once and pass: {}\n{stdout}\n{stderr}",
        output.status,
    );
}
