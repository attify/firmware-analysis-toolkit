use crate::profile::BootloaderProfile;
use fat_core::bootloader::BootloaderSnapshot;
use std::collections::BTreeMap;

pub fn render_env(
    profile: &BootloaderProfile,
    imported: Option<&BootloaderSnapshot>,
) -> Result<String, std::convert::Infallible> {
    let mut lines = Vec::new();
    let mut overrides = imported_env(imported);

    push_merged_line(&mut lines, &mut overrides, "prompt", profile.prompt.clone());
    push_merged_line(
        &mut lines,
        &mut overrides,
        "bootdelay",
        profile.bootdelay.to_string(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "loadaddr",
        profile.loadaddr.clone(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "bootcmd",
        profile.bootcmd.clone(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "bootargs",
        profile.bootargs.clone(),
    );
    push_merged_line(&mut lines, &mut overrides, "verify", profile.verify.clone());
    push_merged_line(
        &mut lines,
        &mut overrides,
        "sig_check",
        profile.sig_check.clone(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "recovery_mode",
        profile.recovery_mode.clone(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "rollback_ctr",
        profile.rollback_ctr.clone(),
    );
    push_merged_line(
        &mut lines,
        &mut overrides,
        "rollback_idx",
        profile.rollback_idx.clone(),
    );

    for (key, value) in overrides {
        lines.push(format!("{key}={value}"));
    }

    Ok(lines.join("\n") + "\n")
}

fn imported_env(imported: Option<&BootloaderSnapshot>) -> BTreeMap<String, String> {
    imported
        .map(|snapshot| {
            snapshot
                .env_variables
                .iter()
                .filter(|variable| is_exportable_imported_env_key(&variable.key))
                .map(|variable| (variable.key.clone(), variable.value.clone()))
                .collect()
        })
        .unwrap_or_default()
}

fn push_merged_line(
    lines: &mut Vec<String>,
    overrides: &mut BTreeMap<String, String>,
    key: &str,
    default_value: String,
) {
    let value = overrides.remove(key).unwrap_or(default_value);
    lines.push(format!("{key}={value}"));
}

fn is_exportable_imported_env_key(key: &str) -> bool {
    if key.len() < 2 {
        return false;
    }

    let mut chars = key.chars();
    let Some(first) = chars.next() else {
        return false;
    };

    if !(first.is_ascii_alphabetic() || first == '_') {
        return false;
    }

    if !chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_') {
        return false;
    }

    let lower = key.to_ascii_lowercase();
    matches!(
        lower.as_str(),
        "autoupdate"
            | "baudrate"
            | "bootargs"
            | "bootcmd"
            | "bootdelay"
            | "console"
            | "ethaddr"
            | "gatewayip"
            | "hostname"
            | "ipaddr"
            | "loadaddr"
            | "mtdids"
            | "mtdparts"
            | "netmask"
            | "recovery_mode"
            | "rollback_ctr"
            | "rollback_idx"
            | "rootpath"
            | "serverip"
            | "sig_check"
            | "verify"
    ) || lower.starts_with("auimg")
        || lower.starts_with("cmd")
}
