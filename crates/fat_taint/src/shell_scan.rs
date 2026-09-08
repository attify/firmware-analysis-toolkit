//! Shell-target rootfs scanning for sink profiles that declare `target: shell`.
//!
//! The ELF string-seed discovery path in [`crate::sink_discovery`] does not
//! apply to shell scripts, so this module consumes the same `SinkProfile`
//! families via their per-family regex `pattern` and scans a rootfs directory
//! of scripts line by line.

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::sink_discovery::{Severity, SinkProfile};

/// Scripts larger than this are skipped during the walk.
pub const MAX_SCRIPT_BYTES: u64 = 512 * 1024;

/// JSON-serializable report for a shell-target rootfs scan.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct ShellScanReport {
    pub root: String,
    #[serde(default)]
    pub profiles: Vec<String>,
    pub summary: ShellScanSummary,
    #[serde(default)]
    pub findings: Vec<ShellFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ShellScanSummary {
    #[serde(default)]
    pub files_scanned: usize,
    #[serde(default)]
    pub findings: usize,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub families: BTreeMap<String, usize>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ShellFinding {
    pub file: String,
    pub line: u32,
    pub family: String,
    pub severity: Severity,
    pub matched_text: String,
}

/// One compiled family rule ready for line scanning.
struct ShellRule {
    family: String,
    severity: Severity,
    pattern: Regex,
}

fn compile_rules(profile: &SinkProfile) -> Result<Vec<ShellRule>, String> {
    let mut rules = Vec::new();
    for (family_name, family) in &profile.families {
        // Families without a `pattern` are ELF-only seeds; they contribute
        // nothing to a line scan.
        let Some(pattern) = &family.pattern else {
            continue;
        };
        let regex = Regex::new(pattern).map_err(|err| {
            format!(
                "profile '{}': family '{family_name}': invalid pattern: {err}",
                profile.name
            )
        })?;
        rules.push(ShellRule {
            family: family_name.clone(),
            severity: family.severity.unwrap_or(Severity::Medium),
            pattern: regex,
        });
    }
    Ok(rules)
}

/// Scan a rootfs directory of shell scripts against shell-target sink profiles.
///
/// Candidate files are `*.sh` or carry a shell shebang; anything over
/// [`MAX_SCRIPT_BYTES`] is skipped. Every line is matched against each
/// family's pattern and hits are collected as findings.
pub fn scan_rootfs(root: &Path, profiles: &[&SinkProfile]) -> Result<ShellScanReport, String> {
    let mut rules = Vec::new();
    let mut names = Vec::new();
    for profile in profiles {
        rules.extend(compile_rules(profile)?);
        names.push(profile.name.clone());
    }

    let mut findings = Vec::new();
    let mut files_scanned = 0usize;

    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry.map_err(|err| format!("walking '{}': {err}", root.display()))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if entry
            .metadata()
            .map_err(|err| format!("stat '{}': {err}", path.display()))?
            .len()
            > MAX_SCRIPT_BYTES
        {
            continue;
        }
        let Ok(bytes) = fs::read(path) else {
            continue;
        };
        if !is_shell_script(path, &bytes) {
            continue;
        }
        files_scanned += 1;
        let text = String::from_utf8_lossy(&bytes);
        let display = path
            .strip_prefix(root)
            .unwrap_or(path)
            .display()
            .to_string();
        for (line_no, line) in text.lines().enumerate() {
            for rule in &rules {
                if rule.pattern.is_match(line) {
                    findings.push(ShellFinding {
                        file: display.clone(),
                        line: (line_no + 1) as u32,
                        family: rule.family.clone(),
                        severity: rule.severity,
                        matched_text: line.trim().to_string(),
                    });
                }
            }
        }
    }

    findings.sort_by(|a, b| (&a.file, a.line, &a.family).cmp(&(&b.file, b.line, &b.family)));

    let mut families = BTreeMap::new();
    for finding in &findings {
        *families.entry(finding.family.clone()).or_insert(0) += 1;
    }

    Ok(ShellScanReport {
        root: root.display().to_string(),
        profiles: names,
        summary: ShellScanSummary {
            files_scanned,
            findings: findings.len(),
            families,
        },
        findings,
    })
}

/// A file is a scan candidate when its extension is `.sh` or its first line
/// is a shell shebang (`#!` line naming a `*sh` interpreter).
pub fn is_shell_script(path: &Path, bytes: &[u8]) -> bool {
    if path.extension().is_some_and(|ext| ext == "sh") {
        return true;
    }
    let Some(first_line_end) = bytes.iter().position(|&b| b == b'\n') else {
        return false;
    };
    let first = &bytes[..first_line_end];
    first.starts_with(b"#!") && first.windows(2).any(|window| window == b"sh")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sink_discovery::{parse_sink_profile, SHELL_COMMAND_EXEC_PROFILE_YAML};

    fn write_script(root: &Path, rel: &str, body: &str) {
        let path = root.join(rel);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, body).unwrap();
    }

    fn scan(root: &Path) -> ShellScanReport {
        let profile = parse_sink_profile(SHELL_COMMAND_EXEC_PROFILE_YAML).unwrap();
        scan_rootfs(root, &[&profile]).unwrap()
    }

    #[test]
    fn scanner_reports_expected_families_and_lines() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "etc/wifi.sh",
            "#!/bin/sh\nfwver=$(nvram get ver)\nsed -i \"s/old/$fwver/g\" /etc/config\n",
        );
        write_script(
            dir.path(),
            "etc/init.d/mod.sh",
            "#!/bin/sh\nmod=xt_multiport\ninsmod $mod\n",
        );
        write_script(
            dir.path(),
            "tmp-stage.sh",
            "#!/bin/sh\ncp /tmp/updater /tmp/run.sh\nsh /tmp/run.sh\n",
        );

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 3);
        assert_eq!(report.summary.findings, 3);

        let sed = report
            .findings
            .iter()
            .find(|f| f.family == "sed-var-injection")
            .expect("sed-var-injection finding");
        assert_eq!(sed.file, "etc/wifi.sh");
        assert_eq!(sed.line, 3);
        assert_eq!(sed.severity, Severity::High);

        let insmod = report
            .findings
            .iter()
            .find(|f| f.family == "insmod-var-path")
            .expect("insmod-var-path finding");
        assert_eq!(insmod.file, "etc/init.d/mod.sh");
        assert_eq!(insmod.line, 3);
        assert_eq!(insmod.severity, Severity::Medium);

        let staged = report
            .findings
            .iter()
            .find(|f| f.family == "tmpfs-staged-exec")
            .expect("tmpfs-staged-exec finding");
        assert_eq!(staged.file, "tmp-stage.sh");
        assert_eq!(staged.line, 3);
        assert_eq!(staged.severity, Severity::High);
    }

    /// Regression on the `fat sink-discovery --rootfs` path.
    #[test]
    fn scanner_flags_digit_suffixed_mkfs_variants() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "sbin/format.sh",
            concat!(
                "#!/bin/sh\n",
                "dev=$1\n",
                "mkfs.ext4 $dev\n",
                "mkfs.ext2 $dev\n",
                "mkfs.f2fs $dev\n",
                "mkfs.vfat $dev\n",
                "mount $dev /mnt/usb\n",
                "mountpoint -q $dev\n",
            ),
        );

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        let lines: Vec<u32> = report
            .findings
            .iter()
            .filter(|f| f.family == "unquoted-var-as-path")
            .map(|f| f.line)
            .collect();
        // Lines 3-7 are sinks; line 8 (`mountpoint`) must not be flagged.
        assert_eq!(lines, vec![3, 4, 5, 6, 7], "{:?}", report.findings);
        assert!(report
            .findings
            .iter()
            .all(|f| f.family == "unquoted-var-as-path"));
    }

    /// Regression on the `fat sink-discovery --rootfs` path:
    /// the four command-anchored families used to fire on any longer word
    /// ending in the command name, and must keep firing on the plain and
    /// absolute-path invocations.
    #[test]
    fn scanner_ignores_command_names_embedded_in_longer_words() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "etc/boundary.sh",
            concat!(
                "#!/bin/sh\n",
                "ver=$1\n",
                // Lines 3-6: longer words that merely end in the command name.
                "parsed -i \"s/old/$ver/g\" /etc/config\n",
                "xinsmod $ver\n",
                "flush -c \"$ver\"\n",
                "flash /tmp/$ver\n",
                // Lines 7-10: the real invocations, plain and absolute-path.
                "sed -i \"s/old/$ver/g\" /etc/config\n",
                "/sbin/insmod $ver\n",
                "/bin/sh -c \"$ver\"\n",
                "/bin/sh /tmp/run.sh\n",
            ),
        );

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        let mut hits: Vec<(u32, &str)> = report
            .findings
            .iter()
            .map(|f| (f.line, f.family.as_str()))
            .collect();
        hits.sort_unstable();
        assert_eq!(
            hits,
            vec![
                (7, "sed-var-injection"),
                (8, "insmod-var-path"),
                (9, "sh-c-var"),
                (10, "tmpfs-staged-exec"),
            ],
            "{:?}",
            report.findings
        );
    }

    /// Shell-alternation regression on the `fat sink-discovery
    /// --rootfs` path: every shell the two families name must be flagged, in
    /// plain, absolute-path and busybox-applet form, and words that merely end
    /// in a shell name must not be.
    #[test]
    fn scanner_flags_every_named_shell_but_no_longer_word() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "etc/shells.sh",
            concat!(
                "#!/bin/sh\n",
                "c=$1\n",
                // Lines 3-8: sh-c-var across the alternation.
                "ash -c \"$c\"\n",
                "/bin/bash -c \"$c\"\n",
                "busybox dash -c \"$c\"\n",
                "/system/bin/mksh -c \"$c\"\n",
                "hush -c \"$c\"\n",
                "ksh -c \"$c\"\n",
                // Lines 9-11: tmpfs-staged-exec across the alternation.
                "ash /tmp/run.sh\n",
                "/bin/bash /tmp/run.sh\n",
                "busybox hush /tmp/run.sh\n",
                // Lines 12-14: words that merely end in a shell name.
                "flush -c \"$c\"\n",
                "refresh -c \"$c\"\n",
                "flash /tmp/run.sh\n",
            ),
        );

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        let mut hits: Vec<(u32, &str)> = report
            .findings
            .iter()
            .map(|f| (f.line, f.family.as_str()))
            .collect();
        hits.sort_unstable();
        assert_eq!(
            hits,
            vec![
                (3, "sh-c-var"),
                (4, "sh-c-var"),
                (5, "sh-c-var"),
                (6, "sh-c-var"),
                (7, "sh-c-var"),
                (8, "sh-c-var"),
                (9, "tmpfs-staged-exec"),
                (10, "tmpfs-staged-exec"),
                (11, "tmpfs-staged-exec"),
            ],
            "{:?}",
            report.findings
        );
    }

    #[test]
    fn scanner_picks_up_shebang_files_without_sh_extension() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "etc/init.d/S01setup",
            "#!/bin/sh\nsh -c \"$CMD\"\n",
        );

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        let hit = report
            .findings
            .iter()
            .find(|f| f.family == "sh-c-var")
            .expect("sh-c-var finding");
        assert_eq!(hit.line, 2);
    }

    #[test]
    fn scanner_skips_clean_scripts_and_non_scripts() {
        let dir = tempfile::tempdir().unwrap();
        write_script(
            dir.path(),
            "bin/clean.sh",
            "#!/bin/sh\necho hello\nfwver=1.0\necho $fwver\nmount \"$part\" /mnt/usb\n",
        );
        write_script(dir.path(), "etc/version", "1.0.2 build 42\n");

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        assert_eq!(report.summary.findings, 0);
        assert!(report.findings.is_empty());
        assert!(report.summary.families.is_empty());
    }

    #[test]
    fn scanner_skips_oversize_files() {
        let dir = tempfile::tempdir().unwrap();
        let big = "eval \"$x\"\n".repeat(60_000); // ~720 KiB, above the cap
        write_script(dir.path(), "big.sh", &big);
        write_script(dir.path(), "small.sh", "eval \"$cmd\"\n");

        let report = scan(dir.path());

        assert_eq!(report.summary.files_scanned, 1);
        assert_eq!(report.summary.findings, 1);
        assert_eq!(report.findings[0].file, "small.sh");
    }

    #[test]
    fn scanner_report_serializes_to_json() {
        let dir = tempfile::tempdir().unwrap();
        write_script(dir.path(), "run.sh", "sh -c \"$CMD\"\n");

        let report = scan(dir.path());
        let json = serde_json::to_value(&report).unwrap();

        assert_eq!(json["findings"][0]["family"], "sh-c-var");
        assert_eq!(json["findings"][0]["severity"], "high");
        assert_eq!(json["findings"][0]["line"], 1);
        assert_eq!(json["summary"]["files_scanned"], 1);
    }
}
