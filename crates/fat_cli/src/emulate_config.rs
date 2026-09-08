use std::path::Path;

use serde::Deserialize;

const EMULATION_TOML: &str = "profiles/emulation.toml";

#[derive(Debug, Clone, Default, Deserialize)]
pub struct EmulationConfig {
    #[serde(default)]
    pub lifecycle: LifecycleConfig,
}

#[derive(Debug, Clone, Deserialize)]
pub struct LifecycleConfig {
    #[serde(default = "default_idle_timeout_secs")]
    pub idle_timeout_secs: u64,
    #[serde(default)]
    pub max_total_memory_mb: u64,
    #[serde(default)]
    pub max_concurrent: u32,
    #[serde(default = "default_prune_staging_on_stop")]
    pub prune_staging_on_stop: bool,
}

fn default_idle_timeout_secs() -> u64 {
    600
}

fn default_prune_staging_on_stop() -> bool {
    true
}

impl Default for LifecycleConfig {
    fn default() -> Self {
        Self {
            idle_timeout_secs: default_idle_timeout_secs(),
            max_total_memory_mb: 0,
            max_concurrent: 0,
            prune_staging_on_stop: default_prune_staging_on_stop(),
        }
    }
}

pub fn load_config(project_dir: &Path, data_dir: Option<&Path>) -> EmulationConfig {
    let mut config = EmulationConfig::default();

    // 1. Data-dir config (lower priority)
    if let Some(data) = data_dir {
        let data_toml = data.join(EMULATION_TOML);
        if data_toml.is_file() {
            if let Ok(contents) = std::fs::read_to_string(&data_toml) {
                if let Ok(parsed) = toml::from_str::<EmulationConfig>(&contents) {
                    config = parsed;
                }
            }
        }
    }

    // 2. Project-local config (higher priority — overrides data-dir)
    let project_toml = project_dir.join(EMULATION_TOML);
    if project_toml.is_file() {
        if let Ok(contents) = std::fs::read_to_string(&project_toml) {
            // Both roots use the same file name, so both use the same shape: a
            // `[lifecycle]` table. Parsing this one as a bare `LifecycleConfig`
            // used to make a correctly written project file read as all
            // defaults and silently overwrite the data-dir config.
            if let Ok(parsed) = toml::from_str::<EmulationConfig>(&contents) {
                config = parsed;
            }
        }
    }

    config
}

/// Refuse a launch that the configured lifecycle caps do not have room for.
///
/// Scope is one project: the caps are measured over the sessions recorded in
/// this project's runtime store, which is the only set of sessions FAT can
/// observe. Sessions in other projects are not counted.
///
/// Memory is judged on what is already resident rather than on what the
/// incoming session will use, because a session's footprint is not knowable
/// until it runs. A launch is refused when live sessions already sit at or
/// above the cap.
pub fn enforce_lifecycle_caps(
    project_dir: &Path,
    data_dir: Option<&Path>,
) -> Result<(), Box<dyn std::error::Error>> {
    let lifecycle = load_config(project_dir, data_dir).lifecycle;
    if lifecycle.max_concurrent == 0 && lifecycle.max_total_memory_mb == 0 {
        return Ok(());
    }

    let report = crate::emulate_list::collect_emulation_list(project_dir)
        .map_err(|err| format!("failed to measure running emulations: {err}"))?;

    match cap_refusal(&lifecycle, report.live_count, report.total_rss_kb) {
        Some(refusal) => Err(refusal.into()),
        None => Ok(()),
    }
}

/// The refusal message for a launch, or `None` when the caps have room.
///
/// Split out from the measurement so the arithmetic — including which side of
/// each boundary refuses — is testable without running emulations.
fn cap_refusal(
    lifecycle: &LifecycleConfig,
    live_count: usize,
    total_rss_kb: u64,
) -> Option<String> {
    if lifecycle.max_concurrent > 0 {
        let live = u32::try_from(live_count).unwrap_or(u32::MAX);
        if live >= lifecycle.max_concurrent {
            return Some(format!(
                "refusing to launch: {live} emulation session(s) already running and \
                 max_concurrent is {}. Stop one with `fat emulate --stop`, or raise \
                 max_concurrent in profiles/emulation.toml.",
                lifecycle.max_concurrent
            ));
        }
    }

    if lifecycle.max_total_memory_mb > 0 {
        let resident_mb = total_rss_kb / 1024;
        if resident_mb >= lifecycle.max_total_memory_mb {
            return Some(format!(
                "refusing to launch: running emulations already hold {resident_mb}MB and \
                 max_total_memory_mb is {}. Stop one with `fat emulate --stop`, or raise \
                 max_total_memory_mb in profiles/emulation.toml.",
                lifecycle.max_total_memory_mb
            ));
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use tempfile::tempdir;

    fn lifecycle(max_concurrent: u32, max_total_memory_mb: u64) -> LifecycleConfig {
        LifecycleConfig {
            max_concurrent,
            max_total_memory_mb,
            ..LifecycleConfig::default()
        }
    }

    #[test]
    fn zero_means_no_cap() {
        assert!(cap_refusal(&lifecycle(0, 0), 99, 99 * 1024 * 1024).is_none());
    }

    #[test]
    fn the_concurrency_cap_refuses_once_the_slots_are_taken() {
        // Two live sessions with a cap of two: the next launch is the third.
        assert!(cap_refusal(&lifecycle(2, 0), 1, 0).is_none());
        let refusal = cap_refusal(&lifecycle(2, 0), 2, 0).expect("cap should refuse");
        assert!(refusal.contains("max_concurrent is 2"), "got: {refusal}");
    }

    #[test]
    fn the_memory_cap_refuses_at_the_boundary_not_below_it() {
        // 511MB resident against a 512MB cap still has room.
        assert!(cap_refusal(&lifecycle(0, 512), 1, 511 * 1024).is_none());
        let refusal =
            cap_refusal(&lifecycle(0, 512), 1, 512 * 1024).expect("cap should refuse at the limit");
        assert!(refusal.contains("512MB"), "got: {refusal}");
    }

    #[test]
    fn resident_memory_below_a_megabyte_does_not_round_up_into_a_refusal() {
        assert!(cap_refusal(&lifecycle(0, 1), 1, 900).is_none());
    }

    #[test]
    fn a_project_config_in_the_documented_form_is_read() {
        // Parsed as a `[lifecycle]` table, the same shape the bundled file uses.
        // Reading it as a bare LifecycleConfig silently produced defaults.
        let dir = tempdir().expect("tempdir");
        fs::create_dir_all(dir.path().join("profiles")).expect("profiles dir");
        fs::write(
            dir.path().join("profiles/emulation.toml"),
            "[lifecycle]\nidle_timeout_secs = 42\nmax_concurrent = 3\n",
        )
        .expect("write config");

        let config = load_config(dir.path(), None);
        assert_eq!(config.lifecycle.idle_timeout_secs, 42);
        assert_eq!(config.lifecycle.max_concurrent, 3);
    }
}
