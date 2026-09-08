use std::fs;
use std::path::Path;
use std::process::Command;

use fat_core::discovery::{DiscoveryLifecycleStatus, HarnessAttemptRecord};
use shell_words::join;

use crate::attempt_generation::GeneratedAttemptBinding;
use crate::harnesses::{ArgTemplate, EnvTemplate, HarnessPlan, InputBinding};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DiscoveryExecutionResult {
    pub attempt: HarnessAttemptRecord,
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResolvedRuntimeAttempt {
    pub attempt_id: String,
    pub generated_binding_id: Option<String>,
    pub generated_input_bindings: std::collections::BTreeMap<String, String>,
    pub argv: Vec<String>,
    pub env: std::collections::BTreeMap<String, String>,
    pub cwd: String,
    pub timeout_ms: u64,
    pub artifact_dir: String,
}

pub fn resolve_runtime_attempt(
    plan: &HarnessPlan,
    retry_count: u32,
) -> Result<ResolvedRuntimeAttempt, String> {
    let default_binding = GeneratedAttemptBinding {
        binding_id: format!("{}::g0", plan.harness_id),
        inputs: plan.input_bindings.clone(),
    };
    resolve_runtime_attempt_with_binding(plan, &default_binding, retry_count)
}

pub fn resolve_runtime_attempt_with_binding(
    plan: &HarnessPlan,
    binding: &GeneratedAttemptBinding,
    retry_count: u32,
) -> Result<ResolvedRuntimeAttempt, String> {
    let artifact_dir = artifact_root_for_attempt(plan, retry_count, Some(&binding.binding_id));
    let attempt_id = format!("{}::r{}", binding.binding_id, retry_count);
    let bindings = plan
        .input_bindings
        .iter()
        .chain(binding.inputs.iter())
        .map(|binding| (binding.key.as_str(), binding.value.as_str()))
        .collect::<std::collections::BTreeMap<_, _>>();

    let argv = if plan.base_command.is_empty() && plan.argv_template.is_empty() {
        if plan.launcher_command.is_empty() {
            return Err("harness plan launcher_command must not be empty".into());
        }
        plan.launcher_command.clone()
    } else {
        if plan.base_command.is_empty() {
            return Err("templated harness plans must define base_command".into());
        }
        let mut argv = plan.base_command.clone();
        for template in &plan.argv_template {
            argv.push(resolve_arg_template(template, &bindings)?);
        }
        argv
    };

    if argv.is_empty() {
        return Err("resolved runtime attempt argv must not be empty".into());
    }

    let mut env = plan.required_env.clone();
    for (key, template) in &plan.env_template {
        env.insert(key.clone(), resolve_env_template(template, &bindings)?);
    }

    Ok(ResolvedRuntimeAttempt {
        attempt_id,
        generated_binding_id: Some(binding.binding_id.clone()),
        generated_input_bindings: binding_map(&binding.inputs),
        argv,
        env,
        cwd: plan.build_dir.clone(),
        timeout_ms: plan.timeout_ms,
        artifact_dir,
    })
}

pub fn execute_harness_plan(
    plan: &HarnessPlan,
    retry_count: u32,
) -> Result<DiscoveryExecutionResult, String> {
    let default_binding = GeneratedAttemptBinding {
        binding_id: format!("{}::g0", plan.harness_id),
        inputs: plan.input_bindings.clone(),
    };
    execute_harness_plan_with_binding(plan, &default_binding, retry_count)
}

pub fn execute_harness_plan_with_binding(
    plan: &HarnessPlan,
    binding: &GeneratedAttemptBinding,
    retry_count: u32,
) -> Result<DiscoveryExecutionResult, String> {
    let resolved = resolve_runtime_attempt_with_binding(plan, binding, retry_count)?;
    let artifact_root = resolved.artifact_dir.clone();
    fs::create_dir_all(&artifact_root)
        .map_err(|e| format!("failed to create artifact root {artifact_root}: {e}"))?;

    let command_line = join(resolved.argv.iter().map(String::as_str));

    let output = Command::new(&resolved.argv[0])
        .args(&resolved.argv[1..])
        .current_dir(&resolved.cwd)
        .envs(&resolved.env)
        .output();

    let result = match output {
        Ok(output) => DiscoveryExecutionResult {
            attempt: HarnessAttemptRecord {
                harness_attempt_id: resolved.attempt_id,
                expansion_id: plan.harness_id.clone(),
                lifecycle: DiscoveryLifecycleStatus::Completed,
                outcome: None,
                attempt_plan_hash: plan.attempt_plan_hash.clone(),
                artifact_root: artifact_root.clone(),
                retry_count,
                launcher_command: command_line,
                generated_binding_id: resolved.generated_binding_id.clone(),
                generated_input_bindings: resolved.generated_input_bindings.clone(),
                resolved_argv: resolved.argv.clone(),
                resolved_env: resolved.env.clone(),
                resolved_cwd: resolved.cwd.clone(),
                timeout_ms: resolved.timeout_ms,
                state_hypothesis_id: plan.state_hypothesis_id.clone(),
                forbidden_transition_id: plan.forbidden_transition_id.clone(),
                attempted_transition_summary: plan.attempted_transition_summary.clone(),
            },
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
            exit_code: output.status.code(),
        },
        Err(error) => DiscoveryExecutionResult {
            attempt: HarnessAttemptRecord {
                harness_attempt_id: resolved.attempt_id,
                expansion_id: plan.harness_id.clone(),
                lifecycle: DiscoveryLifecycleStatus::FailedInfra,
                outcome: None,
                attempt_plan_hash: plan.attempt_plan_hash.clone(),
                artifact_root: artifact_root.clone(),
                retry_count,
                launcher_command: command_line,
                generated_binding_id: resolved.generated_binding_id.clone(),
                generated_input_bindings: resolved.generated_input_bindings.clone(),
                resolved_argv: resolved.argv.clone(),
                resolved_env: resolved.env.clone(),
                resolved_cwd: resolved.cwd.clone(),
                timeout_ms: resolved.timeout_ms,
                state_hypothesis_id: plan.state_hypothesis_id.clone(),
                forbidden_transition_id: plan.forbidden_transition_id.clone(),
                attempted_transition_summary: plan.attempted_transition_summary.clone(),
            },
            stdout: String::new(),
            stderr: format!("failed to launch {}: {}", resolved.argv[0], error),
            exit_code: None,
        },
    };

    write_capture_artifact(Path::new(&artifact_root).join("stdout.txt"), &result.stdout)?;
    write_capture_artifact(Path::new(&artifact_root).join("stderr.txt"), &result.stderr)?;

    Ok(result)
}

fn artifact_root_for_attempt(
    plan: &HarnessPlan,
    retry_count: u32,
    generated_binding_id: Option<&str>,
) -> String {
    let binding_component = generated_binding_id
        .map(sanitize_path_component)
        .unwrap_or_else(|| "default".into());
    Path::new(&plan.artifact_dir)
        .join(&plan.attempt_plan_hash)
        .join(binding_component)
        .join(format!("attempt-{retry_count}"))
        .display()
        .to_string()
}

fn resolve_arg_template(
    template: &ArgTemplate,
    bindings: &std::collections::BTreeMap<&str, &str>,
) -> Result<String, String> {
    match template {
        ArgTemplate::Literal { value } => Ok(value.clone()),
        ArgTemplate::Binding { key } => bindings
            .get(key.as_str())
            .map(|value| (*value).to_string())
            .ok_or_else(|| format!("missing binding for argument template key {key}")),
    }
}

fn resolve_env_template(
    template: &EnvTemplate,
    bindings: &std::collections::BTreeMap<&str, &str>,
) -> Result<String, String> {
    match template {
        EnvTemplate::Literal { value } => Ok(value.clone()),
        EnvTemplate::Binding { key } => bindings
            .get(key.as_str())
            .map(|value| (*value).to_string())
            .ok_or_else(|| format!("missing binding for env template key {key}")),
    }
}

fn write_capture_artifact(path: impl AsRef<Path>, contents: &str) -> Result<(), String> {
    fs::write(path.as_ref(), contents)
        .map_err(|e| format!("failed to write {}: {}", path.as_ref().display(), e))
}

fn binding_map(inputs: &[InputBinding]) -> std::collections::BTreeMap<String, String> {
    inputs
        .iter()
        .map(|binding| (binding.key.clone(), binding.value.clone()))
        .collect()
}

fn sanitize_path_component(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | 'A'..='Z' | '0'..='9' | '-' | '_' => ch,
            _ => '_',
        })
        .collect()
}
