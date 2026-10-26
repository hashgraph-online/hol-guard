//! Hook admission to an owner, never permission to run the original input.

use crate::policy_enforcement::AdmittedPolicySnapshot;
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};

#[cfg(target_os = "macos")]
#[derive(serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct HostDelivery {
    schema: String,
    host: String,
    owner_pid: u32,
    environment: std::collections::BTreeMap<String, String>,
    file_creation_mask: u32,
}

#[cfg(target_os = "macos")]
pub(crate) fn require_owner(
    envelope: &GuardHookEnvelopeV2,
    snapshot: Option<&AdmittedPolicySnapshot>,
    mut result: PreToolResultV1,
) -> PreToolResultV1 {
    if envelope.event != "PreToolUse"
        || envelope.recording_only
        || result.minimum_action == "block"
        || result.command_extensions.is_none()
        || envelope
            .raw_payload
            .get("tool_name")
            .and_then(serde_json::Value::as_str)
            != Some("bash")
    {
        return result;
    }
    let expected_host = match envelope.harness.as_str() {
        "omp" => "omp-input-rewrite-v1",
        "pi" => "pi-input-mutation-v1",
        _ => return result,
    };
    let Some(stamp) = envelope.raw_payload.get("guard_bound_bash_host") else {
        return result;
    };
    let Some(command) = envelope
        .raw_payload
        .pointer("/tool_input/command")
        .and_then(serde_json::Value::as_str)
    else {
        return result;
    };
    let model = guard_command::command_model::parse_shell_command(
        command,
        envelope.source.cwd.as_deref().map(std::path::Path::new),
        Some(std::path::Path::new(&envelope.source.home_dir)),
        "posix",
        "shell_string",
        "guard-shell",
        true,
    );
    if !model.segments.iter().any(|segment| {
        segment
            .executable
            .as_deref()
            .and_then(|value| std::path::Path::new(value).file_name())
            .is_some_and(|name| name == "bash")
    }) {
        return result;
    }
    let Ok(stamp) = serde_json::from_value::<HostDelivery>(stamp.clone()) else {
        return unavailable(result, "bash_host_observation_invalid");
    };
    if stamp.schema != "guard-native-bash-host-delivery.v3"
        || stamp.host != expected_host
        || stamp.owner_pid <= 1
    {
        return unavailable(result, "bash_host_delivery_unavailable");
    }
    let (Some(snapshot), Some(environment), Some(cwd)) = (
        snapshot,
        envelope.source.execution_environment.as_ref(),
        envelope.source.cwd.as_ref(),
    ) else {
        return unavailable(result, "bash_host_context_unavailable");
    };
    let execution_cwd = if envelope.harness == "omp" {
        match guard_command::pretool::generic::omp_bash_execution_directory(
            &envelope.raw_payload,
            Some(&envelope.source.home_dir),
            Some(cwd),
        ) {
            Ok(Some(path)) => path,
            _ => return unavailable(result, "bash_working_directory_unavailable"),
        }
    } else {
        cwd.clone()
    };
    let capture = guard_contracts::NativeBashCaptureV1 {
        harness: envelope.harness.clone(),
        command: command.into(),
        cwd: execution_cwd,
        workspace: cwd.clone(),
        home_dir: envelope.source.home_dir.clone(),
        guard_home: envelope.source.guard_home.clone(),
        execution_environment: environment.clone(),
        environment: stamp.environment,
        file_creation_mask: Some(stamp.file_creation_mask),
        budget_ms: envelope.deadline_budget_ms.unwrap_or(750).clamp(1, 1000),
    };
    // This bounded preview proves only that an immutable-owner route exists.
    // Its graph is dropped without execution/output effects. The actual sink
    // observes its own host context and repeats capture, current policy,
    // consent, journal admission and native dispatch acknowledgment.
    if let Err(reason) = super::bash_capture::capture_for_launch(&capture, snapshot) {
        return unavailable(result, &reason);
    }
    result.decision = "deny".into();
    result.minimum_action = "sandbox-required".into();
    result.policy_action = "sandbox-required".into();
    result.explicitly_benign = false;
    result.reason_code = guard_contracts::NATIVE_BASH_DELIVERY_REASON.into();
    result.reason = "Guard must execute this captured Bash invocation through its native owner, which checks the actual context, current policy and consent before launch.".into();
    result
}

#[cfg(target_os = "macos")]
fn unavailable(mut result: PreToolResultV1, reason: &str) -> PreToolResultV1 {
    // A failed closed-graph proof cannot fall back to a generic sandbox route:
    // that route would not execute the immutable version reviewed by this owner.
    result.decision = "deny".into();
    result.minimum_action = "block".into();
    result.policy_action = "block".into();
    result.explicitly_benign = false;
    result.reason_code = "native_bash_owner_unavailable".into();
    result.reason = format!("Guard cannot bind this Bash invocation for native execution ({reason}). Simplify its executable inputs or use a supported invocation; saving consent cannot make this launch safe.");
    result
}

#[cfg(not(target_os = "macos"))]
pub(crate) fn require_owner(
    _envelope: &GuardHookEnvelopeV2,
    _snapshot: Option<&AdmittedPolicySnapshot>,
    result: PreToolResultV1,
) -> PreToolResultV1 {
    result
}
