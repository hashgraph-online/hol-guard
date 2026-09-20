//! Configuration for a bounded, source-qualified generic command producer.
//!
//! Resolve selectors inside each origin before joining the independent origins.
//! Runtime risk/subprocess inputs belong to separate producers and are not
//! generic selectors. The caller must preserve every independent native floor.

use super::join_action;
use super::policy_enforcement_policy::{
    canonical_harness_action, policy_map_action, validate_effective_policy,
};
use guard_command::exact_command::exact_shell_command_from_hook;
use guard_command::pretool::evaluate_pre_tool;
use guard_command::CommandModelRequestV1;
use guard_contracts::{GuardHookEnvelopeV2, PreToolActionTypeV1, PreToolResultV1};
use guard_policy_snapshot::managed_configuration::ManagedConfiguration;
use guard_policy_snapshot::EffectiveNativePolicyV3;
use serde_json::Value;

pub(crate) struct GenericCommandConfiguration {
    configured_action: String,
    relaxed_default: bool,
    exec_command: bool,
}

impl GenericCommandConfiguration {
    pub(crate) fn evaluated_action(&self) -> &str {
        if self.relaxed_default {
            "warn"
        } else {
            &self.configured_action
        }
    }

    pub(crate) fn replaces_fallback_review(&self, intrinsic: &PreToolResultV1) -> bool {
        match (intrinsic.reason_code.as_str(), intrinsic.action.action_type) {
            ("native_command_review_required", PreToolActionTypeV1::Command) => true,
            ("native_pre_tool_unknown_review", PreToolActionTypeV1::Unknown) => self.exec_command,
            _ => false,
        }
    }
}

fn selected(
    policy: &EffectiveNativePolicyV3,
    harness: &str,
    artifact_id: &str,
    publisher: Option<&str>,
) -> Result<(Option<String>, bool), String> {
    validate_effective_policy(policy)?;
    // Python's generic selector lookup uses the exact canonical harness. A
    // normalized alias would invent a match absent from that source lookup.
    if policy
        .harness_actions
        .keys()
        .any(|key| key != harness && super::normalized_harness(key) == harness)
    {
        return Err("native_generic_configuration_unsupported".to_owned());
    }
    let narrow = policy_map_action(&policy.artifact_actions, artifact_id)?.or(publisher
        .map(|value| policy_map_action(&policy.publisher_actions, value))
        .transpose()?
        .flatten());
    let has_narrow = narrow.is_some();
    Ok((
        narrow.or(canonical_harness_action(&policy.harness_actions, harness)?),
        has_narrow,
    ))
}

/// Called only after the original request passes the generic shell producer.
/// Other harnesses, tools and executable families retain their existing fence.
pub(crate) fn generic_command_configuration(
    policy: &EffectiveNativePolicyV3,
    origin: Option<&ManagedConfiguration>,
    envelope: &GuardHookEnvelopeV2,
    harness: &str,
    artifact_id: &str,
) -> Result<Option<GenericCommandConfiguration>, String> {
    if harness != "codex" || envelope.harness != harness || envelope.event != "PreToolUse" {
        return Ok(None);
    }
    let tool = envelope
        .raw_payload
        .get("tool_name")
        .or_else(|| envelope.raw_payload.get("toolName"))
        .and_then(Value::as_str);
    if !matches!(tool, Some("Shell" | "Bash" | "shell" | "exec_command")) {
        return Ok(None);
    }
    let Some(command) = exact_shell_command_from_hook(&envelope.raw_payload) else {
        return Ok(None);
    };
    let native = evaluate_pre_tool(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })?;
    let segments = &native.command_model.segments;
    let [segment] = segments.as_slice() else {
        return Ok(None);
    };
    let verified_pwd = match segment.executable.as_deref() {
        Some("pwd") if segment.arguments.is_empty() => tool != Some("exec_command"),
        Some("printf" | "ssh") => false,
        _ => return Ok(None),
    };
    let publisher = envelope
        .raw_payload
        .get("publisher")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty());
    let (local_selected, local_narrow) = selected(policy, harness, artifact_id, publisher)?;
    let local = local_selected.unwrap_or_else(|| policy.default_action.clone());
    let (configured_action, has_narrow) = if let Some(origin) = origin {
        let managed_policy = origin.effective_policy();
        let (managed_selected, managed_narrow) =
            selected(managed_policy, harness, artifact_id, publisher)?;
        let managed = managed_selected.or_else(|| {
            origin
                .default_action_present()
                .then(|| managed_policy.default_action.clone())
        });
        (
            match managed {
                Some(value) => join_action(&local, &value)?,
                None => local,
            },
            local_narrow || managed_narrow,
        )
    } else {
        (local, local_narrow)
    };
    let relaxed_default = verified_pwd
        && !has_narrow
        && matches!(configured_action.as_str(), "review" | "require-reapproval");
    Ok(Some(GenericCommandConfiguration {
        configured_action,
        relaxed_default,
        exec_command: tool == Some("exec_command"),
    }))
}
