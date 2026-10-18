//! The persistent exact-action token of one native review.

use std::time::Instant;

use guard_command::hook_adapter_envelope::is_shell_tool;
use guard_contracts::{NativeExactActionQueryV1, NativePolicyBindingV1, NativeReviewFactsV1};
use serde_json::{json, Value};

use super::context::{Ctx, Engines};
use super::fs_path;
use super::launch::shell_launch_identity;
use super::reasons::{
    Proof, GUARD_CONTROL, GUARD_CONTROL_ACTION_TYPES, NON_OVERRIDABLE, NO_COMMAND_IDENTITY,
    PACKAGE_ACTION, UNPROVEN_LAUNCH,
};
use super::tool_target::tool_target_identity;
use crate::context_digest::{build_context_token, parse_context_token};
use guard_contracts::ContextDigestComponentsV1;

const POLICY_VERSION: &str = "native-exact-action-v1";
/// The policy version of a token that hashes only the command itself.
const COMMAND_HASH_VERSION: &str = "native-command-hash-v1";
/// A review raised for one of these signals is a risk finding, not a first-seen
/// prompt: it never gets the proven token, so an approval of it binds only the
/// exact command (`command_hash`).
const RISK_REASON_MARKERS: [&str; 11] = [
    "secret",
    "sensitive",
    "credential",
    "exfil",
    "injection",
    "destructive",
    "malware",
    "obfuscat",
    "encoded",
    "poison",
    "dangerous",
];

fn is_review_action(action: Option<&str>) -> bool {
    matches!(action, Some("review" | "require-reapproval"))
}

fn is_overridable(facts: &NativeReviewFactsV1) -> bool {
    let action_type = facts.action_type.as_deref();
    is_review_action(facts.policy_action.as_deref())
        && is_review_action(facts.minimum_action.as_deref())
        && !action_type
            .is_some_and(|kind| GUARD_CONTROL_ACTION_TYPES.contains(&kind) || kind == "package")
}

fn non_overridable_reason(facts: &NativeReviewFactsV1) -> &'static str {
    match facts.action_type.as_deref() {
        Some(kind) if GUARD_CONTROL_ACTION_TYPES.contains(&kind) => GUARD_CONTROL,
        Some("package") => PACKAGE_ACTION,
        _ => NON_OVERRIDABLE,
    }
}

/// `launch_cwd`: the payload cwd, else the workspace; it must be an existing absolute directory.
pub(super) fn launch_cwd(payload_cwd: Option<&str>, workspace: Option<&str>) -> Option<String> {
    let candidate = payload_cwd
        .filter(|raw| !raw.trim().is_empty())
        .or(workspace)?;
    if !fs_path::is_abs(candidate) {
        return None;
    }
    let resolved = fs_path::resolve_strict(candidate)?;
    fs_path::is_dir(&resolved).then_some(resolved)
}

/// `_exact_action_token`: the token, or the reason the action stays one-time.
pub(super) fn exact_action(
    query: &NativeExactActionQueryV1,
    deadline: Instant,
    engines: &dyn Engines,
) -> Proof<String> {
    let components = exact_action_components(query, deadline, engines)?;
    let token = build_context_token(&components).map_err(|_| UNPROVEN_LAUNCH)?;
    parse_context_token(&Value::String(token.clone())).ok_or(UNPROVEN_LAUNCH)?;
    Ok(token)
}

/// The token an approval of `query` is saved and matched under: the proven
/// exact-action token when Guard can prove what the command runs, else the
/// hash of the command itself (`command_hash`). Every review the user can
/// answer gets one, so every review offers Always allow
/// (`docs/guard/approval-invariant.md`).
pub(super) fn approval_token(
    query: &NativeExactActionQueryV1,
    deadline: Instant,
    engines: &dyn Engines,
) -> Proof<String> {
    exact_action(query, deadline, engines).or_else(|reason| command_hash(query).map_err(|_| reason))
}

/// The hash of the command a review paused: harness, tool, a shell's command
/// text (or any other tool's input as sent, empty only when the tool took
/// none), working
/// directory and workspace. Nothing else enters it, so an
/// approval saved under it holds until the command changes or the user
/// revokes it. Only a review the user can answer has one.
pub(super) fn command_hash(query: &NativeExactActionQueryV1) -> Proof<String> {
    let NativeExactActionQueryV1::ExactAction {
        harness,
        tool_name,
        command,
        tool_input,
        raw_tool_input,
        payload_cwd,
        workspace,
        facts,
        ..
    } = query
    else {
        return Err(UNPROVEN_LAUNCH);
    };
    if !is_review_action(facts.policy_action.as_deref())
        || !is_review_action(facts.minimum_action.as_deref())
    {
        return Err(NON_OVERRIDABLE);
    }
    let input = match (tool_input, raw_tool_input) {
        (Some(pairs), _) => {
            let fields: serde_json::Map<String, Value> = pairs.iter().cloned().collect();
            json!({"tool_input": fields})
        }
        // An input that is not an object is hashed as it was sent.
        (None, Some(raw)) => json!({"raw_tool_input": raw}),
        // Only a tool called with no input at all hashes as an empty one.
        (None, None) => json!({"tool_input": {}}),
    };
    let content = match command.as_deref().filter(|text| !text.trim().is_empty()) {
        // A shell runs only its command text; its other fields (a description,
        // a timeout) do not change what runs.
        Some(text) if is_shell_tool(Some(tool_name.as_str())) => json!({"command": text}),
        // Any other tool's fields can change what its `command` does, so the
        // whole input binds the hash.
        Some(text) => json!({"command": text, "input": input}),
        None => input,
    };
    let cwd = payload_cwd
        .as_deref()
        .filter(|raw| !raw.trim().is_empty())
        .or(workspace.as_deref());
    let components = ContextDigestComponentsV1 {
        identity: json!({
            "kind": COMMAND_HASH_VERSION,
            "harness": harness,
            "tool_name": tool_name,
            "workspace": workspace,
            "cwd": cwd,
        }),
        content,
        capabilities: json!({}),
        policy: json!({"version": COMMAND_HASH_VERSION}),
        sandbox: json!({"required": false}),
        extension_control_digest: String::new(),
    };
    let token = build_context_token(&components).map_err(|_| UNPROVEN_LAUNCH)?;
    parse_context_token(&Value::String(token.clone())).ok_or(UNPROVEN_LAUNCH)?;
    Ok(token)
}

/// The five context components the token digests, before hashing.
pub(super) fn exact_action_components(
    query: &NativeExactActionQueryV1,
    deadline: Instant,
    engines: &dyn Engines,
) -> Proof<ContextDigestComponentsV1> {
    let NativeExactActionQueryV1::ExactAction {
        harness,
        tool_name,
        command,
        tool_input,
        payload_cwd,
        workspace,
        home_dir,
        environment,
        facts,
        policy_binding,
        extension_control_digest,
        ..
    } = query
    else {
        return Err(UNPROVEN_LAUNCH);
    };
    if !is_overridable(facts) {
        return Err(non_overridable_reason(facts));
    }
    let reason_code = facts.reason_code.as_deref().unwrap_or("").to_lowercase();
    if RISK_REASON_MARKERS
        .iter()
        .any(|marker| reason_code.contains(marker))
    {
        return Err(NON_OVERRIDABLE);
    }
    let has_command = command
        .as_deref()
        .is_some_and(|text| !text.trim().is_empty());
    let without_identity = if has_command {
        UNPROVEN_LAUNCH
    } else {
        NO_COMMAND_IDENTITY
    };
    if matches!(policy_binding, NativePolicyBindingV1::Invalid) {
        return Err(without_identity);
    }
    let cwd = launch_cwd(payload_cwd.as_deref(), workspace.as_deref()).ok_or(without_identity)?;
    let ctx = Ctx {
        home: home_dir.as_deref(),
        env: environment,
        deadline,
        engines,
    };
    let (launch, content) = if has_command {
        let text = command.as_deref().unwrap_or("");
        (
            shell_launch_identity(harness, tool_name, text, &cwd, &ctx)?,
            json!({"command": text}),
        )
    } else {
        tool_target_identity(
            tool_name,
            tool_input.as_deref(),
            &cwd,
            workspace.as_deref(),
            &ctx,
        )?
    };
    let NativePolicyBindingV1::Bound { value: binding } = policy_binding else {
        return Err(UNPROVEN_LAUNCH);
    };
    let workspace_identity = match workspace.as_deref() {
        Some(path) => Value::String(fs_path::resolve(path).ok_or(UNPROVEN_LAUNCH)?),
        None => Value::Null,
    };
    Ok(ContextDigestComponentsV1 {
        identity: json!({
            "harness": harness,
            "tool_name": tool_name,
            "workspace": workspace_identity,
            "cwd": cwd,
            "launch": launch,
        }),
        content,
        capabilities: json!({
            "action_type": facts.action_type,
            "minimum_action": facts.minimum_action.as_deref().unwrap_or(""),
            "policy_action": facts.policy_action.as_deref().unwrap_or(""),
            "reason_code": facts.reason_code.as_deref().unwrap_or(""),
        }),
        policy: json!({
            "version": POLICY_VERSION,
            "rule_digest": binding.get("rule_digest").cloned().unwrap_or(Value::Null),
            "command_extensions": binding.get("command_extensions").cloned().unwrap_or(Value::Null),
        }),
        sandbox: json!({"required": facts.minimum_action.as_deref() == Some("sandbox-required")}),
        extension_control_digest: extension_control_digest.clone(),
    })
}
