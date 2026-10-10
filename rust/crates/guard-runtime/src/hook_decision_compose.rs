//! Current-action composition for the generic hook path.
//!
//! Folds the configured action, the trusted CLI override, the untrusted
//! payload hint, the native edge floor and the untrusted daemon hint into one
//! action. Classifier verdicts that the composition needs (is this tool call
//! verified benign?) are facts the transport supplies lazily: when a verdict
//! is missing the composition names it and stops, so the classifiers only run
//! when the resident asks for them.

use guard_contracts::{
    hook_event_name, normalize_guard_action, normalize_guard_action_result, GuardAction,
    GuardActionNormalization, HookCompositionInputsV1, HookNativeEdgeV1,
};
use serde_json::Value;

pub(crate) const COPILOT_BENIGN_HINT_REASON: &str =
    "untrusted_hook_payload_hint_ignored_guard_verified_benign";
pub(crate) const BENIGN_DEFAULT_REASON: &str = "configured_default_relaxed_guard_verified_benign";
const DAEMON_FAILURE_STATUSES: [&str; 4] = ["unreachable", "error", "failed", "404"];
const DAEMON_STRICT_REASON: &str =
    "HOL Guard fail safe: the local Guard daemon was unreachable, so this hook blocked the action.";
const DAEMON_PRESERVED_DENY_REASON: &str =
    "HOL Guard daemon was unreachable; preserving the existing deny decision for this action.";
const UNTRUSTED_DAEMON_PERMISSIVE_REASON: &str = "HOL Guard received an unauthenticated hint that the daemon was unreachable in permissive mode; the current local policy action was preserved.";
const DAEMON_PERMISSIVE_CODE: &str = "untrusted_daemon_permissive_hint_preserved_current_action";
const DAEMON_STRICT_CODE: &str = "untrusted_daemon_strict_hint_tightened_to_block";

pub(crate) struct Composed {
    pub(crate) event_name: Option<String>,
    pub(crate) effective_event: String,
    pub(crate) configured: GuardActionNormalization,
    pub(crate) current_config: GuardAction,
    pub(crate) current_config_normalization: GuardActionNormalization,
    pub(crate) relaxed: bool,
    pub(crate) relax_classifier: &'static str,
    pub(crate) cli: Option<GuardActionNormalization>,
    pub(crate) payload: Option<GuardActionNormalization>,
    pub(crate) ignored_payload_reason: Option<&'static str>,
    pub(crate) payload_disposition: Option<&'static str>,
    pub(crate) edge: Option<GuardAction>,
    pub(crate) composed: GuardAction,
    pub(crate) daemon_disposition: Option<&'static str>,
    pub(crate) daemon_reason_code: Option<&'static str>,
    pub(crate) daemon_failure_reason: Option<String>,
    pub(crate) permission_reason: Option<String>,
    pub(crate) daemon_status: Option<String>,
    pub(crate) fail_mode: Option<String>,
    pub(crate) grant_lookups_allowed: bool,
}

/// `Err(name)`: the classifier verdict `name` is needed before composing.
pub(crate) type Needs<T> = Result<T, &'static str>;

pub(crate) fn compose(inputs: &HookCompositionInputsV1) -> Needs<Composed> {
    let event_name = hook_event_name(&inputs.event_fields);
    let event = event_name.as_deref();
    let configured =
        normalize_guard_action_result(&inputs.configured_action, GuardAction::RequireReapproval);
    let relaxed = relax_configured_default(inputs, event, configured.action)?;
    let current_config_normalization = if relaxed {
        normalize_guard_action_result(&Value::from("warn"), GuardAction::RequireReapproval)
    } else {
        configured.clone()
    };
    let current_config = current_config_normalization.action;
    let cli = inputs
        .cli_action
        .as_ref()
        .filter(|value| !value.is_null())
        .map(|value| normalize_guard_action_result(value, GuardAction::RequireReapproval));
    let payload = inputs.has_payload_action.then(|| {
        normalize_guard_action_result(&inputs.payload_action, GuardAction::RequireReapproval)
    });
    let ignored_payload_reason = ignored_payload_reason(inputs, payload.as_ref())?;
    let payload_disposition = if ignored_payload_reason.is_some() {
        Some("ignored")
    } else if payload.is_some() {
        Some("applied")
    } else {
        None
    };
    let edge = edge_floor(inputs.native_edge.as_ref(), event);
    let mut composed = current_config;
    for action in [
        cli.as_ref().map(|item| item.action),
        payload
            .as_ref()
            .filter(|_| ignored_payload_reason.is_none())
            .map(|item| item.action),
        edge,
    ]
    .into_iter()
    .flatten()
    {
        composed = composed.max(action);
    }
    let classifier = relax_classifier(inputs, event);
    let effective_event = event.unwrap_or("PreToolUse").to_owned();
    let mut out = Composed {
        effective_event,
        event_name,
        configured,
        current_config,
        current_config_normalization,
        relaxed,
        relax_classifier: classifier,
        cli,
        payload,
        ignored_payload_reason,
        payload_disposition,
        edge,
        composed,
        daemon_disposition: None,
        daemon_reason_code: None,
        daemon_failure_reason: None,
        permission_reason: None,
        daemon_status: optional_string(&inputs.daemon_status),
        fail_mode: optional_string(&inputs.fail_mode),
        grant_lookups_allowed: false,
    };
    apply_daemon_hint(&mut out, inputs);
    out.grant_lookups_allowed = !inputs.has_configured_override
        && !inputs.has_narrow_override
        && out.cli.is_none()
        && (out.payload.is_none() || out.ignored_payload_reason.is_some())
        && out.daemon_disposition != Some("tightened_to_block");
    Ok(out)
}

pub(crate) fn optional_string(value: &Value) -> Option<String> {
    value
        .as_str()
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
}

fn fact(inputs: &HookCompositionInputsV1, name: &'static str) -> Needs<bool> {
    inputs.facts.get(name).copied().ok_or(name)
}

/// A verified-benign tool call relaxes a review-tier configured default.
fn relax_configured_default(
    inputs: &HookCompositionInputsV1,
    event: Option<&str>,
    configured: GuardAction,
) -> Needs<bool> {
    if inputs.has_narrow_override
        || !matches!(
            configured,
            GuardAction::Review | GuardAction::RequireReapproval
        )
    {
        return Ok(false);
    }
    let canonical = inputs.canonical_harness.as_str();
    if event == Some("UserPromptSubmit") {
        return if inputs.prompt_nonblank {
            fact(inputs, "prompt_clean")
        } else {
            Ok(false)
        };
    }
    if event == Some("PostToolUse") && inputs.runtime_artifact_checked && canonical == "codex" {
        return fact(inputs, "post_tool_read_only_inspection");
    }
    if fact(inputs, "verified_apply_patch")? {
        return Ok(true);
    }
    let pre = event == Some("PreToolUse");
    if pre
        && matches!(canonical, "claude-code" | "codex")
        && fact(inputs, "benign_native_file_read")?
    {
        return Ok(true);
    }
    Ok(pre && fact(inputs, "benign_tool_action")?)
}

/// The classifier that justified (or would justify) the relaxation, for audit.
fn relax_classifier(inputs: &HookCompositionInputsV1, event: Option<&str>) -> &'static str {
    let tool = inputs.tool_name_text.trim().to_lowercase();
    if event == Some("PostToolUse") {
        "_codex_post_tool_command_is_read_only_source_inspection"
    } else if event == Some("PreToolUse") && tool == "read" {
        "is_explicitly_benign_native_file_read_request"
    } else if event == Some("PreToolUse") && tool == "apply_patch" {
        "runtime_artifact_verified_non_sensitive_apply_patch"
    } else {
        "is_explicitly_benign_tool_action_request"
    }
}

/// Why a legacy Copilot payload hint is not an authority input: Guard's own
/// classifier positively established the action is read-only.
fn ignored_payload_reason(
    inputs: &HookCompositionInputsV1,
    payload: Option<&GuardActionNormalization>,
) -> Needs<Option<&'static str>> {
    let recognized = payload.is_some_and(GuardActionNormalization::recognized);
    if !recognized
        || inputs.canonical_harness != "copilot"
        || copilot_stage(inputs).as_deref() != Some("pretooluse")
    {
        return Ok(None);
    }
    Ok(fact(inputs, "benign_tool_action")?.then_some(COPILOT_BENIGN_HINT_REASON))
}

fn copilot_stage(inputs: &HookCompositionInputsV1) -> Option<String> {
    ["hook_name", "hook_event_name", "hookEventName"]
        .iter()
        .filter_map(|key| inputs.event_fields.get(*key).and_then(Value::as_str))
        .map(str::trim)
        .find(|text| !text.is_empty())
        .map(str::to_lowercase)
}

fn truthy(value: &Value) -> bool {
    match value {
        Value::Null => false,
        Value::Bool(flag) => *flag,
        Value::Number(number) => number.as_f64().is_some_and(|n| n != 0.0),
        Value::String(text) => !text.is_empty(),
        Value::Array(items) => !items.is_empty(),
        Value::Object(items) => !items.is_empty(),
    }
}

/// The edge verdict as a floor on the composed action. A present but
/// unrecognized action fails closed to `block`.
fn edge_floor(edge: Option<&HookNativeEdgeV1>, event: Option<&str>) -> Option<GuardAction> {
    let edge = edge?;
    let raw = if truthy(&edge.policy_action) {
        Some(&edge.policy_action)
    } else if truthy(&edge.minimum_action) {
        Some(&edge.minimum_action)
    } else {
        None
    };
    let mut action = match raw {
        Some(value) => Some(normalize_guard_action(value, GuardAction::Block)),
        None if edge.decision.as_str() == Some("deny") => Some(GuardAction::Block),
        None => None,
    };
    let hard = matches!(
        action,
        Some(GuardAction::Block | GuardAction::SandboxRequired)
    );
    if event == Some("PostToolUse") {
        // PostToolUse cannot undo the finished action; the edge deny masks the
        // emitted output while the policy surface stays reviewable.
        if hard {
            action = Some(GuardAction::RequireReapproval);
        }
    } else if !hard {
        // Before execution, the edge's review-tier "unproven" verdict is
        // provenance: grants and configured policy settle reviewability. Only
        // a hard native enforcement verdict floors the emitted decision.
        action = None;
    }
    action
}

fn apply_daemon_hint(out: &mut Composed, inputs: &HookCompositionInputsV1) {
    let failed = out
        .daemon_status
        .as_deref()
        .is_some_and(|status| DAEMON_FAILURE_STATUSES.contains(&status));
    let (true, Some(mode)) = (failed, out.fail_mode.as_deref()) else {
        return;
    };
    match mode {
        "strict" => {
            out.daemon_disposition = Some(if out.composed == GuardAction::Block {
                "preserved_current_block"
            } else {
                "tightened_to_block"
            });
            out.composed = GuardAction::Block;
            out.daemon_reason_code = Some(DAEMON_STRICT_CODE);
            out.daemon_failure_reason = Some(DAEMON_STRICT_REASON.to_owned());
        }
        "permissive" => {
            out.daemon_disposition = Some("preserved_current_action");
            out.daemon_reason_code = Some(DAEMON_PERMISSIVE_CODE);
            out.daemon_failure_reason = Some(if out.composed >= GuardAction::Review {
                optional_string(&inputs.permission_decision_reason)
                    .unwrap_or_else(|| DAEMON_PRESERVED_DENY_REASON.to_owned())
            } else {
                UNTRUSTED_DAEMON_PERMISSIVE_REASON.to_owned()
            });
        }
        _ => return,
    }
    out.permission_reason = out.daemon_failure_reason.clone();
}
