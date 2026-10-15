//! Launch-authority signature, final authority gate and policy-shadow
//! comparison for `RunnerAuthority`.

use std::collections::BTreeMap;

use guard_command::decisions::evaluation_authority_error;
use guard_contracts::is_guard_action;
use serde_json::{json, Map, Value};

use super::context_digest::parse_context_token;
use super::runner_authority_detector::{args_object, detector_context};
use super::runner_authority_op::{KindResult, ERR_INVALID};

const SHADOW_REASON_LIMIT: usize = 4;

/// `_guard_run_launch_plan_signature` for one reusable preview.
fn launch_plan_signature(plan: &Value) -> Option<Value> {
    let plan = plan.as_object()?;
    if plan.get("reusable") != Some(&Value::Bool(true)) {
        return None;
    }
    Some(json!({
        "adapter_command": plan.get("adapter_command").cloned().unwrap_or(Value::Null),
        "environment_sha256": plan.get("environment_sha256").cloned().unwrap_or(Value::Null),
        "identity": plan.get("identity").cloned().unwrap_or(Value::Null),
    }))
}

/// `(artifact_id -> (approval token, policy action))`, or `None` when any
/// artifact cannot be bound exactly (the claim must then fail closed).
fn artifact_contexts(artifacts: &[Value]) -> Option<BTreeMap<&str, (&str, &str)>> {
    let mut contexts = BTreeMap::new();
    for item in artifacts {
        let item = item.as_object()?;
        let artifact_id = item
            .get("artifact_id")
            .and_then(Value::as_str)
            .filter(|id| !id.is_empty())?;
        let token = item.get("approval_context_hash")?;
        parse_context_token(token)?;
        let action = item.get("policy_action").filter(|a| is_guard_action(a))?;
        if contexts
            .insert(artifact_id, (token.as_str()?, action.as_str()?))
            .is_some()
        {
            return None;
        }
    }
    Some(contexts)
}

/// `_guard_run_authority_signature` including the "all previews reusable" gate
/// both call sites apply. `signature: null` means the claim cannot be bound.
pub(crate) fn authority_signature(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let previews = args
        .get("launch_previews")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let plan_signatures: Option<Vec<Value>> = previews.iter().map(launch_plan_signature).collect();
    let (Some(plan_signatures), Some(artifacts)) = (
        plan_signatures.filter(|plans| !plans.is_empty()),
        args.get("artifacts").and_then(Value::as_array),
    ) else {
        return Ok(json!({"signature": null}));
    };
    let Some(contexts) = artifact_contexts(artifacts) else {
        return Ok(json!({"signature": null}));
    };
    let detector = args
        .get("detector")
        .and_then(Value::as_object)
        .and_then(detector_context)
        .unwrap_or(Value::Null);
    let contexts: Vec<Value> = contexts
        .into_iter()
        .map(|(id, (token, action))| json!([id, token, action]))
        .collect();
    Ok(json!({"signature": {
        "harness": args.get("harness").cloned().unwrap_or(Value::Null),
        "installed": args.get("installed").cloned().unwrap_or(Value::Null),
        "command_available": args.get("command_available").cloned().unwrap_or(Value::Null),
        "config_paths": args.get("config_paths").cloned().unwrap_or(Value::Null),
        "contexts": contexts,
        "detector": detector,
        "launch_previews": plan_signatures,
    }}))
}

/// The final fail-closed contradiction check run before any launch.
pub(crate) fn authority_gate(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let evaluation = args.get("evaluation").ok_or(ERR_INVALID)?;
    let require_launch_permitted = args
        .get("require_launch_permitted")
        .and_then(Value::as_bool)
        .ok_or(ERR_INVALID)?;
    Ok(json!({
        "authority_error": evaluation_authority_error(evaluation, require_launch_permitted),
    }))
}

type ShadowRow<'a> = &'a Map<String, Value>;

fn shadow_key(row: ShadowRow<'_>) -> String {
    let field = |name: &str| row.get(name).cloned().unwrap_or(Value::Null);
    Value::Array(
        [
            "harness",
            "scope",
            "artifact_id",
            "artifact_hash",
            "workspace",
            "publisher",
        ]
        .iter()
        .map(|name| field(name))
        .collect(),
    )
    .to_string()
}

fn shadow_rows<'a>(
    args: &'a Map<String, Value>,
    key: &str,
) -> Result<BTreeMap<String, ShadowRow<'a>>, &'static str> {
    let rows = args.get(key).and_then(Value::as_array).ok_or(ERR_INVALID)?;
    let mut keyed = BTreeMap::new();
    for row in rows {
        let row = row.as_object().ok_or(ERR_INVALID)?;
        keyed.insert(shadow_key(row), row);
    }
    Ok(keyed)
}

/// `_policy_shadow_mismatch_reason_codes`.
pub(crate) fn policy_shadow_mismatch(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let count = |key: &str| args.get(key).and_then(Value::as_array).map(Vec::len);
    let (legacy_count, canonical_count) = (
        count("legacy").ok_or(ERR_INVALID)?,
        count("canonical").ok_or(ERR_INVALID)?,
    );
    if legacy_count == 0 {
        return Ok(json!({"reason_codes": ["legacy_unavailable"]}));
    }
    let legacy = shadow_rows(args, "legacy")?;
    let canonical = shadow_rows(args, "canonical")?;
    let mut reasons: Vec<&str> = Vec::new();
    if legacy_count != canonical_count {
        reasons.push("row_count");
    }
    if !legacy.keys().eq(canonical.keys()) {
        reasons.push("selector_set");
    }
    let shared: Vec<(&ShadowRow<'_>, &ShadowRow<'_>)> = legacy
        .iter()
        .filter_map(|(key, row)| canonical.get(key).map(|other| (row, other)))
        .collect();
    let differs = |field: &str| shared.iter().any(|(a, b)| a.get(field) != b.get(field));
    if differs("action") {
        reasons.push("action");
    }
    if differs("expires_at") {
        reasons.push("expiration");
    }
    reasons.truncate(SHADOW_REASON_LIMIT);
    Ok(json!({"reason_codes": reasons}))
}
