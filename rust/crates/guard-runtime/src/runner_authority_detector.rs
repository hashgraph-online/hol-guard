//! Runtime-detector authority, current-authority actions, trusted request
//! overrides and saved-claim partitioning for `RunnerAuthority`.

use guard_command::decisions::parse_signals;
use guard_contracts::{
    compose_action_from_signals, is_guard_action, most_restrictive_guard_action, GuardAction,
};
use serde_json::{json, Map, Value};

use super::context_digest::parse_context_token;
use super::context_digest_json::write_canonical_json_with_limit;
use super::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) const RUNTIME_DETECTOR_WARN_REASON: &str = "runtime_detector_warn";
pub(crate) const RUNTIME_DETECTOR_REVIEW_REASON: &str = "runtime_detector_review";
const INTERACTIVE_ALLOW_LABELS: [&str; 4] = [
    "allow-once",
    "allow-artifact",
    "allow-publisher",
    "allow-harness",
];
const TELEMETRY_KEY_LIMIT: usize = 4 * 1024 * 1024;

pub(crate) fn args_object(args: &Value) -> Result<&Map<String, Value>, &'static str> {
    args.as_object().ok_or(ERR_INVALID)
}

fn non_empty_str(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

/// `_runtime_detector_authority`: only the four non-terminal-aware actions.
pub(crate) fn detector_action_and_reason(
    evaluation: &Map<String, Value>,
) -> (Option<GuardAction>, Option<String>) {
    let Some(composition) = evaluation
        .get("runtime_detector_composition")
        .and_then(Value::as_object)
    else {
        return (None, None);
    };
    let action = composition
        .get("action")
        .filter(|value| is_guard_action(value))
        .and_then(Value::as_str)
        .and_then(GuardAction::from_canonical)
        .filter(|action| {
            matches!(
                action,
                GuardAction::Allow | GuardAction::Warn | GuardAction::Review | GuardAction::Block
            )
        });
    let Some(action) = action else {
        return (None, None);
    };
    let reason = non_empty_str(composition.get("reason")).map(str::to_owned);
    (Some(action), reason)
}

/// `_runtime_detector_nonterminal_evidence`.
pub(crate) fn nonterminal_evidence(
    action: Option<GuardAction>,
    reason: Option<&str>,
) -> Option<Value> {
    let (status, code, default_reason) = match action? {
        GuardAction::Warn => (
            "warning",
            RUNTIME_DETECTOR_WARN_REASON,
            "runtime detector signals require a warning",
        ),
        GuardAction::Review => (
            "review-required",
            RUNTIME_DETECTOR_REVIEW_REASON,
            "runtime detector signals require review",
        ),
        _ => return None,
    };
    Some(json!({
        "source": "runtime_detector_registry",
        "status": status,
        "reason_code": code,
        "reason": reason.unwrap_or(default_reason),
    }))
}

fn telemetry_sort_key(item: &Value) -> Vec<u8> {
    let mut key = Vec::new();
    // An unencodable item sorts by whatever prefix was written; the result is
    // still deterministic and the item itself is preserved.
    let _ = write_canonical_json_with_limit(item, &mut key, TELEMETRY_KEY_LIMIT);
    key
}

/// `_normalized_runtime_detector_telemetry`: excludes nondeterministic timing.
fn normalized_telemetry(evaluation: &Map<String, Value>) -> Vec<Value> {
    let Some(raw) = evaluation
        .get("runtime_detector_telemetry")
        .and_then(Value::as_array)
    else {
        return Vec::new();
    };
    let mut telemetry: Vec<Value> = Vec::new();
    for raw_item in raw {
        let Some(map) = raw_item.as_object() else {
            continue;
        };
        let mut item: Map<String, Value> = map
            .iter()
            .filter(|(key, _)| key.as_str() != "elapsed_ms")
            .map(|(key, value)| (key.clone(), value.clone()))
            .collect();
        if let Some(Value::Array(categories)) = item.get("categories") {
            let mut names: Vec<String> = categories
                .iter()
                .filter_map(|category| category.as_str().map(str::to_owned))
                .collect();
            names.sort();
            names.dedup();
            item.insert(
                "categories".to_owned(),
                Value::Array(names.into_iter().map(Value::String).collect()),
            );
        }
        telemetry.push(Value::Object(item));
    }
    telemetry.sort_by_key(telemetry_sort_key);
    telemetry
}

/// `_runtime_detector_context`: timing-free authority for exact hashing.
pub(crate) fn detector_context(evaluation: &Map<String, Value>) -> Option<Value> {
    let composition = match evaluation
        .get("runtime_detector_composition")
        .and_then(Value::as_object)
    {
        Some(raw) => json!({
            "action": raw.get("action").cloned().unwrap_or(Value::Null),
            "reason": raw.get("reason").cloned().unwrap_or(Value::Null),
            "downgraded": raw.get("downgraded") == Some(&Value::Bool(true)),
            "upgraded": raw.get("upgraded") == Some(&Value::Bool(true)),
        }),
        None => json!({}),
    };
    let signals: Vec<Value> = evaluation
        .get("runtime_detector_signals_v2")
        .and_then(Value::as_array)
        .map(|raw| raw.iter().filter(|s| s.is_object()).cloned().collect())
        .unwrap_or_default();
    let telemetry = normalized_telemetry(evaluation);
    let empty_composition = composition.as_object().is_some_and(Map::is_empty);
    if empty_composition && signals.is_empty() && telemetry.is_empty() {
        return None;
    }
    Some(json!({"composition": composition, "signals_v2": signals, "telemetry": telemetry}))
}

pub(crate) fn detector_authority(args: &Value) -> KindResult {
    let evaluation = args_object(args)?
        .get("evaluation")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)?;
    let (action, reason) = detector_action_and_reason(evaluation);
    let evidence = nonterminal_evidence(action, reason.as_deref());
    let blocked = non_empty_str(evaluation.get("blocked_by_detector"));
    Ok(json!({
        "action": action.map(GuardAction::as_str),
        "reason": reason,
        "context": detector_context(evaluation),
        "nonterminal_evidence": evidence,
        "blocked_by_detector": blocked,
    }))
}

/// `compose_action_from_signals(signals, "allow")` for the detector registry.
pub(crate) fn detector_composition(args: &Value) -> KindResult {
    let signals = args_object(args)?.get("signals").ok_or(ERR_INVALID)?;
    let signals = parse_signals(signals).map_err(|_| ERR_INVALID)?;
    let composition = compose_action_from_signals(&signals, &json!("allow"));
    Ok(json!({
        "composition": {
            "action": composition.action.as_str(),
            "reason": composition.reason,
            "downgraded": composition.downgraded,
            "upgraded": composition.upgraded,
        },
        "blocks": composition.action == GuardAction::Block,
    }))
}

/// `_config_with_current_authority`: stronger of the current action and the
/// detector authority, per artifact. `artifact_actions: null` means no change.
pub(crate) fn current_authority_actions(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let authority = args
        .get("authority_action")
        .and_then(Value::as_str)
        .and_then(GuardAction::from_canonical)
        .ok_or(ERR_INVALID)?;
    let mut actions: Map<String, Value> = args
        .get("artifact_actions")
        .and_then(Value::as_object)
        .cloned()
        .unwrap_or_default();
    let scope: Option<Vec<&str>> = args
        .get("artifact_ids")
        .and_then(Value::as_array)
        .map(|ids| ids.iter().filter_map(Value::as_str).collect());
    let Some(artifacts) = args
        .get("artifacts")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        return Ok(json!({"artifact_actions": null}));
    };
    let mut changed = false;
    for item in artifacts.iter().filter_map(Value::as_object) {
        let Some(artifact_id) = non_empty_str(item.get("artifact_id")) else {
            continue;
        };
        if scope
            .as_ref()
            .is_some_and(|ids| !ids.contains(&artifact_id))
        {
            continue;
        }
        let current = item
            .get("policy_composition")
            .and_then(Value::as_object)
            .and_then(|composition| composition.get("current_action"))
            .filter(|value| is_guard_action(value))
            .or_else(|| item.get("policy_action"))
            .cloned()
            .unwrap_or(Value::Null);
        let composed = most_restrictive_guard_action(
            &[current, Value::String(authority.as_str().to_owned())],
            GuardAction::Block,
        );
        let composed = Value::String(composed.as_str().to_owned());
        if actions.get(artifact_id) != Some(&composed) {
            actions.insert(artifact_id.to_owned(), composed);
            changed = true;
        }
    }
    Ok(json!({"artifact_actions": if changed { Value::Object(actions) } else { Value::Null }}))
}

fn valid_override(artifact_id: Option<&Value>, token: Option<&Value>) -> Option<(String, String)> {
    let artifact_id = non_empty_str(artifact_id)?;
    let token = token?;
    parse_context_token(token)?;
    Some((artifact_id.to_owned(), token.as_str()?.to_owned()))
}

fn exact_overrides(approval_wait: Option<&Value>) -> Map<String, Value> {
    let mut overrides = Map::new();
    let Some(wait) = approval_wait.and_then(Value::as_object) else {
        return overrides;
    };
    if wait.get("resolved") != Some(&Value::Bool(true)) {
        return overrides;
    }
    let Some(raw) = wait
        .get("items")
        .and_then(Value::as_array)
        .filter(|items| !items.is_empty())
    else {
        return overrides;
    };
    let resolved_allow = |item: &Value| {
        item.as_object().is_some_and(|item| {
            item.get("status").and_then(Value::as_str) == Some("resolved")
                && item.get("resolution_action").and_then(Value::as_str) == Some("allow")
        })
    };
    if !raw.iter().all(resolved_allow) {
        return Map::new();
    }
    for item in raw.iter().filter_map(Value::as_object) {
        match valid_override(item.get("artifact_id"), item.get("artifact_hash")) {
            Some((id, token)) => overrides.insert(id, Value::String(token)),
            None => return Map::new(),
        };
    }
    overrides
}

fn interactive_overrides(artifacts: Option<&Value>) -> (Map<String, Value>, Map<String, Value>) {
    let mut overrides = Map::new();
    let mut labels = Map::new();
    for item in artifacts
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_object)
    {
        if item.get("policy_action").and_then(Value::as_str) != Some("allow") {
            continue;
        }
        let Some(label) = item
            .get("user_override")
            .and_then(Value::as_str)
            .filter(|label| INTERACTIVE_ALLOW_LABELS.contains(label))
        else {
            continue;
        };
        let Some((id, token)) =
            valid_override(item.get("artifact_id"), item.get("approval_context_hash"))
        else {
            continue;
        };
        labels.insert(id.clone(), Value::String(label.to_owned()));
        overrides.insert(id, Value::String(token));
    }
    (overrides, labels)
}

pub(crate) fn request_overrides(args: &Value) -> KindResult {
    let args = args_object(args)?;
    let (overrides, labels) = match args.get("mode").and_then(Value::as_str) {
        Some("exact") => {
            let overrides = exact_overrides(args.get("approval_wait"));
            let labels = overrides
                .keys()
                .map(|id| (id.clone(), json!("approval-center")))
                .collect();
            (overrides, labels)
        }
        Some("interactive") => interactive_overrides(args.get("artifacts")),
        _ => return Err(ERR_INVALID),
    };
    Ok(json!({"overrides": overrides, "labels": labels}))
}

/// `_saved_decision_is_retained`: does a successful claim leave the row?
fn decision_is_retained(decision: &Map<String, Value>) -> bool {
    if non_empty_str(decision.get("approval_id")).is_some() {
        return decision
            .get("artifact_id")
            .and_then(Value::as_str)
            .is_some_and(|id| id.contains(":package-request:"));
    }
    if matches!(decision.get("decision_id"), Some(Value::Number(n)) if n.is_i64() || n.is_u64()) {
        let gate = decision.get("source").and_then(Value::as_str) == Some("approval-gate");
        let expires = !matches!(decision.get("expires_at"), None | Some(Value::Null));
        return !(gate && expires);
    }
    // Unknown claim identities are classified as retained: absence may not be
    // treated as proof of consumption.
    true
}

pub(crate) fn claim_partition(args: &Value) -> KindResult {
    let pending = args_object(args)?
        .get("pending")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?;
    let (mut consumed, mut retained, mut qualifications) = (Map::new(), Map::new(), Map::new());
    for entry in pending {
        let entry = entry.as_object().ok_or(ERR_INVALID)?;
        let artifact_id = entry
            .get("artifact_id")
            .and_then(Value::as_str)
            .ok_or(ERR_INVALID)?;
        let token = entry.get("artifact_hash").cloned().unwrap_or(Value::Null);
        let decision = entry
            .get("decision")
            .and_then(Value::as_object)
            .ok_or(ERR_INVALID)?;
        let target = if decision_is_retained(decision) {
            &mut retained
        } else {
            &mut consumed
        };
        target.insert(artifact_id.to_owned(), token);
        qualifications.insert(
            artifact_id.to_owned(),
            json!({
                "fresh_local_approval": decision.get("fresh_local_approval") == Some(&Value::Bool(true)),
                "durable_exact_approval": decision.get("durable_exact_approval") == Some(&Value::Bool(true)),
            }),
        );
    }
    Ok(json!({"consumed": consumed, "retained": retained, "qualifications": qualifications}))
}
