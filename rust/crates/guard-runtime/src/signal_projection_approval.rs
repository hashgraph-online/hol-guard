//! Canonical approval projections are computed by the native owner.
use crate::signal_projection_decode::{decode_v2, python_trim};
use guard_command::decisions::{self, GuardDecisionV2};
use guard_contracts::{
    is_action_bearing_key, normalize_guard_action_result, GuardAction, RiskSignalV2,
};
use serde_json::{json, Map, Value};

pub(crate) const INCONSISTENT: &str = "authoritative_decision_inconsistent";
const DEGRADED: &str = "remembered_rule_ignored_degraded_trust";

pub(crate) fn normalize(value: &Value) -> (GuardAction, bool) {
    let normalized = normalize_guard_action_result(value, GuardAction::RequireReapproval);
    (normalized.action, normalized.recognized())
}

pub(crate) fn unknown_fields(p: Option<&Map<String, Value>>, allowed: &[&str]) -> Vec<String> {
    p.map(|p| {
        p.keys()
            .filter(|key| is_action_bearing_key(key) && !allowed.contains(&key.as_str()))
            .cloned()
            .collect()
    })
    .unwrap_or_default()
}

pub(crate) fn strongest(actions: &[GuardAction]) -> GuardAction {
    actions
        .iter()
        .copied()
        .max_by_key(|action| action.severity())
        .unwrap_or(GuardAction::RequireReapproval)
}

fn product(action: GuardAction) -> &'static str {
    match action {
        GuardAction::Allow => "allow",
        GuardAction::Warn => "warn",
        GuardAction::Block => "block",
        _ => "ask",
    }
}

fn validated_signals(p: Option<&Map<String, Value>>) -> Vec<RiskSignalV2> {
    let Some(signals) = p.and_then(|p| p.get("signals")).and_then(Value::as_array) else {
        return Vec::new();
    };
    signals.iter().enumerate().filter_map(|(index, raw)| {
        let raw = raw.as_object()?;
        let mut payload = json!({"signal_id":format!("approval-signal:{index}"),"category":"policy","severity":"info",
            "confidence":"likely","detector":"guard.approval-boundary","title":"Guard risk signal",
            "plain_reason":"HOL Guard recorded a risk signal for this approval.","technical_detail":null,
            "evidence_ref":null,"redaction_level":"summary","false_positive_hint":null,"advisory_id":null});
        payload.as_object_mut().unwrap().extend(raw.clone());
        decode_v2(&payload).ok()
    }).collect()
}

fn degraded_detail(
    raw: Option<&Map<String, Value>>,
    canonical: &Value,
    action: GuardAction,
) -> bool {
    let Some(raw) = raw else { return false };
    if raw.get("detail_reason_code").and_then(Value::as_str) != Some(DEGRADED)
        || !matches!(action, GuardAction::Review | GuardAction::RequireReapproval)
    {
        return false;
    }
    let Ok(parsed) = GuardDecisionV2::decode(&Value::Object(raw.clone())) else {
        return false;
    };
    if parsed.guard_action != action {
        return false;
    }
    for (key, expected) in canonical.as_object().unwrap() {
        if ![
            "user_title",
            "user_body",
            "harness_message",
            "dashboard_primary_detail",
        ]
        .contains(&key.as_str())
            && raw.get(key) != Some(expected)
        {
            return false;
        }
    }
    let Some(message) = raw.get("harness_message").and_then(Value::as_str) else {
        return false;
    };
    raw.get("dashboard_primary_detail").and_then(Value::as_str) == Some(message)
        && message.chars().count() <= 2000
        && message.contains("remembered local rule was ignored")
        && message.contains("One-time approvals still work")
}

pub(crate) fn approval(action: &Value, decision: &Value, reject: bool) -> Result<Value, String> {
    let (normalized, recognized) = normalize(action);
    let raw = decision.as_object();
    let get = |key| raw.and_then(|p| p.get(key)).unwrap_or(&Value::Null);
    let invalid_payload = !decision.is_null() && raw.is_none();
    let hidden = unknown_fields(raw, &["action", "guard_action"]);
    let guard = if get("guard_action").is_null() {
        None
    } else {
        Some(normalize(get("guard_action")))
    };
    let invalid_guard = guard.is_some_and(|(_, recognized)| !recognized);
    let contradictory_guard =
        guard.is_some_and(|(action, recognized)| recognized && action != normalized);
    let product_action = get("action");
    let known_product = product_action
        .as_str()
        .is_some_and(|value| ["allow", "warn", "ask", "block"].contains(&value));
    let invalid_product = !product_action.is_null() && !known_product;
    let contradictory_product =
        known_product && product_action.as_str() != Some(product(normalized));
    if reject
        && (invalid_payload
            || invalid_guard
            || contradictory_guard
            || invalid_product
            || contradictory_product
            || !hidden.is_empty())
    {
        return Err(INCONSISTENT.into());
    }
    let mut error = !recognized;
    let mut projected = normalized;
    if invalid_payload || invalid_guard || invalid_product || !hidden.is_empty() {
        error = true;
        let mut candidates = vec![projected, GuardAction::RequireReapproval];
        candidates.extend(hidden.iter().map(|key| normalize(get(key)).0));
        projected = strongest(&candidates);
    } else if contradictory_guard || contradictory_product {
        error = true;
        let floor = match product_action.as_str() {
            Some("allow") => GuardAction::Allow,
            Some("warn") => GuardAction::Warn,
            Some("block") => GuardAction::Block,
            _ => GuardAction::RequireReapproval,
        };
        projected = strongest(&[
            projected,
            guard
                .map(|(action, _)| action)
                .unwrap_or(GuardAction::RequireReapproval),
            floor,
        ]);
    }
    let reason = if error {
        "Stored approval decision fields were inconsistent; HOL Guard failed closed."
    } else {
        get("reason")
            .as_str()
            .filter(|value| !python_trim(value).is_empty())
            .unwrap_or(projected.as_str())
    };
    let mut canonical =
        decisions::decision_from_legacy_policy_action(projected, reason, &validated_signals(raw))
            .to_value();
    if degraded_detail(raw, &canonical, projected) {
        canonical["harness_message"] = get("harness_message").clone();
        canonical["dashboard_primary_detail"] = get("dashboard_primary_detail").clone();
        canonical["detail_reason_code"] = json!(DEGRADED);
    }
    if get("policyVersion")
        .as_str()
        .is_some_and(|value| !python_trim(value).is_empty())
    {
        canonical["policyVersion"] = get("policyVersion").clone();
    }
    if get("package_review_cloud_reason_code")
        .as_str()
        .is_some_and(|value| {
            [
                "cloud_auth_error",
                "cloud_http_error",
                "cloud_timeout",
                "cloud_validation_error",
            ]
            .contains(&value)
        })
    {
        canonical["package_review_cloud_reason_code"] =
            get("package_review_cloud_reason_code").clone();
    }
    Ok(
        json!({"policy_action":projected.as_str(),"decision_v2_json":canonical,"contract_error":if error {Some(INCONSISTENT)} else {None}}),
    )
}

#[cfg(test)]
mod tests {
    use super::normalize;
    use guard_contracts::GuardAction;
    use serde_json::json;

    #[test]
    fn canonical_block_is_recognized_and_unknown_falls_back() {
        let (action, recognized) = normalize(&json!("block"));
        assert_eq!(action, GuardAction::Block);
        assert!(recognized);

        let (action, recognized) = normalize(&json!("ask"));
        assert_eq!(action, GuardAction::Review);
        assert!(recognized);

        let (action, recognized) = normalize(&json!("not-an-action"));
        assert_eq!(action, GuardAction::RequireReapproval);
        assert!(!recognized);
    }
}
