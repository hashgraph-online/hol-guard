//! Strict validation and projection of a Rust hook decision receipt for the
//! opt-in binding capture. Mirrors the rules the Python receipt validator
//! applies to the same JSON values, so a sealed row only ever carries a
//! receipt that independently re-derives its own decision id.

use sha2::{Digest, Sha256};

use crate::binding_capture_crypto::is_lower_hex;
use crate::binding_capture_json::{self as json, Json};

const SCHEMA: &str = "guard-native-hook-decision-receipt.v1";
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const BINDING_SCHEMA: &str = "guard.native-command-receipt-binding.v1";
const MAX_OBSERVATIONS: u64 = 2_048;
const ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
const MODEL_ACTIONS: [&str; 4] = [
    "allow_original",
    "replace_with_reviewed_excerpt",
    "block",
    "not_applicable",
];
const PAYLOAD_KINDS: [&str; 3] = ["inline", "source_file_ref", "encrypted_payload_ref"];
const PROMPT_RISK_CLASSES: [&str; 7] = [
    "local_env_read",
    "sensitive_material",
    "exfil_intent",
    "destructive_intent",
    "subprocess_intent",
    "guard_bypass_intent",
    "prompt_injection_intent",
];
const OPTIONAL_FIELDS: [&str; 5] = [
    "command_extensions",
    "origin_authentication",
    "execution_intent_digest",
    "prompt_risk_classes",
    "business_review_binding",
];
/// Required fields in the order a captured projection retains them.
const REQUIRED_FIELDS: [&str; 23] = [
    "schema",
    "version",
    "authority",
    "decision_id",
    "request_id",
    "request_digest",
    "harness",
    "event_name",
    "payload_kind",
    "policy_generation",
    "policy_digest",
    "rule_digest",
    "runtime_identity",
    "decision",
    "model_output_action",
    "policy_action",
    "observed_policy_action",
    "reason_code",
    "workspace_bound",
    "source_ref_external_allowed",
    "reviewed_output_sha256",
    "observe_mode",
    "deadline_budget_ms",
];
const BINDING_FIELDS: [&str; 10] = [
    "schema",
    "program_digest",
    "catalog_digest",
    "trust_digest",
    "control_revision",
    "managed_control_revision",
    "control_effective_digest",
    "observations_digest",
    "observation_count",
    "uncertainty_count",
];

fn bounded_identifier(value: Option<&Json>, first_extra: &[char], rest_max: usize) -> Option<()> {
    let text = value?.as_str()?;
    let mut chars = text.chars();
    let head = chars.next()?;
    let rest: Vec<char> = chars.collect();
    let valid = (head.is_ascii_lowercase() || head.is_ascii_digit())
        && rest.len() <= rest_max
        && rest
            .iter()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || first_extra.contains(c));
    valid.then_some(())
}

fn hex64(value: Option<&Json>) -> bool {
    value
        .and_then(Json::as_str)
        .is_some_and(|text| is_lower_hex(text, 64))
}

fn optional_digest(value: Option<&Json>) -> bool {
    matches!(value, Some(Json::Null)) || hex64(value)
}

fn bounded_count(value: Option<&Json>, maximum: u64) -> bool {
    matches!(value, Some(Json::Int(text)) if text.parse::<u64>().is_ok_and(|n| n <= maximum))
}

fn valid_command_binding(value: &Json) -> bool {
    let mut keys = value.keys();
    keys.sort_unstable();
    let mut expected = BINDING_FIELDS.to_vec();
    expected.sort_unstable();
    keys == expected
        && value.get("schema").and_then(Json::as_str) == Some(BINDING_SCHEMA)
        && [
            "program_digest",
            "catalog_digest",
            "trust_digest",
            "control_effective_digest",
            "observations_digest",
        ]
        .iter()
        .all(|key| hex64(value.get(key)))
        && bounded_count(value.get("control_revision"), u64::MAX)
        && bounded_count(value.get("managed_control_revision"), u64::MAX)
        && bounded_count(value.get("observation_count"), MAX_OBSERVATIONS)
        && bounded_count(value.get("uncertainty_count"), MAX_OBSERVATIONS + 1)
}

fn valid_prompt_risk_classes(value: &Json) -> bool {
    let Json::Arr(items) = value else {
        return false;
    };
    if items.is_empty() || items.len() > 6 {
        return false;
    }
    let mut previous: Option<usize> = None;
    for item in items {
        let Some(index) = item
            .as_str()
            .and_then(|name| PROMPT_RISK_CLASSES.iter().position(|c| *c == name))
        else {
            return false;
        };
        if previous.is_some_and(|last| index <= last) {
            return false;
        }
        previous = Some(index);
    }
    true
}

/// Python's `value != 1` is false for `1`, `1.0` and `True`.
fn equals_one(value: Option<&Json>) -> bool {
    match value {
        Some(Json::Int(text)) => text == "1",
        Some(Json::Float(number)) => *number == 1.0,
        Some(Json::Bool(flag)) => *flag,
        _ => false,
    }
}

fn str_in(value: Option<&Json>, allowed: &[&str]) -> bool {
    value
        .and_then(Json::as_str)
        .is_some_and(|text| allowed.contains(&text))
}

fn optional_action(value: Option<&Json>) -> bool {
    matches!(value, Some(Json::Null)) || str_in(value, &ACTIONS)
}

fn identity_digest(receipt: &Json) -> Option<String> {
    let mut entries: Vec<(&str, Json)> = vec![
        (
            "schema",
            Json::Str("guard-native-hook-decision-identity.v1".to_owned()),
        ),
        ("version", Json::int(1)),
    ];
    for field in [
        "request_id",
        "request_digest",
        "harness",
        "event_name",
        "payload_kind",
        "policy_generation",
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "decision",
        "model_output_action",
        "policy_action",
        "observed_policy_action",
        "reason_code",
        "workspace_bound",
        "source_ref_external_allowed",
        "reviewed_output_sha256",
        "observe_mode",
        "deadline_budget_ms",
        "command_extensions",
        "prompt_risk_classes",
        "business_review_binding",
    ] {
        if let Some(value) = receipt.get(field) {
            entries.push((field, value.clone()));
        }
    }
    Some(hex::encode(Sha256::digest(json::encode(&Json::object(
        entries,
    )))))
}

fn valid_identity(receipt: &Json) -> bool {
    let event = receipt.get("event_name").and_then(Json::as_str);
    let generation = match receipt.get("policy_generation") {
        Some(Json::Int(text)) => text.parse::<i64>().is_ok_and(|n| n > 0),
        _ => false,
    };
    receipt.get("schema").and_then(Json::as_str) == Some(SCHEMA)
        && equals_one(receipt.get("version"))
        && receipt.get("authority").and_then(Json::as_str) == Some("rust")
        && hex64(receipt.get("decision_id"))
        && bounded_identifier(receipt.get("request_id"), &['_', '.', ':', '-'], 255).is_some()
        && hex64(receipt.get("request_digest"))
        && bounded_identifier(receipt.get("harness"), &['-'], 63).is_some()
        && matches!(
            event,
            Some("PreToolUse" | "PostToolUse" | "UserPromptSubmit")
        )
        && str_in(receipt.get("payload_kind"), &PAYLOAD_KINDS)
        && !(event == Some("UserPromptSubmit")
            && receipt.get("payload_kind").and_then(Json::as_str) != Some("inline"))
        && generation
}

fn valid_policy(receipt: &Json) -> bool {
    let prompt = receipt.get("event_name").and_then(Json::as_str) == Some("UserPromptSubmit");
    [
        "policy_digest",
        "rule_digest",
        "runtime_identity",
        "reviewed_output_sha256",
    ]
    .iter()
    .all(|key| optional_digest(receipt.get(key)))
        && str_in(receipt.get("decision"), &["allow", "deny"])
        && str_in(receipt.get("model_output_action"), &MODEL_ACTIONS)
        && !(prompt
            && receipt.get("model_output_action").and_then(Json::as_str) != Some("not_applicable"))
        && receipt
            .get("prompt_risk_classes")
            .is_none_or(|classes| prompt && valid_prompt_risk_classes(classes))
        && optional_action(receipt.get("policy_action"))
        && optional_action(receipt.get("observed_policy_action"))
        && bounded_identifier(receipt.get("reason_code"), &['_', '.', ':', '-'], 127).is_some()
        && [
            "origin_authentication",
            "execution_intent_digest",
            "business_review_binding",
        ]
        .iter()
        .all(|key| receipt.get(key).is_none() || hex64(receipt.get(key)))
}

fn valid_limits(receipt: &Json) -> bool {
    let budget_ok = match receipt.get("deadline_budget_ms") {
        Some(Json::Null) => true,
        Some(Json::Int(text)) => text.parse::<i64>().is_ok_and(|n| (1..=9_000).contains(&n)),
        _ => false,
    };
    [
        "workspace_bound",
        "source_ref_external_allowed",
        "observe_mode",
    ]
    .iter()
    .all(|key| matches!(receipt.get(key), Some(Json::Bool(_))))
        && budget_ok
        && json::encode(receipt).len() <= MAX_RECEIPT_BYTES
}

/// Validate one receipt and return the unchanged projection a capture retains.
pub(crate) fn receipt_projection(receipt: &Json) -> Option<Json> {
    let Json::Obj(entries) = receipt else {
        return None;
    };
    if !REQUIRED_FIELDS
        .iter()
        .all(|field| receipt.get(field).is_some())
        || !entries.iter().all(|(key, _)| {
            REQUIRED_FIELDS.contains(&key.as_str()) || OPTIONAL_FIELDS.contains(&key.as_str())
        })
    {
        return None;
    }
    if receipt
        .get("command_extensions")
        .is_some_and(|value| !valid_command_binding(value))
        || !valid_identity(receipt)
        || !valid_policy(receipt)
        || !valid_limits(receipt)
    {
        return None;
    }
    let decision_id = receipt.get("decision_id").and_then(Json::as_str)?;
    if identity_digest(receipt)? != decision_id {
        return None;
    }
    let mut projection: Vec<(String, Json)> = REQUIRED_FIELDS
        .iter()
        .filter_map(|field| receipt.get(field).map(|v| ((*field).to_owned(), v.clone())))
        .collect();
    for field in [
        "command_extensions",
        "prompt_risk_classes",
        "business_review_binding",
    ] {
        if let Some(value) = receipt.get(field) {
            projection.push((field.to_owned(), value.clone()));
        }
    }
    Some(Json::Obj(projection))
}
