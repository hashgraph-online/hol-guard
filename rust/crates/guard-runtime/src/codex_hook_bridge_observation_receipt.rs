//! `validate_native_decision_receipt` in `native_decision_receipt.py`, on
//! the receipt a daemon answer carries as Python's `json.loads` parsed it:
//! the exact field set, each field's type and bounds, the encoded size, and
//! the decision id that must be the SHA-256 of the receipt's identity.

use sha2::{Digest, Sha256};

use crate::hook_env_stamp::dumps;
use crate::pyjson::PyVal;

const SCHEMA: &str = "guard-native-hook-decision-receipt.v1";
const IDENTITY_SCHEMA: &str = "guard-native-hook-decision-identity.v1";
const BINDING_SCHEMA: &str = "guard.native-command-receipt-binding.v1";
const MAX_BYTES: usize = 16 * 1024;
const MAX_OBSERVATIONS: i128 = 2_048;

const REQUIRED: [&str; 23] = [
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
const OPTIONAL: [&str; 5] = [
    "command_extensions",
    "origin_authentication",
    "execution_intent_digest",
    "prompt_risk_classes",
    "business_review_binding",
];
/// The receipt fields `_identity_payload` copies, besides its own schema
/// and version and the optional fields it copies only when present.
const IDENTITY: [&str; 19] = [
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
const IDENTITY_OPTIONAL: [&str; 3] = [
    "command_extensions",
    "prompt_risk_classes",
    "business_review_binding",
];
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
const EVENTS: [&str; 3] = ["PreToolUse", "PostToolUse", "UserPromptSubmit"];
const PROMPT_RISK_CLASSES: [&str; 7] = [
    "local_env_read",
    "sensitive_material",
    "exfil_intent",
    "destructive_intent",
    "subprocess_intent",
    "guard_bypass_intent",
    "prompt_injection_intent",
];
const BINDING_DIGESTS: [&str; 5] = [
    "program_digest",
    "catalog_digest",
    "trust_digest",
    "control_effective_digest",
    "observations_digest",
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

fn hex64(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

/// `_bounded_identifier`: `^[a-z0-9][<rest>]*$` and at most `maximum`
/// characters (the tighter of the pattern's and the caller's bound), where
/// `dotted` adds `_.:` to the lowercase alphanumerics and hyphen the rest
/// may hold.
fn identifier(text: &str, dotted: bool, maximum: usize) -> bool {
    let mut bytes = text.bytes();
    let first_ok = bytes
        .next()
        .is_some_and(|b| b.is_ascii_lowercase() || b.is_ascii_digit());
    first_ok
        && text.len() <= maximum
        && bytes.all(|b| {
            b.is_ascii_lowercase()
                || b.is_ascii_digit()
                || b == b'-'
                || (dotted && matches!(b, b'_' | b'.' | b':'))
        })
}

fn string(value: &PyVal) -> Option<&str> {
    value.as_str()
}

/// `type(value) is int and minimum <= value <= maximum`.
fn integer(value: &PyVal, minimum: i128, maximum: i128) -> bool {
    match value {
        PyVal::Int(digits) => digits
            .parse::<i128>()
            .is_ok_and(|number| (minimum..=maximum).contains(&number)),
        _ => false,
    }
}

fn one_of(value: &PyVal, allowed: &[&str]) -> bool {
    string(value).is_some_and(|text| allowed.contains(&text))
}

/// Python's `value == 1` for a parsed JSON value.
fn equals_one(value: &PyVal) -> bool {
    match value {
        PyVal::Int(digits) => digits == "1",
        PyVal::Bool(flag) => *flag,
        PyVal::Float(number) => *number == 1.0,
        _ => false,
    }
}

/// `valid_native_command_receipt_binding`.
fn valid_binding(value: &PyVal) -> bool {
    let Some(entries) = value.as_dict() else {
        return false;
    };
    let field = |name: &str| value.get(name).unwrap_or(&PyVal::Null);
    entries.len() == BINDING_FIELDS.len()
        && entries
            .iter()
            .all(|(key, _)| BINDING_FIELDS.contains(&key.as_str()))
        && string(field("schema")) == Some(BINDING_SCHEMA)
        && BINDING_DIGESTS
            .iter()
            .all(|name| string(field(name)).is_some_and(hex64))
        && integer(field("control_revision"), 0, u64::MAX.into())
        && integer(field("managed_control_revision"), 0, u64::MAX.into())
        && integer(field("observation_count"), 0, MAX_OBSERVATIONS)
        && integer(field("uncertainty_count"), 0, MAX_OBSERVATIONS + 1)
}

/// `valid_prompt_risk_classes`: one to six known classes, each once, in
/// their declared order.
fn valid_prompt_risk_classes(value: &PyVal) -> bool {
    let Some(items) = value.as_list() else {
        return false;
    };
    if items.is_empty() || items.len() > 6 {
        return false;
    }
    let mut previous = None;
    for item in items {
        let Some(index) = string(item)
            .and_then(|text| PROMPT_RISK_CLASSES.iter().position(|class| *class == text))
        else {
            return false;
        };
        if previous.is_some_and(|before| before >= index) {
            return false;
        }
        previous = Some(index);
    }
    true
}

/// `receipt.get(name)`, or `None` when the receipt lacks the field.
fn at<'a>(receipt: &'a PyVal, name: &str) -> &'a PyVal {
    receipt.get(name).unwrap_or(&PyVal::Null)
}

/// `_validate_receipt_identity`.
fn valid_identity(receipt: &PyVal) -> bool {
    let event_name = string(at(receipt, "event_name"));
    let payload_kind = string(at(receipt, "payload_kind"));
    string(at(receipt, "schema")) == Some(SCHEMA)
        && equals_one(at(receipt, "version"))
        && string(at(receipt, "authority")) == Some("rust")
        && string(at(receipt, "decision_id")).is_some_and(hex64)
        && string(at(receipt, "request_id")).is_some_and(|text| identifier(text, true, 256))
        && string(at(receipt, "request_digest")).is_some_and(hex64)
        && string(at(receipt, "harness")).is_some_and(|text| identifier(text, false, 64))
        && event_name.is_some_and(|text| EVENTS.contains(&text))
        && payload_kind.is_some_and(|text| PAYLOAD_KINDS.contains(&text))
        && (event_name != Some("UserPromptSubmit") || payload_kind == Some("inline"))
        && integer(at(receipt, "policy_generation"), 1, i64::MAX.into())
}

/// `_validate_receipt_policy`.
fn valid_policy(receipt: &PyVal) -> bool {
    let prompt = string(at(receipt, "event_name")) == Some("UserPromptSubmit");
    let optional_digest = |name: &str| match at(receipt, name) {
        PyVal::Null => true,
        value => string(value).is_some_and(hex64),
    };
    let action = |name: &str| {
        matches!(at(receipt, name), PyVal::Null) || one_of(at(receipt, name), &ACTIONS)
    };
    ["policy_digest", "rule_digest", "runtime_identity", "reviewed_output_sha256"]
        .iter()
        .all(|name| optional_digest(name))
        && one_of(at(receipt, "decision"), &["allow", "deny"])
        && one_of(at(receipt, "model_output_action"), &MODEL_ACTIONS)
        && (!prompt || string(at(receipt, "model_output_action")) == Some("not_applicable"))
        && receipt
            .get("prompt_risk_classes")
            .is_none_or(|classes| prompt && valid_prompt_risk_classes(classes))
        && action("policy_action")
        && action("observed_policy_action")
        // `_IDENTIFIER` allows 128 characters, under the 512-byte string cap.
        && string(at(receipt, "reason_code")).is_some_and(|text| identifier(text, true, 128))
        && ["origin_authentication", "execution_intent_digest", "business_review_binding"]
            .iter()
            .all(|name| receipt.get(name).is_none_or(|value| string(value).is_some_and(hex64)))
}

/// `json.dumps(value, sort_keys=True, separators=(",", ":"), ...)`.
pub(super) fn dumps_sorted(value: &PyVal, ensure_ascii: bool) -> String {
    let mut out = String::new();
    dumps(&sorted(value), ensure_ascii, false, &mut out);
    out
}

fn sorted(value: &PyVal) -> PyVal {
    match value {
        PyVal::Dict(entries) => {
            let mut entries: Vec<(String, PyVal)> = entries
                .iter()
                .map(|(key, item)| (key.clone(), sorted(item)))
                .collect();
            entries.sort_by(|left, right| left.0.cmp(&right.0));
            PyVal::Dict(entries)
        }
        PyVal::List(items) => PyVal::List(items.iter().map(sorted).collect()),
        other => other.clone(),
    }
}

/// `_validate_receipt_limits`.
fn valid_limits(receipt: &PyVal) -> bool {
    [
        "workspace_bound",
        "source_ref_external_allowed",
        "observe_mode",
    ]
    .iter()
    .all(|name| matches!(at(receipt, name), PyVal::Bool(_)))
        && (matches!(at(receipt, "deadline_budget_ms"), PyVal::Null)
            || integer(at(receipt, "deadline_budget_ms"), 1, 9_000))
        && dumps_sorted(receipt, true).len() <= MAX_BYTES
}

/// `canonical_receipt_bytes`: the identity the decision id commits to.
fn canonical_identity(receipt: &PyVal) -> String {
    let mut identity = vec![
        ("schema".to_owned(), PyVal::Str(IDENTITY_SCHEMA.to_owned())),
        ("version".to_owned(), PyVal::Int("1".to_owned())),
    ];
    for name in IDENTITY {
        identity.push((name.to_owned(), at(receipt, name).clone()));
    }
    for name in IDENTITY_OPTIONAL {
        if let Some(value) = receipt.get(name) {
            identity.push((name.to_owned(), value.clone()));
        }
    }
    dumps_sorted(&PyVal::Dict(identity), false)
}

/// `validate_native_decision_receipt(value) is not None`.
pub(super) fn valid(receipt: &PyVal) -> bool {
    let Some(entries) = receipt.as_dict() else {
        return false;
    };
    if !REQUIRED.iter().all(|name| receipt.get(name).is_some())
        || !entries
            .iter()
            .all(|(key, _)| REQUIRED.contains(&key.as_str()) || OPTIONAL.contains(&key.as_str()))
    {
        return false;
    }
    if receipt
        .get("command_extensions")
        .is_some_and(|binding| !valid_binding(binding))
    {
        return false;
    }
    if !valid_identity(receipt) || !valid_policy(receipt) || !valid_limits(receipt) {
        return false;
    }
    let expected = hex::encode(Sha256::digest(canonical_identity(receipt).as_bytes()));
    string(at(receipt, "decision_id")) == Some(expected.as_str())
}
