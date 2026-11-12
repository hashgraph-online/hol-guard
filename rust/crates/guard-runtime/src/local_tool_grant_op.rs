//! `LocalToolGrant` — what a trusted-local-tool grant is allowed to be.
//!
//! Eligibility answers whether a command may carry a reusable grant at all.
//! This op answers the rest: which targets and durations the approval card may
//! offer for that evidence, and, for one pick, the selector the grant is filed
//! under, when it expires and the policy row that records it.
//!
//! The evidence arrives as the approval request filed it, so it is untrusted:
//! anything that is not an eligible trusted-local-tool entry answers "no
//! grant" rather than failing. A pick that names a target or duration the
//! evidence does not allow is refused by code; nothing here widens a grant to
//! fit the pick.

use guard_contracts::{
    LocalToolGrantRequestV1, LocalToolGrantResultV1, LocalToolGrantSelectionRequestV1,
    LOCAL_TOOL_GRANT_REQUEST_SCHEMA, LOCAL_TOOL_GRANT_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

/// `LOCAL_TOOL_GRANT_TARGETS`, narrowest first: the capability grant covers
/// one capability of the tool, the version grant the whole verified build. The
/// read side probes them in this order.
pub(crate) const TARGETS: [&str; 2] = ["capability", "version"];
/// `_SELECTOR_PREFIX`.
pub(crate) const SELECTOR_PREFIX: &str = "local-tool-grant:v1";
/// `_POLICY_SOURCE` — the only source whose row counts as a grant.
pub(crate) const POLICY_SOURCE: &str = "trusted-local-tool";
/// `LOCAL_TOOL_GRANT_DURATIONS`, in the order the card offers them.
const DURATIONS: [&str; 5] = ["15m", "1h", "5h", "version", "always"];
/// `_DURATION_SECONDS`. The two open-ended durations have no entry: they never
/// expire.
const DURATION_SECONDS: [(&str, i64); 3] = [("15m", 900), ("1h", 3600), ("5h", 18000)];
/// `_HARD_RISK_EXCLUSIONS` — the shapes no grant ever covers, carried on the
/// card so the surface can say so.
const HARD_RISK_EXCLUSIONS: [&str; 7] = [
    "shell_chaining",
    "shell_redirection",
    "embedded_execution",
    "environment_override",
    "unresolved_entrypoint",
    "mutating_capability",
    "untrusted_output_processor",
];
const VERIFIED_FILES: &str = "verified-files";
const PACKAGE_PROFILE: &str = "package-profile";

/// One eligible trusted-local-tool entry of an approval request's evidence.
struct Eligibility {
    tool_name: String,
    tool_identity_hash: String,
    capability: String,
    read_only_reason: String,
    trust_basis: String,
    indefinite_allowed: bool,
}

pub(crate) fn evaluate_local_tool_grant_request(
    request: &LocalToolGrantRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest(request)?;
    if request.schema != LOCAL_TOOL_GRANT_REQUEST_SCHEMA {
        return Err("native_local_tool_grant_schema_mismatch".to_owned());
    }
    let eligibility = eligibility(&request.scanner_evidence);
    let approval = eligibility.as_ref().map_or(Value::Null, approval_payload);
    let (selection, refusal) = match (&eligibility, &request.selection) {
        (_, None) => (Value::Null, Value::Null),
        (None, Some(_)) => (
            Value::Null,
            Value::String("local_tool_approval_ineligible".to_owned()),
        ),
        (Some(found), Some(pick)) => match select(found, pick) {
            Ok(selection) => (selection, Value::Null),
            Err(code) => (Value::Null, Value::String(code.to_owned())),
        },
    };
    crate::resident_protocol::encode_response(&LocalToolGrantResultV1 {
        schema: LOCAL_TOOL_GRANT_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: "ok".to_owned(),
        code: "ok".to_owned(),
        payload: json!({
            "approval": approval,
            "selection": selection,
            "refusal": refusal,
        }),
    })
}

fn request_digest(request: &LocalToolGrantRequestV1) -> Result<String, String> {
    let material = serde_json::to_value(request)
        .map_err(|_| "native_local_tool_grant_request_invalid".to_owned())?;
    let mut bytes = Vec::new();
    crate::context_digest_json::write_canonical_json_with_limit(&material, &mut bytes, usize::MAX)
        .map_err(|_| "native_local_tool_grant_request_invalid".to_owned())?;
    Ok(format!(
        "sha256:{}",
        guard_policy_snapshot::digest_bytes(&bytes)
    ))
}

/// The first eligible trusted-local-tool entry of the filed evidence. An entry
/// of that source that fails a field check does not end the search: the list
/// is read to the end, as `_eligibility_from_request` reads it.
fn eligibility(scanner_evidence: &Value) -> Option<Eligibility> {
    for item in scanner_evidence.as_array()? {
        let Some(entry) = item.as_object() else {
            continue;
        };
        if entry.get("source").and_then(Value::as_str) != Some("trusted_local_tool") {
            continue;
        }
        let trust_basis = match entry.get("trust_basis") {
            None => VERIFIED_FILES,
            Some(Value::String(text)) if text == VERIFIED_FILES || text == PACKAGE_PROFILE => text,
            Some(_) => continue,
        };
        let (Some(tool_name), Some(tool_identity_hash), Some(capability), Some(read_only_reason)) = (
            nonempty(entry.get("tool_name")),
            nonempty(entry.get("tool_identity_hash")),
            nonempty(entry.get("capability")),
            nonempty(entry.get("read_only_reason")),
        ) else {
            continue;
        };
        if entry.get("eligible") != Some(&Value::Bool(true)) || !is_sha256(&tool_identity_hash) {
            continue;
        }
        return Some(Eligibility {
            tool_name,
            tool_identity_hash,
            capability,
            read_only_reason,
            trust_basis: trust_basis.to_owned(),
            // Truthiness, as `bool(...)` reads it: the field is advisory and a
            // non-boolean does not disqualify the entry.
            indefinite_allowed: truthy(entry.get("indefinite_allowed")),
        });
    }
    None
}

/// `LocalToolApprovalEligibility.to_payload` — the card's evidence plus what
/// it may offer. An indefinite grant is a package-profile tool's alone, and
/// the whole-version target is never a package profile's.
fn approval_payload(found: &Eligibility) -> Value {
    let package_profile = found.trust_basis == PACKAGE_PROFILE;
    let mut durations: Vec<&str> = if package_profile {
        vec!["15m", "1h", "5h"]
    } else {
        DURATIONS[..DURATIONS.len() - 1].to_vec()
    };
    if package_profile && found.indefinite_allowed {
        durations.push("always");
    }
    let targets: Vec<&str> = if package_profile {
        vec!["capability"]
    } else {
        TARGETS.to_vec()
    };
    json!({
        "source": "trusted_local_tool",
        "version": 1,
        "eligible": true,
        "tool_name": found.tool_name,
        "tool_identity_hash": found.tool_identity_hash,
        "capability": found.capability,
        "read_only_reason": found.read_only_reason,
        "trust_basis": found.trust_basis,
        "indefinite_allowed": found.indefinite_allowed,
        "allowed_targets": targets,
        "allowed_durations": std::iter::once("once").chain(durations).collect::<Vec<&str>>(),
        "hard_risk_exclusions": HARD_RISK_EXCLUSIONS,
    })
}

/// `parse_local_tool_grant_selection` and `local_tool_grant_decision` in one
/// answer: the pick, the moment it runs out and the policy row that records
/// it. A pick the evidence does not allow is refused by code.
fn select(
    found: &Eligibility,
    pick: &LocalToolGrantSelectionRequestV1,
) -> Result<Value, &'static str> {
    let payload = approval_payload(found);
    let target = pick.target.as_str().unwrap_or_default();
    let duration = pick.duration.as_str().unwrap_or_default();
    if !TARGETS.contains(&target) || !offers(&payload, "allowed_targets", target) {
        return Err("invalid_local_tool_grant_target");
    }
    if !DURATIONS.contains(&duration) || !offers(&payload, "allowed_durations", duration) {
        return Err("invalid_local_tool_grant_duration");
    }
    let expires_at = match DURATION_SECONDS
        .iter()
        .find_map(|(name, seconds)| (*name == duration).then_some(*seconds))
    {
        None => Value::Null,
        Some(seconds) => Value::String(
            crate::guard_store_json::add_seconds_utc_isoformat(&pick.now, seconds * 1_000_000)
                .ok_or("invalid_local_tool_grant_timestamp")?,
        ),
    };
    Ok(json!({
        "target": target,
        "duration": duration,
        "expires_at": expires_at.clone(),
        "decision": {
            "harness": pick.harness,
            "scope": "artifact",
            "action": "allow",
            "artifact_id": selector(&found.tool_identity_hash, &found.capability, target),
            "reason": pick.reason,
            "source": POLICY_SOURCE,
            "expires_at": expires_at,
        },
    }))
}

/// Whether the card offers `wanted` under `field`.
fn offers(payload: &Value, field: &str, wanted: &str) -> bool {
    payload[field]
        .as_array()
        .is_some_and(|offered| offered.iter().any(|value| value.as_str() == Some(wanted)))
}

/// `local_tool_grant_selector` — the artifact id a grant for `target` is filed
/// under. The version target is capability-independent, which Python spells as
/// the digest of `*`.
pub(crate) fn selector(tool_identity_hash: &str, capability: &str, target: &str) -> String {
    let subject = if target == "capability" {
        capability
    } else {
        "*"
    };
    let digest = hex::encode(Sha256::digest(subject.as_bytes()));
    format!("{SELECTOR_PREFIX}:{tool_identity_hash}:{target}:{digest}")
}

/// `_nonempty_string`.
fn nonempty(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    (!text.is_empty()).then(|| text.to_owned())
}

/// `_is_sha256`.
fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// `bool(value)` for the JSON a filed evidence entry can hold.
fn truthy(value: Option<&Value>) -> bool {
    match value {
        None | Some(Value::Null) => false,
        Some(Value::Bool(flag)) => *flag,
        Some(Value::Number(number)) => number.as_f64().is_some_and(|value| value != 0.0),
        Some(Value::String(text)) => !text.is_empty(),
        Some(Value::Array(items)) => !items.is_empty(),
        Some(Value::Object(fields)) => !fields.is_empty(),
    }
}

#[cfg(test)]
#[path = "local_tool_grant_op_tests.rs"]
mod tests;
