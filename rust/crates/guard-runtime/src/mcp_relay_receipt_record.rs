//! Which queued relay records are plain: the record shape the relay writes
//! and the native decision's checks, as the Python drain's `_decode` and
//! `_validated_decision` read them.

use guard_contracts::{
    BrowserMcpArtifactV1, McpCallProjectionQueryV1, McpToolArgumentsV1, McpToolRiskInputV1,
};
use serde_json::{Map, Value};

const KIND: &str = "mcp_tool_call";
/// The harnesses whose MCP proxy the relay replaces.
const RELAY_HARNESSES: [&str; 6] = ["cline", "codex", "copilot", "cursor", "hermes", "opencode"];
pub(super) const RECORD_KEYS: [&str; 10] = [
    "kind",
    "harness",
    "outcome",
    "decision_source",
    "policy_action",
    "tool_name",
    "params",
    "arguments",
    "identity",
    "decision",
];
/// The post-claim check's evidence.
const APPEND_KEY: &str = "evidence_append";
/// The approval request an ask block was queued on, `_queued_approval`.
pub(super) const APPROVAL_KEY: &str = "approval";
const APPROVAL_KEYS: [&str; 5] = [
    "approval_center_url",
    "review_url",
    "request_id",
    "workspace",
    "notices",
];
/// An ask block's decision source.
pub(super) const APPROVAL_PENDING_SOURCE: &str = "approval-center-pending";
/// The inbox row a safe-alternative block adds, `_redaction_level`, and the
/// approval center origin the resident links it to.
const REVIEW_KEY: &str = "review";
const REVIEW_FIELDS: [&str; 2] = ["redaction_level", "approval_center_url"];
const REDACTION_LEVELS: [&str; 3] = ["full", "partial", "none"];
/// A safe-alternative block's decision source.
const SAFE_ALTERNATIVE_SOURCE: &str = "policy-safe-alternative";
/// `_needs_review`: the actions `queue_blocked_approvals` writes a row for.
const REVIEWABLE: [&str; 2] = ["review", "require-reapproval"];
/// The relay harness whose approval flow opens the approval center in the
/// browser (`approval-center` tier, `auto_open_browser`), which the daemon's
/// `_open_approval_center` still does for an ask block.
pub(super) const BROWSER_APPROVAL_HARNESS: &str = "cline";
const IDENTITY_KEYS: [&str; 4] = [
    "artifact",
    "runtime_private_metadata",
    "artifact_hash",
    "risk_categories",
];
const ARTIFACT_KEYS: [&str; 9] = [
    "artifact_id",
    "name",
    "harness",
    "source_scope",
    "config_path",
    "command",
    "transport",
    "publisher",
    "metadata",
];
const TOKEN_PREFIX: &str = "guard-approval-context:v1:";
/// The native decision's keys, `_validated_decision`'s `_PAYLOAD_KEYS`. A
/// decision naming a connector setup also writes the review row, which the
/// daemon does.
const DECISION_KEYS: [&str; 16] = [
    "action",
    "policy_action",
    "source",
    "signals",
    "summary",
    "risk_categories",
    "normalization_reason_code",
    "original_action",
    "approval_reuse_status",
    "approval_reuse_reason_code",
    "current_action",
    "saved_action",
    "pending_approval_reuse_decision",
    "approval_reuse_claim_disposition",
    "post_claim_revalidated",
    "post_claim_authority",
];
const GUARD_ACTIONS: [&str; 6] = [
    "allow",
    "warn",
    "review",
    "require-reapproval",
    "sandbox-required",
    "block",
];
pub(super) const FORWARD_ACTIONS: [&str; 2] = ["allow", "warn"];
/// A policy block, and the two refusals of the client's inline prompt.
const BLOCK_SOURCES: [&str; 3] = ["policy-block", "inline-denied", "inline-invalid"];
/// `_NON_EXECUTED_TOOL_CALL_TAXONOMY`: the event and provenance of a block.
const BLOCK_TAXONOMY: [(&str, &str, &str); 4] = [
    (
        "review",
        "runtime_tool_call_review_required",
        "runtime tool call awaiting review",
    ),
    (
        "require-reapproval",
        "runtime_tool_call_reapproval_required",
        "runtime tool call awaiting fresh approval",
    ),
    (
        "sandbox-required",
        "runtime_tool_call_sandbox_required",
        "runtime tool call requires an enforceable sandbox",
    ),
    (
        "block",
        "runtime_tool_call_blocked",
        "runtime tool call blocked",
    ),
];

/// The fields of a record the resident can write the receipt of.
pub(super) struct Plain<'a> {
    pub(super) harness: &'a str,
    pub(super) forward: bool,
    pub(super) source: &'a str,
    pub(super) policy_action: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) params: &'a Value,
    pub(super) artifact: &'a Map<String, Value>,
    pub(super) artifact_hash: &'a str,
    pub(super) firewall: &'a Value,
    pub(super) decision: &'a Map<String, Value>,
    pub(super) append: &'a [Value],
    /// An ask or safe-alternative block's risk input: the proxy projects a
    /// queued call with its artifact for the receipt's risk categories.
    pub(super) projected_risk: Option<McpToolRiskInputV1>,
    /// A safe-alternative block's redaction level and approval center
    /// origin, which its inbox row is written with.
    pub(super) review: Option<(&'a str, &'a str)>,
}

impl Plain<'_> {
    /// The call projected with its artifact when the proxy projects it so,
    /// and `Some(None)` when it does not.
    pub(super) fn projected(&self) -> Option<Option<Value>> {
        let Some(risk) = &self.projected_risk else {
            return Some(None);
        };
        crate::mcp_proxy_projection::call_projection(&McpCallProjectionQueryV1 {
            tool_name: self.tool_name.to_owned(),
            params: self.params.clone(),
            risk: Some(risk.clone()),
        })
        .ok()
        .map(Some)
    }

    /// The receipt's risk categories: the projected ones, else the
    /// decision's.
    pub(super) fn risk_categories(&self, projected: Option<&Value>) -> Option<Vec<String>> {
        let Some(projected) = projected else {
            return Some(strings(&self.decision["risk_categories"]));
        };
        let categories = projected.get("risk")?.get("risk_categories")?;
        string_list(categories).then(|| strings(categories))
    }

    /// The redaction level and center of the inbox row
    /// `queue_blocked_approvals` writes for this block, if it writes one.
    pub(super) fn silent_review(&self) -> Option<(&str, &str)> {
        self.review
            .filter(|_| REVIEWABLE.contains(&self.policy_action))
    }
}

pub(super) fn plain(record: &Value) -> Option<Plain<'_>> {
    let record = record.as_object()?;
    if !keys_fit(
        record,
        &RECORD_KEYS,
        &[APPEND_KEY, APPROVAL_KEY, REVIEW_KEY],
    ) {
        return None;
    }
    // An ask block whose desktop notice the resident raised; one still
    // carrying a notice is the daemon's to raise.
    let queued = match record.get(APPROVAL_KEY) {
        None => false,
        Some(approval) if approval_fits(approval) => true,
        Some(_) => return None,
    };
    // Only a safe-alternative block carries its inbox row, and it must; an
    // ask block's request answers the call instead.
    let review = match record.get(REVIEW_KEY) {
        None => None,
        Some(_) if queued => return None,
        Some(review) => Some(review_fields(review)?),
    };
    let reviewed = review.is_some();
    let append = match record.get(APPEND_KEY) {
        None => &[][..],
        Some(Value::Array(items)) if items.iter().all(Value::is_object) => items.as_slice(),
        Some(_) => return None,
    };
    let call = relayed(record, KIND)?;
    if queued && call.harness == BROWSER_APPROVAL_HARNESS {
        return None;
    }
    let forward = match call.outcome {
        "forward" if !queued && !reviewed && FORWARD_ACTIONS.contains(&call.policy_action) => true,
        "block"
            if block_taxonomy(call.policy_action).is_some()
                && block_source_fits(queued, reviewed, call.source) =>
        {
            false
        }
        _ => return None,
    };
    let artifact = call.artifact;
    // Without it the proxy enriches the artifact first, which the daemon does.
    let firewall = artifact["metadata"]
        .as_object()?
        .get("mcpSkillFirewall")
        .filter(|firewall| firewall.is_object())?;
    let projected_risk = if queued || reviewed {
        Some(risk_input(artifact, call.params, &record["arguments"])?)
    } else {
        None
    };
    Some(Plain {
        harness: call.harness,
        forward,
        source: call.source,
        policy_action: call.policy_action,
        tool_name: call.tool_name,
        params: call.params,
        artifact,
        artifact_hash: call.artifact_hash,
        firewall,
        decision: call.decision,
        append,
        projected_risk,
        review,
    })
}

/// The fields every relayed call's record carries, tool or package.
pub(super) struct Relayed<'a> {
    pub(super) harness: &'a str,
    pub(super) outcome: &'a str,
    pub(super) source: &'a str,
    pub(super) policy_action: &'a str,
    pub(super) tool_name: &'a str,
    pub(super) params: &'a Value,
    /// The tool call's own artifact, from its identity.
    pub(super) artifact: &'a Map<String, Value>,
    pub(super) artifact_hash: &'a str,
    pub(super) decision: &'a Map<String, Value>,
}

/// Whether `record` has every one of `keys` and nothing beyond `optional`.
pub(super) fn keys_fit(record: &Map<String, Value>, keys: &[&str], optional: &[&str]) -> bool {
    keys.iter().all(|key| record.contains_key(*key))
        && record
            .keys()
            .all(|key| keys.contains(&key.as_str()) || optional.contains(&key.as_str()))
}

/// The shared fields of a `kind` record, as `_decode`, `_decision` and
/// `_ordered_params` read them.
pub(super) fn relayed<'a>(record: &'a Map<String, Value>, kind: &str) -> Option<Relayed<'a>> {
    let text = |key: &str| record.get(key).and_then(Value::as_str);
    let harness = text("harness").filter(|harness| RELAY_HARNESSES.contains(harness))?;
    let outcome = text("outcome")?;
    let source = text("decision_source")?;
    let policy_action = text("policy_action")?;
    let tool_name = text("tool_name")?;
    let params = &record["params"];
    if text("kind") != Some(kind)
        || !params.is_object()
        || params.get("name").and_then(Value::as_str) != Some(tool_name)
    {
        return None;
    }
    let identity = exact_object(&record["identity"], &IDENTITY_KEYS)?;
    let artifact = exact_object(&identity["artifact"], &ARTIFACT_KEYS)?;
    let artifact_hash = identity["artifact_hash"]
        .as_str()
        .filter(|hash| hash.starts_with(TOKEN_PREFIX))?;
    if !identity["runtime_private_metadata"].is_object()
        || !string_list(&identity["risk_categories"])
        || artifact["harness"].as_str() != Some(harness)
        || ["artifact_id", "name", "source_scope", "config_path"]
            .iter()
            .any(|key| !artifact[*key].is_string())
        || ["command", "transport", "publisher"]
            .iter()
            .any(|key| !(artifact[*key].is_string() || artifact[*key].is_null()))
    {
        return None;
    }
    let decision = exact_object(&record["decision"], &DECISION_KEYS)?;
    if !decision_fits(decision) || !arguments_fit(params, &record["arguments"]) {
        return None;
    }
    Some(Relayed {
        harness,
        outcome,
        source,
        policy_action,
        tool_name,
        params,
        artifact,
        artifact_hash,
        decision,
    })
}

/// `_block_source_fits`: whether a block's decision source fits its queue
/// route.
fn block_source_fits(queued: bool, reviewed: bool, source: &str) -> bool {
    if queued {
        source == APPROVAL_PENDING_SOURCE
    } else if reviewed {
        source == SAFE_ALTERNATIVE_SOURCE
    } else {
        BLOCK_SOURCES.contains(&source)
    }
}

/// `_redaction_level` with the center the resident links the row to: a
/// known level and a loopback origin. A record from a binding with no center
/// leaves the row, and so the receipt, to the daemon.
fn review_fields(review: &Value) -> Option<(&str, &str)> {
    let review = exact_object(review, &REVIEW_FIELDS)?;
    let level = review["redaction_level"]
        .as_str()
        .filter(|level| REDACTION_LEVELS.contains(level))?;
    let center = review["approval_center_url"]
        .as_str()
        .filter(|center| !center.trim().is_empty())?;
    Some((level, center))
}

/// `_queued_approval`, with no desktop notice left to raise.
pub(super) fn approval_fits(approval: &Value) -> bool {
    let Some(approval) = exact_object(approval, &APPROVAL_KEYS) else {
        return false;
    };
    let filled = |key: &str| {
        approval[key]
            .as_str()
            .is_some_and(|text| !text.trim().is_empty())
    };
    (approval["workspace"].is_string() || approval["workspace"].is_null())
        && approval["notices"].as_array().is_some_and(Vec::is_empty)
        && ["approval_center_url", "review_url", "request_id"]
            .iter()
            .all(|key| filled(key))
}

/// `risk_input(artifact, params["arguments"])` with the arguments in the
/// order the host sent them. Only a mapping's entries keep that order, so
/// another record whose arguments are an object is left to the daemon.
fn risk_input(
    artifact: &Map<String, Value>,
    params: &Value,
    arguments: &Value,
) -> Option<McpToolRiskInputV1> {
    let arguments = match params.get("arguments") {
        Some(Value::Object(_)) => match serde_json::from_value(arguments.clone()).ok()? {
            mapping @ McpToolArgumentsV1::Mapping { .. } => mapping,
            _ => return None,
        },
        Some(Value::String(text)) => McpToolArgumentsV1::Json { text: text.clone() },
        other => McpToolArgumentsV1::Other {
            value: other.cloned().unwrap_or(Value::Null),
        },
    };
    Some(McpToolRiskInputV1 {
        artifact: BrowserMcpArtifactV1 {
            name: artifact["name"].as_str()?.to_owned(),
            command: artifact["command"].as_str().map(str::to_owned),
            metadata: artifact["metadata"].as_object()?.clone(),
        },
        arguments,
        risk_categories: None,
        summary_code: None,
    })
}

/// `_validated_decision` and `_decision`: a well-formed native decision that
/// was not claimed under a fresh authority, which the daemon owns.
fn decision_fits(decision: &Map<String, Value>) -> bool {
    let action = |key: &str| {
        decision[key]
            .as_str()
            .is_some_and(|action| GUARD_ACTIONS.contains(&action))
    };
    let one_of = |key: &str, allowed: &[&str]| match &decision[key] {
        Value::Null => true,
        Value::String(text) => allowed.contains(&text.as_str()),
        _ => false,
    };
    action("action")
        && action("policy_action")
        && decision["source"].is_string()
        && decision["summary"].is_string()
        && string_list(&decision["signals"])
        && string_list(&decision["risk_categories"])
        && [
            "normalization_reason_code",
            "original_action",
            "approval_reuse_reason_code",
        ]
        .iter()
        .all(|key| decision[*key].is_null() || decision[*key].is_string())
        && one_of(
            "approval_reuse_status",
            &["accepted", "rejected", "not-applicable"],
        )
        && one_of("current_action", &GUARD_ACTIONS)
        && one_of("saved_action", &GUARD_ACTIONS)
        && (decision["pending_approval_reuse_decision"].is_null()
            || decision["pending_approval_reuse_decision"].is_object())
        && one_of(
            "approval_reuse_claim_disposition",
            &["consumed", "retained"],
        )
        && decision["post_claim_revalidated"] == Value::Bool(false)
        && decision["post_claim_authority"].is_null()
}

fn exact_object<'a>(value: &'a Value, keys: &[&str]) -> Option<&'a Map<String, Value>> {
    value.as_object().filter(|object| {
        object.len() == keys.len() && keys.iter().all(|key| object.contains_key(*key))
    })
}

fn strings(value: &Value) -> Vec<String> {
    value
        .as_array()
        .map(|items| {
            items
                .iter()
                .filter_map(Value::as_str)
                .map(str::to_owned)
                .collect()
        })
        .unwrap_or_default()
}

pub(super) fn string_list(value: &Value) -> bool {
    value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string))
}

/// `_ordered_params`: a mapping's host-ordered entries must name exactly the
/// decoded arguments.
fn arguments_fit(params: &Value, arguments: &Value) -> bool {
    if arguments.get("format").and_then(Value::as_str) != Some("mapping") {
        return true;
    }
    let (Some(entries), Some(current)) = (
        arguments.get("entries").and_then(Value::as_array),
        params.get("arguments").and_then(Value::as_object),
    ) else {
        return false;
    };
    let mut ordered = Map::new();
    for entry in entries {
        let Some([Value::String(key), value]) = entry.as_array().map(Vec::as_slice) else {
            return false;
        };
        ordered.insert(key.clone(), value.clone());
    }
    &ordered == current
}

pub(super) fn block_taxonomy(policy_action: &str) -> Option<(&'static str, &'static str)> {
    BLOCK_TAXONOMY
        .iter()
        .find(|(action, ..)| *action == policy_action)
        .map(|(_, event, provenance)| (*event, *provenance))
}
