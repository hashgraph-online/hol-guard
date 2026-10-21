//! The approval request a queue write stores: `GuardApprovalRequest` as the
//! daemon's `to_dict` spells it, and the derived column values of
//! the former Python writer (review links, continuation snapshot, watch-only
//! flag) with the exact JSON text Python's `json.dumps` writes.

use serde::Deserialize;
use serde_json::{Map, Value};

use crate::guard_store_db::{StoreError, StoreResult};
use crate::guard_store_json::{dumps_default, dumps_sorted, py_strip};
use crate::guard_store_outbox_identity::{
    correlation_id, correlation_shaped, validated_continuation_snapshot,
};

const REQUEST_INVALID: StoreError =
    StoreError::Invalid("native_guard_store_approval_request_invalid");
const CORRELATION_KEYS: [&str; 2] = ["correlationId", "correlation_id"];
const RETRY_ONLY_HARNESSES: [&str; 7] = [
    "codex", "grok", "hermes", "oh-my-pi", "omp", "openclaw", "pi",
];

fn default_artifact_type() -> String {
    "artifact".to_owned()
}

fn default_dedupe_count() -> i64 {
    1
}

/// `GuardApprovalRequest.to_dict()`.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct ApprovalRequest {
    pub(crate) request_id: String,
    pub(crate) harness: String,
    pub(crate) artifact_id: String,
    pub(crate) artifact_name: String,
    pub(crate) artifact_hash: String,
    pub(crate) policy_action: Value,
    pub(crate) recommended_scope: String,
    pub(crate) changed_fields: Vec<String>,
    pub(crate) source_scope: String,
    pub(crate) config_path: String,
    pub(crate) review_command: String,
    pub(crate) approval_url: String,
    #[serde(default)]
    pub(crate) workspace: Option<String>,
    #[serde(default = "default_artifact_type")]
    pub(crate) artifact_type: String,
    #[serde(default)]
    pub(crate) launch_target: Option<String>,
    #[serde(default)]
    pub(crate) transport: Option<String>,
    #[serde(default)]
    pub(crate) publisher: Option<String>,
    #[serde(default)]
    pub(crate) risk_summary: Option<String>,
    #[serde(default)]
    pub(crate) risk_signals: Vec<String>,
    #[serde(default)]
    pub(crate) artifact_label: Option<String>,
    #[serde(default)]
    pub(crate) source_label: Option<String>,
    #[serde(default)]
    pub(crate) trigger_summary: Option<String>,
    #[serde(default)]
    pub(crate) why_now: Option<String>,
    #[serde(default)]
    pub(crate) launch_summary: Option<String>,
    #[serde(default)]
    pub(crate) risk_headline: Option<String>,
    #[serde(default)]
    pub(crate) action_envelope_json: Option<Map<String, Value>>,
    #[serde(default)]
    pub(crate) decision_v2_json: Option<Map<String, Value>>,
    #[serde(default)]
    pub(crate) fallback_cli_command: Option<String>,
    #[serde(default)]
    pub(crate) action_identity: Option<String>,
    #[serde(default)]
    pub(crate) queue_group_id: Option<String>,
    #[serde(default = "default_dedupe_count")]
    pub(crate) dedupe_count: i64,
    #[serde(default)]
    pub(crate) last_seen_at: Option<String>,
    #[serde(default)]
    pub(crate) scanner_evidence: Vec<Map<String, Value>>,
    #[serde(default)]
    pub(crate) browser_intent: Option<Map<String, Value>>,
    #[serde(default)]
    pub(crate) raw_command_text: Option<String>,
    #[serde(default)]
    pub(crate) guard_version: Option<String>,
    #[serde(default)]
    pub(crate) first_seen_guard_version: Option<String>,
    #[serde(default)]
    pub(crate) last_seen_guard_version: Option<String>,
    #[serde(default)]
    pub(crate) continuation_snapshot: Option<Map<String, Value>>,
    #[serde(default)]
    pub(crate) extension_allow_hint: Option<Map<String, Value>>,
}

impl ApprovalRequest {
    pub(crate) fn decode(value: Option<&Value>) -> StoreResult<Self> {
        serde_json::from_value(value.cloned().ok_or(REQUEST_INVALID)?).map_err(|_| REQUEST_INVALID)
    }

    pub(crate) fn envelope(&self) -> Value {
        optional_object(self.action_envelope_json.as_ref())
    }

    pub(crate) fn decision(&self) -> Value {
        optional_object(self.decision_v2_json.as_ref())
    }

    /// `request.first_seen_guard_version or request.guard_version`.
    pub(crate) fn first_seen_version(&self) -> Value {
        version_or(
            self.first_seen_guard_version.as_deref(),
            self.guard_version.as_deref(),
        )
    }

    pub(crate) fn last_seen_version(&self) -> Value {
        version_or(
            self.last_seen_guard_version.as_deref(),
            self.guard_version.as_deref(),
        )
    }

    /// `_scanner_evidence_is_watch_only`.
    pub(crate) fn watch_only(&self) -> i64 {
        i64::from(
            self.scanner_evidence.iter().any(|item| {
                item.get("source").and_then(Value::as_str) == Some("observe_mode_inbox")
            }),
        )
    }

    /// `json.dumps(list(request.changed_fields))`.
    pub(crate) fn changed_fields_json(&self) -> StoreResult<Value> {
        json_text(&Value::from(self.changed_fields.clone()))
    }

    pub(crate) fn risk_signals_json(&self) -> StoreResult<Value> {
        json_text(&Value::from(self.risk_signals.clone()))
    }

    /// `json.dumps(list(request.scanner_evidence), sort_keys=True)`.
    pub(crate) fn scanner_evidence_json(&self) -> StoreResult<Value> {
        let items = self
            .scanner_evidence
            .iter()
            .cloned()
            .map(Value::Object)
            .collect();
        json_text(&Value::Array(items))
    }

    pub(crate) fn browser_intent_json(&self) -> StoreResult<Value> {
        optional_json(&optional_object(self.browser_intent.as_ref()))
    }

    pub(crate) fn extension_allow_hint_json(&self) -> StoreResult<Value> {
        optional_json(&optional_object(self.extension_allow_hint.as_ref()))
    }

    /// `_continuation_snapshot_json`: the request's frozen snapshot, else an
    /// explicit no-transport one, with `correlation` when an update keeps the
    /// stored request's correlation.
    pub(crate) fn continuation_snapshot_json(
        &self,
        correlation: Option<String>,
    ) -> StoreResult<Value> {
        let supplied = optional_object(self.continuation_snapshot.as_ref());
        let mut snapshot = match validated_continuation_snapshot(&supplied) {
            Some(snapshot) => snapshot,
            None => self.non_resumable_snapshot()?,
        };
        if let Some(correlation) = correlation {
            snapshot.insert("correlationId".to_owned(), Value::String(correlation));
        }
        dumps_sorted(&Value::Object(snapshot))
            .map(Value::String)
            .ok_or(REQUEST_INVALID)
    }

    /// `non_resumable_continuation_snapshot(request.to_dict())`.
    fn non_resumable_snapshot(&self) -> StoreResult<Map<String, Value>> {
        let request_id = py_strip(&self.request_id);
        if request_id.is_empty() {
            return Err(StoreError::Value(
                "continuation_request_id_missing".to_owned(),
            ));
        }
        let harness = match py_strip(&self.harness) {
            "" => "unknown".to_owned(),
            text => text.to_lowercase(),
        };
        let capability = if RETRY_ONLY_HARNESSES.contains(&harness.as_str()) {
            "retry-only"
        } else {
            "unsupported"
        };
        // The request row's own keys are its dataclass fields, so it never
        // carries a correlation of its own.
        let sources = [
            self.continuation_snapshot.as_ref(),
            self.decision_v2_json.as_ref(),
            self.action_envelope_json.as_ref(),
        ];
        let correlation = sources
            .into_iter()
            .flatten()
            .flat_map(|source| CORRELATION_KEYS.iter().map(move |key| source.get(*key)))
            .find_map(correlation_candidate)
            .map_or_else(|| correlation_id(request_id), Some)
            .ok_or_else(|| StoreError::Value("local_request_id is required".to_owned()))?;
        let mut snapshot = Map::new();
        snapshot.insert("correlationId".to_owned(), Value::String(correlation));
        snapshot.insert("capability".to_owned(), Value::from(capability));
        snapshot.insert("hookAttached".to_owned(), Value::Bool(false));
        snapshot.insert("opaqueTargetId".to_owned(), Value::Null);
        snapshot.insert("waitDeadline".to_owned(), Value::Null);
        Ok(snapshot)
    }
}

/// A correlation-shaped candidate of `canonical_continuation_correlation_id`.
fn correlation_candidate(value: Option<&Value>) -> Option<String> {
    let text = py_strip(value?.as_str()?);
    correlation_shaped(text).then(|| text.to_owned())
}

/// The correlation an update keeps: the stored row's frozen snapshot, else
/// the one derived from the stored request id.
pub(crate) fn stored_correlation(
    request_id: &str,
    stored_snapshot: Option<&str>,
) -> Option<String> {
    let frozen = stored_snapshot
        .filter(|text| !text.is_empty())
        .and_then(|text| serde_json::from_str::<Value>(text).ok())
        .and_then(|value| validated_continuation_snapshot(&value));
    match frozen
        .as_ref()
        .and_then(|snapshot| snapshot.get("correlationId"))
    {
        Some(Value::String(correlation)) => Some(correlation.clone()),
        _ => correlation_id(request_id),
    }
}

fn optional_object(value: Option<&Map<String, Value>>) -> Value {
    value.map_or(Value::Null, |map| Value::Object(map.clone()))
}

fn version_or(version: Option<&str>, fallback: Option<&str>) -> Value {
    match version.filter(|text| !text.is_empty()) {
        Some(text) => Value::from(text),
        None => fallback.map_or(Value::Null, Value::from),
    }
}

/// `json.dumps(value)`. Every object the queue writes has sorted keys, since
/// each one came out of a canonical projection or is dumped with `sort_keys`.
pub(crate) fn json_text(value: &Value) -> StoreResult<Value> {
    dumps_default(value)
        .map(Value::String)
        .ok_or(REQUEST_INVALID)
}

/// `_optional_json`.
pub(crate) fn optional_json(value: &Value) -> StoreResult<Value> {
    if value.is_null() {
        return Ok(Value::Null);
    }
    json_text(value)
}

/// `_rewrite_review_command`: the command with its last word replaced by the
/// stored request id.
pub(crate) fn rewrite_review_command(command: &str, request_id: &str) -> String {
    match command.rsplit_once(' ') {
        Some((prefix, _)) if !prefix.is_empty() => format!("{prefix} {request_id}"),
        _ => request_id.to_owned(),
    }
}

/// `_rewrite_approval_url`.
pub(crate) fn rewrite_approval_url(url: &str, request_id: &str) -> String {
    let url = url.replace("/approvals/", "/requests/");
    match url.rsplit_once('/') {
        Some((prefix, _)) if !prefix.is_empty() => format!("{prefix}/{request_id}"),
        _ => request_id.to_owned(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn review_links_point_at_the_stored_request() {
        assert_eq!(
            rewrite_review_command("hol-guard approvals approve a", "b"),
            "hol-guard approvals approve b"
        );
        assert_eq!(rewrite_review_command("a", "b"), "b");
        assert_eq!(rewrite_review_command(" a", "b"), "b");
        assert_eq!(
            rewrite_approval_url("http://127.0.0.1:1/approvals/a", "b"),
            "http://127.0.0.1:1/requests/b"
        );
        assert_eq!(rewrite_approval_url("a", "b"), "b");
        assert_eq!(rewrite_approval_url("/a", "b"), "b");
    }
}
