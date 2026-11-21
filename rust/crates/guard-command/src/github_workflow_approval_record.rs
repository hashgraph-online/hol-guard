//! Rust port of `runtime/github_workflow_approval_record.py` — the privacy-safe
//! persisted evidence row carried on an approval request.
//!
//! `from_descriptor`/`matches_descriptor` depend on `GitHubWorkflowDescriptor`
//! (built by `github_workflow_context.py`'s live `git`/`gh` subprocess leg);
//! that stays host-side until RTM-016 lands the context collector. The dict
//! surface — `from_dict`, `to_dict`, `__post_init__` — is fully ported so the
//! persisted record can be decoded + validated natively.
//!
//! Error strings match the Python `ValueError` messages verbatim.

use guard_contracts::WorkflowCapabilityBinding;
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// `GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA` (:19).
pub const GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA: &str = "guard.github-workflow-approval-record.v1";

/// The ten authorization-eligible `operation_kind` values (:34-46).
const OPERATION_KINDS: &[&str] = &[
    "resolve-review-thread",
    "unresolve-review-thread",
    "lock-issue",
    "unlock-issue",
    "pin-issue",
    "unpin-issue",
    "lock-pr",
    "unlock-pr",
    "mark-pr-ready",
    "mark-pr-draft",
];

/// The three legal `resource_type` values (:47).
const RESOURCE_TYPES: &[&str] = &["github-review-thread", "github-issue", "github-pr"];

/// `GitHubWorkflowApprovalRecord` (:22). Construct via `decode` so
/// `__post_init__` runs; the struct fields are `pub` for read access but
/// callers assembling one directly MUST call [`validate`].
#[derive(Debug, Clone, PartialEq)]
pub struct GitHubWorkflowApprovalRecord {
    pub schema_version: String,
    pub operation_kind: String,
    pub resource_type: String,
    pub command_identity_sha256: String,
    pub operation_digest_sha256: String,
    pub binding: WorkflowCapabilityBinding,
}

/// Python `ValueError` surface — the record uses plain `ValueError` messages
/// (`"invalid GitHub workflow approval record shape"`, …), not
/// `WorkflowCapabilityError`. Rust returns the message verbatim.
type RecordResult<T> = Result<T, String>;

impl GitHubWorkflowApprovalRecord {
    /// `from_dict` (:69) — strict-key decode; `binding` goes through
    /// `WorkflowCapabilityBinding.from_dict` (strict keys, full validation).
    pub fn decode(payload: &Value) -> RecordResult<Self> {
        let m = payload
            .as_object()
            .ok_or_else(|| "invalid GitHub workflow approval record shape".to_string())?;
        const EXPECTED: &[&str] = &[
            "schema_version",
            "operation_kind",
            "resource_type",
            "command_identity_sha256",
            "operation_digest_sha256",
            "binding",
        ];
        if m.len() != EXPECTED.len() || EXPECTED.iter().any(|k| !m.contains_key(*k)) {
            return Err("invalid GitHub workflow approval record shape".to_string());
        }
        let binding_value = m.get("binding").unwrap();
        let record = GitHubWorkflowApprovalRecord {
            schema_version: required_string(m, "schema_version")?,
            operation_kind: required_string(m, "operation_kind")?,
            resource_type: required_string(m, "resource_type")?,
            command_identity_sha256: required_string(m, "command_identity_sha256")?,
            operation_digest_sha256: required_string(m, "operation_digest_sha256")?,
            binding: WorkflowCapabilityBinding::decode(binding_value).map_err(|e| e.to_string())?,
        };
        record.validate()?;
        Ok(record)
    }

    /// `to_dict` (:90) — exact key order the canonical serializer uses.
    /// `binding.to_value()` produces the identical nested shape.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert(
            "operation_kind".into(),
            Value::String(self.operation_kind.clone()),
        );
        m.insert(
            "resource_type".into(),
            Value::String(self.resource_type.clone()),
        );
        m.insert(
            "command_identity_sha256".into(),
            Value::String(self.command_identity_sha256.clone()),
        );
        m.insert(
            "operation_digest_sha256".into(),
            Value::String(self.operation_digest_sha256.clone()),
        );
        m.insert("binding".into(), self.binding.to_value());
        Value::Object(m)
    }

    /// `__post_init__` (:31) — every check, same order, same messages.
    pub fn validate(&self) -> RecordResult<()> {
        if self.schema_version != GITHUB_WORKFLOW_APPROVAL_RECORD_SCHEMA {
            return Err("unsupported GitHub workflow approval record".to_string());
        }
        if !OPERATION_KINDS.contains(&self.operation_kind.as_str()) {
            return Err("invalid GitHub workflow operation kind".to_string());
        }
        if !RESOURCE_TYPES.contains(&self.resource_type.as_str()) {
            return Err("invalid GitHub workflow resource type".to_string());
        }
        if self.binding.operation_id != format!("github.{}.v1", self.operation_kind) {
            return Err("GitHub workflow operation binding mismatch".to_string());
        }
        if self.binding.resource_type != self.resource_type {
            return Err("GitHub workflow resource binding mismatch".to_string());
        }
        validate_sha256(&self.command_identity_sha256)?;
        validate_sha256(&self.operation_digest_sha256)?;
        Ok(())
    }

    /// `matches` — the `matches_descriptor` digest-equality core. The Python
    /// version compares `hmac.compare_digest(framed(self.to_dict()),
    /// framed(candidate.to_dict()))`; with both records already decoded this
    /// reduces to constant-time comparing the two framed digests. Used by the
    /// runtime when a fresh candidate is built separately.
    pub fn digest_matches(&self, candidate: &GitHubWorkflowApprovalRecord) -> bool {
        let left = approval_record_digest(&self.to_value());
        let right = approval_record_digest(&candidate.to_value());
        hmac_compare_digest(&left, &right)
    }
}

/// `_digest("github-workflow-approval-record", self.to_dict())` (:139-140).
pub fn approval_record_digest(record_value: &Value) -> String {
    framed_sha256("github-workflow-approval-record", record_value)
}

/// `_required_string` (:127) — `Mapping[str]` → non-empty `str`.
fn required_string(m: &Map<String, Value>, key: &str) -> RecordResult<String> {
    let value = m.get(key).and_then(Value::as_str).unwrap_or("");
    if value.is_empty() {
        return Err(format!("missing {key}"));
    }
    Ok(value.to_string())
}

/// `_validate_sha256` (:134).
fn validate_sha256(value: &str) -> RecordResult<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err("invalid GitHub workflow approval digest".to_string());
    }
    Ok(())
}

/// `_digest` (:139) — sha256 of the canonical framed payload.
fn framed_sha256(purpose: &str, payload: &Value) -> String {
    // Mirrors `_digest`; the payload here is always a well-formed `to_value`
    // map so `canonical_framed_payload` cannot fail. Keep the message anyway.
    let framed =
        guard_contracts::canonical_framed_payload(purpose, payload).unwrap_or_else(|_| Vec::new());
    let mut hasher = Sha256::new();
    hasher.update(&framed);
    hasher
        .finalize()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// `hmac.compare_digest` on two 64-hex digests.
fn hmac_compare_digest(left: &str, right: &str) -> bool {
    let (a, b) = (left.as_bytes(), right.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter()
        .zip(b.iter())
        .fold(0u8, |acc, (x, y)| acc | (x ^ y))
        == 0
}
