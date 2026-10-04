//! Workflow-capability signed-claim contract (`workflow_capabilities.py`).
//!
//! The pure cryptographic half of RTM-013's `WorkflowCapabilityClaim` op:
//! the immutable claim/binding/receipt value types, the length-delimited
//! `canonical_framed_payload` envelope, and the HMAC-SHA256 sign/verify.
//! Everything is strict: `from_dict`-equivalent `decode_*` fns enforce the
//! exact key set, identifier pattern, sha256 shape, timestamp window, and
//! max-uses bound, and return `WorkflowCapabilityError` (fail-closed) — the
//! same `ValueError` subclasses Python raises.
//!
//! The store-CAS (`claim_workflow_capability`, `issue_workflow_capability`,
//! `_policy_integrity_secret_material`, the authority-transition chain)
//! lives in `guard-runtime` — it consumes these primitives against an open
//! `rusqlite` connection.

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

use crate::canonical_json::write_canonical_json;

pub const WORKFLOW_CAPABILITY_SCHEMA: &str = "hol-guard.workflow-capability.v1";
pub const WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA: &str = "hol-guard.workflow-capability-envelope.v1";
pub const WORKFLOW_CAPABILITY_RECEIPT_SCHEMA: &str = "hol-guard.workflow-capability-receipt.v1";
pub const WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA: &str =
    "hol-guard.workflow-capability-receipt-envelope.v1";
pub const WORKFLOW_CAPABILITY_ALGORITHM: &str = "hmac-sha256";
const FRAME_MAGIC: &[u8] = b"hol-guard.workflow-capability\x00";

type HmacSha256 = Hmac<Sha256>;

/// `WorkflowCapabilityError` — a fail-closed contract reject. The payload
/// is the same reason string the Python `ValueError` subclasses carry so
/// callers can surface identical errors.
#[derive(Debug, Clone, PartialEq)]
pub struct WorkflowCapabilityError(pub &'static str);

impl std::fmt::Display for WorkflowCapabilityError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for WorkflowCapabilityError {}

type WfResult<T> = Result<T, WorkflowCapabilityError>;
fn err<T>(reason: &'static str) -> WfResult<T> {
    Err(WorkflowCapabilityError(reason))
}

// ─── validators ──────────────────────────────────────────────────────────

fn is_sha256(v: &str) -> bool {
    v.len() == 64
        && v.bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn validate_sha256(v: &str) -> WfResult<()> {
    if is_sha256(v) {
        Ok(())
    } else {
        err("invalid_sha256")
    }
}

/// `_IDENTIFIER_PATTERN`: `^[A-Za-z0-9][A-Za-z0-9._:/@+-]{0,255}$` and no `*`.
fn validate_identifier(v: &str) -> WfResult<()> {
    let valid = !v.is_empty()
        && v.len() <= 256
        && !v.contains('*')
        && v.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && v.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '+' | '-')
        });
    if valid {
        Ok(())
    } else {
        err("invalid_identifier")
    }
}

/// `validate_workflow_capability_identifier(name, value)` — the named-export
/// validator used across the authority-state/transition modules; rejects with
/// `invalid_{name}` (a per-field reason), not `invalid_identifier`.
pub fn validate_workflow_capability_identifier(name: &'static str, v: &str) -> WfResult<()> {
    let valid = !v.is_empty()
        && v.len() <= 256
        && !v.contains('*')
        && v.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && v.chars().all(|c| {
            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '@' | '+' | '-')
        });
    if valid {
        Ok(())
    } else {
        Err(WorkflowCapabilityError(match name {
            "capability_id" => "invalid_capability_id",
            "revocation_id" => "invalid_revocation_id",
            "receipt_id" => "invalid_receipt_id",
            "key_id" => "invalid_key_id",
            _ => "invalid_identifier",
        }))
    }
}

/// `_TIMESTAMP_PATTERN`: `^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{6}Z$`.
fn is_canonical_timestamp(v: &str) -> bool {
    let b = v.as_bytes();
    if b.len() != 27
        || b[4] != b'-'
        || b[7] != b'-'
        || b[10] != b'T'
        || b[13] != b':'
        || b[16] != b':'
        || b[19] != b'.'
        || b[26] != b'Z'
    {
        return false;
    }
    for i in [0..4usize, 5..7, 8..10, 11..13, 14..16, 17..19, 20..26] {
        if !b[i].iter().all(|c| c.is_ascii_digit()) {
            return false;
        }
    }
    true
}
fn parse_utc_timestamp(v: &str) -> WfResult<()> {
    if is_canonical_timestamp(v) {
        Ok(())
    } else {
        err("invalid_canonical_timestamp")
    }
}

fn validate_key(key: &[u8]) -> WfResult<()> {
    if key.len() >= 32 {
        Ok(())
    } else {
        err("invalid_capability_key")
    }
}

// ─── rule binding ────────────────────────────────────────────────────────

/// `WorkflowCapabilityRuleBinding` — an ordered `(rule_id, rule_version)`
/// pair inside a binding's `rules` tuple.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct WorkflowCapabilityRuleBinding {
    pub rule_id: String,
    pub rule_version: String,
}

impl WorkflowCapabilityRuleBinding {
    fn validate(&self) -> WfResult<()> {
        validate_identifier(&self.rule_id)?;
        validate_identifier(&self.rule_version)
    }
}

// ─── binding ─────────────────────────────────────────────────────────────

/// `WorkflowCapabilityBinding` — the exact immutable execution/authority
/// context the claim binds. All `*_sha256` fields must be 64-lower-hex;
/// all id/version fields must be identifiers.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityBinding {
    pub operation_id: String,
    pub resource_type: String,
    pub resource_sha256: String,
    pub repository_sha256: String,
    pub workspace_sha256: String,
    pub executable_sha256: String,
    pub launch_sha256: String,
    pub policy_id: String,
    pub policy_version: String,
    pub effect_id: String,
    pub effect_version: String,
    pub decision_id: String,
    pub decision_version: String,
    pub rules: Vec<WorkflowCapabilityRuleBinding>,
}

impl WorkflowCapabilityBinding {
    /// `__post_init__` — Python validates at construction; the Rust binding is
    /// a plain struct so callers invoke this before persisting/signing.
    pub fn validate(&self) -> WfResult<()> {
        for id in [
            &self.operation_id,
            &self.resource_type,
            &self.policy_id,
            &self.policy_version,
            &self.effect_id,
            &self.effect_version,
            &self.decision_id,
            &self.decision_version,
        ] {
            validate_identifier(id)?;
        }
        for sha in [
            &self.resource_sha256,
            &self.repository_sha256,
            &self.workspace_sha256,
            &self.executable_sha256,
            &self.launch_sha256,
        ] {
            validate_sha256(sha)?;
        }
        // Python: `if not self.rules or len > 32 or rules != sorted(set(rules))`
        // — non-empty, bounded, deduplicated, sorted (rule_id, rule_version).
        if self.rules.is_empty() || self.rules.len() > 32 {
            return err("invalid_rule_bindings");
        }
        let mut sorted: Vec<_> = self.rules.clone();
        sorted.sort();
        sorted.dedup();
        if sorted != self.rules {
            return err("invalid_rule_bindings");
        }
        for rule in &self.rules {
            rule.validate()?;
        }
        Ok(())
    }

    /// `from_dict` — strict-key decode: every dataclass field present, no
    /// extras, `rules` an array of strict rule-binding objects.
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(payload, BINDING_KEYS)?;
        let rules_v = require(m, "rules")?
            .as_array()
            .ok_or(WorkflowCapabilityError("invalid_rule_bindings"))?;
        let mut rules = Vec::with_capacity(rules_v.len());
        for r in rules_v {
            let rm = strict_object(r, RULE_KEYS)?;
            let rb = WorkflowCapabilityRuleBinding {
                rule_id: require_str(rm, "rule_id")?,
                rule_version: require_str(rm, "rule_version")?,
            };
            rb.validate()?;
            rules.push(rb);
        }
        let binding = WorkflowCapabilityBinding {
            operation_id: require_str(m, "operation_id")?,
            resource_type: require_str(m, "resource_type")?,
            resource_sha256: require_str(m, "resource_sha256")?,
            repository_sha256: require_str(m, "repository_sha256")?,
            workspace_sha256: require_str(m, "workspace_sha256")?,
            executable_sha256: require_str(m, "executable_sha256")?,
            launch_sha256: require_str(m, "launch_sha256")?,
            policy_id: require_str(m, "policy_id")?,
            policy_version: require_str(m, "policy_version")?,
            effect_id: require_str(m, "effect_id")?,
            effect_version: require_str(m, "effect_version")?,
            decision_id: require_str(m, "decision_id")?,
            decision_version: require_str(m, "decision_version")?,
            rules,
        };
        binding.validate()?;
        Ok(binding)
    }

    /// `to_value` — canonical binding `Value` for canonical-JSON persistence.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "operation_id".into(),
            Value::String(self.operation_id.clone()),
        );
        m.insert(
            "resource_type".into(),
            Value::String(self.resource_type.clone()),
        );
        m.insert(
            "resource_sha256".into(),
            Value::String(self.resource_sha256.clone()),
        );
        m.insert(
            "repository_sha256".into(),
            Value::String(self.repository_sha256.clone()),
        );
        m.insert(
            "workspace_sha256".into(),
            Value::String(self.workspace_sha256.clone()),
        );
        m.insert(
            "executable_sha256".into(),
            Value::String(self.executable_sha256.clone()),
        );
        m.insert(
            "launch_sha256".into(),
            Value::String(self.launch_sha256.clone()),
        );
        m.insert("policy_id".into(), Value::String(self.policy_id.clone()));
        m.insert(
            "policy_version".into(),
            Value::String(self.policy_version.clone()),
        );
        m.insert("effect_id".into(), Value::String(self.effect_id.clone()));
        m.insert(
            "effect_version".into(),
            Value::String(self.effect_version.clone()),
        );
        m.insert(
            "decision_id".into(),
            Value::String(self.decision_id.clone()),
        );
        m.insert(
            "decision_version".into(),
            Value::String(self.decision_version.clone()),
        );
        let rules: Vec<Value> = self
            .rules
            .iter()
            .map(|r| {
                let mut rm = Map::new();
                rm.insert("rule_id".into(), Value::String(r.rule_id.clone()));
                rm.insert("rule_version".into(), Value::String(r.rule_version.clone()));
                Value::Object(rm)
            })
            .collect();
        m.insert("rules".into(), Value::Array(rules));
        Value::Object(m)
    }
}

const BINDING_KEYS: &[&str] = &[
    "operation_id",
    "resource_type",
    "resource_sha256",
    "repository_sha256",
    "workspace_sha256",
    "executable_sha256",
    "launch_sha256",
    "policy_id",
    "policy_version",
    "effect_id",
    "effect_version",
    "decision_id",
    "decision_version",
    "rules",
];
const RULE_KEYS: &[&str] = &["rule_id", "rule_version"];

// ─── claim ───────────────────────────────────────────────────────────────

/// `WorkflowCapabilityClaim` — the unsigned immutable claim; signing turns
/// it into persisted authority.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityClaim {
    pub schema_version: String,
    pub algorithm: String,
    pub capability_id: String,
    pub approval_provenance_id: String,
    pub task_id: String,
    pub nonce: String,
    pub issuer_id: String,
    pub subject_id: String,
    pub binding: WorkflowCapabilityBinding,
    pub issued_at: String,
    pub not_before: String,
    pub expires_at: String,
    pub max_uses: i64,
}

const CLAIM_KEYS: &[&str] = &[
    "schema_version",
    "algorithm",
    "capability_id",
    "approval_provenance_id",
    "task_id",
    "nonce",
    "issuer_id",
    "subject_id",
    "binding",
    "issued_at",
    "not_before",
    "expires_at",
    "max_uses",
];

impl WorkflowCapabilityClaim {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        capability_id: &str,
        approval_provenance_id: &str,
        task_id: &str,
        nonce: &str,
        issuer_id: &str,
        subject_id: &str,
        binding: WorkflowCapabilityBinding,
        issued_at: &str,
        not_before: &str,
        expires_at: &str,
        max_uses: i64,
    ) -> WfResult<Self> {
        let claim = WorkflowCapabilityClaim {
            schema_version: WORKFLOW_CAPABILITY_SCHEMA.to_string(),
            algorithm: WORKFLOW_CAPABILITY_ALGORITHM.to_string(),
            capability_id: capability_id.to_string(),
            approval_provenance_id: approval_provenance_id.to_string(),
            task_id: task_id.to_string(),
            nonce: nonce.to_string(),
            issuer_id: issuer_id.to_string(),
            subject_id: subject_id.to_string(),
            binding,
            issued_at: issued_at.to_string(),
            not_before: not_before.to_string(),
            expires_at: expires_at.to_string(),
            max_uses,
        };
        claim.validate()?;
        Ok(claim)
    }

    fn validate(&self) -> WfResult<()> {
        if self.schema_version != WORKFLOW_CAPABILITY_SCHEMA {
            return err("unsupported_capability_schema");
        }
        if self.algorithm != WORKFLOW_CAPABILITY_ALGORITHM {
            return err("unsupported_capability_algorithm");
        }
        self.binding
            .validate()
            .map_err(|_| WorkflowCapabilityError("invalid_capability_binding"))?;
        for id in [
            &self.capability_id,
            &self.approval_provenance_id,
            &self.task_id,
            &self.issuer_id,
            &self.subject_id,
        ] {
            validate_identifier(id)?;
        }
        // nonce: `[0-9a-f]{32,64}`
        if self.nonce.len() < 32
            || self.nonce.len() > 64
            || !self
                .nonce
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return err("invalid_nonce");
        }
        parse_utc_timestamp(&self.issued_at)?;
        parse_utc_timestamp(&self.not_before)?;
        parse_utc_timestamp(&self.expires_at)?;
        // issued <= not_before < expires (lexicographic on canonical strings).
        if !(self.issued_at <= self.not_before && self.not_before < self.expires_at) {
            return err("invalid_capability_time_window");
        }
        // TTL <= 86400 s — compare via seconds to avoid a date library; the
        // window is already ordered so expires - issued is non-negative.
        if !ttl_within_alpha_limit(&self.issued_at, &self.expires_at) {
            return err("capability_ttl_exceeds_alpha_limit");
        }
        if !(1..=50).contains(&self.max_uses) {
            return err("invalid_capability_max_uses");
        }
        Ok(())
    }

    /// `from_dict` strict-key decode.
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(payload, CLAIM_KEYS)?;
        let max_uses = require(m, "max_uses")?
            .as_i64()
            .ok_or(WorkflowCapabilityError("invalid_capability_max_uses"))?;
        let claim = WorkflowCapabilityClaim {
            schema_version: require_str(m, "schema_version")?,
            algorithm: require_str(m, "algorithm")?,
            capability_id: require_str(m, "capability_id")?,
            approval_provenance_id: require_str(m, "approval_provenance_id")?,
            task_id: require_str(m, "task_id")?,
            nonce: require_str(m, "nonce")?,
            issuer_id: require_str(m, "issuer_id")?,
            subject_id: require_str(m, "subject_id")?,
            binding: WorkflowCapabilityBinding::decode(require(m, "binding")?)?,
            issued_at: require_str(m, "issued_at")?,
            not_before: require_str(m, "not_before")?,
            expires_at: require_str(m, "expires_at")?,
            max_uses,
        };
        claim.validate()?;
        Ok(claim)
    }

    /// `asdict` — the exact key order serde emits is irrelevant; canonical
    /// framing sorts keys. Emit the Python field set.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert("algorithm".into(), Value::String(self.algorithm.clone()));
        m.insert(
            "capability_id".into(),
            Value::String(self.capability_id.clone()),
        );
        m.insert(
            "approval_provenance_id".into(),
            Value::String(self.approval_provenance_id.clone()),
        );
        m.insert("task_id".into(), Value::String(self.task_id.clone()));
        m.insert("nonce".into(), Value::String(self.nonce.clone()));
        m.insert("issuer_id".into(), Value::String(self.issuer_id.clone()));
        m.insert("subject_id".into(), Value::String(self.subject_id.clone()));
        m.insert(
            "binding".into(),
            serde_json::to_value(&self.binding).unwrap_or(Value::Null),
        );
        m.insert("issued_at".into(), Value::String(self.issued_at.clone()));
        m.insert("not_before".into(), Value::String(self.not_before.clone()));
        m.insert("expires_at".into(), Value::String(self.expires_at.clone()));
        m.insert("max_uses".into(), Value::from(self.max_uses));
        Value::Object(m)
    }
}

/// `(expires_at - issued_at).total_seconds() <= 86400` on canonical
/// `%Y-%m-%dT%H:%M:%S.%fZ` strings. Both parse to the same fixed shape and
/// `issued <= expires` is already established. Convert each to a
/// days-since-epoch + day-fraction and compare; leap-seconds don't exist in
/// this format so arithmetic is exact.
fn ttl_within_alpha_limit(issued: &str, expires: &str) -> bool {
    fn to_seconds(ts: &str) -> i64 {
        // days_from_civil (Howard Hinnant) for the date part.
        let y: i64 = ts[0..4].parse().unwrap_or(0);
        let m: i64 = ts[5..7].parse().unwrap_or(0);
        let d: i64 = ts[8..10].parse().unwrap_or(0);
        let yy = if m <= 2 { y - 1 } else { y };
        let era = if yy >= 0 { yy } else { yy - 399 } / 400;
        let yoe = yy - era * 400;
        let mp = (m + 9) % 12;
        let doy = (153 * mp + 2) / 5 + d - 1;
        let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
        let days = era * 146097 + doe - 719468;
        let hh: i64 = ts[11..13].parse().unwrap_or(0);
        let mm: i64 = ts[14..16].parse().unwrap_or(0);
        let ss: i64 = ts[17..19].parse().unwrap_or(0);
        let us: i64 = ts[20..26].parse().unwrap_or(0);
        days * 86_400 * 1_000_000 + (hh * 3600 + mm * 60 + ss) * 1_000_000 + us
    }
    to_seconds(expires) - to_seconds(issued) <= 86_400 * 1_000_000
}

// ─── signed claim ────────────────────────────────────────────────────────

/// `SignedWorkflowCapability` — the persisted authority object.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedWorkflowCapability {
    pub envelope_schema: String,
    pub algorithm: String,
    pub claim: WorkflowCapabilityClaim,
    pub key_id: String,
    pub signature: String,
}

const SIGNED_KEYS: &[&str] = &[
    "envelope_schema",
    "algorithm",
    "claim",
    "key_id",
    "signature",
];

impl SignedWorkflowCapability {
    /// `from_dict` strict-key decode + post-init validation (no signature
    /// check — that's `verify_workflow_capability`).
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(payload, SIGNED_KEYS)?;
        let signed = SignedWorkflowCapability {
            envelope_schema: require_str(m, "envelope_schema")?,
            algorithm: require_str(m, "algorithm")?,
            claim: WorkflowCapabilityClaim::decode(require(m, "claim")?)?,
            key_id: require_str(m, "key_id")?,
            signature: require_str(m, "signature")?,
        };
        signed.validate_shape()?;
        Ok(signed)
    }

    fn validate_shape(&self) -> WfResult<()> {
        if self.envelope_schema != WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA {
            return err("unsupported_capability_envelope");
        }
        if self.algorithm != WORKFLOW_CAPABILITY_ALGORITHM || self.algorithm != self.claim.algorithm
        {
            return err("unsupported_capability_algorithm");
        }
        validate_identifier(&self.key_id)?;
        validate_sha256(&self.signature)
    }

    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "envelope_schema".into(),
            Value::String(self.envelope_schema.clone()),
        );
        m.insert("algorithm".into(), Value::String(self.algorithm.clone()));
        m.insert("claim".into(), self.claim.to_value());
        m.insert("key_id".into(), Value::String(self.key_id.clone()));
        m.insert("signature".into(), Value::String(self.signature.clone()));
        Value::Object(m)
    }
}

// ─── receipt ─────────────────────────────────────────────────────────────

/// `WorkflowCapabilityReceipt` — the signed consumption record.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkflowCapabilityReceipt {
    pub schema_version: String,
    pub receipt_id: String,
    pub capability_id: String,
    pub task_id: String,
    pub invocation_id: String,
    pub approval_provenance_id: String,
    pub claim_sha256: String,
    pub binding: WorkflowCapabilityBinding,
    pub use_number: i64,
    pub event_id: i64,
    pub claimed_at: String,
}

const RECEIPT_KEYS: &[&str] = &[
    "schema_version",
    "receipt_id",
    "capability_id",
    "task_id",
    "invocation_id",
    "approval_provenance_id",
    "claim_sha256",
    "binding",
    "use_number",
    "event_id",
    "claimed_at",
];

impl WorkflowCapabilityReceipt {
    pub fn decode(payload: &Value) -> WfResult<Self> {
        let m = strict_object(payload, RECEIPT_KEYS)?;
        let use_number = require(m, "use_number")?
            .as_i64()
            .ok_or(WorkflowCapabilityError("invalid_receipt_use_number"))?;
        let event_id = require(m, "event_id")?
            .as_i64()
            .ok_or(WorkflowCapabilityError("invalid_receipt_event_id"))?;
        let receipt = WorkflowCapabilityReceipt {
            schema_version: require_str(m, "schema_version")?,
            receipt_id: require_str(m, "receipt_id")?,
            capability_id: require_str(m, "capability_id")?,
            task_id: require_str(m, "task_id")?,
            invocation_id: require_str(m, "invocation_id")?,
            approval_provenance_id: require_str(m, "approval_provenance_id")?,
            claim_sha256: require_str(m, "claim_sha256")?,
            binding: WorkflowCapabilityBinding::decode(require(m, "binding")?)?,
            use_number,
            event_id,
            claimed_at: require_str(m, "claimed_at")?,
        };
        receipt.validate()?;
        Ok(receipt)
    }

    fn validate(&self) -> WfResult<()> {
        if self.schema_version != WORKFLOW_CAPABILITY_RECEIPT_SCHEMA {
            return err("unsupported_receipt_schema");
        }
        for id in [
            &self.receipt_id,
            &self.capability_id,
            &self.task_id,
            &self.invocation_id,
            &self.approval_provenance_id,
        ] {
            validate_identifier(id)?;
        }
        validate_sha256(&self.claim_sha256)?;
        parse_utc_timestamp(&self.claimed_at)?;
        if self.use_number < 1 {
            return err("invalid_receipt_use_number");
        }
        if self.event_id < 1 {
            return err("invalid_receipt_event_id");
        }
        self.binding
            .validate()
            .map_err(|_| WorkflowCapabilityError("invalid_receipt_binding"))
    }

    /// `to_value` — canonical receipt `Value`.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "schema_version".into(),
            Value::String(self.schema_version.clone()),
        );
        m.insert("receipt_id".into(), Value::String(self.receipt_id.clone()));
        m.insert(
            "capability_id".into(),
            Value::String(self.capability_id.clone()),
        );
        m.insert("task_id".into(), Value::String(self.task_id.clone()));
        m.insert(
            "invocation_id".into(),
            Value::String(self.invocation_id.clone()),
        );
        m.insert(
            "approval_provenance_id".into(),
            Value::String(self.approval_provenance_id.clone()),
        );
        m.insert(
            "claim_sha256".into(),
            Value::String(self.claim_sha256.clone()),
        );
        m.insert("binding".into(), self.binding.to_value());
        m.insert("use_number".into(), Value::from(self.use_number));
        m.insert("event_id".into(), Value::from(self.event_id));
        m.insert("claimed_at".into(), Value::String(self.claimed_at.clone()));
        Value::Object(m)
    }
}

/// `SignedWorkflowCapabilityReceipt`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SignedWorkflowCapabilityReceipt {
    pub envelope_schema: String,
    pub algorithm: String,
    pub receipt: WorkflowCapabilityReceipt,
    pub key_id: String,
    pub signature: String,
}

// ─── framing + sign/verify ───────────────────────────────────────────────

/// `canonical_framed_payload` — length-delimited framing:
/// `MAGIC + u32(purpose_len) + purpose + u64(canonical_len) + canonical`.
pub fn canonical_framed_payload(purpose: &str, payload: &Value) -> WfResult<Vec<u8>> {
    let purpose_bytes = purpose.as_bytes();
    if !purpose.is_ascii() {
        return err("invalid_framing_purpose");
    }
    let mut canonical = Vec::new();
    write_canonical_json(payload, &mut canonical)
        .map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))?;
    let mut out =
        Vec::with_capacity(FRAME_MAGIC.len() + 4 + purpose_bytes.len() + 8 + canonical.len());
    out.extend_from_slice(FRAME_MAGIC);
    out.extend_from_slice(&(purpose_bytes.len() as u32).to_be_bytes());
    out.extend_from_slice(purpose_bytes);
    out.extend_from_slice(&(canonical.len() as u64).to_be_bytes());
    out.extend_from_slice(&canonical);
    Ok(out)
}

/// `_canonical_json` — the store-side canonical serializer for a `to_value`.
/// Used to persist `signed_claim_json`/`signed_receipt_json`/event payloads
/// byte-identically to Python `json.dumps(sort_keys=True,separators=(",",":"),ensure_ascii=True)`.
pub fn capability_canonical_json(value: &Value) -> WfResult<String> {
    let mut out = Vec::new();
    write_canonical_json(value, &mut out)
        .map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))?;
    String::from_utf8(out).map_err(|_| WorkflowCapabilityError("invalid_canonical_payload"))
}

impl SignedWorkflowCapability {
    /// `to_dict` — canonical-JSON encode of the signed-claim envelope, the
    /// exact bytes persisted into `signed_claim_json`.
    pub fn to_canonical_json(&self) -> WfResult<String> {
        capability_canonical_json(&self.to_value())
    }

    /// `from_dict` over a canonical JSON string (the `_decode_signed_claim`
    /// store helper).
    pub fn from_canonical_json(encoded: &str) -> WfResult<Self> {
        let payload: Value = serde_json::from_str(encoded)
            .map_err(|_| WorkflowCapabilityError("capability_claim_invalid"))?;
        Self::decode(&payload)
    }
}

impl SignedWorkflowCapabilityReceipt {
    /// `to_value` — canonical receipt-envelope `Value`.
    pub fn to_value(&self) -> Value {
        let mut m = Map::new();
        m.insert(
            "envelope_schema".into(),
            Value::String(self.envelope_schema.clone()),
        );
        m.insert("algorithm".into(), Value::String(self.algorithm.clone()));
        m.insert("receipt".into(), self.receipt.to_value());
        m.insert("key_id".into(), Value::String(self.key_id.clone()));
        m.insert("signature".into(), Value::String(self.signature.clone()));
        Value::Object(m)
    }

    /// `to_dict` — canonical-JSON encode of the signed-receipt envelope.
    pub fn to_canonical_json(&self) -> WfResult<String> {
        capability_canonical_json(&self.to_value())
    }

    /// `from_dict` over a canonical JSON string.
    pub fn from_canonical_json(encoded: &str) -> WfResult<Self> {
        let payload: Value = serde_json::from_str(encoded)
            .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?;
        let m = strict_object(&payload, SIGNED_RECEIPT_KEYS)
            .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?;
        let receipt = WorkflowCapabilityReceipt::decode(require(m, "receipt")?)
            .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?;
        Ok(SignedWorkflowCapabilityReceipt {
            envelope_schema: require_str(m, "envelope_schema")
                .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?,
            algorithm: require_str(m, "algorithm")
                .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?,
            receipt,
            key_id: require_str(m, "key_id")
                .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?,
            signature: require_str(m, "signature")
                .map_err(|_| WorkflowCapabilityError("receipt_payload_invalid"))?,
        })
    }
}

const SIGNED_RECEIPT_KEYS: &[&str] = &[
    "envelope_schema",
    "algorithm",
    "receipt",
    "key_id",
    "signature",
];

fn hmac_hex(key: &[u8], message: &[u8]) -> String {
    let mut mac = <HmacSha256 as Mac>::new_from_slice(key).expect("hmac accepts any key length");
    mac.update(message);
    hex_lower(&mac.finalize().into_bytes())
}

/// `sign_workflow_capability` — HMAC-SHA256 over the framed claim-envelope.
pub fn sign_workflow_capability(
    claim: WorkflowCapabilityClaim,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedWorkflowCapability> {
    validate_key(key)?;
    validate_identifier(key_id)?;
    claim.validate()?;
    let mut authenticated = Map::new();
    authenticated.insert(
        "algorithm".into(),
        Value::String(WORKFLOW_CAPABILITY_ALGORITHM.to_string()),
    );
    authenticated.insert("claim".into(), claim.to_value());
    authenticated.insert(
        "envelope_schema".into(),
        Value::String(WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA.to_string()),
    );
    authenticated.insert("key_id".into(), Value::String(key_id.to_string()));
    let framed = canonical_framed_payload("claim-envelope", &Value::Object(authenticated))?;
    let signature = hmac_hex(key, &framed);
    Ok(SignedWorkflowCapability {
        envelope_schema: WORKFLOW_CAPABILITY_ENVELOPE_SCHEMA.to_string(),
        algorithm: WORKFLOW_CAPABILITY_ALGORITHM.to_string(),
        claim,
        key_id: key_id.to_string(),
        signature,
    })
}

/// `verify_workflow_capability` — shape + key-id + signature check.
pub fn verify_workflow_capability(
    signed: &SignedWorkflowCapability,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    validate_key(key)?;
    validate_identifier(key_id)?;
    signed.validate_shape()?;
    signed.claim.validate()?;
    if signed.key_id != key_id {
        return err("capability_key_mismatch");
    }
    let expected = sign_workflow_capability(signed.claim.clone(), key, key_id)?.signature;
    if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return err("capability_signature_invalid");
    }
    Ok(())
}

/// `workflow_capability_claim_sha256` — sha256 of the framed signed-claim.
pub fn workflow_capability_claim_sha256(signed: &SignedWorkflowCapability) -> WfResult<String> {
    let framed = canonical_framed_payload("signed-claim", &signed.to_value())?;
    Ok(hex_lower(&Sha256::digest(&framed)))
}

/// `sign_workflow_capability_receipt`.
pub fn sign_workflow_capability_receipt(
    receipt: WorkflowCapabilityReceipt,
    key: &[u8],
    key_id: &str,
) -> WfResult<SignedWorkflowCapabilityReceipt> {
    validate_key(key)?;
    validate_identifier(key_id)?;
    receipt.validate()?;
    let mut authenticated = Map::new();
    authenticated.insert(
        "algorithm".into(),
        Value::String(WORKFLOW_CAPABILITY_ALGORITHM.to_string()),
    );
    authenticated.insert(
        "envelope_schema".into(),
        Value::String(WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA.to_string()),
    );
    authenticated.insert("key_id".into(), Value::String(key_id.to_string()));
    authenticated.insert(
        "receipt".into(),
        serde_json::to_value(&receipt).unwrap_or(Value::Null),
    );
    let framed = canonical_framed_payload("receipt-envelope", &Value::Object(authenticated))?;
    Ok(SignedWorkflowCapabilityReceipt {
        envelope_schema: WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA.to_string(),
        algorithm: WORKFLOW_CAPABILITY_ALGORITHM.to_string(),
        receipt,
        key_id: key_id.to_string(),
        signature: hmac_hex(key, &framed),
    })
}

/// `verify_workflow_capability_receipt` — recompute the envelope signature and
/// compare in constant time. Mirrors `sign_workflow_capability_receipt`'s
/// framed `receipt-envelope` payload.
pub fn verify_workflow_capability_receipt(
    signed: &SignedWorkflowCapabilityReceipt,
    key: &[u8],
    key_id: &str,
) -> WfResult<()> {
    validate_key(key)?;
    validate_identifier(key_id)?;
    if signed.envelope_schema != WORKFLOW_CAPABILITY_RECEIPT_ENVELOPE_SCHEMA {
        return err("unsupported_receipt_envelope");
    }
    if signed.receipt.schema_version != WORKFLOW_CAPABILITY_RECEIPT_SCHEMA {
        return err("unsupported_receipt_schema");
    }
    if signed.algorithm != WORKFLOW_CAPABILITY_ALGORITHM {
        return err("unsupported_receipt_algorithm");
    }
    validate_identifier(&signed.key_id)?;
    validate_sha256(&signed.signature)?;
    if signed.key_id != key_id {
        return err("receipt_key_mismatch");
    }
    let expected = sign_workflow_capability_receipt(signed.receipt.clone(), key, key_id)?.signature;
    if !constant_time_eq(expected.as_bytes(), signed.signature.as_bytes()) {
        return err("receipt_signature_invalid");
    }
    Ok(())
}

fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ─── strict decode helpers ───────────────────────────────────────────────

/// `_strict_object` — payload must be an object with exactly `expected`
/// keys, no more, no fewer.
fn strict_object<'v>(payload: &'v Value, expected: &[&str]) -> WfResult<&'v Map<String, Value>> {
    let m = payload
        .as_object()
        .ok_or(WorkflowCapabilityError("invalid_contract_keys"))?;
    if m.len() != expected.len() || !expected.iter().all(|k| m.contains_key(*k)) {
        return err("invalid_contract_keys");
    }
    Ok(m)
}

fn require<'v>(m: &'v Map<String, Value>, key: &str) -> WfResult<&'v Value> {
    m.get(key)
        .ok_or(WorkflowCapabilityError("invalid_contract_keys"))
}

fn require_str(m: &Map<String, Value>, key: &str) -> WfResult<String> {
    require(m, key)?
        .as_str()
        .map(str::to_string)
        .ok_or(WorkflowCapabilityError("invalid_field_type"))
}

fn hex_lower(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn sha(c: char) -> String {
        c.to_string().repeat(64)
    }
    fn binding() -> WorkflowCapabilityBinding {
        WorkflowCapabilityBinding {
            operation_id: "op-1".into(),
            resource_type: "repo".into(),
            resource_sha256: sha('a'),
            repository_sha256: sha('b'),
            workspace_sha256: sha('c'),
            executable_sha256: sha('d'),
            launch_sha256: sha('e'),
            policy_id: "pol-1".into(),
            policy_version: "v1".into(),
            effect_id: "eff-1".into(),
            effect_version: "v1".into(),
            decision_id: "dec-1".into(),
            decision_version: "v1".into(),
            rules: vec![WorkflowCapabilityRuleBinding {
                rule_id: "rule-1".into(),
                rule_version: "v1".into(),
            }],
        }
    }
    fn claim() -> WorkflowCapabilityClaim {
        WorkflowCapabilityClaim::new(
            "cap-1",
            "prov-1",
            "task-1",
            &"f".repeat(32),
            "issuer",
            "subject",
            binding(),
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T01:00:00.000000Z",
            1,
        )
        .unwrap()
    }
    fn key() -> Vec<u8> {
        (0u8..64).collect()
    }

    #[test]
    fn sign_and_verify_round_trip() {
        let signed = sign_workflow_capability(claim(), &key(), "key-1").unwrap();
        verify_workflow_capability(&signed, &key(), "key-1").unwrap();
        assert_eq!(signed.signature.len(), 64);
    }

    #[test]
    fn verify_rejects_wrong_key() {
        let signed = sign_workflow_capability(claim(), &key(), "key-1").unwrap();
        let bad: Vec<u8> = (0u8..32).map(|x| x ^ 0xff).collect();
        assert_eq!(
            verify_workflow_capability(&signed, &bad, "key-1")
                .unwrap_err()
                .0,
            "capability_signature_invalid"
        );
        assert_eq!(
            verify_workflow_capability(&signed, &key(), "key-2")
                .unwrap_err()
                .0,
            "capability_key_mismatch"
        );
    }

    #[test]
    fn verify_rejects_short_key_and_tampered_signature() {
        let signed = sign_workflow_capability(claim(), &key(), "key-1").unwrap();
        assert_eq!(
            sign_workflow_capability(claim(), &[1u8; 8], "key-1")
                .unwrap_err()
                .0,
            "invalid_capability_key"
        );
        let mut tampered = signed.clone();
        tampered.signature = sha('9');
        assert_eq!(
            verify_workflow_capability(&tampered, &key(), "key-1")
                .unwrap_err()
                .0,
            "capability_signature_invalid"
        );
    }

    #[test]
    fn claim_validates_window_and_nonce() {
        // not_before after expires → invalid window.
        let r = WorkflowCapabilityClaim::new(
            "cap-1",
            "p",
            "t",
            &"f".repeat(32),
            "i",
            "s",
            binding(),
            "2026-01-01T00:00:00.000000Z",
            "2026-01-02T00:00:00.000000Z",
            "2026-01-01T00:00:00.000000Z",
            1,
        );
        assert_eq!(r.unwrap_err().0, "invalid_capability_time_window");
        // bad nonce chars.
        let r = WorkflowCapabilityClaim::new(
            "cap-1",
            "p",
            "t",
            "xyz",
            "i",
            "s",
            binding(),
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T01:00:00.000000Z",
            1,
        );
        assert_eq!(r.unwrap_err().0, "invalid_nonce");
        // TTL > 86400 s.
        let r = WorkflowCapabilityClaim::new(
            "cap-1",
            "p",
            "t",
            &"f".repeat(32),
            "i",
            "s",
            binding(),
            "2026-01-01T00:00:00.000000Z",
            "2026-01-01T00:00:00.000000Z",
            "2026-01-03T00:00:00.000000Z",
            1,
        );
        assert_eq!(r.unwrap_err().0, "capability_ttl_exceeds_alpha_limit");
    }

    #[test]
    fn decode_is_strict_key() {
        let claim = claim();
        let mut v = claim.to_value().as_object().unwrap().clone();
        v.insert("extra".into(), json!(1));
        assert_eq!(
            WorkflowCapabilityClaim::decode(&Value::Object(v))
                .unwrap_err()
                .0,
            "invalid_contract_keys"
        );
    }

    #[test]
    fn framed_payload_is_deterministic_and_length_delimited() {
        let a = canonical_framed_payload("claim-envelope", &json!({"b":2,"a":1})).unwrap();
        let b = canonical_framed_payload("claim-envelope", &json!({"a":1,"b":2})).unwrap();
        assert_eq!(a, b); // canonical key order
        assert!(a.starts_with(FRAME_MAGIC));
        // purpose length + bytes then 8-byte canonical length
        let plen = u32::from_be_bytes([
            a[FRAME_MAGIC.len()],
            a[FRAME_MAGIC.len() + 1],
            a[FRAME_MAGIC.len() + 2],
            a[FRAME_MAGIC.len() + 3],
        ]) as usize;
        assert_eq!(
            &a[FRAME_MAGIC.len() + 4..FRAME_MAGIC.len() + 4 + plen],
            b"claim-envelope"
        );
        let off = FRAME_MAGIC.len() + 4 + plen;
        let clen = u64::from_be_bytes(a[off..off + 8].try_into().unwrap()) as usize;
        assert_eq!(clen, a.len() - off - 8);
    }

    #[test]
    fn claim_sha256_stable() {
        let signed = sign_workflow_capability(claim(), &key(), "key-1").unwrap();
        let s1 = workflow_capability_claim_sha256(&signed).unwrap();
        let s2 = workflow_capability_claim_sha256(&signed).unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64);
    }

    #[test]
    fn identifier_rejects_wildcard_and_bad_shape() {
        assert!(validate_identifier("good.id-1").is_ok());
        assert_eq!(
            validate_identifier("wild*card").unwrap_err().0,
            "invalid_identifier"
        );
        assert_eq!(validate_identifier("").unwrap_err().0, "invalid_identifier");
        assert_eq!(
            validate_identifier("no spaces").unwrap_err().0,
            "invalid_identifier"
        );
        assert!(validate_identifier(&"x".repeat(256)).is_ok());
        assert_eq!(
            validate_identifier(&"x".repeat(257)).unwrap_err().0,
            "invalid_identifier"
        );
    }

    /// Cross-implementation parity oracle: signature + claim-sha256 of the
    /// canonical claim against `workflow_capabilities.py`. The Python oracle
    /// run produced SIG `d39c6c36…` and CLAIMSHA `ee60f27a…` for this exact
    /// claim/key/key_id — any framing/canonicalization drift breaks it.
    #[test]
    fn python_signature_parity() {
        let signed = sign_workflow_capability(claim(), &key(), "key-1").unwrap();
        assert_eq!(
            signed.signature,
            "d39c6c360102b3977d56d7f0e74165ffc93c2d1faf4f6ffe1f68487f086cbbd2"
        );
        assert_eq!(
            workflow_capability_claim_sha256(&signed).unwrap(),
            "ee60f27a6f3c1b1a73f212e0138d6d21d6635b21c59a88fe06117a63c18ecda8"
        );
    }
}
