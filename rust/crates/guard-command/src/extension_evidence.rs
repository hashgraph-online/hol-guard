//! `extension_evidence.py` — immutable, lossless evidence contract for command
//! safety extensions.
//!
//! Every `__post_init__` invariant is enforced by `validate()`, which runs
//! before a value is admitted into the pipeline, exactly as Python's frozen
//! dataclass boundary does. `semantic_key` is emitted as nested `Value` arrays
//! (Python tuples → JSON arrays) because `_extension_evidence_digest` hashes
//! the canonical JSON of that structure byte-for-byte.

use std::sync::LazyLock;

use regex::Regex;
use serde::Serialize;
use serde_json::Value;

use crate::effect_decision::{
    maximum_action_floor, EffectKind, GuardAction, ProofRequirement, UncertaintyKind,
};

static STABLE_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*\z").unwrap());
static SEMANTIC_VERSION: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(
        r"\A(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)(?:-[0-9a-z]+(?:[.-][0-9a-z]+)*)?(?:\+[0-9a-z]+(?:[.-][0-9a-z]+)*)?\z",
    )
    .unwrap()
});
static CANONICAL_REFERENCE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\A[a-z][a-z0-9_-]*:[a-z0-9][a-z0-9._/-]*\z").unwrap());

pub const EXTENSION_EVIDENCE_SCHEMA_VERSION: &str = "1.0.0";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtensionMatchClass {
    Unsafe,
    Uncertainty,
}

impl ExtensionMatchClass {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Unsafe => "unsafe",
            Self::Uncertainty => "uncertainty",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceSeverity {
    Info,
    Low,
    Medium,
    High,
    Critical,
}

impl EvidenceSeverity {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Info => "info",
            Self::Low => "low",
            Self::Medium => "medium",
            Self::High => "high",
            Self::Critical => "critical",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "kebab-case")]
pub enum SafeVariantOutcome {
    OwnedRuleNotRaised,
}

impl SafeVariantOutcome {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnedRuleNotRaised => "owned-rule-not-raised",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionRuleIdentity {
    pub extension_id: String,
    pub extension_version: String,
    pub rule_id: String,
    pub rule_version: String,
}

impl ExtensionRuleIdentity {
    pub fn validate(&self) -> Result<(), &'static str> {
        require_stable_id(&self.extension_id, "extension_id")?;
        require_stable_id(&self.rule_id, "rule_id")?;
        require_stable_version(&self.extension_version, "extension_version")?;
        require_stable_version(&self.rule_version, "rule_version")?;
        if !self.rule_id.starts_with(&format!("{}.", self.extension_id)) {
            return Err("rule_id must be owned by extension_id");
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSafeVariant {
    pub identity: ExtensionRuleIdentity,
    pub safe_variant_id: String,
    pub outcome: SafeVariantOutcome,
}

impl OwnedSafeVariant {
    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        require_stable_id(&self.safe_variant_id, "safe_variant.safe_variant_id")?;
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionEvidence {
    pub identity: ExtensionRuleIdentity,
    pub match_class: ExtensionMatchClass,
    pub severity: EvidenceSeverity,
    pub declared_floor: GuardAction,
    pub base_fact: String,
    pub segment_ref: String,
    pub operation_ref: String,
    pub effect_claims: Vec<EffectKind>,
    pub proof_requirements: Vec<ProofRequirement>,
    pub uncertainty_reasons: Vec<UncertaintyKind>,
    pub safe_variant: Option<OwnedSafeVariant>,
    pub schema_version: String,
}

impl ExtensionEvidence {
    /// `ExtensionEvidence.__post_init__` (extension_evidence.py:113).
    pub fn validate(&self) -> Result<(), &'static str> {
        self.identity.validate()?;
        if self.schema_version != EXTENSION_EVIDENCE_SCHEMA_VERSION {
            return Err("unsupported extension evidence schema version");
        }
        require_stable_id(&self.base_fact, "base_fact")?;
        require_reference(&self.segment_ref, "segment_ref")?;
        require_reference(&self.operation_ref, "operation_ref")?;
        if self.effect_claims.is_empty() {
            return Err("effect_claims must be a non-empty frozenset");
        }
        if self.proof_requirements.is_empty() {
            return Err("proof_requirements must be a non-empty frozenset");
        }
        if let Some(safe_variant) = &self.safe_variant {
            safe_variant.validate()?;
            if safe_variant.identity != self.identity {
                return Err("safe variant must be owned by the exact matched rule identity");
            }
        }
        match self.match_class {
            ExtensionMatchClass::Uncertainty => {
                if self.safe_variant.is_some() {
                    return Err("uncertainty evidence cannot declare a safe variant");
                }
                if self.uncertainty_reasons.is_empty() {
                    return Err("uncertainty evidence requires at least one uncertainty reason");
                }
                let floors: Vec<GuardAction> =
                    self.uncertainty_reasons.iter().map(|u| u.floor()).collect();
                let required_floor = maximum_action_floor(floors.iter());
                if self.declared_floor.severity() < required_floor.severity() {
                    return Err(
                        "uncertainty evidence cannot understate its canonical uncertainty floor",
                    );
                }
            }
            ExtensionMatchClass::Unsafe => {
                if !self.uncertainty_reasons.is_empty() {
                    return Err("unsafe evidence must use a separate uncertainty observation");
                }
                if self.declared_floor.severity() < GuardAction::Review.severity() {
                    return Err("unsafe evidence must declare a review-or-stronger floor");
                }
            }
        }
        Ok(())
    }

    /// `effective_floor`: `None` only when this exact owned match has a safe
    /// outcome.
    pub fn effective_floor(&self) -> Option<GuardAction> {
        if self.safe_variant.is_some() {
            return None;
        }
        Some(self.declared_floor)
    }

    /// `semantic_key` (extension_evidence.py:152) emitted as nested JSON arrays
    /// (Python tuples → JSON arrays) so `_extension_evidence_digest` can hash
    /// the canonical form byte-for-byte.
    pub fn semantic_key(&self) -> Value {
        let safe_key = match &self.safe_variant {
            None => Value::Array(vec![
                Value::from("0"),
                Value::from(""),
                Value::from(""),
                Value::from(""),
                Value::from(""),
                Value::from(""),
                Value::from(""),
            ]),
            Some(safe) => Value::Array(vec![
                Value::from("1"),
                Value::from(safe.identity.extension_id.as_str()),
                Value::from(safe.identity.extension_version.as_str()),
                Value::from(safe.identity.rule_id.as_str()),
                Value::from(safe.identity.rule_version.as_str()),
                Value::from(safe.safe_variant_id.as_str()),
                Value::from(safe.outcome.as_str()),
            ]),
        };
        let mut claims: Vec<String> = self
            .effect_claims
            .iter()
            .map(|kind| kind.as_str().to_owned())
            .collect();
        claims.sort_unstable();
        let mut requirements: Vec<String> = self
            .proof_requirements
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect();
        requirements.sort_unstable();
        let mut uncertainties: Vec<String> = self
            .uncertainty_reasons
            .iter()
            .map(|item| item.as_str().to_owned())
            .collect();
        uncertainties.sort_unstable();
        Value::Array(vec![
            Value::from(self.identity.extension_id.as_str()),
            Value::from(self.identity.extension_version.as_str()),
            Value::from(self.identity.rule_id.as_str()),
            Value::from(self.identity.rule_version.as_str()),
            Value::from(self.segment_ref.as_str()),
            Value::from(self.operation_ref.as_str()),
            Value::from(self.match_class.as_str()),
            Value::from(self.severity.as_str()),
            Value::from(self.declared_floor.as_str()),
            Value::from(self.base_fact.as_str()),
            Value::Array(claims.into_iter().map(Value::from).collect()),
            Value::Array(requirements.into_iter().map(Value::from).collect()),
            Value::Array(uncertainties.into_iter().map(Value::from).collect()),
            safe_key,
            Value::from(self.schema_version.as_str()),
        ])
    }

    /// Canonical JSON bytes of `semantic_key` for ordering/dedup. Two evidence
    /// items compare equal iff these bytes match — Python compares the nested
    /// tuples, which serialize identically, so canonical bytes are a sound
    /// ordering key.
    fn canonical_key(&self) -> Vec<u8> {
        let mut out = Vec::new();
        // Unencodable only if a field violates CPython `json.dumps`; every
        // field is a `String`/enum `as_str` so it always encodes.
        let _ = guard_contracts::write_canonical_json(&self.semantic_key(), &mut out);
        out
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionEvidenceBatch {
    pub evidence: Vec<ExtensionEvidence>,
}

impl ExtensionEvidenceBatch {
    /// `ExtensionEvidenceBatch.__post_init__`: sorts by `semantic_key` and
    /// rejects duplicates.
    pub fn new(mut evidence: Vec<ExtensionEvidence>) -> Result<Self, &'static str> {
        evidence.sort_by_key(ExtensionEvidence::canonical_key);
        for item in &evidence {
            item.validate()?;
        }
        for pair in evidence.windows(2) {
            if pair[0].canonical_key() == pair[1].canonical_key() {
                return Err("duplicate extension evidence is not allowed");
            }
        }
        Ok(Self { evidence })
    }

    /// `evidence_floor`: compose effective floors without inventing a floor for
    /// neutralized evidence.
    pub fn evidence_floor(&self) -> Option<GuardAction> {
        let floors: Vec<GuardAction> = self
            .evidence
            .iter()
            .filter_map(ExtensionEvidence::effective_floor)
            .collect();
        if floors.is_empty() {
            return None;
        }
        Some(maximum_action_floor(floors.iter()))
    }
}

/// `_require_stable_id`: `[a-z][a-z0-9]*(?:[.-][a-z0-9]+)*`, max 128 bytes.
fn require_stable_id(value: &str, _label: &str) -> Result<(), &'static str> {
    if value.len() > 128 || STABLE_ID.find(value).is_none() {
        return Err("must be a stable lowercase identifier");
    }
    Ok(())
}

/// `_require_stable_version`: full semver.
fn require_stable_version(value: &str, _label: &str) -> Result<(), &'static str> {
    if SEMANTIC_VERSION.find(value).is_none() {
        return Err("must be a stable semantic version");
    }
    Ok(())
}

/// `_require_reference`: canonical `prefix:ref`.
fn require_reference(value: &str, _label: &str) -> Result<(), &'static str> {
    if CANONICAL_REFERENCE.find(value).is_none() {
        return Err("must be a canonical reference");
    }
    Ok(())
}
