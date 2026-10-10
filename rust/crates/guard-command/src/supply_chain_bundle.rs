//! Rust port of the supply-chain bundle surface:
//!   - `supply_chain_bundle.py` (:61) — public re-export surface.
//!   - `supply_chain_bundle_base.py` — shared parsing primitives and the
//!     exception hierarchy.
//!   - `supply_chain_bundle_models.py` (:478) — frozen dataclasses mirrored
//!     as serde structs with manual `from_dict` validators keeping Python's
//!     fail-closed error strings verbatim.
//!   - `supply_chain_bundle_runtime.py` (:349) — verification and offline
//!     evaluation. RSA-PSS-SHA256 signature verification is a crypto seam
//!     (`RsaPssVerify`) since the default implementation must support
//!     maximum-length RSA-PSS salts and both SPKI and PKCS#1 public keys.

use std::collections::HashMap;
use std::fmt;

use base64ct::{Base64, Encoding};
use guard_contracts::write_canonical_json;
use rsa::pkcs1::DecodeRsaPublicKey;
use rsa::pkcs8::DecodePublicKey;
use rsa::pss::{Signature as RsaPssSignature, VerifyingKey as RsaPssVerifyingKey};
use rsa::signature::Verifier;
use rsa::traits::PublicKeyParts;
use rsa::RsaPublicKey;
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use crate::local_supply_chain::parse_timestamp;
use crate::supply_chain_package_identity::{
    canonical_package_identity, normalize_ecosystem, parse_package_identity,
    CanonicalPackageIdentity,
};

// ---------------------------------------------------------------------------
// `supply_chain_bundle_base` constants (:7-13).
// ---------------------------------------------------------------------------

const BUNDLE_MAX_AGE_SECONDS: f64 = 86_400.0 * 7.0;
const BUNDLE_CLOCK_SKEW_SECONDS: f64 = 300.0;

const PACKAGE_ACTION_VALUES: &[&str] = &["allow", "monitor", "warn", "ask", "block"];
const SEVERITY_VALUES: &[&str] = &["unknown", "low", "medium", "high", "critical"];
const EXPLOIT_LEVEL_VALUES: &[&str] = &["none", "elevated", "active"];
const MALWARE_STATE_VALUES: &[&str] = &["none", "suspected", "known"];
const STALE_STATUS_VALUES: &[&str] = &["fresh", "stale", "unknown"];
const VERIFICATION_KEY_STATE_VALUES: &[&str] = &["active", "grace", "revoked"];

// ---------------------------------------------------------------------------
// `supply_chain_bundle_base` error hierarchy (:16-41) — one enum mirroring
// the exception classes; `kind` preserves the Python subclass identity.
// ---------------------------------------------------------------------------

/// `SupplyChainBundleError` and subclasses — the `kind` discriminant mirrors
/// the concrete Python exception class.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SupplyChainBundleError {
    /// `SupplyChainBundleSignatureError`
    Signature(String),
    /// `SupplyChainBundleExpiredError`
    Expired(String),
    /// `SupplyChainBundleRollbackError`
    Rollback(String),
    /// `SupplyChainBundleMalformedError`
    Malformed(String),
    /// `SupplyChainBundlePayloadHashError`
    PayloadHash(String),
    /// `SupplyChainBundleKeyringError`
    Keyring(String),
}

impl fmt::Display for SupplyChainBundleError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Signature(m)
            | Self::Expired(m)
            | Self::Rollback(m)
            | Self::Malformed(m)
            | Self::PayloadHash(m)
            | Self::Keyring(m) => f.write_str(m),
        }
    }
}

impl std::error::Error for SupplyChainBundleError {}

pub type BundleResult<T> = Result<T, SupplyChainBundleError>;

fn malformed(message: impl Into<String>) -> SupplyChainBundleError {
    SupplyChainBundleError::Malformed(message.into())
}

// ---------------------------------------------------------------------------
// `supply_chain_bundle_base` parsing primitives (:45-97).
// ---------------------------------------------------------------------------

/// `_require_string` (:45).
fn require_string(data: &Map<String, Value>, key: &str) -> BundleResult<String> {
    match data.get(key) {
        Some(Value::String(value)) if !value.trim().is_empty() => Ok(value.trim().to_string()),
        _ => Err(malformed(format!("Missing required string field: {key:?}"))),
    }
}

/// `_optional_string` (:52).
fn optional_string(data: &Map<String, Value>, key: &str) -> BundleResult<Option<String>> {
    match data.get(key) {
        None | Some(Value::Null) => Ok(None),
        Some(Value::String(value)) => {
            let normalized = value.trim();
            Ok((!normalized.is_empty()).then(|| normalized.to_string()))
        }
        _ => Err(malformed(format!(
            "Field must be a string when present: {key:?}"
        ))),
    }
}

/// `_require_int` (:63) — Python `int` accepts any JSON integer.
fn require_int(data: &Map<String, Value>, key: &str) -> BundleResult<i64> {
    match data.get(key) {
        Some(Value::Number(n)) if n.as_i64().is_some() || n.as_u64().is_some() => {
            Ok(n.as_i64().unwrap_or_else(|| n.as_u64().unwrap() as i64))
        }
        _ => Err(malformed(format!("Missing required int field: {key:?}"))),
    }
}

/// `_require_bool` (:70).
fn require_bool(data: &Map<String, Value>, key: &str) -> BundleResult<bool> {
    match data.get(key) {
        Some(Value::Bool(flag)) => Ok(*flag),
        _ => Err(malformed(format!(
            "Missing required boolean field: {key:?}"
        ))),
    }
}

/// `_require_string_array` (:77).
fn require_string_array(data: &Map<String, Value>, key: &str) -> BundleResult<Vec<String>> {
    let Some(Value::Array(items)) = data.get(key) else {
        return Err(malformed(format!("Missing required list field: {key:?}")));
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Value::String(text) if !text.trim().is_empty() => out.push(text.trim().to_string()),
            _ => {
                return Err(malformed(format!(
                    "Field contains invalid string item: {key:?}"
                )))
            }
        }
    }
    Ok(out)
}

/// `_parse_iso_timestamp` (:89) — naive values are UTC; returns unix seconds.
fn parse_iso_timestamp(value: &str, field_name: &str) -> BundleResult<f64> {
    parse_timestamp(value)
        .map(|t| t.unix_seconds() as f64)
        .ok_or_else(|| malformed(format!("Invalid ISO timestamp for {field_name:?}")))
}

/// `_bundle_version_timestamp` (:98).
pub fn bundle_version_timestamp(bundle_version: &str) -> BundleResult<i64> {
    let prefix = bundle_version.split('-').next().unwrap_or("");
    prefix
        .parse::<i64>()
        .map_err(|_| malformed("bundleVersion must start with a unix-ms timestamp prefix"))
}

// ---------------------------------------------------------------------------
// `supply_chain_bundle_models` — dataclass mirrors.
// ---------------------------------------------------------------------------

/// `SupplyChainVerificationKey` (:31).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainVerificationKey {
    pub key_id: String,
    pub public_key_pem: String,
    pub fingerprint_sha256: String,
    pub state: String,
    pub valid_until: Option<String>,
}

impl SupplyChainVerificationKey {
    /// `valid_until_timestamp` (:42) — parsed eagerly in `from_dict`; this
    /// returns the validated timestamp without re-raising.
    pub fn valid_until_timestamp(&self) -> BundleResult<Option<f64>> {
        match &self.valid_until {
            None => Ok(None),
            Some(value) => parse_iso_timestamp(value, "validUntil").map(Some),
        }
    }

    /// `to_dict` (:46).
    pub fn to_dict(&self) -> Value {
        json!({
            "fingerprintSha256": self.fingerprint_sha256,
            "keyId": self.key_id,
            "publicKeyPem": self.public_key_pem,
            "state": self.state,
            "validUntil": self.valid_until,
        })
    }

    /// `from_dict` (:55).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let state = require_string(data, "state")?;
        if !VERIFICATION_KEY_STATE_VALUES.contains(&state.as_str()) {
            return Err(malformed(format!(
                "Unsupported verification key state: {state:?}"
            )));
        }
        let valid_until = optional_string(data, "validUntil")?;
        if let Some(value) = &valid_until {
            parse_iso_timestamp(value, "validUntil")?;
        }
        Ok(Self {
            key_id: require_string(data, "keyId")?,
            public_key_pem: require_string(data, "publicKeyPem")?,
            fingerprint_sha256: require_string(data, "fingerprintSha256")?,
            state,
            valid_until,
        })
    }
}

/// `SupplyChainBundleAdvisory` (:72).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundleAdvisory {
    pub advisory_id: String,
    pub aliases: Vec<String>,
    pub confidence: i64,
    pub exploit_level: String,
    pub known_exploited: bool,
    pub malware_state: String,
    pub normalized_severity: String,
    pub recommended_fix_version: Option<String>,
    pub source_key: String,
    pub summary: String,
    pub title: String,
}

impl SupplyChainBundleAdvisory {
    /// `to_dict` (:89).
    pub fn to_dict(&self) -> Value {
        json!({
            "advisoryId": self.advisory_id,
            "aliases": self.aliases,
            "confidence": self.confidence,
            "exploitLevel": self.exploit_level,
            "knownExploited": self.known_exploited,
            "malwareState": self.malware_state,
            "normalizedSeverity": self.normalized_severity,
            "recommendedFixVersion": self.recommended_fix_version,
            "sourceKey": self.source_key,
            "summary": self.summary,
            "title": self.title,
        })
    }

    /// `from_dict` (:105).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let exploit_level = require_string(data, "exploitLevel")?;
        if !EXPLOIT_LEVEL_VALUES.contains(&exploit_level.as_str()) {
            return Err(malformed(format!(
                "Unsupported advisory exploitLevel: {exploit_level:?}"
            )));
        }
        let malware_state = require_string(data, "malwareState")?;
        if !MALWARE_STATE_VALUES.contains(&malware_state.as_str()) {
            return Err(malformed(format!(
                "Unsupported advisory malwareState: {malware_state:?}"
            )));
        }
        let normalized_severity = require_string(data, "normalizedSeverity")?;
        if !SEVERITY_VALUES.contains(&normalized_severity.as_str()) {
            return Err(malformed(format!(
                "Unsupported advisory normalizedSeverity: {normalized_severity:?}"
            )));
        }
        Ok(Self {
            advisory_id: require_string(data, "advisoryId")?,
            aliases: require_string_array(data, "aliases")?,
            confidence: require_int(data, "confidence")?,
            exploit_level,
            known_exploited: require_bool(data, "knownExploited")?,
            malware_state,
            normalized_severity,
            recommended_fix_version: optional_string(data, "recommendedFixVersion")?,
            source_key: require_string(data, "sourceKey")?,
            summary: require_string(data, "summary")?,
            title: require_string(data, "title")?,
        })
    }
}

/// `SupplyChainBundlePackage` (:129).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundlePackage {
    pub confidence: i64,
    pub default_action: String,
    pub ecosystem: String,
    pub exploit_level: String,
    pub known_exploited: bool,
    pub malware_state: String,
    pub name: String,
    pub namespace: Option<String>,
    pub normalized_severity: String,
    pub package_age_state: String,
    pub purl: String,
    pub reachability: String,
    pub recommended_fix_version: Option<String>,
    pub related_advisory_ids: Vec<String>,
    pub risk_score: i64,
    pub source_integrity_state: String,
    pub version: String,
}

impl SupplyChainBundlePackage {
    /// `to_dict` (:149).
    pub fn to_dict(&self) -> Value {
        json!({
            "confidence": self.confidence,
            "defaultAction": self.default_action,
            "ecosystem": self.ecosystem,
            "exploitLevel": self.exploit_level,
            "knownExploited": self.known_exploited,
            "malwareState": self.malware_state,
            "name": self.name,
            "namespace": self.namespace,
            "normalizedSeverity": self.normalized_severity,
            "packageAgeState": self.package_age_state,
            "purl": self.purl,
            "reachability": self.reachability,
            "recommendedFixVersion": self.recommended_fix_version,
            "relatedAdvisoryIds": self.related_advisory_ids,
            "riskScore": self.risk_score,
            "sourceIntegrityState": self.source_integrity_state,
            "version": self.version,
        })
    }

    /// `from_dict` (:174) — including the legacy Packagist name-split fallback.
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let default_action = require_string(data, "defaultAction")?;
        if !PACKAGE_ACTION_VALUES.contains(&default_action.as_str()) {
            return Err(malformed(format!(
                "Unsupported package defaultAction: {default_action:?}"
            )));
        }
        let exploit_level = require_string(data, "exploitLevel")?;
        if !EXPLOIT_LEVEL_VALUES.contains(&exploit_level.as_str()) {
            return Err(malformed(format!(
                "Unsupported package exploitLevel: {exploit_level:?}"
            )));
        }
        let malware_state = require_string(data, "malwareState")?;
        if !MALWARE_STATE_VALUES.contains(&malware_state.as_str()) {
            return Err(malformed(format!(
                "Unsupported package malwareState: {malware_state:?}"
            )));
        }
        let normalized_severity = require_string(data, "normalizedSeverity")?;
        if !SEVERITY_VALUES.contains(&normalized_severity.as_str()) {
            return Err(malformed(format!(
                "Unsupported package normalizedSeverity: {normalized_severity:?}"
            )));
        }
        let ecosystem = normalize_ecosystem(&require_string(data, "ecosystem")?)
            .map_err(|error| malformed(format!("Invalid package identity: {error}")))?;
        let mut name = require_string(data, "name")?;
        let mut namespace = optional_string(data, "namespace")?;
        if ecosystem == "packagist" && namespace.is_none() && name.matches('/').count() == 1 {
            let legacy_identity = parse_package_identity(&ecosystem, &name, "*")
                .map_err(|error| malformed(format!("Invalid package identity: {error}")))?;
            namespace = legacy_identity.namespace;
            name = legacy_identity.name;
        }
        Ok(Self {
            confidence: require_int(data, "confidence")?,
            default_action,
            ecosystem,
            exploit_level,
            known_exploited: require_bool(data, "knownExploited")?,
            malware_state,
            name,
            namespace,
            normalized_severity,
            package_age_state: require_string(data, "packageAgeState")?,
            purl: require_string(data, "purl")?,
            reachability: require_string(data, "reachability")?,
            recommended_fix_version: optional_string(data, "recommendedFixVersion")?,
            related_advisory_ids: require_string_array(data, "relatedAdvisoryIds")?,
            risk_score: require_int(data, "riskScore")?,
            source_integrity_state: require_string(data, "sourceIntegrityState")?,
            version: require_string(data, "version")?,
        })
    }
}

/// `SupplyChainBundlePolicyRule` (:222).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundlePolicyRule {
    pub action: String,
    pub rule_id: String,
    pub ecosystem_selector: Option<String>,
    pub enabled: Option<bool>,
    pub expires_at: Option<String>,
    pub harness_selector: Option<String>,
    pub package_selector: Option<String>,
    pub priority: Option<i64>,
    pub severity_threshold: Option<String>,
    pub version_range_selector: Option<String>,
}

impl SupplyChainBundlePolicyRule {
    /// `to_dict` (:237).
    pub fn to_dict(&self) -> Value {
        json!({
            "action": self.action,
            "ruleId": self.rule_id,
            "ecosystemSelector": self.ecosystem_selector,
            "enabled": self.enabled,
            "expiresAt": self.expires_at,
            "harnessSelector": self.harness_selector,
            "packageSelector": self.package_selector,
            "priority": self.priority,
            "severityThreshold": self.severity_threshold,
            "versionRangeSelector": self.version_range_selector,
        })
    }

    /// `from_dict` (:251).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let action = require_string(data, "action")?;
        if !(PACKAGE_ACTION_VALUES.contains(&action.as_str()) || action == "review") {
            return Err(malformed(format!("Unsupported policy action: {action:?}")));
        }
        let severity_threshold = optional_string(data, "severityThreshold")?;
        if let Some(threshold) = &severity_threshold {
            if !SEVERITY_VALUES.contains(&threshold.as_str()) {
                return Err(malformed(format!(
                    "Unsupported policy severityThreshold: {threshold:?}"
                )));
            }
        }
        let expires_at = optional_string(data, "expiresAt")?;
        if let Some(value) = &expires_at {
            parse_iso_timestamp(value, "expiresAt")?;
        }
        let enabled = match data.get("enabled") {
            None | Some(Value::Null) => None,
            Some(Value::Bool(flag)) => Some(*flag),
            _ => {
                return Err(malformed(
                    "Policy enabled must be a boolean when present".to_string(),
                ))
            }
        };
        let priority = match data.get("priority") {
            None | Some(Value::Null) => None,
            Some(Value::Number(n)) if n.as_i64().is_some() || n.as_u64().is_some() => {
                Some(n.as_i64().unwrap_or_else(|| n.as_u64().unwrap() as i64))
            }
            _ => {
                return Err(malformed(
                    "Policy priority must be an int when present".to_string(),
                ))
            }
        };
        Ok(Self {
            action,
            rule_id: require_string(data, "ruleId")?,
            ecosystem_selector: optional_string(data, "ecosystemSelector")?,
            enabled,
            expires_at,
            harness_selector: optional_string(data, "harnessSelector")?,
            package_selector: optional_string(data, "packageSelector")?,
            priority,
            severity_threshold,
            version_range_selector: optional_string(data, "versionRangeSelector")?,
        })
    }
}

/// `SupplyChainBundleEmergencyDeny` (:281).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundleEmergencyDeny {
    pub ecosystem: String,
    pub name: String,
    pub namespace: Option<String>,
    pub reason: String,
    pub recommended_fix_version: Option<String>,
}

impl SupplyChainBundleEmergencyDeny {
    /// `to_dict` (:291).
    pub fn to_dict(&self) -> Value {
        json!({
            "ecosystem": self.ecosystem,
            "name": self.name,
            "namespace": self.namespace,
            "reason": self.reason,
            "recommendedFixVersion": self.recommended_fix_version,
        })
    }

    /// `from_dict` (:301).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let ecosystem = normalize_ecosystem(&require_string(data, "ecosystem")?)
            .map_err(|error| malformed(format!("Invalid package identity: {error}")))?;
        Ok(Self {
            ecosystem,
            name: require_string(data, "name")?,
            namespace: optional_string(data, "namespace")?,
            reason: require_string(data, "reason")?,
            recommended_fix_version: optional_string(data, "recommendedFixVersion")?,
        })
    }
}

/// `SupplyChainBundleSourceHash` (:312).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundleSourceHash {
    pub payload_hash: Option<String>,
    pub source_key: String,
    pub stale_status: String,
}

impl SupplyChainBundleSourceHash {
    /// `to_dict` (:323).
    pub fn to_dict(&self) -> Value {
        json!({
            "payloadHash": self.payload_hash,
            "sourceKey": self.source_key,
            "staleStatus": self.stale_status,
        })
    }

    /// `from_dict` (:331).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let payload_hash = optional_string(data, "payloadHash")?;
        let stale_status = require_string(data, "staleStatus")?;
        if !STALE_STATUS_VALUES.contains(&stale_status.as_str()) {
            return Err(malformed(format!(
                "Unsupported source staleStatus: {stale_status:?}"
            )));
        }
        Ok(Self {
            payload_hash,
            source_key: require_string(data, "sourceKey")?,
            stale_status,
        })
    }
}

/// `SupplyChainBundle` (:344).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct SupplyChainBundle {
    pub advisories: Vec<SupplyChainBundleAdvisory>,
    pub bundle_version: String,
    pub emergency_denylist: Vec<SupplyChainBundleEmergencyDeny>,
    pub expires_at: String,
    pub feed_snapshot_hash: String,
    pub generated_at: String,
    pub key_id: String,
    pub packages: Vec<SupplyChainBundlePackage>,
    pub policy_hash: String,
    pub policy_rules: Vec<SupplyChainBundlePolicyRule>,
    pub scoring_version: String,
    pub source_hashes: Vec<SupplyChainBundleSourceHash>,
    pub tier: String,
    pub workspace_id: String,
}

impl SupplyChainBundle {
    /// `generated_at_timestamp` (:359).
    pub fn generated_at_timestamp(&self) -> BundleResult<f64> {
        parse_iso_timestamp(&self.generated_at, "generatedAt")
    }

    /// `expires_at_timestamp` (:363).
    pub fn expires_at_timestamp(&self) -> BundleResult<f64> {
        parse_iso_timestamp(&self.expires_at, "expiresAt")
    }

    /// `version_timestamp` (:367).
    pub fn version_timestamp(&self) -> BundleResult<i64> {
        bundle_version_timestamp(&self.bundle_version)
    }

    /// `to_dict` (:372).
    pub fn to_dict(&self) -> Value {
        json!({
            "advisories": self.advisories.iter().map(|item| item.to_dict()).collect::<Vec<Value>>(),
            "bundleVersion": self.bundle_version,
            "emergencyDenylist": self
                .emergency_denylist
                .iter()
                .map(|item| item.to_dict())
                .collect::<Vec<Value>>(),
            "expiresAt": self.expires_at,
            "feedSnapshotHash": self.feed_snapshot_hash,
            "generatedAt": self.generated_at,
            "keyId": self.key_id,
            "packages": self.packages.iter().map(|item| item.to_dict()).collect::<Vec<Value>>(),
            "policyHash": self.policy_hash,
            "policyRules": self
                .policy_rules
                .iter()
                .map(|item| item.to_dict())
                .collect::<Vec<Value>>(),
            "scoringVersion": self.scoring_version,
            "sourceHashes": self
                .source_hashes
                .iter()
                .map(|item| item.to_dict())
                .collect::<Vec<Value>>(),
            "tier": self.tier,
            "workspaceId": self.workspace_id,
        })
    }

    /// `from_dict` (:394).
    pub fn from_dict(data: &Map<String, Value>) -> BundleResult<Self> {
        let raw_advisories = data.get("advisories");
        let raw_emergency_denylist = data.get("emergencyDenylist");
        let raw_packages = data.get("packages");
        let raw_policy_rules = data.get("policyRules");
        let raw_source_hashes = data.get("sourceHashes");
        let advisories_list = match raw_advisories {
            Some(Value::Array(items)) => items.clone(),
            _ => return Err(malformed("Bundle advisories must be a list".to_string())),
        };
        let denylist_list = match raw_emergency_denylist {
            None | Some(Value::Null) => Vec::new(),
            Some(Value::Array(items)) => items.clone(),
            _ => {
                return Err(malformed(
                    "Bundle emergencyDenylist must be a list".to_string(),
                ))
            }
        };
        let packages_list = match raw_packages {
            Some(Value::Array(items)) => items.clone(),
            _ => return Err(malformed("Bundle packages must be a list".to_string())),
        };
        let rules_list = match raw_policy_rules {
            Some(Value::Array(items)) => items.clone(),
            _ => return Err(malformed("Bundle policyRules must be a list".to_string())),
        };
        let hashes_list = match raw_source_hashes {
            Some(Value::Array(items)) => items.clone(),
            _ => return Err(malformed("Bundle sourceHashes must be a list".to_string())),
        };

        let mut parsed_packages = Vec::with_capacity(packages_list.len());
        for item in &packages_list {
            if let Value::Object(map) = item {
                parsed_packages.push(SupplyChainBundlePackage::from_dict(map)?);
            }
        }
        let packages = deduplicate_bundle_packages(parsed_packages.to_vec())?;
        let mut advisories = Vec::with_capacity(advisories_list.len());
        for item in &advisories_list {
            if let Value::Object(map) = item {
                advisories.push(SupplyChainBundleAdvisory::from_dict(map)?);
            }
        }
        let mut emergency_denylist = Vec::with_capacity(denylist_list.len());
        for item in &denylist_list {
            if let Value::Object(map) = item {
                emergency_denylist.push(SupplyChainBundleEmergencyDeny::from_dict(map)?);
            }
        }
        let mut policy_rules = Vec::with_capacity(rules_list.len());
        for item in &rules_list {
            if let Value::Object(map) = item {
                policy_rules.push(SupplyChainBundlePolicyRule::from_dict(map)?);
            }
        }
        let mut source_hashes = Vec::with_capacity(hashes_list.len());
        for item in &hashes_list {
            if let Value::Object(map) = item {
                source_hashes.push(SupplyChainBundleSourceHash::from_dict(map)?);
            }
        }

        let bundle = Self {
            advisories,
            bundle_version: require_string(data, "bundleVersion")?,
            emergency_denylist,
            expires_at: require_string(data, "expiresAt")?,
            feed_snapshot_hash: require_string(data, "feedSnapshotHash")?,
            generated_at: require_string(data, "generatedAt")?,
            key_id: require_string(data, "keyId")?,
            packages,
            policy_hash: require_string(data, "policyHash")?,
            policy_rules,
            scoring_version: require_string(data, "scoringVersion")?,
            source_hashes,
            tier: require_string(data, "tier")?,
            workspace_id: require_string(data, "workspaceId")?,
        };
        if bundle.advisories.len() != advisories_list.len() {
            return Err(malformed(
                "Bundle advisories must contain only objects".to_string(),
            ));
        }
        if bundle.emergency_denylist.len() != denylist_list.len() {
            return Err(malformed(
                "Bundle emergencyDenylist must contain only objects".to_string(),
            ));
        }
        if parsed_packages_len(&packages_list) != packages_list.len() {
            return Err(malformed(
                "Bundle packages must contain only objects".to_string(),
            ));
        }
        if bundle.policy_rules.len() != rules_list.len() {
            return Err(malformed(
                "Bundle policyRules must contain only objects".to_string(),
            ));
        }
        if bundle.source_hashes.len() != hashes_list.len() {
            return Err(malformed(
                "Bundle sourceHashes must contain only objects".to_string(),
            ));
        }
        // `_ = (generated_at, expires_at, version)` timestamp validation (:454).
        bundle.generated_at_timestamp()?;
        bundle.expires_at_timestamp()?;
        bundle.version_timestamp()?;
        Ok(bundle)
    }
}

/// Count of `isinstance(item, dict)` entries — the pre-dedup length check.
fn parsed_packages_len(raw: &[Value]) -> usize {
    raw.iter().filter(|item| item.is_object()).count()
}

/// `SupplyChainBundleResponse` (:460).
#[derive(Debug, Clone, Default)]
pub struct SupplyChainBundleResponse {
    pub bundle: SupplyChainBundle,
    /// Preserves the exact bundle JSON for hash/signature verification.
    pub signed_bundle: Map<String, Value>,
    pub payload_hash: String,
    pub signature: String,
    pub signature_algorithm: String,
    pub verification_keys: Vec<SupplyChainVerificationKey>,
}

impl SupplyChainBundleResponse {
    /// `to_dict` (:470).
    pub fn to_dict(&self) -> Value {
        json!({
            "bundle": Value::Object(self.signed_bundle.clone()),
            "payloadHash": self.payload_hash,
            "signature": self.signature,
            "signatureAlgorithm": self.signature_algorithm,
            "verificationKeys": self
                .verification_keys
                .iter()
                .map(|item| item.to_dict())
                .collect::<Vec<Value>>(),
        })
    }
}

// ---------------------------------------------------------------------------
// `supply_chain_bundle_package_identity._deduplicate_bundle_packages` (:1).
// ---------------------------------------------------------------------------

fn deduplicate_bundle_packages(
    packages: Vec<SupplyChainBundlePackage>,
) -> BundleResult<Vec<SupplyChainBundlePackage>> {
    let mut by_identity: HashMap<CanonicalPackageIdentity, SupplyChainBundlePackage> =
        HashMap::new();
    let mut ordered: Vec<SupplyChainBundlePackage> = Vec::with_capacity(packages.len());
    for package in packages {
        let identity = canonical_package_identity(
            &package.ecosystem,
            package.namespace.as_deref(),
            &package.name,
            &package.version,
        )
        .map_err(|error| malformed(format!("Invalid package identity: {error}")))?;
        match by_identity.get(&identity) {
            None => {
                by_identity.insert(identity, package.clone());
                ordered.push(package);
            }
            Some(existing) if *existing != package => {
                return Err(malformed(format!(
                    "Conflicting package records for canonical identity {}",
                    identity.display()
                )));
            }
            Some(_) => {}
        }
    }
    Ok(ordered)
}

// ---------------------------------------------------------------------------
// `supply_chain_bundle_runtime` (:1-349).
// ---------------------------------------------------------------------------

/// `OfflineSupplyChainDecision` (:38).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct OfflineSupplyChainDecision {
    pub action: String,
    pub bundle_version: String,
    pub matched_advisory_ids: Vec<String>,
    pub reason: String,
    pub stale: bool,
    pub recommended_fix_version: Option<String>,
    pub emergency_deny: bool,
}

fn now_seconds() -> f64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs_f64())
        .unwrap_or(0.0)
}

/// `canonical_supply_chain_bundle_payload` (:57) — `json.dumps` with
/// `sort_keys=True`, `separators=(",", ":")`, `ensure_ascii=True` (CPython
/// default), `allow_nan=True`.
pub fn canonical_supply_chain_bundle_payload(payload: &Map<String, Value>) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = write_canonical_json(&Value::Object(payload.clone()), &mut out);
    out
}

/// `payload_hash_for_supply_chain_bundle` (:65).
pub fn payload_hash_for_supply_chain_bundle(payload: &Map<String, Value>) -> String {
    let digest = Sha256::digest(canonical_supply_chain_bundle_payload(payload));
    hex::encode(digest)
}

/// `check_supply_chain_bundle_freshness` (:71).
pub fn check_supply_chain_bundle_freshness(
    bundle: &SupplyChainBundle,
    now: Option<f64>,
) -> BundleResult<()> {
    let current_time = now.unwrap_or_else(now_seconds);
    let expires_at_timestamp = bundle.expires_at_timestamp()?;
    if current_time > expires_at_timestamp + BUNDLE_CLOCK_SKEW_SECONDS {
        return Err(SupplyChainBundleError::Expired(format!(
            "Bundle expired at {}, current time is {:.0}",
            bundle.expires_at, current_time
        )));
    }
    let generated_at_timestamp = bundle.generated_at_timestamp()?;
    if current_time < generated_at_timestamp - BUNDLE_CLOCK_SKEW_SECONDS {
        return Err(SupplyChainBundleError::Expired(format!(
            "Bundle generatedAt {} is in the future",
            bundle.generated_at
        )));
    }
    let age = current_time - generated_at_timestamp;
    if age > BUNDLE_MAX_AGE_SECONDS {
        return Err(SupplyChainBundleError::Expired(format!(
            "Bundle age {age:.0}s exceeds maximum allowed age of {BUNDLE_MAX_AGE_SECONDS:.0}s"
        )));
    }
    Ok(())
}

/// `check_supply_chain_bundle_rollback` (:91).
pub fn check_supply_chain_bundle_rollback(
    bundle: &SupplyChainBundle,
    cached_bundle_version: &str,
) -> BundleResult<()> {
    if bundle.version_timestamp()? < bundle_version_timestamp(cached_bundle_version)? {
        return Err(SupplyChainBundleError::Rollback(format!(
            "Bundle version {} is older than cached version {}",
            bundle.bundle_version, cached_bundle_version
        )));
    }
    Ok(())
}

/// `load_supply_chain_bundle_response` (:100) — string input variant.
pub fn load_supply_chain_bundle_response_from_str(
    raw_json: &str,
) -> BundleResult<SupplyChainBundleResponse> {
    let data: Value = serde_json::from_str(raw_json)
        .map_err(|error| malformed(format!("Bundle JSON is invalid: {error}")))?;
    load_supply_chain_bundle_response(&data)
}

/// `load_supply_chain_bundle_response` (:100) — object input variant.
pub fn load_supply_chain_bundle_response(raw: &Value) -> BundleResult<SupplyChainBundleResponse> {
    let data = match raw {
        Value::Object(map) => map,
        _ => return Err(malformed("Bundle root must be a JSON object".to_string())),
    };
    let raw_bundle = match data.get("bundle") {
        Some(Value::Object(map)) => map.clone(),
        _ => {
            return Err(malformed(
                "Bundle response missing bundle object".to_string(),
            ))
        }
    };
    let signature_algorithm = require_string(data, "signatureAlgorithm")?;
    if signature_algorithm != "rsa-pss-sha256" {
        return Err(malformed(
            "Unsupported bundle signature algorithm".to_string(),
        ));
    }
    let verification_keys =
        load_supply_chain_verification_keys(data.get("verificationKeys").cloned().as_ref())?;
    if verification_keys.is_empty() {
        return Err(malformed(
            "Bundle response must include verification keys".to_string(),
        ));
    }
    Ok(SupplyChainBundleResponse {
        bundle: SupplyChainBundle::from_dict(&raw_bundle)?,
        signed_bundle: raw_bundle,
        payload_hash: require_string(data, "payloadHash")?,
        signature: require_string(data, "signature")?,
        signature_algorithm,
        verification_keys,
    })
}

/// `load_supply_chain_verification_keys` (:127).
pub fn load_supply_chain_verification_keys(
    raw: Option<&Value>,
) -> BundleResult<Vec<SupplyChainVerificationKey>> {
    let raw_keys = match raw {
        Some(Value::Object(map)) => map.get("keys").cloned(),
        other => other.cloned(),
    };
    let Some(Value::Array(items)) = raw_keys else {
        return Ok(Vec::new());
    };
    let mut parsed = Vec::with_capacity(items.len());
    for item in &items {
        match item {
            Value::Object(map) => parsed.push(SupplyChainVerificationKey::from_dict(map)?),
            _ => {
                return Err(malformed(
                    "verificationKeys must contain objects".to_string(),
                ))
            }
        }
    }
    Ok(parsed)
}

/// `_validate_key_fingerprints` (:148).
fn validate_key_fingerprints(response: &SupplyChainBundleResponse) -> BundleResult<()> {
    for key in &response.verification_keys {
        if key.fingerprint_sha256 != computed_key_fingerprint(key) {
            return Err(SupplyChainBundleError::Keyring(
                "Verification key fingerprint does not match its public key".to_string(),
            ));
        }
    }
    Ok(())
}

/// `_computed_key_fingerprint` (:155).
fn computed_key_fingerprint(key: &SupplyChainVerificationKey) -> String {
    let normalized_pem = key.public_key_pem.replace("\r\n", "\n").trim().to_string();
    hex::encode(Sha256::digest(normalized_pem.as_bytes()))
}

/// `_signing_key_is_trusted` (:161).
fn signing_key_is_trusted(
    signing_key: &SupplyChainVerificationKey,
    trusted_keys: &[SupplyChainVerificationKey],
) -> bool {
    trusted_keys
        .iter()
        .any(|item| item.fingerprint_sha256 == signing_key.fingerprint_sha256)
}

/// RSA-PSS-SHA256 verification seam (:310-322). `verify` receives the SPKI or
/// PKCS#1 DER extracted from the advertised PEM plus the canonical payload and
/// decoded signature; `Err` maps to `SupplyChainBundleSignatureError`.
pub trait RsaPssVerify {
    fn verify(&self, public_key_der: &[u8], payload: &[u8], signature: &[u8])
        -> Result<(), String>;
}

/// Default seam — verifies RSA-PSS-SHA256 with a maximum-length salt.
pub struct RingRsaPssVerify;

impl RsaPssVerify for RingRsaPssVerify {
    fn verify(
        &self,
        public_key_der: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> Result<(), String> {
        let public_key = match RsaPublicKey::from_public_key_der(public_key_der) {
            Ok(key) => key,
            Err(_) => RsaPublicKey::from_pkcs1_der(public_key_der)
                .map_err(|_| "failed to parse RSA public key".to_string())?,
        };
        let modulus_bits = public_key.n().bits();
        if !(2048..=8192).contains(&modulus_bits) {
            return Err("RSA modulus must be between 2048 and 8192 bits".to_string());
        }
        let encoded_message_len = (modulus_bits - 1).div_ceil(8);
        let salt_len = encoded_message_len - Sha256::output_size() - 2;
        let verifying_key = RsaPssVerifyingKey::<Sha256>::new_with_salt_len(public_key, salt_len);
        let signature = RsaPssSignature::try_from(signature)
            .map_err(|_| "invalid RSA-PSS signature".to_string())?;
        verifying_key
            .verify(payload, &signature)
            .map_err(|_| "RSA-PSS verification failed".to_string())
    }
}

/// Extract DER + confirm the PEM carries an RSA public key.
fn load_rsa_public_key_der(pem: &str) -> Result<Vec<u8>, SupplyChainBundleError> {
    let normalized = pem.replace("\r\n", "\n");
    let mut label: Option<String> = None;
    let mut body_lines: Vec<String> = Vec::new();
    let mut inside = false;
    for line in normalized.lines() {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("-----BEGIN ") {
            if let Some(name) = rest.strip_suffix("-----") {
                label = Some(name.trim().to_string());
                inside = true;
            }
            continue;
        }
        if line.starts_with("-----END ") {
            inside = false;
            continue;
        }
        if inside && !line.is_empty() && !line.contains(':') {
            body_lines.push(line.to_string());
        }
    }
    let label = label.ok_or_else(|| {
        SupplyChainBundleError::Signature(
            "Failed to load verification key: missing PEM armor".to_string(),
        )
    })?;
    let der = Base64::decode_vec(&body_lines.concat()).map_err(|error| {
        SupplyChainBundleError::Signature(format!("Failed to load verification key: {error}"))
    })?;
    // `isinstance(public_key, RSAPublicKey)` — SPKI carries the RSA OID
    // 1.2.840.113549.1.1.1 (DER: 06 09 2a 86 48 86 f7 0d 01 01 01).
    const RSA_OID_DER: &[u8] = &[
        0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
    ];
    let is_rsa = if label == "PUBLIC KEY" {
        der.windows(RSA_OID_DER.len()).any(|w| w == RSA_OID_DER)
    } else {
        label == "RSA PUBLIC KEY"
    };
    if !is_rsa {
        return Err(SupplyChainBundleError::Signature(
            "Verification key must be RSA".to_string(),
        ));
    }
    Ok(der)
}

/// Python `base64.b64decode` — tolerates non-alphabet bytes (whitespace).
fn python_b64decode(value: &str) -> Result<Vec<u8>, String> {
    let filtered: Vec<u8> = value
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'='))
        .collect();
    Base64::decode_vec(&String::from_utf8_lossy(&filtered)).map_err(|e| e.to_string())
}

/// `verify_supply_chain_bundle_response` (:169).
pub fn verify_supply_chain_bundle_response(
    response: &SupplyChainBundleResponse,
    trusted_keys: Option<&[SupplyChainVerificationKey]>,
    cached_bundle_version: Option<&str>,
    now: Option<f64>,
    verifier: &dyn RsaPssVerify,
) -> BundleResult<()> {
    let canonical_payload = canonical_supply_chain_bundle_payload(&response.signed_bundle);
    if hex::encode(Sha256::digest(&canonical_payload)) != response.payload_hash {
        return Err(SupplyChainBundleError::PayloadHash(
            "Bundle payloadHash does not match the canonical payload".to_string(),
        ));
    }
    if let Some(cached) = cached_bundle_version {
        check_supply_chain_bundle_rollback(&response.bundle, cached)?;
    }
    check_supply_chain_bundle_freshness(&response.bundle, now)?;
    let signing_key = response
        .verification_keys
        .iter()
        .find(|item| item.key_id == response.bundle.key_id)
        .ok_or_else(|| {
            SupplyChainBundleError::Keyring(
                "Bundle keyId is not present in the advertised verification keyring".to_string(),
            )
        })?;
    validate_key_fingerprints(response)?;
    if let Some(trusted) = trusted_keys {
        if !trusted.is_empty() && !signing_key_is_trusted(signing_key, trusted) {
            return Err(SupplyChainBundleError::Keyring(
                "Bundle signing key is not anchored to the trusted keyring".to_string(),
            ));
        }
    }
    let current_time = now.unwrap_or_else(now_seconds);
    if signing_key.state == "revoked" {
        return Err(SupplyChainBundleError::Keyring(
            "Revoked verification key cannot sign supply-chain bundles".to_string(),
        ));
    }
    if signing_key.state == "grace" {
        if let Some(valid_until) = signing_key.valid_until_timestamp()? {
            if current_time > valid_until {
                return Err(SupplyChainBundleError::Keyring(
                    "Grace verification key is expired".to_string(),
                ));
            }
        }
    }
    let public_key_der = load_rsa_public_key_der(&signing_key.public_key_pem)?;
    let signature_bytes = python_b64decode(&response.signature).map_err(|error| {
        SupplyChainBundleError::Signature(format!("Signature is not valid base64: {error}"))
    })?;
    verifier
        .verify(&public_key_der, &canonical_payload, &signature_bytes)
        .map_err(|_| {
            SupplyChainBundleError::Signature(
                "Supply-chain bundle signature verification failed".to_string(),
            )
        })
}

/// `evaluate_cached_supply_chain_bundle` (:228).
pub fn evaluate_cached_supply_chain_bundle(
    response: &SupplyChainBundleResponse,
    package_name: &str,
    package_version: Option<&str>,
    ecosystem: Option<&str>,
    now: Option<f64>,
) -> OfflineSupplyChainDecision {
    let stale = check_supply_chain_bundle_freshness(&response.bundle, now)
        .map_err(|error| {
            debug_assert!(matches!(error, SupplyChainBundleError::Expired(_)));
            error
        })
        .is_err();
    let normalized_ecosystem = match ecosystem {
        Some(value) => normalize_ecosystem(value).unwrap_or_default(),
        None => String::new(),
    };
    let ecosystem_opt: Option<String> = if ecosystem.is_some() {
        Some(normalized_ecosystem.clone())
    } else {
        None
    };
    let deny_entries =
        matching_emergency_deny_entries(&response.bundle, package_name, ecosystem_opt.as_deref());
    if let Some(deny_entry) = deny_entries.first() {
        return OfflineSupplyChainDecision {
            action: "block".to_string(),
            bundle_version: response.bundle.bundle_version.clone(),
            matched_advisory_ids: Vec::new(),
            reason: deny_entry.reason.clone(),
            stale,
            recommended_fix_version: deny_entry.recommended_fix_version.clone(),
            emergency_deny: true,
        };
    }
    let matches: Vec<&SupplyChainBundlePackage> = response
        .bundle
        .packages
        .iter()
        .filter(|item| {
            (ecosystem_opt.is_none() || item.ecosystem == normalized_ecosystem)
                && package_matches(item, package_name, package_version)
        })
        .collect();
    if matches.is_empty() {
        return OfflineSupplyChainDecision {
            action: "monitor".to_string(),
            bundle_version: response.bundle.bundle_version.clone(),
            matched_advisory_ids: Vec::new(),
            reason: "no_cached_match".to_string(),
            stale,
            recommended_fix_version: None,
            emergency_deny: false,
        };
    }
    let package = matches
        .iter()
        .rev()
        .max_by_key(|item| item.risk_score)
        .expect("non-empty matches");
    if let Some(blocking_reason) = blocking_bundle_reason(package) {
        return OfflineSupplyChainDecision {
            action: "block".to_string(),
            bundle_version: response.bundle.bundle_version.clone(),
            matched_advisory_ids: package.related_advisory_ids.clone(),
            reason: blocking_reason.to_string(),
            stale,
            recommended_fix_version: None,
            emergency_deny: false,
        };
    }
    if stale {
        return OfflineSupplyChainDecision {
            action: "monitor".to_string(),
            bundle_version: response.bundle.bundle_version.clone(),
            matched_advisory_ids: package.related_advisory_ids.clone(),
            reason: "stale_low_confidence".to_string(),
            stale: true,
            recommended_fix_version: None,
            emergency_deny: false,
        };
    }
    OfflineSupplyChainDecision {
        action: if package.default_action != "allow" {
            package.default_action.clone()
        } else {
            "monitor".to_string()
        },
        bundle_version: response.bundle.bundle_version.clone(),
        matched_advisory_ids: package.related_advisory_ids.clone(),
        reason: "bundle_match".to_string(),
        stale: false,
        recommended_fix_version: None,
        emergency_deny: false,
    }
}

/// `_matching_emergency_deny_entries` (:298).
fn matching_emergency_deny_entries<'a>(
    bundle: &'a SupplyChainBundle,
    package_name: &str,
    ecosystem: Option<&str>,
) -> Vec<&'a SupplyChainBundleEmergencyDeny> {
    bundle
        .emergency_denylist
        .iter()
        .filter(|item| {
            (ecosystem.is_none() || item.ecosystem == ecosystem.unwrap_or_default())
                && emergency_deny_identity_matches(item, package_name)
        })
        .collect()
}

/// `_emergency_deny_identity_matches` (:305).
fn emergency_deny_identity_matches(
    entry: &SupplyChainBundleEmergencyDeny,
    package_name: &str,
) -> bool {
    package_identity_matches(
        &entry.ecosystem,
        entry.namespace.as_deref(),
        &entry.name,
        package_name,
    )
}

/// `_is_high_confidence_block` (:310).
fn is_high_confidence_block(package: &SupplyChainBundlePackage) -> bool {
    package.default_action == "block"
        && (package.known_exploited
            || package.malware_state == "known"
            || (package.normalized_severity == "critical" && package.exploit_level == "active"))
}

/// `_blocking_bundle_reason` (:315).
fn blocking_bundle_reason(package: &SupplyChainBundlePackage) -> Option<&'static str> {
    if is_high_confidence_block(package) {
        return Some("known_malware_or_kev");
    }
    if package.default_action == "block"
        && package.source_integrity_state == "high-risk"
        && matches!(package.exploit_level.as_str(), "active" | "elevated")
        && matches!(package.normalized_severity.as_str(), "high" | "critical")
    {
        return Some("maintainer_compromise");
    }
    None
}

/// `_package_matches` (:328).
fn package_matches(
    package: &SupplyChainBundlePackage,
    package_name: &str,
    package_version: Option<&str>,
) -> bool {
    if !package_identity_matches(
        &package.ecosystem,
        package.namespace.as_deref(),
        &package.name,
        package_name,
    ) {
        return false;
    }
    package_version.is_none() || package.version == package_version.unwrap_or_default()
}

/// `_package_identity_matches` (:333).
fn package_identity_matches(
    ecosystem: &str,
    namespace: Option<&str>,
    name: &str,
    package_name: &str,
) -> bool {
    let package_identity = canonical_package_identity(ecosystem, namespace, name, "*");
    let target_identity = parse_package_identity(ecosystem, package_name, "*");
    match (package_identity, target_identity) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}
