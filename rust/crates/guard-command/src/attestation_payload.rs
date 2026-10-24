//! The shape a trust attestation payload has to have before anyone signs or
//! trusts it.
//!
//! `_validate_attestation_payload` in `runtime/trust_attestation.py` is the
//! only door into a signed attestation: the builder goes through it before it
//! hands a payload to a signing key, and the verifier goes through it again
//! before it believes one. Both sides name the payload by the digest of its
//! canonical form, so a Rust twin that accepted a field Python refused — or
//! stripped whitespace somewhere Python left it — would sign and then trust a
//! payload the Python route had never agreed to.
//!
//! The rejections carry Python's own wording so the two runtimes can be read
//! against each other in one fixture.

use serde_json::{Map, Value};

use crate::attestation_timestamp::{parse_attestation_timestamp, python_strip};

/// `GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3`.
pub const GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3: &str = "guard-aibom-trust-attestation.v3";

/// `GUARD_TRUST_ATTESTATION_DOMAIN`.
pub const GUARD_TRUST_ATTESTATION_DOMAIN: &str = "hol-guard:aibom-trust-attestation:v3";

/// `_ATTESTATION_PAYLOAD_REQUIRED_FIELDS`, in sorted order.
const REQUIRED_FIELDS: [&str; 10] = [
    "agentId",
    "capturedAt",
    "claimHash",
    "contentHash",
    "domainSeparator",
    "evidenceHash",
    "itemId",
    "itemKind",
    "payloadVersion",
    "scope",
];

/// `_ATTESTATION_PAYLOAD_OPTIONAL_STRING_FIELDS`, in sorted order.
const OPTIONAL_STRING_FIELDS: [&str; 19] = [
    "adapterId",
    "adapterVersion",
    "analyzerId",
    "analyzerSpecVersion",
    "analyzerVersion",
    "challengeId",
    "configPathHash",
    "deviceId",
    "evidenceSchemaVersion",
    "expiresAt",
    "installationId",
    "layerId",
    "layerType",
    "nonce",
    "policyVersion",
    "repositoryId",
    "signedAt",
    "uploadId",
    "workspaceId",
];

/// `_ATTESTATION_SUBJECT_BINDING_FIELDS`, in sorted order.
const SUBJECT_BINDING_FIELDS: [&str; 5] = [
    "adapterId",
    "adapterVersion",
    "configPathHash",
    "policyVersion",
    "repositoryId",
];

/// The two scopes an attestation may claim.
const SCOPES: [&str; 2] = ["trust_layer", "trust_resolution"];

/// What the caller is validating for.
///
/// Python spells these as three keyword arguments. The builder validates a
/// payload it is about to sign (`require_signed_at: false`, because it has not
/// signed it yet); the verifier validates one that arrived already signed.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AttestationPayloadRules {
    /// `require_signed_at`: the payload must carry a readable `signedAt`, and
    /// when this is false carrying one at all is refused.
    pub require_signed_at: bool,
    /// `require_nonce`: a replay-protected payload has to name its nonce.
    pub require_nonce: bool,
    /// `require_subject_bindings`: every field in
    /// `_ATTESTATION_SUBJECT_BINDING_FIELDS` has to be present.
    pub require_subject_bindings: bool,
}

impl AttestationPayloadRules {
    /// `_validate_attestation_payload(payload, require_signed_at=False)`.
    ///
    /// The one call Python makes while a payload is still being assembled: no
    /// signing time yet, and the nonce and subject bindings are not demanded
    /// until the payload is handed to a key.
    pub const BUILDER: Self = Self {
        require_signed_at: false,
        require_nonce: false,
        require_subject_bindings: false,
    };

    /// The rules both `sign_trust_attestation` and `verify_trust_attestation`
    /// use: `require_signed_at=True, require_nonce=True,
    /// require_subject_bindings=True`.
    ///
    /// A verifier has no say in these. `TrustAttestationVerificationPolicy`
    /// carries its own `require_nonce`, which is the separate, later check
    /// Python makes against the verifier's policy and which defaults to false
    /// there; it does not loosen the nonce a signed payload must already name.
    pub const SIGNED: Self = Self {
        require_signed_at: true,
        require_nonce: true,
        require_subject_bindings: true,
    };
}

/// The payload was refused, with the message Python raises.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationPayloadError(String);

impl AttestationPayloadError {
    /// The refusal, worded as `ValueError`'s argument is.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.0
    }
}

impl std::fmt::Display for AttestationPayloadError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for AttestationPayloadError {}

fn refuse<T>(message: impl Into<String>) -> Result<T, AttestationPayloadError> {
    Err(AttestationPayloadError(message.into()))
}

/// Whether `field` is one of the names the payload may carry at all.
fn is_allowed(field: &str) -> bool {
    REQUIRED_FIELDS.contains(&field)
        || OPTIONAL_STRING_FIELDS.contains(&field)
        || field == "sequence"
}

/// Python's `int` check, minus the `bool` that `isinstance` would let through.
///
/// `json` reads an integer literal as `int` and anything with a point or an
/// exponent as `float`, and `isinstance(1.0, int)` is false. Reading the
/// number back as the text it was written as keeps that split without pinning
/// a width: a sequence larger than `u64` is still an integer to Python, and
/// still one here.
fn is_non_negative_integer(value: &Value) -> bool {
    let Value::Number(number) = value else {
        return false;
    };
    let text = number.to_string();
    // `json.loads` reads `-0` as the `int` `0`, which is not negative, so the
    // sign is only a refusal when some digit under it is not a zero.
    let digits = text.strip_prefix('-').unwrap_or(&text);
    if !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()) {
        return digits.len() == text.len() || digits.bytes().all(|byte| byte == b'0');
    }
    false
}

/// A readable timestamp, by the same reading `_parse_attestation_timestamp` does.
fn reads_as_instant(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|text| parse_attestation_timestamp(text).is_some())
}

/// `_validate_attestation_payload(payload, …)`.
///
/// Returns the payload with every string field stripped, exactly as Python
/// returns its normalized mapping.
///
/// # Errors
///
/// Returns [`AttestationPayloadError`] carrying Python's own wording for an
/// unknown or missing field, a blank string, an unsupported version, domain or
/// scope, an unreadable timestamp, a missing nonce or subject binding, a
/// sequence that is not a non-negative integer, or layer identity that does
/// not match the scope.
pub fn validate_attestation_payload(
    payload: &Map<String, Value>,
    rules: AttestationPayloadRules,
) -> Result<Map<String, Value>, AttestationPayloadError> {
    let mut normalized = payload.clone();

    let mut unknown: Vec<&str> = normalized
        .keys()
        .map(String::as_str)
        .filter(|field| !is_allowed(field))
        .collect();
    unknown.sort_unstable();
    if !unknown.is_empty() {
        return refuse(format!(
            "Unknown trust attestation payload fields: {}",
            unknown.join(", ")
        ));
    }

    let missing: Vec<&str> = REQUIRED_FIELDS
        .iter()
        .copied()
        .filter(|field| !normalized.contains_key(*field))
        .collect();
    if !missing.is_empty() {
        return refuse(format!(
            "Missing trust attestation payload fields: {}",
            missing.join(", ")
        ));
    }

    // Python walks a set, so the field it names first when more than one is
    // blank depends on the run. Walking the names in order names the first
    // one by a rule a reader can follow.
    for field in REQUIRED_FIELDS.iter().chain(OPTIONAL_STRING_FIELDS.iter()) {
        let Some(value) = normalized.get(*field) else {
            continue;
        };
        let stripped = value
            .as_str()
            .map(python_strip)
            .filter(|text| !text.is_empty())
            .ok_or_else(|| {
                AttestationPayloadError(format!(
                    "Trust attestation payload field {field} must be a non-empty string"
                ))
            })?
            .to_owned();
        normalized.insert((*field).to_owned(), Value::String(stripped));
    }

    let field = |name: &str| normalized.get(name).and_then(Value::as_str);
    if field("payloadVersion") != Some(GUARD_TRUST_ATTESTATION_PAYLOAD_VERSION_V3) {
        return refuse("Unsupported trust attestation payload version");
    }
    if field("domainSeparator") != Some(GUARD_TRUST_ATTESTATION_DOMAIN) {
        return refuse("Trust attestation domain separator mismatch");
    }
    let scope = field("scope").unwrap_or_default().to_owned();
    if !SCOPES.contains(&scope.as_str()) {
        return refuse("Unsupported trust attestation scope");
    }
    if !reads_as_instant(normalized.get("capturedAt")) {
        return refuse("Trust attestation capturedAt is invalid");
    }
    if normalized.contains_key("expiresAt") && !reads_as_instant(normalized.get("expiresAt")) {
        return refuse("Trust attestation expiresAt is invalid");
    }
    if rules.require_signed_at {
        if !reads_as_instant(normalized.get("signedAt")) {
            return refuse("Trust attestation signedAt is invalid");
        }
    } else if normalized.contains_key("signedAt") {
        return refuse("Trust attestation builder cannot accept signedAt");
    }
    if rules.require_nonce && !normalized.contains_key("nonce") {
        return refuse("Trust attestation nonce is required");
    }
    if rules.require_subject_bindings {
        let missing_bindings: Vec<&str> = SUBJECT_BINDING_FIELDS
            .iter()
            .copied()
            .filter(|binding| !normalized.contains_key(*binding))
            .collect();
        if !missing_bindings.is_empty() {
            return refuse(format!(
                "Missing trust attestation subject bindings: {}",
                missing_bindings.join(", ")
            ));
        }
    }
    if normalized
        .get("sequence")
        .is_some_and(|sequence| !is_non_negative_integer(sequence))
    {
        return refuse("Trust attestation sequence must be a non-negative integer");
    }
    if scope == "trust_layer" {
        if !normalized.contains_key("layerId") || !normalized.contains_key("layerType") {
            return refuse("Trust layer attestation requires layer identity");
        }
    } else if normalized.contains_key("layerId") || normalized.contains_key("layerType") {
        return refuse("Trust resolution attestation cannot contain layer identity");
    }

    Ok(normalized)
}
