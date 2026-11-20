//! The payloads `runtime/trust_attestation.py` signs, spelled and checked here.
//!
//! - `{"op": "build", "fields": {...}}` spells the builder's snake_case
//!   `fields` as an unsigned payload and answers as the `payload` op does with
//!   every rule off.
//! - `{"op": "sign_plan", "resolution": ..., "layers": ..., "fields": {...}}`
//!   answers `{"resolution": claim | null, "layers": [claim], "signing": [...]}`.
//!   The claims are the ones `claims` admits. Each `signing` entry names its
//!   claim (`"layer": null` for the resolution, otherwise the index into
//!   `layers`), the `signed_at` time, the `bindings` recorded beside the
//!   signature, and either the validated `payload` or the `refused` message. A
//!   claim without an evidence hash, evidence schema version, capture time or,
//!   for a layer, its layer identity is admitted but not signed. `fields` must
//!   carry a non-empty `nonce`; workspace and device fields turn on the
//!   analyzer bindings.

use guard_command::attestation_payload::AttestationPayloadRules;
use serde_json::{json, Map, Value};

use crate::runner_authority_op::{KindResult, ERR_INVALID};

const PAYLOAD_VERSION: &str = "guard-aibom-trust-attestation.v3";
const DOMAIN_SEPARATOR: &str = "hol-guard:aibom-trust-attestation:v3";
const DEFAULT_POLICY_VERSION: &str = "guard-local-policy:default";

const REQUIRED: [(&str, &str); 7] = [
    ("agent_id", "agentId"),
    ("item_id", "itemId"),
    ("item_kind", "itemKind"),
    ("content_hash", "contentHash"),
    ("captured_at", "capturedAt"),
    ("evidence_hash", "evidenceHash"),
    ("scope", "scope"),
];
const OPTIONAL: [(&str, &str); 20] = [
    ("analyzer_id", "analyzerId"),
    ("analyzer_version", "analyzerVersion"),
    ("analyzer_spec_version", "analyzerSpecVersion"),
    ("evidence_schema_version", "evidenceSchemaVersion"),
    ("policy_version", "policyVersion"),
    ("workspace_id", "workspaceId"),
    ("device_id", "deviceId"),
    ("installation_id", "installationId"),
    ("upload_id", "uploadId"),
    ("challenge_id", "challengeId"),
    ("nonce", "nonce"),
    ("sequence", "sequence"),
    ("expires_at", "expiresAt"),
    ("layer_id", "layerId"),
    ("layer_type", "layerType"),
    ("adapter_id", "adapterId"),
    ("adapter_version", "adapterVersion"),
    ("config_path_hash", "configPathHash"),
    ("repository_id", "repositoryId"),
    ("claim_hash", "claimHash"),
];
/// Subject fields every signature's bindings repeat.
const BOUND: [(&str, &str); 11] = [
    ("challenge_id", "challengeId"),
    ("device_id", "deviceId"),
    ("expires_at", "expiresAt"),
    ("installation_id", "installationId"),
    ("sequence", "sequence"),
    ("upload_id", "uploadId"),
    ("workspace_id", "workspaceId"),
    ("adapter_id", "adapterId"),
    ("adapter_version", "adapterVersion"),
    ("config_path_hash", "configPathHash"),
    ("repository_id", "repositoryId"),
];
/// Bound, and signed, only alongside a workspace or device.
const ANALYZER: [(&str, &str); 3] = [
    ("analyzer_id", "analyzerId"),
    ("analyzer_spec_version", "analyzerSpecVersion"),
    ("analyzer_version", "analyzerVersion"),
];

fn present<'a>(fields: &'a Map<String, Value>, name: &str) -> Option<&'a Value> {
    fields.get(name).filter(|value| !value.is_null())
}

fn text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
}

fn fields_arg(args: &Map<String, Value>) -> Result<&Map<String, Value>, &'static str> {
    args.get("fields")
        .and_then(Value::as_object)
        .ok_or(ERR_INVALID)
}

/// The unvalidated payload the verifier reads, spelled from builder fields.
fn spelled(fields: &Map<String, Value>) -> Value {
    let mut payload = Map::new();
    payload.insert("payloadVersion".into(), json!(PAYLOAD_VERSION));
    payload.insert("domainSeparator".into(), json!(DOMAIN_SEPARATOR));
    for (name, key) in REQUIRED {
        let value = fields.get(name).cloned().unwrap_or(Value::Null);
        payload.insert(key.into(), value);
    }
    for (name, key) in OPTIONAL {
        if let Some(value) = present(fields, name) {
            payload.insert(key.into(), value.clone());
        }
    }
    Value::Object(payload)
}

pub(super) fn build(args: &Map<String, Value>) -> KindResult {
    super::verdict(
        &spelled(fields_arg(args)?),
        AttestationPayloadRules::BUILDER,
    )
}

/// The item's subject: the payload fields every claim shares, and the
/// bindings every signature records.
struct Subject {
    fields: Map<String, Value>,
    bindings: Map<String, Value>,
}

impl Subject {
    fn new(raw: &Map<String, Value>) -> Result<Self, &'static str> {
        let nonce = text(raw.get("nonce")).ok_or(ERR_INVALID)?;
        let policy_version = text(raw.get("policy_version")).unwrap_or(DEFAULT_POLICY_VERSION);
        let analyzer =
            present(raw, "workspace_id").is_some() || present(raw, "device_id").is_some();
        let mut fields = raw.clone();
        let mut bindings = Map::new();
        bindings.insert("domainSeparator".into(), json!(DOMAIN_SEPARATOR));
        for (name, key) in BOUND {
            if let Some(value) = present(raw, name) {
                bindings.insert(key.into(), value.clone());
            }
        }
        for (name, key) in ANALYZER {
            match present(raw, name) {
                Some(value) if analyzer => {
                    bindings.insert(key.into(), value.clone());
                }
                _ => {
                    fields.remove(name);
                }
            }
        }
        fields.insert("policy_version".into(), json!(policy_version));
        bindings.insert("nonce".into(), json!(nonce));
        bindings.insert("policyVersion".into(), json!(policy_version));
        Ok(Self { fields, bindings })
    }

    /// The signing entry for one admitted claim, or `null` when it is not signed.
    fn entry(&self, admitted: &Value, layer: Value) -> KindResult {
        let Some(claim) = admitted.get("claim").and_then(Value::as_object) else {
            return Ok(Value::Null);
        };
        let claim_hash = admitted.get("claim_hash").cloned().unwrap_or(Value::Null);
        let metadata = claim.get("metadata").and_then(Value::as_object);
        let evidence = |key: &str| text(metadata.and_then(|metadata| metadata.get(key)));
        let (Some(evidence_hash), Some(schema), Some(captured_at)) = (
            evidence("evidenceHash"),
            evidence("evidenceSchemaVersion"),
            text(claim.get("capturedAt")),
        ) else {
            return Ok(Value::Null);
        };
        let mut fields = self.fields.clone();
        let scope = if layer.is_null() {
            "trust_resolution"
        } else {
            let (Some(layer_id), Some(layer_type)) =
                (text(claim.get("layerId")), text(claim.get("layerType")))
            else {
                return Ok(Value::Null);
            };
            fields.insert("layer_id".into(), json!(layer_id));
            fields.insert("layer_type".into(), json!(layer_type));
            "trust_layer"
        };
        fields.insert("captured_at".into(), json!(captured_at));
        fields.insert("evidence_hash".into(), json!(evidence_hash));
        fields.insert("evidence_schema_version".into(), json!(schema));
        fields.insert("scope".into(), json!(scope));
        fields.insert("claim_hash".into(), claim_hash.clone());
        let mut payload = spelled(&fields);
        if let Some(payload) = payload.as_object_mut() {
            payload.insert("signedAt".into(), json!(captured_at));
        }
        let mut entry = match super::verdict(&payload, AttestationPayloadRules::SIGNED)? {
            Value::Object(entry) => entry,
            _ => return Err(ERR_INVALID),
        };
        let mut bindings = self.bindings.clone();
        bindings.insert("evidenceSchemaVersion".into(), json!(schema));
        bindings.insert("claimHash".into(), claim_hash);
        entry.insert("layer".into(), layer);
        entry.insert("signed_at".into(), json!(captured_at));
        entry.insert("bindings".into(), Value::Object(bindings));
        Ok(Value::Object(entry))
    }
}

pub(super) fn sign_plan(args: &Map<String, Value>) -> KindResult {
    let subject = Subject::new(fields_arg(args)?)?;
    let admitted = super::claims(args)?;
    let resolution = &admitted["resolution"];
    let layers = admitted["layers"].as_array().ok_or(ERR_INVALID)?;
    let mut signing = Vec::new();
    let resolution_entry = subject.entry(resolution, Value::Null)?;
    if !resolution_entry.is_null() {
        signing.push(resolution_entry);
    }
    for (index, layer) in layers.iter().enumerate() {
        let entry = subject.entry(layer, json!(index))?;
        if !entry.is_null() {
            signing.push(entry);
        }
    }
    let claim = |admitted: &Value| admitted.get("claim").cloned().unwrap_or(Value::Null);
    Ok(json!({
        "resolution": claim(resolution),
        "layers": layers.iter().map(claim).collect::<Vec<Value>>(),
        "signing": signing,
    }))
}

#[cfg(test)]
#[path = "trust_attestation_plan_tests.rs"]
mod tests;
