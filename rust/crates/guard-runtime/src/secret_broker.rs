//! Resident secret broker. The broker owns reference parsing, native lookup,
//! exact binding construction and value lifetime. Outward responses contain
//! metadata only. A value is returned only to the delivery module.

use serde::Deserialize;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::secret_reference::SecretReference;
use crate::secret_store_platform::{self, NativeSecret};

pub(crate) const SCHEMA: &str = "guard.secret-broker-request.v1";
pub(crate) const FEATURE: &str = "secret-broker-v1";
const MAX_PURPOSE_BYTES: usize = 128;
const MAX_DIGEST_BYTES: usize = 64;

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Request {
    pub(crate) schema: String,
    pub(crate) operation: String,
    pub(crate) reference: String,
    pub(crate) capability: String,
    pub(crate) sink: String,
    pub(crate) destination: String,
    pub(crate) process_digest: String,
    pub(crate) workspace_digest: String,
    pub(crate) purpose: String,
    pub(crate) policy_digest: String,
    pub(crate) extension_digest: String,
    #[serde(default)]
    pub(crate) approval_binding: Option<String>,
    #[serde(default)]
    pub(crate) version: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Binding {
    pub(crate) provider: String,
    pub(crate) connection: String,
    pub(crate) reference_digest: String,
    pub(crate) version_selector: Option<String>,
    pub(crate) capability: String,
    pub(crate) sink: String,
    pub(crate) destination: String,
    pub(crate) process_digest: String,
    pub(crate) workspace_digest: String,
    pub(crate) purpose: String,
    pub(crate) policy_digest: String,
    pub(crate) extension_digest: String,
}

impl Binding {
    pub(crate) fn digest(&self) -> String {
        let mut hasher = Sha256::new();
        for value in [
            self.provider.as_str(),
            self.connection.as_str(),
            self.reference_digest.as_str(),
            self.version_selector.as_deref().unwrap_or(""),
            self.capability.as_str(),
            self.sink.as_str(),
            self.destination.as_str(),
            self.process_digest.as_str(),
            self.workspace_digest.as_str(),
            self.purpose.as_str(),
            self.policy_digest.as_str(),
            self.extension_digest.as_str(),
        ] {
            hasher.update(value.as_bytes());
            hasher.update([0]);
        }
        hex::encode(hasher.finalize())
    }
}

pub(crate) struct BrokerSecret {
    pub(crate) value: NativeSecret,
    pub(crate) binding: Binding,
}

impl std::fmt::Debug for BrokerSecret {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("BrokerSecret")
            .field("binding_digest", &self.binding.digest())
            .field("value", &"REDACTED")
            .finish()
    }
}

pub(crate) fn evaluate(request: &Request) -> Result<Value, String> {
    let (reference, binding) = validate_request(request)?;
    match request.operation.as_str() {
        "metadata" => Ok(metadata(&reference, &binding)),
        "resolve" | "materialize" => Err("secret_value_delivery_requires_bound_sink".to_owned()),
        _ => Err("secret_broker_operation_unknown".to_owned()),
    }
}

pub(crate) fn resolve_native(request: &Request) -> Result<BrokerSecret, String> {
    let (reference, binding) = validate_request(request)?;
    if request.operation != "resolve" && request.operation != "materialize" {
        return Err("secret_broker_operation_invalid".to_owned());
    }
    let expected = binding.digest();
    if request.approval_binding.as_deref() != Some(expected.as_str()) {
        return Err("secret_approval_required".to_owned());
    }
    if binding.sink == "agent_text"
        || binding.sink == "arguments"
        || binding.sink == "url"
        || binding.sink == "clipboard"
        || binding.sink == "workspace_file"
    {
        return Err("secret_sink_refused".to_owned());
    }
    let value = secret_store_platform::read(&reference.canonical_digest())?
        .ok_or_else(|| "secret_reference_missing".to_owned())?;
    Ok(BrokerSecret { value, binding })
}

fn validate_request(request: &Request) -> Result<(SecretReference, Binding), String> {
    if request.schema != SCHEMA {
        return Err("secret_broker_schema_invalid".to_owned());
    }
    let reference = SecretReference::parse(&request.reference)
        .map_err(|_| "secret_reference_invalid".to_owned())?;
    for value in [
        request.capability.as_str(),
        request.sink.as_str(),
        request.destination.as_str(),
        request.process_digest.as_str(),
        request.workspace_digest.as_str(),
        request.policy_digest.as_str(),
        request.extension_digest.as_str(),
    ] {
        if value.is_empty() || value.len() > MAX_DIGEST_BYTES {
            return Err("secret_binding_invalid".to_owned());
        }
    }
    if request.purpose.is_empty() || request.purpose.len() > MAX_PURPOSE_BYTES {
        return Err("secret_binding_invalid".to_owned());
    }
    if !matches!(
        request.sink.as_str(),
        "environment" | "stdin" | "file_descriptor"
    ) {
        return Err("secret_sink_unsupported".to_owned());
    }
    if request.destination.contains(['\0', '\r', '\n']) {
        return Err("secret_destination_invalid".to_owned());
    }
    if let Some(version) = &request.version {
        if reference.version.as_deref() != Some(version.as_str()) {
            return Err("secret_version_binding_invalid".to_owned());
        }
    }
    let binding = Binding {
        provider: reference.provider.clone(),
        connection: reference.provider.clone(),
        reference_digest: reference.canonical_digest(),
        version_selector: reference.version.clone(),
        capability: request.capability.clone(),
        sink: request.sink.clone(),
        destination: request.destination.clone(),
        process_digest: request.process_digest.clone(),
        workspace_digest: request.workspace_digest.clone(),
        purpose: request.purpose.clone(),
        policy_digest: request.policy_digest.clone(),
        extension_digest: request.extension_digest.clone(),
    };
    Ok((reference, binding))
}

fn metadata(reference: &SecretReference, binding: &Binding) -> Value {
    let state = match secret_store_platform::read(&binding.reference_digest) {
        Ok(Some(_)) => "available",
        Ok(None) => "missing",
        Err(_) => "unavailable",
    };
    json!({
        "ok": true,
        "schema": "guard.secret-result.v1",
        "provider": reference.provider,
        "reference": reference.to_string(),
        "reference_digest": binding.reference_digest,
        "version": reference.version,
        "state": state,
        "capability": binding.capability,
        "sink": binding.sink,
        "binding_digest": binding.digest(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request() -> Request {
        Request {
            schema: SCHEMA.to_owned(),
            operation: "metadata".to_owned(),
            reference: "guard-secret://native/scope/name?version=v1".to_owned(),
            capability: "secret.resolve".to_owned(),
            sink: "environment".to_owned(),
            destination: "TEST_TOKEN".to_owned(),
            process_digest: "a".repeat(64),
            workspace_digest: "b".repeat(64),
            purpose: "fixture".to_owned(),
            policy_digest: "c".repeat(64),
            extension_digest: "d".repeat(64),
            approval_binding: None,
            version: Some("v1".to_owned()),
        }
    }

    #[test]
    fn metadata_is_value_free_and_binding_changes_with_sink() {
        let first = evaluate(&request()).unwrap();
        assert!(first.get("binding_digest").is_some());
        assert!(!first.to_string().contains("fixture-value-7"));
        let mut changed = request();
        changed.sink = "stdin".to_owned();
        assert_ne!(
            evaluate(&request()).unwrap()["binding_digest"],
            evaluate(&changed).unwrap()["binding_digest"]
        );
    }

    #[test]
    fn direct_and_unknown_sinks_are_refused() {
        let mut changed = request();
        changed.sink = "agent_text".to_owned();
        assert_eq!(evaluate(&changed).unwrap_err(), "secret_sink_unsupported");
        changed.sink = "environment".to_owned();
        changed.operation = "resolve".to_owned();
        assert_eq!(
            evaluate(&changed).unwrap_err(),
            "secret_value_delivery_requires_bound_sink"
        );
    }
}
