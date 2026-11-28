//! Offline conformance checks for a secret-provider contribution.
//!
//! The command only reads a manifest and emits metadata. It never opens a
//! provider connection or loads a credential.

use std::fs;
use std::path::Path;

use serde::Deserialize;
use serde_json::{json, Value};

pub(crate) const COMMAND: &str = "secret-provider-conformance";
const MAX_MANIFEST_BYTES: u64 = 256 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    manifest: String,
}

pub(crate) fn run_command(bytes: &[u8]) -> Value {
    let Ok(request) = serde_json::from_slice::<Request>(bytes) else {
        return failure("secret_provider_manifest_request_invalid");
    };
    let path = Path::new(&request.manifest);
    let Ok(metadata) = fs::metadata(path) else {
        return failure("secret_provider_manifest_unavailable");
    };
    if !metadata.is_file() || metadata.len() > MAX_MANIFEST_BYTES {
        return failure("secret_provider_manifest_bounds_invalid");
    }
    let Ok(bytes) = fs::read(path) else {
        return failure("secret_provider_manifest_unavailable");
    };
    let Ok(manifest) = serde_json::from_slice::<Value>(&bytes) else {
        return failure("secret_provider_manifest_invalid");
    };
    let Some(problems) = validate(&manifest) else {
        return json!({
            "ok": true,
            "passed": true,
            "provider_id": manifest.get("id"),
            "status": manifest.get("status"),
            "default_enabled": false,
            "local_enablement_required": true,
        });
    };
    json!({"ok": true, "passed": false, "problems": problems})
}

fn validate(manifest: &Value) -> Option<Vec<&'static str>> {
    let mut problems = Vec::new();
    let Some(object) = manifest.as_object() else {
        return Some(vec!["manifest_not_object"]);
    };
    const TOP_LEVEL: &[&str] = &[
        "schema",
        "id",
        "publisher",
        "display_name",
        "status",
        "default_enabled",
        "connection",
        "endpoints",
        "capabilities",
        "references",
        "limits",
        "delivery",
        "responses",
        "privacy",
    ];
    if object.keys().any(|key| !TOP_LEVEL.contains(&key.as_str())) {
        problems.push("unknown_manifest_field");
    }
    for key in TOP_LEVEL {
        if !object.contains_key(*key) {
            problems.push("manifest_field_missing");
            break;
        }
    }
    if manifest.get("schema").and_then(Value::as_str) != Some("guard.secret-provider.v1") {
        problems.push("schema_invalid");
    }
    if manifest.get("id").and_then(Value::as_str).is_none() {
        problems.push("provider_id_missing");
    }
    if manifest.get("default_enabled") != Some(&Value::Bool(false)) {
        problems.push("external_provider_must_be_disabled");
    }
    if manifest.get("status").and_then(Value::as_str) == Some("external")
        && manifest.get("default_enabled") != Some(&Value::Bool(false))
    {
        problems.push("external_provider_opt_in_required");
    }
    let endpoints = manifest.get("endpoints").and_then(Value::as_array);
    if endpoints.is_none_or(|items| {
        items.is_empty()
            || items.iter().any(|item| {
                item.as_object().is_none_or(|endpoint| {
                    endpoint.len() != 5
                        || ["scheme", "host", "port", "paths", "redirects"]
                            .iter()
                            .any(|key| !endpoint.contains_key(*key))
                })
            })
    }) {
        problems.push("endpoints_invalid");
    } else if endpoints.is_some_and(|items| {
        items.iter().any(|item| {
            item.get("scheme").and_then(Value::as_str) != Some("https")
                || item.get("port").and_then(Value::as_u64) != Some(443)
                || item.get("redirects") != Some(&Value::Bool(false))
                || item.get("host").and_then(Value::as_str).is_none_or(|host| {
                    host.parse::<std::net::IpAddr>().is_ok() || host.contains('*')
                })
        })
    }) {
        problems.push("endpoint_trust_invalid");
    }
    if manifest.get("execute").is_some()
        || manifest.get("command").is_some()
        || manifest.get("script").is_some()
    {
        problems.push("provider_execution_fields_forbidden");
    }
    if !manifest
        .get("publisher")
        .and_then(Value::as_object)
        .is_some_and(|publisher| {
            publisher.len() == 2
                && publisher.contains_key("id")
                && publisher.contains_key("display_name")
        })
    {
        problems.push("publisher_invalid");
    }
    if !manifest
        .get("connection")
        .and_then(Value::as_object)
        .is_some_and(|connection| {
            connection.len() == 2
                && connection.contains_key("auth")
                && connection.contains_key("credential_scope")
        })
    {
        problems.push("connection_invalid");
    }
    if !manifest
        .get("references")
        .and_then(Value::as_object)
        .is_some_and(|references| {
            references.len() == 4
                && ["scope_pattern", "name_pattern", "fields", "versions"]
                    .iter()
                    .all(|key| references.contains_key(*key))
        })
    {
        problems.push("references_invalid");
    }
    if !manifest
        .get("limits")
        .and_then(Value::as_object)
        .is_some_and(|limits| {
            limits.len() == 5
                && [
                    "request_bytes",
                    "response_bytes",
                    "json_depth",
                    "timeout_ms",
                    "retries",
                ]
                .iter()
                .all(|key| limits.contains_key(*key))
        })
    {
        problems.push("limits_invalid");
    }
    if !manifest
        .get("responses")
        .and_then(Value::as_object)
        .is_some_and(|responses| {
            (responses.len() == 3 || responses.len() == 4)
                && responses.keys().all(|key| {
                    [
                        "metadata_pointer",
                        "value_pointer",
                        "version_pointer",
                        "lease_pointer",
                    ]
                    .contains(&key.as_str())
                })
                && ["metadata_pointer", "value_pointer", "version_pointer"]
                    .iter()
                    .all(|key| responses.contains_key(*key))
        })
    {
        problems.push("responses_invalid");
    }
    if !manifest
        .get("privacy")
        .and_then(Value::as_object)
        .is_some_and(|privacy| {
            privacy.len() == 3
                && privacy.get("shares_secret_values") == Some(&Value::Bool(false))
                && privacy.get("shares_connection_credentials") == Some(&Value::Bool(false))
                && privacy.get("shares").and_then(Value::as_array).is_some()
        })
    {
        problems.push("privacy_invalid");
    }
    (!problems.is_empty()).then_some(problems)
}

fn failure(code: &'static str) -> Value {
    json!({"ok": false, "error": code})
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn synthetic_manifest_passes_and_external_remains_opt_in() {
        let manifest = serde_json::json!({
            "schema": "guard.secret-provider.v1",
            "id": "provider.examplevault",
            "publisher": {"id": "publisher.example-org", "display_name": "Example Org"},
            "display_name": "Example Vault",
            "status": "external",
            "default_enabled": false,
            "connection": {"auth": ["api_token"], "credential_scope": "provider.examplevault.connection"},
            "endpoints": [{"scheme": "https", "host": "vault.example.test", "port": 443, "paths": ["/v1/fixture/data/team/token"], "redirects": false}],
            "capabilities": ["secret.metadata", "secret.resolve"],
            "references": {"scope_pattern": "fixture", "name_pattern": "fixture", "fields": ["value"], "versions": ["latest", "pinned"]},
            "limits": {"request_bytes": 8192, "response_bytes": 1048576, "json_depth": 8, "timeout_ms": 3000, "retries": 1},
            "delivery": ["environment", "stdin"],
            "responses": {"metadata_pointer": "/data/metadata", "value_pointer": "/data/data/value", "version_pointer": "/data/metadata/version"},
            "privacy": {"shares": ["outcome"], "shares_secret_values": false, "shares_connection_credentials": false}
        });
        assert!(validate(&manifest).is_none());
    }

    #[test]
    fn unsafe_manifest_is_rejected() {
        let manifest = serde_json::json!({
            "schema": "guard.secret-provider.v1",
            "id": "provider.examplevault",
            "publisher": {"id": "publisher.example-org", "display_name": "Example Org"},
            "display_name": "Example Vault",
            "status": "external",
            "default_enabled": true,
            "connection": {"auth": ["api_token"], "credential_scope": "provider.examplevault.connection"},
            "command": "fixture-program",
            "endpoints": [{"scheme": "http", "host": "127.0.0.1", "port": 80, "paths": ["/v1/fixture"], "redirects": true}],
            "capabilities": ["secret.resolve"],
            "references": {"scope_pattern": "fixture", "name_pattern": "fixture", "fields": ["value"], "versions": ["latest"]},
            "limits": {"request_bytes": 8192, "response_bytes": 1024, "json_depth": 8, "timeout_ms": 3000, "retries": 1},
            "delivery": ["stdin"],
            "responses": {"metadata_pointer": "/data/metadata", "value_pointer": "/data/data/value", "version_pointer": "/data/metadata/version"},
            "privacy": {"shares": ["outcome"], "shares_secret_values": false, "shares_connection_credentials": false}
        });
        assert!(validate(&manifest).is_some());
    }
}
