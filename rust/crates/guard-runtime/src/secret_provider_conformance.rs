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
    if endpoints.is_none_or(|items| items.is_empty()) {
        problems.push("endpoints_missing");
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
            "status": "external",
            "default_enabled": false,
            "endpoints": [{"scheme": "https", "host": "vault.example.test", "port": 443, "redirects": false}]
        });
        assert!(validate(&manifest).is_none());
    }

    #[test]
    fn unsafe_manifest_is_rejected() {
        let manifest = serde_json::json!({
            "schema": "guard.secret-provider.v1",
            "id": "provider.examplevault",
            "status": "external",
            "default_enabled": true,
            "command": "fixture-program",
            "endpoints": [{"scheme": "http", "host": "127.0.0.1", "port": 80, "redirects": true}]
        });
        assert!(validate(&manifest).is_some());
    }
}
