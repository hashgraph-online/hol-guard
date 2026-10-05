//! Port of `package_execution_context.py` (:1-316) — the pure
//! evidence/identity surface only.
//!
//! `build_package_execution_context` (:101-200) is NOT ported: it reads
//! manifests, configuration files, and VCS state off the filesystem via
//! `package_execution_context_inputs` / `package_execution_context_configuration`
//! — that leg lands with the secure-FS-backed context builder (RTM-026 chain).
//! What is here: the frozen dataclasses, `to_evidence`, the strict
//! `from_evidence` validator (byte-parity component digests), scanner-evidence
//! unwrapping, and `changed_package_execution_context_components`.

use std::collections::BTreeSet;

use guard_contracts::write_canonical_json;
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

/// `PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND` (:30).
pub const PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND: &str = "package_execution_context";
/// `PACKAGE_EXECUTION_CONTEXT_VERSION` (:31).
pub const PACKAGE_EXECUTION_CONTEXT_VERSION: u64 = 2;

/// `_PACKAGE_CONTEXT_COMPONENTS` (:59-70 of launch_identity_binding.py).
/// Lives here so both `launch_identity_binding` and future context callers
/// share one definition.
pub const PACKAGE_CONTEXT_COMPONENTS: &[&str] = &[
    "repository_identity",
    "workspace_identity",
    "package_manager_executable",
    "manifests_and_lockfiles",
    "registry_and_proxy_configuration",
    "workspace_configuration",
    "lifecycle_hooks_overrides_and_patches",
    "environment_policy",
];

/// `_NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS` (:71) = components + `exact_workspace`.
pub const NON_PORTABLE_PACKAGE_CONTEXT_COMPONENTS: &[&str] = &[
    "repository_identity",
    "workspace_identity",
    "package_manager_executable",
    "manifests_and_lockfiles",
    "registry_and_proxy_configuration",
    "workspace_configuration",
    "lifecycle_hooks_overrides_and_patches",
    "environment_policy",
    "exact_workspace",
];

/// `_PACKAGE_LAUNCHERS` (:41-58 of launch_identity_binding.py).
pub const PACKAGE_LAUNCHERS: &[&str] = &[
    "bun", "bunx", "corepack", "npm", "npx", "pip", "pip3", "pipenv", "pipx", "pnpm", "poetry",
    "uv", "uvx", "yarn",
];

/// `PackageExecutionContextComponent` (:75-79).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageExecutionContextComponent {
    pub name: String,
    pub digest: String,
}

/// `PackageExecutionContext` (:82-98).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackageExecutionContext {
    pub digest: String,
    pub portable: bool,
    pub components: Vec<PackageExecutionContextComponent>,
    pub non_portable_reason: Option<String>,
}

impl PackageExecutionContext {
    /// `to_evidence` (:85-98) minus the `changed_components` leg — that field
    /// is appended by callers that have a previous context; use
    /// `to_evidence_with_changes` for parity.
    pub fn to_evidence(&self) -> Value {
        self.to_evidence_with_changes(&[])
    }

    /// `to_evidence` with the `changed_components` payload (:95-97).
    /// `changed_components` is filtered through `dict.fromkeys(item for item
    /// in changed if item)` — dedup preserving order, dropping empties.
    pub fn to_evidence_with_changes(&self, changed_components: &[String]) -> Value {
        let mut payload = Map::new();
        payload.insert(
            "kind".to_string(),
            Value::String(PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND.to_string()),
        );
        payload.insert(
            "schema_version".to_string(),
            Value::Number(PACKAGE_EXECUTION_CONTEXT_VERSION.into()),
        );
        payload.insert(
            "context_digest".to_string(),
            Value::String(self.digest.clone()),
        );
        payload.insert("portable".to_string(), Value::Bool(self.portable));
        payload.insert(
            "components".to_string(),
            Value::Array(
                self.components
                    .iter()
                    .map(|component| json!({"name": component.name, "digest": component.digest}))
                    .collect(),
            ),
        );
        payload.insert(
            "portable_summary".to_string(),
            Value::String(
                if self.portable {
                    "Reusable only across linked Git worktrees when every package execution input matches."
                } else {
                    "Bound to this retry because Guard could not prove a complete portable package context."
                }
                .to_string(),
            ),
        );
        if let Some(reason) = &self.non_portable_reason {
            payload.insert(
                "non_portable_reason".to_string(),
                Value::String(reason.clone()),
            );
        }
        let mut seen = BTreeSet::new();
        let normalized: Vec<Value> = changed_components
            .iter()
            .filter(|item| !item.is_empty())
            .filter(|item| seen.insert((*item).clone()))
            .map(|item| Value::String(item.clone()))
            .collect();
        if !normalized.is_empty() {
            payload.insert("changed_components".to_string(), Value::Array(normalized));
        }
        Value::Object(payload)
    }
}

/// `package_execution_context_from_evidence` (:203-247). Strict validation:
/// returns `None` on any shape or digest violation.
pub fn package_execution_context_from_evidence(value: &Value) -> Option<PackageExecutionContext> {
    let object = value.as_object()?;
    if object.get("kind")?.as_str()? != PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND {
        return None;
    }
    if object.get("schema_version")?.as_u64()? != PACKAGE_EXECUTION_CONTEXT_VERSION {
        return None;
    }
    let digest = sha256_value(object.get("context_digest"))?;
    let portable_value = object.get("portable")?;
    if !portable_value.is_boolean() {
        return None;
    }
    let raw_components = object.get("components")?.as_array()?;
    let mut components: Vec<PackageExecutionContextComponent> = Vec::new();
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for item in raw_components {
        let item = item.as_object()?;
        let name = string_value(item.get("name"))?;
        let component_digest = sha256_value(item.get("digest"))?;
        if seen.contains(&name) {
            return None;
        }
        seen.insert(name.clone());
        components.push(PackageExecutionContextComponent {
            name,
            digest: component_digest,
        });
    }
    if components.is_empty() {
        return None;
    }
    let portable = portable_value.as_bool()?;
    let expected_digest = digest_json(&json!({
        "components": components
            .iter()
            .map(|item| json!({"name": item.name, "digest": item.digest}))
            .collect::<Vec<_>>(),
        "portable": portable,
        "version": PACKAGE_EXECUTION_CONTEXT_VERSION,
    }));
    if digest != expected_digest {
        return None;
    }
    let reason = string_value(object.get("non_portable_reason"));
    Some(PackageExecutionContext {
        digest,
        portable,
        components,
        non_portable_reason: reason,
    })
}

/// `package_execution_context_from_scanner_evidence` (:250-257). First
/// valid context in a scanner evidence array; `None` on non-array or strings.
pub fn package_execution_context_from_scanner_evidence(
    value: &Value,
) -> Option<PackageExecutionContext> {
    let items = value.as_array()?;
    for item in items {
        if let Some(context) = package_execution_context_from_evidence(item) {
            return Some(context);
        }
    }
    None
}

/// `changed_package_execution_context_components` (:260-272): sorted names
/// whose digest differs between previous and current.
pub fn changed_package_execution_context_components(
    previous: &PackageExecutionContext,
    current: &PackageExecutionContext,
) -> Vec<String> {
    let previous: std::collections::BTreeMap<&str, &str> = previous
        .components
        .iter()
        .map(|item| (item.name.as_str(), item.digest.as_str()))
        .collect();
    let current: std::collections::BTreeMap<&str, &str> = current
        .components
        .iter()
        .map(|item| (item.name.as_str(), item.digest.as_str()))
        .collect();
    let mut names: BTreeSet<&str> = previous.keys().copied().collect();
    names.extend(current.keys().copied());
    names
        .into_iter()
        .filter(|name| previous.get(name) != current.get(name))
        .map(|name| name.to_string())
        .collect()
}

/// `_component` (:275-276).
pub fn package_context_component(name: &str, material: &Value) -> PackageExecutionContextComponent {
    PackageExecutionContextComponent {
        name: name.to_string(),
        digest: digest_json(material),
    }
}

/// `_digest_json` (:279-283) = `context_sha256_digest(value,
/// unbound_label="package-context-component", strict=False)` — the
/// byte-identical local canonical-JSON sha256 path (worker output matches
/// byte-for-byte; `strict=False` means the fallback IS the canonical hash).
pub fn digest_json(value: &Value) -> String {
    let mut bytes = Vec::with_capacity(256);
    // canonical_json_unencodable only fires on non-finite floats; context
    // material is digests/strings/bools — treat encode failure as a distinct
    // label instead of panicking.
    if write_canonical_json(value, &mut bytes).is_err() {
        return format!(
            "guard-context-unbound:package-context-component:{}",
            hex::encode(Sha256::digest(b""))
        );
    }
    hex::encode(Sha256::digest(&bytes))
}

/// `_string_value` (:286-287): strip + non-empty.
fn string_value(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?.trim();
    if text.is_empty() {
        None
    } else {
        Some(text.to_string())
    }
}

/// `_sha256_value` (:296-299): lowercase-hex-64 fullmatch.
fn sha256_value(value: Option<&Value>) -> Option<String> {
    let text = value?.as_str()?;
    if text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        Some(text.to_string())
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex64(byte: u8) -> String {
        hex::encode([byte; 32])
    }

    #[test]
    fn digest_json_matches_python_oracle() {
        // python: json.dumps({components:[{name,digest}...],portable:true,
        // version:2}, sort_keys, (",",":"), ensure_ascii) -> sha256
        // = 216ed00c07e7010746a2d02c93359ec47999e63c1244ad92be00bb1eda30a4a4
        let value = json!({
            "components": [
                {"name": "repository_identity", "digest": "a".repeat(64)},
                {"name": "workspace_identity", "digest": "b".repeat(64)},
            ],
            "portable": true,
            "version": 2,
        });
        assert_eq!(
            digest_json(&value),
            "216ed00c07e7010746a2d02c93359ec47999e63c1244ad92be00bb1eda30a4a4"
        );
    }

    fn valid_context() -> PackageExecutionContext {
        let components: Vec<PackageExecutionContextComponent> = PACKAGE_CONTEXT_COMPONENTS
            .iter()
            .enumerate()
            .map(|(i, name)| PackageExecutionContextComponent {
                name: name.to_string(),
                digest: hex64(i as u8),
            })
            .collect();
        let digest = digest_json(&json!({
            "components": components
                .iter()
                .map(|c| json!({"name": c.name, "digest": c.digest}))
                .collect::<Vec<_>>(),
            "portable": true,
            "version": 2,
        }));
        PackageExecutionContext {
            digest,
            portable: true,
            components,
            non_portable_reason: None,
        }
    }

    #[test]
    fn evidence_round_trip_validates() {
        let context = valid_context();
        let evidence = context.to_evidence();
        assert_eq!(evidence["kind"], PACKAGE_EXECUTION_CONTEXT_EVIDENCE_KIND);
        let decoded = package_execution_context_from_evidence(&evidence).unwrap();
        assert_eq!(decoded, context);
    }

    #[test]
    fn tampered_digest_fails_validation() {
        let context = valid_context();
        let mut evidence = context.to_evidence();
        evidence["components"][0]["digest"] = Value::String(hex64(0xff));
        assert!(package_execution_context_from_evidence(&evidence).is_none());
    }

    #[test]
    fn duplicate_component_names_rejected() {
        let context = valid_context();
        let mut evidence = context.to_evidence();
        let first = evidence["components"][0].clone();
        evidence["components"].as_array_mut().unwrap().push(first);
        assert!(package_execution_context_from_evidence(&evidence).is_none());
    }

    #[test]
    fn changed_components_sorted_set_diff() {
        let previous = valid_context();
        let mut current = previous.clone();
        current.components[1].digest = hex64(0xaa);
        let changed = changed_package_execution_context_components(&previous, &current);
        assert_eq!(changed, vec![current.components[1].name.clone()]);
    }
}
