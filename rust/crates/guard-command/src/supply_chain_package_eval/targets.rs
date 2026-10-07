use super::manifest_dependency_targets::manifest_dependency_targets;
use super::manifest_versions::{
    default_registry_range, source_url_from_raw_spec, source_url_from_specifier,
};
use super::*;

/// `_evaluation_targets` (:2167-2175).
// supply_chain_package_eval.py:2167-2175
#[allow(dead_code)]
pub(super) fn evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    let explicit = targets_from_artifact(artifact);
    if !explicit.is_empty() {
        return explicit;
    }
    let intent_kind = optional_string(artifact.metadata.get("intent_kind"));
    if !matches!(
        intent_kind.as_deref(),
        None | Some("install") | Some("sync")
    ) {
        return Vec::new();
    }
    manifest_dependency_targets(deps, artifact, workspace_dir, false)
}

/// `_cloud_evaluation_targets` (:2178-2187).
// supply_chain_package_eval.py:2178-2187
#[allow(dead_code)]
pub(super) fn cloud_evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    let explicit = targets_from_artifact(artifact);
    if !explicit.is_empty() {
        return explicit;
    }
    let intent_kind = optional_string(artifact.metadata.get("intent_kind"));
    if !matches!(
        intent_kind.as_deref(),
        None | Some("install") | Some("sync")
    ) {
        return Vec::new();
    }
    manifest_dependency_targets(deps, artifact, workspace_dir, true)
}

/// `_targets_from_artifact` (:2190-2254).
// supply_chain_package_eval.py:2190-2254
#[allow(dead_code)]
pub(super) fn targets_from_artifact(artifact: &GuardArtifact) -> Vec<Map<String, Value>> {
    let public_targets = artifact.metadata.get("targets");
    let Some(public_arr) = public_targets.and_then(Value::as_array) else {
        return Vec::new();
    };
    let private_targets = artifact
        .runtime_private_metadata
        .get("package_targets")
        .and_then(Value::as_array);
    let (raw_targets, private_integrity_invalid): (&[Value], bool) = match private_targets {
        Some(private_arr) => {
            let invalid = !private_package_targets_match_public(private_arr, public_arr);
            if invalid {
                (public_arr.as_slice(), true)
            } else {
                (private_arr.as_slice(), false)
            }
        }
        None => (
            public_arr.as_slice(),
            !public_package_targets_are_self_consistent(public_arr),
        ),
    };
    let package_manager = optional_string(artifact.metadata.get("package_manager"))
        .unwrap_or_else(|| "npm".to_string());
    let redacted_command = optional_string(artifact.metadata.get("redacted_command"));
    let mut parsed: Vec<Map<String, Value>> = Vec::new();
    for item in raw_targets {
        let Some(item_map) = item.as_object() else {
            continue;
        };
        let ecosystem =
            optional_string(item_map.get("ecosystem")).unwrap_or_else(|| "npm".to_string());
        let Some(package_name) = optional_string(item_map.get("package_name")) else {
            continue;
        };
        let (namespace, name) = split_namespace_name(&package_name, &ecosystem);
        let mut requested = optional_string(item_map.get("requested_specifier"));
        let raw_spec =
            optional_string(item_map.get("raw_spec")).or_else(|| Some(package_name.clone()));
        let source_url = optional_string(item_map.get("source_url"))
            .or_else(|| source_url_from_specifier(requested.as_deref()))
            .or_else(|| {
                if item_map.contains_key("source_kind") {
                    None
                } else {
                    raw_spec.as_deref().and_then(source_url_from_raw_spec)
                }
            });
        if source_url.is_some() {
            requested = None;
        } else if requested.is_none() {
            requested = default_registry_range(&ecosystem).map(str::to_owned);
        }
        let source_spec = npm_source_spec(source_url.as_deref(), &ecosystem);
        let version = requested
            .as_deref()
            .filter(|specifier| !requested_specifier_is_range(Some(specifier), &ecosystem));
        let version = version.and_then(exact_version);
        let normalized = crate::supply_chain_package_identity::normalize_qualified_package_name(
            &ecosystem,
            &package_name,
        )
        .unwrap_or_else(|_| package_name.trim().to_string());
        let mut target = Map::new();
        target.insert("ecosystem".to_string(), Value::String(ecosystem));
        target.insert(
            "package_name".to_string(),
            Value::String(package_name.clone()),
        );
        target.insert("name".to_string(), Value::String(name.clone()));
        target.insert("normalized_name".to_string(), Value::String(normalized));
        target.insert(
            "range".to_string(),
            if version.is_none() {
                requested.clone().map(Value::String).unwrap_or(Value::Null)
            } else {
                Value::Null
            },
        );
        target.insert(
            "version".to_string(),
            version.map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "namespace".to_string(),
            namespace.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "requested_specifier".to_string(),
            requested.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "raw_spec".to_string(),
            raw_spec.clone().map(Value::String).unwrap_or(Value::Null),
        );
        target.insert(
            "source_url".to_string(),
            source_url.clone().map(Value::String).unwrap_or(Value::Null),
        );
        if let Some(spec) = &source_spec {
            target.insert(
                "source_kind".to_string(),
                Value::String(spec.source_kind.as_str().to_owned()),
            );
            target.insert(
                "source_repository".to_string(),
                spec.canonical_repository
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
            target.insert(
                "source_revision_kind".to_string(),
                Value::String(spec.revision_kind.as_str().to_owned()),
            );
            target.insert(
                "source_identity".to_string(),
                Value::String(spec.identity.clone()),
            );
            target.insert(
                "source_redacted".to_string(),
                Value::String(spec.redacted.clone()),
            );
            target.insert(
                "source_invalid_reason".to_string(),
                spec.reason
                    .clone()
                    .map(Value::String)
                    .unwrap_or(Value::Null),
            );
        } else {
            target.insert("source_kind".to_string(), Value::Null);
            target.insert("source_repository".to_string(), Value::Null);
            target.insert("source_revision_kind".to_string(), Value::Null);
            target.insert("source_identity".to_string(), Value::Null);
            target.insert("source_redacted".to_string(), Value::Null);
            target.insert("source_invalid_reason".to_string(), Value::Null);
        }
        target.insert(
            "alias".to_string(),
            optional_string(item_map.get("alias"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "dependency_group".to_string(),
            optional_string(item_map.get("dependency_group"))
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "extras".to_string(),
            Value::Array(
                string_tuple(item_map.get("extras"))
                    .into_iter()
                    .map(Value::String)
                    .collect(),
            ),
        );
        target.insert(
            "editable".to_string(),
            Value::Bool(item_map.get("editable") == Some(&Value::Bool(true))),
        );
        target.insert(
            "package_manager".to_string(),
            Value::String(package_manager.clone()),
        );
        target.insert(
            "redacted_command".to_string(),
            redacted_command
                .clone()
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        target.insert(
            "external_archive_source_integrity_invalid".to_string(),
            Value::Bool(private_integrity_invalid),
        );
        parsed.push(target);
    }
    parsed
}

pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(bytes))
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn named_https_archive_uses_source_url_not_install_spec() {
        let source = "https://packages.example.com/demo.tgz";
        for source_fields in [
            json!({"source_url": source, "requested_specifier": "^1.0.0"}),
            json!({"requested_specifier": source}),
            json!({}),
        ] {
            let Value::Object(mut item) = source_fields else {
                unreachable!("source fixture must be an object");
            };
            item.insert("ecosystem".into(), json!("npm"));
            item.insert("package_name".into(), json!("demo"));
            item.insert("raw_spec".into(), json!(format!("demo@{source}")));
            let artifact = GuardArtifact {
                artifact_id: "archive-source".into(),
                name: "demo".into(),
                harness: "guard-cli".into(),
                artifact_type: "package_request".into(),
                source_scope: "project".into(),
                config_path: "guard.json".into(),
                command: None,
                args: Vec::new(),
                url: None,
                transport: None,
                publisher: None,
                metadata: json!({"package_manager": "npm", "targets": [item]}),
                runtime_private_metadata: Value::Null,
            };
            let targets = targets_from_artifact(&artifact);
            let target = &targets[0];
            assert_eq!(target["source_url"], source);
            assert_eq!(target["source_kind"], "url");
            assert_eq!(target["source_invalid_reason"], Value::Null);
            assert_eq!(target["requested_specifier"], Value::Null);
            assert_eq!(target["version"], Value::Null);
            assert_eq!(target["external_archive_source_integrity_invalid"], false);
            assert!(target_is_external_https_archive(target));
        }
    }
}
