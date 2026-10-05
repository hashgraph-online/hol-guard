use super::*;

/// `_evaluation_targets` (:2167-2175).
// supply_chain_package_eval.py:2167-2175
#[allow(dead_code)]
pub(super) fn evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    deps.manifest.evaluation_targets(
        artifact,
        workspace_dir,
        &targets_from_artifact(artifact),
        false,
    )
}

/// `_cloud_evaluation_targets` (:2178-2187).
// supply_chain_package_eval.py:2178-2187
#[allow(dead_code)]
pub(super) fn cloud_evaluation_targets(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    workspace_dir: Option<&Path>,
) -> Vec<Map<String, Value>> {
    deps.manifest.evaluation_targets(
        artifact,
        workspace_dir,
        &targets_from_artifact(artifact),
        true,
    )
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
        let requested = optional_string(item_map.get("requested_specifier"));
        let raw_spec =
            optional_string(item_map.get("raw_spec")).or_else(|| Some(package_name.clone()));
        let source_url = optional_string(item_map.get("source_url"));
        let source_spec = npm_source_spec(raw_spec.as_deref(), &ecosystem);
        let mut target = Map::new();
        target.insert("ecosystem".to_string(), Value::String(ecosystem));
        target.insert(
            "package_name".to_string(),
            Value::String(package_name.clone()),
        );
        target.insert("name".to_string(), Value::String(name.clone()));
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
                if spec.is_git() {
                    Value::String("git".into())
                } else {
                    Value::Null
                },
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
                Value::String(format!("{:?}", spec.revision_kind)),
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
