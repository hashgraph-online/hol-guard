use super::*;

/// `_local_trust_domain_for_artifact(artifact, *, item_kind, metadata, workspace_dir)`
pub(super) fn _local_trust_domain_for_artifact(
    artifact: &Map<String, Value>,
    deps: &TrustDeps<'_>,
    item_kind: &str,
    metadata: &Map<String, Value>,
    workspace_dir: Option<&Path>,
) -> Option<TrustDomainScore> {
    let trust_root = _trust_root_for_artifact(artifact, item_kind, workspace_dir)?;
    match item_kind {
        "plugin" => deps.scoring.build_plugin_domain(&trust_root),
        "skill" => {
            let options = ScanOptions::inventory_trust_scan_options();
            let context = deps
                .scoring
                .resolve_skill_security_context(&trust_root, &options);
            if let Some(domain) = deps.scoring.build_skill_domain(&trust_root, &context) {
                return Some(domain);
            }
            if a_str(artifact, "artifact_type") == Some("skill_file") {
                if let Some(config_path) = a_str(artifact, "config_path") {
                    if !config_path.trim().is_empty() {
                        let file_path = PathBuf::from(config_path);
                        if file_path.is_file() {
                            return deps.scoring.build_instruction_domain(
                                &file_path,
                                "skill_file",
                                "skill",
                            );
                        }
                    }
                }
            }
            None
        }
        "mcp_server" => deps.scoring.build_mcp_domain(&trust_root).or_else(|| {
            deps.scoring.build_mcp_surface_domain(
                a_str(artifact, "name"),
                a_str(artifact, "command"),
                a_str(artifact, "url"),
                a_str(artifact, "transport"),
            )
        }),
        "mcp_tool" => deps.scoring.build_mcp_surface_domain(
            Some(
                meta_str(metadata, "toolName")
                    .or_else(|| meta_str(metadata, "title"))
                    .unwrap_or(""),
            ),
            meta_str(metadata, "serverCommand"),
            meta_str(metadata, "serverUrl"),
            meta_str(metadata, "serverTransport"),
        ),
        _ if INSTRUCTION_BASELINE_ITEM_KINDS.contains(&item_kind) => {
            let role = metadata.get("instructionRole").and_then(Value::as_str);
            let normalized_role = role
                .filter(|r| !r.is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| format!("{item_kind}_config"));
            deps.scoring
                .build_instruction_domain(&trust_root, &normalized_role, item_kind)
        }
        _ => None,
    }
}

/// `_trust_root_for_artifact(artifact, *, item_kind, workspace_dir)`
pub(super) fn _trust_root_for_artifact(
    artifact: &Map<String, Value>,
    item_kind: &str,
    workspace_dir: Option<&Path>,
) -> Option<PathBuf> {
    let config_path = a_str(artifact, "config_path")?;
    if config_path.trim().is_empty() {
        return None;
    }
    let path = PathBuf::from(config_path);
    if !path.exists() {
        return None;
    }

    if item_kind == "skill" {
        let skill_dir = if path
            .file_name()
            .map(|n| n.to_string_lossy().to_lowercase() == "skill.md")
            .unwrap_or(false)
        {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone())
        } else {
            path.clone()
        };
        for candidate in std::iter::once(skill_dir.clone())
            .chain(skill_dir.ancestors().skip(1).map(Path::to_path_buf))
        {
            if candidate
                .join(".codex-plugin")
                .join("plugin.json")
                .is_file()
            {
                return Some(candidate);
            }
            let name_is_skill_md = path
                .file_name()
                .map(|n| n.to_string_lossy().to_lowercase() == "skill.md")
                .unwrap_or(false);
            if !name_is_skill_md && candidate.join("SKILL.md").is_file() {
                return Some(candidate);
            }
            if a_str(artifact, "artifact_type") == Some("skill_file")
                && candidate
                    .parent()
                    .and_then(|p| p.file_name())
                    .map(|n| n.to_string_lossy().to_lowercase() == "skills")
                    .unwrap_or(false)
                && (candidate.join("README.md").is_file()
                    || candidate.join("SECURITY.md").is_file())
                && _skill_file_name_matches_root(artifact, &candidate)
            {
                return Some(candidate);
            }
            if workspace_dir.is_some()
                && candidate
                    .file_name()
                    .map(|n| n.to_string_lossy().to_lowercase() == "skills")
                    .unwrap_or(false)
                && candidate.join("SKILL.md").is_file()
            {
                return Some(candidate);
            }
        }
        return None;
    }

    if item_kind == "mcp_server" || item_kind == "mcp_tool" {
        let dir = if path.is_dir() {
            path.clone()
        } else {
            path.parent()
                .map(Path::to_path_buf)
                .unwrap_or_else(|| path.clone())
        };
        return Some(dir);
    }

    Some(path)
}

/// `_skill_file_name_matches_root(artifact, root)`
pub(super) fn _skill_file_name_matches_root(artifact: &Map<String, Value>, root: &Path) -> bool {
    let root_name = match root.file_name().map(|n| n.to_string_lossy().into_owned()) {
        Some(n) if !n.is_empty() => n,
        _ => return false,
    };
    let name = a_str(artifact, "name").unwrap_or("");
    if !name.is_empty() && (name == root_name || name.starts_with(&format!("{root_name}/"))) {
        return true;
    }
    let artifact_id = a_str(artifact, "artifact_id").unwrap_or("");
    !artifact_id.is_empty() && artifact_id.contains(&format!(":{root_name}:"))
}

/// `_trust_layer_from_domain(domain, *, captured_at)`
pub(super) fn _trust_layer_from_domain(
    domain: &TrustDomainScore,
    deps: &TrustDeps<'_>,
    captured_at: &str,
) -> Map<String, Value> {
    let trust_components = _trust_components_from_domain(domain);
    let normalized_captured_at =
        normalize_inventory_datetime(&Value::String(captured_at.to_string()));
    let evidence =
        _local_baseline_evidence_payload(domain, &normalized_captured_at, &trust_components);
    let mut out = Map::new();
    out.insert("layerId".into(), json!("local_baseline"));
    out.insert("layerType".into(), json!("local_baseline"));
    out.insert("status".into(), json!("local"));
    out.insert("evidenceAuthority".into(), json!("device_claim"));
    out.insert("affectsV4Score".into(), json!(false));
    out.insert("trustScore".into(), json!(py_round(domain.score)));
    out.insert(
        "trustComponents".into(),
        Value::Array(trust_components.into_iter().map(Value::Object).collect()),
    );
    out.insert("capturedAt".into(), normalized_captured_at);
    out.insert(
        "provenance".into(),
        Value::Object(_local_claim_provenance("hol-guard-local-baseline")),
    );
    let metadata = json!({
        "scorer": "hol-guard-local",
        "specId": domain.spec_id,
        "specVersion": domain.spec_version,
        "trustDomain": domain.domain,
        "attestationStatus": "unsigned",
        "evidenceSchemaVersion": "guard-aibom-local-baseline-evidence.v1",
        "evidenceAuthority": "device_claim",
        "affectsV4Score": false,
        "evidence": evidence,
        "evidenceHash": _trust_evidence_hash(&evidence, deps),
    });
    out.insert("metadata".into(), metadata);
    out
}

/// `_local_baseline_evidence_payload(domain, *, captured_at, trust_components)`
pub(super) fn _local_baseline_evidence_payload(
    domain: &TrustDomainScore,
    captured_at: &Value,
    trust_components: &[Map<String, Value>],
) -> Map<String, Value> {
    let mut payload = Map::new();
    payload.insert("source".into(), json!("hol-guard-local-baseline"));
    payload.insert("layerId".into(), json!("local_baseline"));
    payload.insert("label".into(), json!("Local baseline"));
    payload.insert("status".into(), json!("local"));
    payload.insert("capturedAt".into(), captured_at.clone());
    payload.insert("trustScore".into(), json!(py_round(domain.score)));
    payload.insert(
        "componentCount".into(),
        json!(trust_components.len() as i64),
    );
    payload.insert("specId".into(), json!(domain.spec_id));
    payload.insert("specVersion".into(), json!(domain.spec_version));
    payload.insert("profileId".into(), json!(domain.profile_id));
    payload.insert("profileVersion".into(), json!(domain.profile_version));
    payload.insert("trustDomain".into(), json!(domain.domain));
    payload
}

/// `_merge_trust_layers(existing, additions)`
pub(super) fn _merge_trust_layers(
    existing: Option<&Vec<Value>>,
    additions: Vec<Map<String, Value>>,
) -> Vec<Value> {
    let mut merged: Vec<(String, Map<String, Value>)> = Vec::new();
    let mut index: std::collections::HashMap<String, usize> = std::collections::HashMap::new();
    if let Some(existing) = existing {
        for raw_layer in existing {
            if let Some(layer) = raw_layer.as_object() {
                if let Some(layer_type) = layer.get("layerType").and_then(Value::as_str) {
                    if !layer_type.is_empty() {
                        let key = layer_type.to_string();
                        if let Some(&i) = index.get(&key) {
                            merged[i] = (key, layer.clone());
                        } else {
                            index.insert(key.clone(), merged.len());
                            merged.push((key, layer.clone()));
                        }
                    }
                }
            }
        }
    }
    for layer in additions {
        if let Some(layer_type) = layer.get("layerType").and_then(Value::as_str) {
            if !layer_type.is_empty() {
                let key = layer_type.to_string();
                if let Some(&i) = index.get(&key) {
                    merged[i] = (key, layer);
                } else {
                    index.insert(key.clone(), merged.len());
                    merged.push((key, layer));
                }
            }
        }
    }
    merged.into_iter().map(|(_, l)| Value::Object(l)).collect()
}

/// `_local_claim_provenance(derivation)`
pub(super) fn _local_claim_provenance(derivation: &str) -> Map<String, Value> {
    let mut out = Map::new();
    out.insert("origin".into(), json!("hol-guard-local"));
    out.insert("verificationStatus".into(), json!("locally_derived"));
    out.insert("derivation".into(), json!(derivation));
    out
}
