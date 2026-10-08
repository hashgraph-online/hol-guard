use super::*;

/// `_workspace_fingerprint` (:2459-2477).
// supply_chain_package_eval.py:2459-2477
#[allow(dead_code)]
pub(super) fn workspace_fingerprint(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_id: &str,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
    bundle_meta: Option<&BTreeMap<String, String>>,
) -> String {
    let manifest_hashes = hash_paths(deps, workspace_dir, artifact.metadata.get("manifest_paths"));
    let lockfile_hashes = hash_paths(deps, workspace_dir, artifact.metadata.get("lockfile_paths"));
    let workspace_name = workspace_dir
        .and_then(|d| d.file_name())
        .map(|n| n.to_string_lossy().into_owned());
    let mut payload = Map::new();
    payload.insert(
        "workspace_id".to_string(),
        Value::String(workspace_id.to_string()),
    );
    payload.insert(
        "workspace_name".to_string(),
        workspace_name.map(Value::String).unwrap_or(Value::Null),
    );
    payload.insert(
        "manifest_hashes".to_string(),
        Value::Array(manifest_hashes.into_iter().map(Value::String).collect()),
    );
    payload.insert(
        "lockfile_hashes".to_string(),
        Value::Array(lockfile_hashes.into_iter().map(Value::String).collect()),
    );
    payload.insert(
        "lockfile_parser_version".to_string(),
        Value::String(crate::local_supply_chain::LOCKFILE_PARSER_VERSION.to_string()),
    );
    payload.insert(
        "bundle_policy_hash".to_string(),
        bundle_meta
            .and_then(|m| m.get("policy_hash").cloned())
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    stable_hash(&Value::Object(payload))
}

/// `_build_request_payload` (:2480-2527).
// supply_chain_package_eval.py:2480-2527
#[allow(clippy::too_many_arguments)]
#[allow(dead_code)]
pub(super) fn build_request_payload(
    deps: &SupplyChainEvalDeps<'_>,
    artifact: &GuardArtifact,
    targets: &[Map<String, Value>],
    workspace_dir: Option<&Path>,
    workspace_fingerprint: &str,
    policy_version: &str,
) -> Map<String, Value> {
    let lockfile_context = lockfile_context(deps, workspace_dir, artifact);
    let redacted = optional_string(artifact.metadata.get("redacted_command")).unwrap_or_default();
    let arg_count = redacted.split_whitespace().count() as u64;
    let flags: Vec<Value> = string_tuple(artifact.metadata.get("flags"))
        .into_iter()
        .map(Value::String)
        .collect();
    let mut command_shape = Map::new();
    command_shape.insert(
        "argCount".to_string(),
        Value::Number(serde_json::Number::from(arg_count)),
    );
    command_shape.insert("flags".to_string(), Value::Array(flags));
    command_shape.insert(
        "packageManager".to_string(),
        Value::String(
            optional_string(artifact.metadata.get("package_manager"))
                .unwrap_or_else(|| "unknown".to_string()),
        ),
    );
    command_shape.insert("redacted".to_string(), Value::Bool(true));
    command_shape.insert(
        "verb".to_string(),
        Value::String(
            optional_string(artifact.metadata.get("intent_kind"))
                .unwrap_or_else(|| "install".to_string()),
        ),
    );
    let packages: Vec<Value> = targets
        .iter()
        .map(|target| {
            let mut pkg = Map::new();
            pkg.insert("direct".to_string(), Value::Bool(true));
            pkg.insert(
                "ecosystem".to_string(),
                target.get("ecosystem").cloned().unwrap_or(Value::Null),
            );
            pkg.insert(
                "name".to_string(),
                target.get("name").cloned().unwrap_or(Value::Null),
            );
            pkg.insert(
                "namespace".to_string(),
                target.get("namespace").cloned().unwrap_or(Value::Null),
            );
            let source_url_value = target
                .get("source_redacted")
                .or_else(|| target.get("source_url"));
            if target.get("source_url").is_some() {
                pkg.insert(
                    "sourceUrl".to_string(),
                    source_url_value.cloned().unwrap_or(Value::Null),
                );
            }
            if let Some(v) = target.get("source_identity") {
                pkg.insert("sourceIdentity".to_string(), v.clone());
            }
            if let Some(v) = target.get("version") {
                pkg.insert("version".to_string(), v.clone());
            }
            if let Some(v) = target.get("range") {
                pkg.insert("range".to_string(), v.clone());
            }
            Value::Object(pkg)
        })
        .collect();
    let mut payload = Map::new();
    payload.insert("commandShape".to_string(), Value::Object(command_shape));
    payload.insert(
        "harness".to_string(),
        Value::String(artifact.harness.clone()),
    );
    payload.insert("packages".to_string(), Value::Array(packages));
    payload.insert(
        "policyVersion".to_string(),
        Value::String(policy_version.to_string()),
    );
    payload.insert(
        "workspaceFingerprint".to_string(),
        Value::String(workspace_fingerprint.to_string()),
    );
    if let Some(ctx) = lockfile_context {
        let mut ctx_obj = Map::new();
        for key in [
            "dependencyCount",
            "fileName",
            "lockfileHash",
            "manifestHash",
            "repository",
        ] {
            if let Some(v) = ctx.get(key) {
                if !v.is_null() {
                    ctx_obj.insert(key.to_string(), v.clone());
                }
            }
        }
        payload.insert("lockfileContext".to_string(), Value::Object(ctx_obj));
    }
    payload
}

/// `_lockfile_context` (:2530-2563).
// supply_chain_package_eval.py:2530-2563
#[allow(dead_code)]
pub(super) fn lockfile_context(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    artifact: &GuardArtifact,
) -> Option<Map<String, Value>> {
    let workspace_dir = workspace_dir?;
    let lockfile_paths = artifact.metadata.get("lockfile_paths")?.as_array()?;
    if lockfile_paths.is_empty() {
        return None;
    }
    let rel = lockfile_paths.first()?.as_str()?;
    let lockfile_path = resolve_path_within_workspace(workspace_dir, rel)?;
    if !lockfile_path.exists() {
        return None;
    }
    if lockfile_path
        .file_name()
        .map(|n| n.to_string_lossy().eq_ignore_ascii_case("bun.lockb"))
        .unwrap_or(false)
    {
        return None;
    }
    let lockfile_text = deps.workspace_io.read_text(workspace_dir, rel)?;
    let parse_result = parse_lockfile_text_result(
        deps,
        &lockfile_path.file_name()?.to_string_lossy(),
        lockfile_text.as_bytes(),
    );
    if !parse_result.complete {
        let mut out = Map::new();
        out.insert(
            "dependencyCount".to_string(),
            Value::Number(serde_json::Number::from(0)),
        );
        out.insert(
            "fileName".to_string(),
            Value::String(lockfile_path.file_name()?.to_string_lossy().into_owned()),
        );
        out.insert(
            "lockfileHash".to_string(),
            Value::String(parse_result.source_hash),
        );
        out.insert(
            "lockfileParserVersion".to_string(),
            Value::String(parse_result.parser_version),
        );
        out.insert("parseComplete".to_string(), Value::Bool(false));
        out.insert(
            "parseError".to_string(),
            parse_result
                .error_reason
                .map(Value::String)
                .unwrap_or(Value::Null),
        );
        return Some(out);
    }
    let manifest_hashes = hash_paths(
        deps,
        Some(workspace_dir),
        artifact.metadata.get("manifest_paths"),
    );
    let mut out = Map::new();
    out.insert(
        "dependencyCount".to_string(),
        Value::Number(serde_json::Number::from(parse_result.entries.len() as u64)),
    );
    out.insert(
        "fileName".to_string(),
        Value::String(lockfile_path.file_name()?.to_string_lossy().into_owned()),
    );
    out.insert(
        "lockfileHash".to_string(),
        Value::String(parse_result.source_hash),
    );
    out.insert(
        "lockfileParserVersion".to_string(),
        Value::String(parse_result.parser_version),
    );
    out.insert(
        "manifestHash".to_string(),
        manifest_hashes
            .first()
            .cloned()
            .map(Value::String)
            .unwrap_or(Value::Null),
    );
    out.insert("parseComplete".to_string(), Value::Bool(true));
    out.insert(
        "repository".to_string(),
        workspace_dir
            .file_name()
            .map(|n| Value::String(n.to_string_lossy().into_owned()))
            .unwrap_or(Value::Null),
    );
    Some(out)
}
