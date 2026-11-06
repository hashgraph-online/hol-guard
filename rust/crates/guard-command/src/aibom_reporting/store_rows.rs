use super::*;

/// `_artifact_rows_from_store(store, snapshots, *, context, generated_at)`
pub fn _artifact_rows_from_store(
    snapshots: &[GuardAgentInventorySnapshot],
    deps: &ReportingDeps<'_>,
    context: &HarnessContext,
    generated_at: &str,
) -> Vec<Map<String, Value>> {
    let metadata_by_artifact = _metadata_lookup_from_snapshots(snapshots, deps);
    let mut artifacts = Vec::new();
    for item in deps.store.list_inventory() {
        let trust_verdict = item
            .get("last_policy_action")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_else(|| "unknown".to_string());
        let harness = item
            .get("harness")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let artifact_id = item
            .get("artifact_id")
            .and_then(Value::as_str)
            .map(str::to_string)
            .unwrap_or_default();
        let mut row = _redact_inventory_store_item(&item, deps, &context.home_dir);
        row.insert("trust_verdict".into(), json!(trust_verdict));
        let key = format!("{harness}\u{1f}{artifact_id}");
        let mut extensions = metadata_by_artifact
            .get(&key)
            .and_then(Value::as_object)
            .cloned();
        let config_path = if item.get("artifact_type").and_then(Value::as_str) == Some("skill_file")
        {
            _store_row_config_path(&item)
        } else {
            None
        };
        let config_path_exists = config_path.as_ref().map(|p| p.exists());
        if extensions.as_ref().is_none_or(Map::is_empty) {
            extensions = {
                let ext = _store_only_artifact_metadata_extensions(
                    &row,
                    deps,
                    context,
                    generated_at,
                    config_path.as_deref(),
                    config_path_exists,
                );
                if ext.is_empty() {
                    None
                } else {
                    Some(ext)
                }
            };
            if config_path_exists == Some(false) {
                row.insert("present".into(), json!(false));
            }
        }
        if let Some(ext) = extensions {
            for (k, v) in ext {
                row.insert(k, v);
            }
        }
        artifacts.push(row);
    }
    artifacts
}

/// `_store_row_config_path(row)`
pub(super) fn _store_row_config_path(row: &Map<String, Value>) -> Option<PathBuf> {
    let raw = row.get("config_path").and_then(Value::as_str)?;
    if raw.trim().is_empty() {
        return None;
    }
    // `Path(...).expanduser()` — expand a leading `~` against `$HOME`.
    let expanded = if let Some(rest) = raw.strip_prefix("~/") {
        if let Ok(home) = std::env::var("HOME") {
            PathBuf::from(home).join(rest)
        } else {
            PathBuf::from(raw)
        }
    } else if raw == "~" {
        std::env::var("HOME").map_or_else(|_| PathBuf::from(raw), PathBuf::from)
    } else {
        PathBuf::from(raw)
    };
    Some(expanded)
}

/// `_store_only_artifact_metadata_extensions(row, *, context, generated_at, config_path, config_path_exists)`
pub(super) fn _store_only_artifact_metadata_extensions(
    row: &Map<String, Value>,
    deps: &ReportingDeps<'_>,
    context: &HarnessContext,
    generated_at: &str,
    config_path: Option<&std::path::Path>,
    config_path_exists: Option<bool>,
) -> Map<String, Value> {
    let artifact_type = row
        .get("artifact_type")
        .and_then(Value::as_str)
        .unwrap_or("");
    if artifact_type != "skill_file" {
        return Map::new();
    }
    if config_path.is_none() || config_path_exists != Some(true) {
        return Map::new();
    }
    let config_path = config_path.unwrap();
    let mut artifact = Map::new();
    artifact.insert(
        "artifact_id".into(),
        json!(row.get("artifact_id").and_then(Value::as_str).unwrap_or("")),
    );
    artifact.insert("artifact_type".into(), json!(artifact_type));
    artifact.insert(
        "config_path".into(),
        json!(config_path.to_string_lossy().into_owned()),
    );
    artifact.insert(
        "name".into(),
        json!(row
            .get("artifact_name")
            .and_then(Value::as_str)
            .or_else(|| row.get("artifact_id").and_then(Value::as_str))
            .unwrap_or("skill_file")),
    );
    let mut metadata = Map::new();
    metadata.insert("artifactType".into(), json!(artifact_type));
    let enriched = deps.api.apply_local_trust_metadata(
        &artifact,
        generated_at,
        "skill",
        metadata,
        context.workspace_dir.as_deref(),
    );
    deps.api.extract_aibom_metadata_extensions(&enriched)
}

/// `_redact_inventory_store_item(item, *, home_dir)`
pub(super) fn _redact_inventory_store_item(
    item: &Map<String, Value>,
    deps: &ReportingDeps<'_>,
    home_dir: &std::path::Path,
) -> Map<String, Value> {
    let mut redacted = item.clone();
    if let Some(config_path) = item.get("config_path").and_then(Value::as_str) {
        if !config_path.is_empty() {
            let p = PathBuf::from(config_path);
            let redacted_path = deps.redaction.redact_local_path(&p, home_dir);
            redacted.insert("config_path".into(), json!(redacted_path));
        }
    }
    if let Some(launch_command) = item.get("launch_command").and_then(Value::as_str) {
        let redacted_cmd = deps
            .redaction
            ._redact_command_value(launch_command, home_dir, None);
        redacted.insert("launch_command".into(), json!(redacted_cmd));
    }
    redacted
}
