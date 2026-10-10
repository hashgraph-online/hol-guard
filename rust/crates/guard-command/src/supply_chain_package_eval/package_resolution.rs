use super::*;

// ---------------------------------------------------------------------------
// Batch C — missing helper fns ported from supply_chain_package_eval.py and
// npm_policy_range.py. Access bundle/packages/rules via Map<String, Value>.
// ---------------------------------------------------------------------------

#[allow(dead_code)]
pub(super) fn optional_string_map(map: &Map<String, Value>, key: &str) -> Option<String> {
    optional_string(map.get(key))
}

#[allow(dead_code)]
pub(super) fn value_to_plain_string(value: &Value) -> String {
    match value {
        Value::Null => String::new(),
        Value::Bool(b) => b.to_string(),
        Value::Number(n) => n.to_string(),
        Value::String(s) => s.clone(),
        other => other.to_string(),
    }
}

#[allow(dead_code)]
pub(super) fn first_dict_item(value: Option<&Value>) -> Option<Map<String, Value>> {
    dict_items(value).into_iter().next()
}

#[allow(dead_code)]
pub(super) fn stable_hash(value: &Value) -> String {
    let canonical = serde_json::to_string(value).unwrap_or_default();
    stable_digest_hex(canonical.as_bytes())
}

#[allow(dead_code)]
pub(super) fn hash_paths(
    deps: &SupplyChainEvalDeps<'_>,
    workspace_dir: Option<&Path>,
    paths: Option<&Value>,
) -> Vec<String> {
    let Some(ws) = workspace_dir else {
        return Vec::new();
    };
    let Some(arr) = paths.and_then(Value::as_array) else {
        return Vec::new();
    };
    let mut out = Vec::new();
    for item in arr {
        let Some(rel) = item.as_str() else { continue };
        let Some(bytes) = deps.workspace_io.read_bytes_within_workspace(ws, rel) else {
            continue;
        };
        out.push(stable_digest_hex(&bytes));
    }
    out
}

#[allow(dead_code)]
pub(super) fn split_namespace_name(
    package_name: &str,
    _ecosystem: &str,
) -> (Option<String>, String) {
    if let Some(rest) = package_name.strip_prefix('@') {
        if let Some(slash) = rest.find('/') {
            return (
                Some(format!("@{}", &rest[..slash])),
                rest[slash + 1..].to_string(),
            );
        }
    }
    (None, package_name.to_string())
}

#[allow(dead_code)]
pub(super) fn npm_source_spec(value: Option<&str>, ecosystem: &str) -> Option<NpmSourceSpec> {
    if ecosystem.eq_ignore_ascii_case("npm") {
        parse_npm_source_spec(value)
    } else {
        None
    }
}

/// `_lockfile_target_key`: `(normalized_name, alias)` flattened into one key.
pub(super) fn lockfile_target_key(target: &Map<String, Value>) -> Option<String> {
    let normalized = optional_string(target.get("normalized_name"))?;
    let alias = optional_string(target.get("alias")).unwrap_or_default();
    Some(format!("{normalized}\u{1f}{alias}"))
}

/// `_exact_version`.
pub(super) fn exact_version(value: &str) -> Option<String> {
    let normalized = value.trim();
    if normalized.is_empty() || parse_npm_source_spec(Some(normalized)).is_some() {
        return None;
    }
    if normalized.starts_with(['^', '~', '<', '>', '!', '*'])
        || normalized.contains("||")
        || normalized.contains(" - ")
        || normalized.contains(',')
    {
        return None;
    }
    Some(normalized.to_owned())
}

#[allow(dead_code)]
pub(super) fn registry_resolved_target_version(
    _deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<String> {
    let _ = target;
    None
}
