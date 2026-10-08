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

#[allow(dead_code)]
pub(super) fn lockfile_target_key(target: &Map<String, Value>) -> Option<String> {
    let eco = optional_string(target.get("ecosystem"))?;
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    Some(format!("{eco}:{name}"))
}

#[allow(dead_code)]
pub(super) fn exact_version(spec: &str) -> Option<String> {
    let s = spec.trim();
    if s.is_empty() {
        return None;
    }
    let mut chars = s.chars();
    match chars.next() {
        Some(c) if c.is_ascii_digit() => Some(s.to_string()),
        _ => None,
    }
}

#[allow(dead_code)]
pub(super) fn registry_resolved_target_version(
    _deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
) -> Option<String> {
    let _ = target;
    None
}

#[allow(dead_code)]
pub(super) fn resolved_target_version(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    lockfile_versions: &BTreeMap<String, String>,
) -> Option<String> {
    if let Some(key) = lockfile_target_key(target) {
        if let Some(v) = lockfile_versions.get(&key) {
            return Some(v.clone());
        }
    }
    if let Some(name) = optional_string(target.get("package_name")) {
        if let Some(v) = lockfile_versions.get(&name) {
            return Some(v.clone());
        }
    }
    if let Some(version) = optional_string(target.get("version")) {
        if !version.is_empty() {
            return Some(version);
        }
    }
    if let Some(requested) = optional_string(target.get("requested_specifier"))
        .or_else(|| optional_string(target.get("range")))
    {
        let ecosystem = optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".into());
        if !requested_specifier_is_range(Some(requested.as_str()), &ecosystem) {
            if let Some(exact) = exact_version(&requested) {
                return Some(exact);
            }
        }
    }
    registry_resolved_target_version(deps, target)
}

#[allow(dead_code)]
pub(super) fn bundle_package_index(
    bundle_response: &SupplyChainBundleResponse,
) -> Vec<Map<String, Value>> {
    dict_items(bundle_response.bundle.get("packages"))
}

#[allow(dead_code)]
pub(super) fn bundle_package_name_matches(pkg: &Map<String, Value>, name: &str) -> bool {
    let pkg_name = optional_string_map(pkg, "name").unwrap_or_default();
    let normalized = pkg_name.trim().to_lowercase();
    let needle = name.trim().to_lowercase();
    normalized == needle || pkg_name.eq_ignore_ascii_case(name)
}

#[allow(dead_code)]
pub(super) fn bundle_package_from_index(
    index: &[Map<String, Value>],
    target: &Map<String, Value>,
) -> Option<Map<String, Value>> {
    let eco = optional_string(target.get("ecosystem"))?;
    let name = optional_string(target.get("package_name"))
        .or_else(|| optional_string(target.get("name")))?;
    for pkg in index {
        if optional_string_map(pkg, "ecosystem").as_deref() != Some(eco.as_str()) {
            continue;
        }
        if bundle_package_name_matches(pkg, &name) {
            return Some(pkg.clone());
        }
    }
    None
}

#[allow(dead_code)]
pub(super) fn bundle_package(
    bundle_response: &SupplyChainBundleResponse,
    target: &Map<String, Value>,
    version: &str,
) -> Option<Map<String, Value>> {
    let index = bundle_package_index(bundle_response);
    let pkg = bundle_package_from_index(&index, target)?;
    if let Some(pkg_version) = optional_string_map(&pkg, "version") {
        if !pkg_version.is_empty() && pkg_version != version {
            return None;
        }
    }
    Some(pkg)
}

#[allow(dead_code)]
pub(super) fn bundle_package_label(pkg: &Map<String, Value>) -> String {
    optional_string_map(pkg, "packageName")
        .or_else(|| optional_string_map(pkg, "name"))
        .unwrap_or_else(|| "package".to_string())
}

#[allow(dead_code)]
pub(super) fn is_bundle_stale(
    _deps: &SupplyChainEvalDeps<'_>,
    bundle_response: &SupplyChainBundleResponse,
    _now_timestamp: Option<f64>,
) -> bool {
    let _ = bundle_response;
    false
}
