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

/// `_split_namespace_name`: the canonical identity decides the namespace, so
/// Packagist `vendor/package` and npm `@scope/name` both split; a name the
/// identity parser rejects stays whole.
pub(super) fn split_namespace_name(
    package_name: &str,
    ecosystem: &str,
) -> (Option<String>, String) {
    match crate::supply_chain_package_identity::parse_package_identity(ecosystem, package_name, "*")
    {
        Ok(identity) => (identity.namespace, identity.name),
        Err(_) => (None, package_name.to_string()),
    }
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

/// `supply_chain_package_services._NPM_REGISTRY_METADATA_BASE_URL`.
const NPM_REGISTRY_METADATA_BASE_URL: &str = "https://registry.npmjs.org";
/// `supply_chain_package_services._PYPI_REGISTRY_METADATA_BASE_URL`.
const PYPI_REGISTRY_METADATA_BASE_URL: &str = "https://pypi.org/pypi";

/// `supply_chain_package_services._optional_string` — a non-blank `str`,
/// stripped. Unlike the evaluator's own helper, numbers are not coerced.
fn registry_optional_string(value: Option<&Value>) -> Option<String> {
    let trimmed = value?.as_str()?.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_owned())
}

/// `urllib.parse.quote(value, safe="")`.
fn quote_registry_path_segment(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

/// `supply_chain_package_services._registry_resolved_target_version` — resolve
/// a requested range to a concrete registry version, or `None` (unresolved)
/// for anything that is not a plain registry npm/pypi target or any registry
/// failure. Only the metadata fetch is delegated to `deps.registry`.
pub fn registry_resolved_target_version(
    deps: &SupplyChainEvalDeps<'_>,
    target: &Map<String, Value>,
    requested_range: &str,
) -> Option<String> {
    let ecosystem =
        registry_optional_string(target.get("ecosystem")).unwrap_or_else(|| "npm".to_owned());
    if registry_optional_string(target.get("source_url")).is_some() {
        return None;
    }
    let name = registry_optional_string(target.get("name"))?;
    let package_name = match registry_optional_string(target.get("namespace")) {
        Some(namespace) => format!("{namespace}/{name}"),
        None => name,
    };
    match ecosystem.as_str() {
        "npm" => npm_registry_resolved_version(deps, &package_name, requested_range),
        "pypi" => {
            let normalized = normalize_package_name(deps, "pypi", &package_name);
            pypi_registry_resolved_version(deps, &normalized, requested_range)
        }
        _ => None,
    }
}

fn npm_registry_resolved_version(
    deps: &SupplyChainEvalDeps<'_>,
    package_name: &str,
    requested_range: &str,
) -> Option<String> {
    let url = format!(
        "{}/{}",
        NPM_REGISTRY_METADATA_BASE_URL.trim_end_matches('/'),
        quote_registry_path_segment(package_name)
    );
    let document = deps
        .registry
        .fetch_registry_metadata(&url, "application/vnd.npm.install-v1+json")?;
    // Document order, not the sorted `Map` order: Python walks the `versions`
    // dict in insertion order, which decides a tie between equal versions.
    let versions = document.version_order;
    if versions.is_empty() {
        return None;
    }
    deps.semver
        .highest_js_version_for_selector(&versions, requested_range)
}

fn pypi_registry_resolved_version(
    deps: &SupplyChainEvalDeps<'_>,
    package_name: &str,
    requested_range: &str,
) -> Option<String> {
    let url = format!(
        "{}/{}/json",
        PYPI_REGISTRY_METADATA_BASE_URL.trim_end_matches('/'),
        quote_registry_path_segment(package_name)
    );
    let payload = deps
        .registry
        .fetch_registry_metadata(&url, "application/json")?
        .object;
    let releases = payload.get("releases")?.as_object()?;
    let specifier =
        crate::pep440::SpecifierSet::parse(&normalized_pypi_requested_range(requested_range)?)
            .ok()?;
    releases
        .keys()
        .filter_map(|release| crate::pep440::Version::parse(release).ok())
        .filter(|version| specifier.contains(version))
        .max()
        .map(|version| version.normalized)
}

/// `_normalized_pypi_requested_range`.
fn normalized_pypi_requested_range(requested_range: &str) -> Option<String> {
    let normalized = requested_range.trim();
    if normalized.is_empty() {
        return None;
    }
    if normalized.starts_with("~=") {
        return Some(normalized.to_owned());
    }
    if let Some(rest) = normalized.strip_prefix('^') {
        return pypi_bounded_specifier(rest, PypiBound::Caret);
    }
    if let Some(rest) = normalized.strip_prefix('~') {
        return pypi_bounded_specifier(rest, PypiBound::Tilde);
    }
    Some(normalized.to_owned())
}

enum PypiBound {
    Caret,
    Tilde,
}

/// `_pypi_caret_specifier` / `_pypi_tilde_specifier` — `>=base,<upper`.
fn pypi_bounded_specifier(value: &str, bound: PypiBound) -> Option<String> {
    let base = value.trim();
    if base.is_empty() {
        return None;
    }
    let parsed = crate::pep440::Version::parse(base).ok()?;
    let release = parsed.release();
    let part = |index: usize| u128::from(release.get(index).copied().unwrap_or(0));
    let (major, minor, patch) = (part(0), part(1), part(2));
    let upper = match bound {
        PypiBound::Caret if major > 0 => format!("{}", major + 1),
        PypiBound::Caret if minor > 0 => format!("0.{}", minor + 1),
        PypiBound::Caret => format!("0.0.{}", patch + 1),
        PypiBound::Tilde if release.len() >= 2 => format!("{major}.{}", minor + 1),
        PypiBound::Tilde => format!("{}", major + 1),
    };
    Some(format!(">={base},<{upper}"))
}

#[cfg(test)]
mod split_namespace_tests {
    use super::split_namespace_name;

    #[test]
    fn splits_the_namespace_for_every_ecosystem_that_has_one() {
        assert_eq!(
            split_namespace_name("@scope/pkg", "npm"),
            (Some("@scope".to_owned()), "pkg".to_owned())
        );
        assert_eq!(
            split_namespace_name("monolog/monolog", "packagist"),
            (Some("monolog".to_owned()), "monolog".to_owned())
        );
        assert_eq!(
            split_namespace_name("lodash", "npm"),
            (None, "lodash".to_owned())
        );
    }

    #[test]
    fn keeps_a_name_the_identity_parser_rejects_whole() {
        assert_eq!(
            split_namespace_name("not/valid", "npm"),
            (None, "not/valid".to_owned())
        );
        assert_eq!(
            split_namespace_name("single", "packagist"),
            (None, "single".to_owned())
        );
    }
}
