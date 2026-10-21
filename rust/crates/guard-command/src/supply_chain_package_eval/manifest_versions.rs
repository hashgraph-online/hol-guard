use super::*;

static SOURCE_SCHEME_RE: std::sync::LazyLock<Regex> =
    std::sync::LazyLock::new(|| Regex::new(r"^[A-Za-z][A-Za-z0-9+.-]*://").expect("scheme re"));

/// `_source_url_from_specifier` (:4647-4655) — return the specifier when it is
/// already a usable source URL/spec.
// supply_chain_package_eval.py:4647-4655
#[allow(dead_code)]
pub(super) fn source_url_from_specifier(specifier: Option<&str>) -> Option<String> {
    let specifier = specifier?;
    if parse_npm_source_spec(Some(specifier)).is_some() {
        return Some(specifier.to_string());
    }
    let lower = specifier.to_lowercase();
    if SOURCE_SCHEME_RE.is_match(specifier)
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("file:")
    {
        return Some(specifier.to_string());
    }
    None
}

/// `_source_url_from_raw_spec` (:4659-4671) — pull a source URL out of a raw
/// install spec, stripping a leading named-source separator if present.
// supply_chain_package_eval.py:4659-4671
#[allow(dead_code)]
pub(super) fn source_url_from_raw_spec(raw_spec: &str) -> Option<String> {
    let candidate = match NAMED_SOURCE_SEPARATOR_RE.find(raw_spec) {
        Some(m) => &raw_spec[m.start() + 1..],
        None => raw_spec,
    };
    let lower = candidate.to_lowercase();
    if candidate.contains("://")
        || lower.starts_with("http:")
        || lower.starts_with("https:")
        || lower.starts_with("git+")
        || lower.starts_with("github:")
        || lower.starts_with("gitlab:")
        || lower.starts_with("bitbucket:")
        || lower.starts_with("file:")
    {
        return Some(candidate.to_string());
    }
    if source_url_from_specifier(Some(raw_spec)).is_some() {
        return Some(raw_spec.to_string());
    }
    for (index, ch) in raw_spec.char_indices() {
        if ch == '@' && index > 0 && parse_npm_source_spec(Some(&raw_spec[index + 1..])).is_some() {
            return Some(raw_spec[index + 1..].to_string());
        }
    }
    None
}

/// `_manifest_exact_version` (:4733-4743) — extract an exact pinned version
/// from a manifest specifier for the given ecosystem.
// supply_chain_package_eval.py:4733-4743
#[allow(dead_code)]
pub(super) fn manifest_exact_version(
    deps: &SupplyChainEvalDeps<'_>,
    ecosystem: &str,
    value: Option<&str>,
) -> Option<String> {
    if ecosystem == "pypi" {
        return python_lockfile_version(deps, value.map(|v| Value::String(v.to_string())).as_ref());
    }
    if ecosystem == "cargo" {
        let normalized = value?;
        if let Some(rest) = normalized.strip_prefix('=') {
            return exact_version(rest.trim_start_matches('='));
        }
        return None;
    }
    value.and_then(exact_version)
}

/// `_with_package_reason` (:4754-4761) — clone a package result dict and append
/// one reason.
// supply_chain_package_eval.py:4754-4761
#[allow(dead_code)]
pub(super) fn with_package_reason(
    package: &Map<String, Value>,
    reason: Map<String, Value>,
) -> Map<String, Value> {
    let mut updated = package.clone();
    let mut reasons: Vec<Value> = match package.get("reasons") {
        Some(Value::Array(items)) => items
            .iter()
            .filter(|item| item.is_object())
            .cloned()
            .collect(),
        _ => Vec::new(),
    };
    reasons.push(Value::Object(reason));
    updated.insert("reasons".to_string(), Value::Array(reasons));
    updated
}

/// `_default_registry_range` (:4924-4925) — default registry range for an
/// ecosystem (`latest` for npm, `>=0` for pypi).
// supply_chain_package_eval.py:4924-4925
#[allow(dead_code)]
pub(super) fn default_registry_range(ecosystem: &str) -> Option<&'static str> {
    registry_default_ranges().get(ecosystem).copied()
}

/// `_requested_specifier_is_range` (:4928-4934) — whether a requested specifier
/// is a non-exact range (or a dist-tag for npm).
// supply_chain_package_eval.py:4928-4934
#[allow(dead_code)]
pub(super) fn requested_specifier_is_range(value: Option<&str>, ecosystem: &str) -> bool {
    let Some(normalized) = value.map(str::to_string) else {
        return false;
    };
    if exact_version(&normalized).is_none() {
        return true;
    }
    if !dist_tag_range_ecosystems().contains(ecosystem) {
        return false;
    }
    Regex::new(r"[A-Za-z][A-Za-z0-9_.-]*")
        .expect("dist-tag re")
        .is_match(&normalized)
        && normalized
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'))
        && normalized
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic())
}
