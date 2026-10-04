use super::*;

/// `_pypi_caret_specifier` (:4542-4560) — map a `^x.y.z` requested range to the
/// equivalent PEP-440 `>=base,<upper` specifier.
// supply_chain_package_eval.py:4542-4560
#[allow(dead_code)]
pub(super) fn pypi_caret_specifier(deps: &SupplyChainEvalDeps<'_>, value: &str) -> Option<String> {
    let base = {
        let v = value.trim();
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    }?;
    let parsed = deps.semver.version(&base).ok()?;
    let release = &parsed.release;
    let major = release.first().copied().unwrap_or(0);
    let minor = release.get(1).copied().unwrap_or(0);
    let patch = release.get(2).copied().unwrap_or(0);
    let upper_bound = if major > 0 {
        format!("{}", major + 1)
    } else if minor > 0 {
        format!("0.{}", minor + 1)
    } else {
        format!("0.0.{}", patch + 1)
    };
    Some(format!(">={base},<{upper_bound}"))
}

/// `_pypi_tilde_specifier` (:4563-4574) — map a `~x.y` requested range to the
/// equivalent PEP-440 `>=base,<upper` specifier.
// supply_chain_package_eval.py:4563-4574
#[allow(dead_code)]
pub(super) fn pypi_tilde_specifier(deps: &SupplyChainEvalDeps<'_>, value: &str) -> Option<String> {
    let base = {
        let v = value.trim();
        if v.is_empty() {
            None
        } else {
            Some(v.to_string())
        }
    }?;
    let parsed = deps.semver.version(&base).ok()?;
    let release = &parsed.release;
    let major = release.first().copied().unwrap_or(0);
    let upper_bound = if release.len() >= 2 {
        format!("{major}.{}", release[1] + 1)
    } else {
        format!("{}", major + 1)
    };
    Some(format!(">={base},<{upper_bound}"))
}

/// `_normalized_pypi_requested_range` (:4529-4539) — normalize a requested pypi
/// range: pass through `~=`/exact specifiers, translate `^`/`~` shorthands.
// supply_chain_package_eval.py:4529-4539
#[allow(dead_code)]
pub(super) fn normalized_pypi_requested_range(
    deps: &SupplyChainEvalDeps<'_>,
    requested_range: &str,
) -> Option<String> {
    let normalized = requested_range.trim();
    if normalized.is_empty() {
        return None;
    }
    if normalized.starts_with("~=") {
        return Some(normalized.to_string());
    }
    if let Some(rest) = normalized.strip_prefix('^') {
        return pypi_caret_specifier(deps, rest);
    }
    if let Some(rest) = normalized.strip_prefix('~') {
        return pypi_tilde_specifier(deps, rest);
    }
    Some(normalized.to_string())
}

/// `_registry_package_name` (:4452-4457) — qualified `namespace/name` for
/// registry lookups, or the bare name.
// supply_chain_package_eval.py:4452-4457
#[allow(dead_code)]
pub(super) fn registry_package_name(target: &Map<String, Value>) -> Option<String> {
    let package_name = optional_string(target.get("name"))?;
    match optional_string(target.get("namespace")) {
        Some(ns) => Some(format!("{ns}/{package_name}")),
        None => Some(package_name),
    }
}

/// `_dependency_package_name` (:4403-4412) — leaf package name for a lockfile
/// dependency path.
// supply_chain_package_eval.py:4403-4412
#[allow(dead_code)]
pub(super) fn dependency_package_name(dependency_path: &str) -> Option<String> {
    let normalized = dependency_path.trim_matches('/').to_lowercase();
    if normalized.is_empty() {
        return None;
    }
    if let Some((_, after)) = normalized.rsplit_once("node_modules/") {
        return Some(after.to_string());
    }
    if !normalized.contains('/') || normalized.starts_with('@') {
        return Some(normalized);
    }
    None
}

/// `_target_versions_from_direct_map` (:4371-4383) — resolve each target's
/// version from a `{candidate_name: version}` direct map.
// supply_chain_package_eval.py:4371-4383
#[allow(dead_code)]
pub(super) fn target_versions_from_direct_map(
    deps: &SupplyChainEvalDeps<'_>,
    targets: &[Map<String, Value>],
    direct_versions: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(key) = lockfile_target_key(target) else {
            continue;
        };
        for candidate in target_candidate_names(deps, target) {
            if let Some(version) = direct_versions.get(&candidate) {
                versions.insert(key, version.clone());
                break;
            }
        }
    }
    versions
}

/// `_direct_lockfile_version` (:4386-4400) — extract an exact version from a
/// lockfile value that may be a range, alias (`npm:`), or `name@version`.
// supply_chain_package_eval.py:4386-4400
#[allow(dead_code)]
pub(super) fn direct_lockfile_version(value: &str) -> Option<String> {
    let mut normalized = value.split('(').next().unwrap_or("").trim().to_string();
    if let Some(rest) = normalized.strip_prefix("npm:") {
        normalized = rest.to_string();
    }
    if normalized.contains('@') && !normalized.starts_with('@') {
        if let Some((_, candidate)) = normalized.rsplit_once('@') {
            if exact_version(candidate).is_some() {
                return Some(candidate.to_string());
            }
        }
    }
    if exact_version(&normalized).is_some() {
        return Some(normalized);
    }
    None
}
