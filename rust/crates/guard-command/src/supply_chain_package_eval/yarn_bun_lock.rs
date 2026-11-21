use super::*;

/// `_expected_yarn_selectors` (:4258-4267) — yarn.lock selector spellings a
/// target may appear under.
// supply_chain_package_eval.py:4258-4267
#[allow(dead_code)]
pub(super) fn expected_yarn_selectors(target: &Map<String, Value>) -> Vec<String> {
    let requested =
        optional_string(target.get("version")).or_else(|| optional_string(target.get("range")));
    let Some(requested) = requested else {
        return Vec::new();
    };
    let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
    let mut selectors = vec![
        format!("{normalized_name}@{requested}"),
        format!("{normalized_name}@npm:{requested}"),
    ];
    if let Some(alias) = optional_string(target.get("alias")) {
        selectors.push(format!("{alias}@npm:{normalized_name}@{requested}"));
    }
    let mut seen = HashSet::new();
    selectors
        .into_iter()
        .filter(|s| seen.insert(s.clone()))
        .collect()
}

/// `_yarn_lock_target_versions` (:4234-4255) — resolve yarn.lock `version`
/// lines by matching a target's expected selectors.
// supply_chain_package_eval.py:4234-4255
#[allow(dead_code)]
pub(super) fn yarn_lock_target_versions(
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    let mut current_selectors: Vec<String> = Vec::new();
    let target_selectors: Vec<(String, HashSet<String>)> = targets
        .iter()
        .filter_map(|t| {
            lockfile_target_key(t).map(|k| {
                (
                    k,
                    expected_yarn_selectors(t)
                        .into_iter()
                        .collect::<HashSet<_>>(),
                )
            })
        })
        .collect();
    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        if !raw_line.starts_with(' ') && !raw_line.starts_with('\t') {
            current_selectors = stripped
                .trim_end_matches(':')
                .split(',')
                .map(|part| part.trim().trim_matches('"').trim_matches('\'').to_string())
                .filter(|s| !s.is_empty() && s != "__metadata")
                .collect();
            continue;
        }
        if current_selectors.is_empty() {
            continue;
        }
        let version: Option<String> = {
            static RE1: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r#"^version\s+"([^"]+)"$"#).expect("yarn version re"));
            static RE2: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(r#"^version:\s*"?([^"\s]+)"?$"#).expect("yarn version re2")
            });
            RE1.captures(stripped)
                .or_else(|| RE2.captures(stripped))
                .and_then(|c| c.get(1).map(|m| m.as_str().to_string()))
        };
        let Some(version) = version else { continue };
        let selector_set: HashSet<String> = current_selectors.iter().cloned().collect();
        for (target_key, expected) in &target_selectors {
            if versions.contains_key(target_key) || expected.is_empty() {
                continue;
            }
            if selector_set.iter().any(|s| expected.contains(s)) {
                versions.insert(target_key.clone(), version.clone());
            }
        }
    }
    versions
}

/// `_bun_lock_target_versions` (:4270-4290) — resolve bun.lock targets via
/// unique-per-name versions, disambiguated by the requested range.
// supply_chain_package_eval.py:4270-4290
#[allow(dead_code)]
pub(super) fn bun_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    parse_result: &LockfileParseResult,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut versions_by_name: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for entry in &parse_result.entries {
        let candidate_versions = versions_by_name
            .entry(entry.package_name.clone())
            .or_default();
        if !candidate_versions.contains(&entry.version) {
            candidate_versions.push(entry.version.clone());
        }
    }
    let mut versions: BTreeMap<String, String> = BTreeMap::new();
    for target in targets {
        let Some(target_key) = lockfile_target_key(target) else {
            continue;
        };
        let requested = optional_string(target.get("range"));
        let normalized_name = optional_string(target.get("normalized_name")).unwrap_or_default();
        let candidates = versions_by_name
            .get(&normalized_name)
            .cloned()
            .unwrap_or_default();
        if candidates.len() == 1 {
            versions.insert(target_key, candidates[0].clone());
            continue;
        }
        let Some(requested) = requested else { continue };
        let matching: Vec<&String> = candidates
            .iter()
            .filter(|v| deps.semver.version_matches_js_selector(v, &requested))
            .collect();
        if matching.len() == 1 {
            versions.insert(target_key, matching[0].clone());
        }
    }
    versions
}
