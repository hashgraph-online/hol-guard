use super::*;

/// `_pnpm_lock_target_versions` (:4159-4231) — parse pnpm-lock.yaml direct
/// dependency versions (top-level + `importers.`/default blocks).
// supply_chain_package_eval.py:4159-4231
#[allow(dead_code)]
pub(super) fn pnpm_lock_target_versions(
    deps: &SupplyChainEvalDeps<'_>,
    text: &str,
    targets: &[Map<String, Value>],
) -> BTreeMap<String, String> {
    let mut direct_versions: BTreeMap<String, String> = BTreeMap::new();
    let mut section: Option<String> = None;
    let mut importer: Option<String> = None;
    let mut dependency_block: Option<String> = None;
    let mut dependency_name: Option<String> = None;
    const TOP_LEVEL_DEP_SECTIONS: [&str; 3] =
        ["dependencies", "devDependencies", "optionalDependencies"];
    for raw_line in text.lines() {
        let stripped = raw_line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        let indent = raw_line.len() - raw_line.trim_start_matches(' ').len();
        if indent == 0 {
            section = Some(stripped.trim_end_matches(':').to_string());
            importer = None;
            dependency_block = None;
            dependency_name = None;
            continue;
        }
        if TOP_LEVEL_DEP_SECTIONS.contains(&section.as_deref().unwrap_or("")) {
            if indent == 2 && stripped.contains(':') {
                let (raw_name, _, raw_value) = {
                    let parts: Vec<&str> = stripped.splitn(2, ':').collect();
                    (parts[0], ":", parts.get(1).copied().unwrap_or(""))
                };
                let name = raw_name
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string();
                let direct_value = raw_value.trim().trim_matches('"').trim_matches('\'');
                if let Some(exact) = direct_lockfile_version(direct_value) {
                    direct_versions.insert(name, exact);
                    dependency_name = None;
                } else {
                    dependency_name = Some(name);
                }
                continue;
            }
            if dependency_name.is_some() && indent >= 4 && stripped.starts_with("version:") {
                let v = stripped
                    .split_once(':')
                    .map(|x| x.1)
                    .unwrap_or("")
                    .trim()
                    .trim_matches('"')
                    .trim_matches('\'');
                if let Some(exact) = direct_lockfile_version(v) {
                    if let Some(name) = dependency_name.take() {
                        direct_versions.insert(name, exact);
                    }
                }
                dependency_name = None;
            }
            continue;
        }
        if section.as_deref() != Some("importers") {
            continue;
        }
        if indent == 2 && stripped.ends_with(':') {
            importer = Some(
                stripped[..stripped.len() - 1]
                    .trim_matches('"')
                    .trim_matches('\'')
                    .to_string(),
            );
            dependency_block = None;
            dependency_name = None;
            continue;
        }
        if !matches!(importer.as_deref(), Some(".") | Some("default")) {
            continue;
        }
        if indent == 4 && stripped.ends_with(':') {
            let block_name = stripped.trim_end_matches(':').to_string();
            dependency_block = if block_name.to_lowercase().contains("dependencies") {
                Some(block_name)
            } else {
                None
            };
            dependency_name = None;
            continue;
        }
        if dependency_block.is_none() {
            continue;
        }
        if indent == 6 && stripped.contains(':') {
            let parts: Vec<&str> = stripped.splitn(2, ':').collect();
            let name = parts[0]
                .trim()
                .trim_matches('"')
                .trim_matches('\'')
                .to_string();
            let direct_value = parts
                .get(1)
                .copied()
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if let Some(exact) = direct_lockfile_version(direct_value) {
                direct_versions.insert(name, exact);
                dependency_name = None;
            } else {
                dependency_name = Some(name);
            }
            continue;
        }
        if dependency_name.is_some() && indent >= 8 && stripped.starts_with("version:") {
            let v = stripped
                .split_once(':')
                .map(|x| x.1)
                .unwrap_or("")
                .trim()
                .trim_matches('"')
                .trim_matches('\'');
            if let Some(exact) = direct_lockfile_version(v) {
                if let Some(name) = dependency_name.take() {
                    direct_versions.insert(name, exact);
                }
            }
            dependency_name = None;
        }
    }
    target_versions_from_direct_map(deps, targets, &direct_versions)
}
