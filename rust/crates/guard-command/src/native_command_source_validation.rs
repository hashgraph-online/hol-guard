//! Catalog constraints precede lowering; native admission remains mandatory.

use super::contract::*;
use std::collections::{BTreeMap, BTreeSet};

fn id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value.split(['.', '-']).all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit())
        })
}

fn version(value: &str) -> bool {
    let parts: Vec<_> = value.split('.').collect();
    value.len() <= 32
        && parts.len() == 3
        && !parts[0].starts_with('0')
        && parts
            .iter()
            .all(|part| !part.is_empty() && part.bytes().all(|b| b.is_ascii_digit()))
}

fn text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 4096 && !value.chars().any(|ch| ch.is_control())
}

fn unique(values: &[String]) -> bool {
    values.iter().all(|value| text(value))
        && values.iter().collect::<BTreeSet<_>>().len() == values.len()
}

fn risk(value: &str) -> bool {
    matches!(value, "low" | "medium" | "high" | "critical")
}

fn namespace(value: &str, owner: &str) -> bool {
    id(value)
        && value
            .strip_prefix(owner)
            .is_some_and(|tail| tail.starts_with('.'))
}

fn known_subset(values: &[String], owners: &[String]) -> bool {
    unique(values) && values.iter().all(|value| owners.contains(value))
}

fn validate(document: &SourceDocument, mcp: bool) -> Result<(), &'static str> {
    if document.schema != SOURCE_SCHEMA {
        return Err("command_source_version_unsupported");
    }
    let extension = &document.extension;
    let owner = extension.extension_id.as_str();
    if !id(owner)
        || !owner.starts_with("command.")
        || (!mcp && owner.starts_with("command.mcp-"))
        || !version(&extension.version)
        || !text(&extension.name)
        || !text(&extension.description)
        || extension.icon.as_ref().is_some_and(|icon| !icon.valid())
        || extension.rules.len() > 1024
        || extension.permissions.len() > 512
        || extension.permissions.is_empty()
        || !matches!(
            extension.source.as_str(),
            "built-in" | "local-admin" | "signed-cloud"
        )
        || (extension.required && extension.source != "built-in")
    {
        return Err("command_source_extension_invalid");
    }
    if extension
        .homepage
        .as_deref()
        .is_some_and(|value| !text(value) || value.len() > 512 || !value.starts_with("https://"))
        || extension
            .license
            .as_deref()
            .is_some_and(|value| !text(value) || value.len() > 64)
        || extension.publisher.as_ref().is_some_and(|publisher| {
            !id(&publisher.id)
                || publisher.id.len() > 128
                || matches!(publisher.id.as_str(), "hol" | "hol-curated")
                || !text(&publisher.display_name)
                || publisher.display_name.len() > 128
                || publisher.url.as_deref().is_some_and(|value| {
                    !text(value) || value.len() > 512 || !value.starts_with("https://")
                })
        })
    {
        return Err("command_source_attribution_invalid");
    }
    for values in [
        &extension.action_classes,
        &extension.risk_classes,
        &extension.safer_alternatives,
        &extension.reference_urls,
        &extension.aliases,
        &extension.dependencies,
        &extension.conflicts,
        &extension.ecosystem_ids,
        &extension.executables,
        &extension.project_markers,
    ] {
        if !unique(values) {
            return Err("command_source_metadata_invalid");
        }
    }
    if extension.risk_classes.is_empty()
        || extension.safer_alternatives.is_empty()
        || extension
            .aliases
            .iter()
            .chain(&extension.dependencies)
            .chain(&extension.conflicts)
            .any(|value| !id(value) || !value.starts_with("command.") || value == owner)
        || extension
            .executables
            .iter()
            .any(|value| value.contains(['/', '\\']))
        || extension.project_markers.iter().any(|value| {
            value.starts_with('/')
                || value.contains('\\')
                || value.split('/').any(|part| part == "..")
        })
        || extension
            .reference_urls
            .iter()
            .any(|value| !value.starts_with("https://"))
    {
        return Err("command_source_metadata_invalid");
    }
    if let Some(delegate) = &extension.delegated_protection {
        const OWNERS: &[&str] = &[
            "command.package.go",
            "command.package.jvm",
            "command.package.node",
            "command.package.php",
            "command.package.python",
            "command.package.ruby",
            "command.package.rust",
            "command.package.system",
        ];
        if delegate != "package-firewall"
            || !OWNERS.contains(&owner)
            || !extension.rules.is_empty()
            || !extension.action_classes.is_empty()
            || extension.executables.is_empty()
            || extension.ecosystem_ids.is_empty()
            || extension.reference_urls.is_empty()
        {
            return Err("command_source_delegation_invalid");
        }
    } else if extension.rules.is_empty() && !mcp {
        return Err("command_source_rules_missing");
    }

    let mut permissions = BTreeMap::new();
    let mut owned_actions = BTreeSet::new();
    for permission in &extension.permissions {
        if !namespace(&permission.permission_id, &format!("{owner}.permission"))
            || permissions
                .insert(permission.permission_id.as_str(), permission)
                .is_some()
            || !version(&permission.implementation_version)
            || !version(&permission.introduced_version)
            || !text(&permission.label)
            || !text(&permission.description)
            || !risk(&permission.risk_tier)
            || !permission.default_enabled
            || !matches!(
                permission.baseline_floor.as_str(),
                "allow" | "review" | "block" | "require-reapproval"
            )
            || (permission.configurable && permission.fixed_reason.is_some())
            || (!permission.configurable && !permission.fixed_reason.as_deref().is_some_and(text))
            || (permission.configurable && permission.example_command.is_none())
            || permission
                .example_command
                .as_deref()
                .is_some_and(|value| !text(value) || value.chars().count() > 120)
            || permission.family.as_deref().is_some_and(|value| !id(value))
        {
            return Err("command_source_permission_invalid");
        }
        for values in [
            &permission.typed_capabilities,
            &permission.action_classes,
            &permission.dependencies,
            &permission.conflicts,
            &permission.implied_permissions,
            &permission.safer_guidance,
        ] {
            if !unique(values) {
                return Err("command_source_permission_invalid");
            }
        }
        for action in &permission.action_classes {
            if !extension.action_classes.contains(action) {
                return Err("command_source_permission_action_ownership_invalid");
            }
            owned_actions.insert(action);
        }
    }
    if owned_actions != extension.action_classes.iter().collect() {
        return Err("command_source_permission_action_ownership_invalid");
    }
    let mut rule_ids = BTreeSet::new();
    let mut rule_actions = BTreeSet::new();
    for rule in &extension.rules {
        let permission = permissions
            .get(rule.permission_id.as_str())
            .ok_or("command_source_rule_permission_missing")?;
        if !namespace(&rule.rule_id, owner)
            || !rule_ids.insert(&rule.rule_id)
            || !version(&rule.rule_version)
            || !text(&rule.title)
            || !text(&rule.description)
            || !risk(&rule.severity)
            || rule.safe_variants.len() > 64
            || !matches!(
                rule.default_mode.as_str(),
                "required" | "enforce" | "review" | "monitor" | "disabled"
            )
            || rule.action_classes.is_empty()
            || rule.risk_classes.is_empty()
            || !known_subset(&rule.action_classes, &permission.action_classes)
            || !known_subset(&rule.risk_classes, &extension.risk_classes)
            || !unique(&rule.safer_alternatives)
            || rule.family.as_deref().is_some_and(|value| !id(value))
        {
            return Err("command_source_rule_invalid");
        }
        if rule.matcher.is_some() == rule.native_capability.is_some() {
            return Err("command_source_rule_requires_exactly_one_predicate");
        }
        if let Some(capability) = &rule.native_capability {
            if !super::capabilities::valid_binding(
                capability,
                owner,
                &rule.rule_id,
                &rule.permission_id,
            ) || !super::capabilities::valid_scope(owner, &extension.executables)
            {
                return Err("command_source_capability_binding_invalid");
            }
            if !rule.safe_variants.is_empty() {
                return Err("command_source_capability_variants_unsupported");
            }
        }
        let mut variants = BTreeSet::new();
        for variant in &rule.safe_variants {
            if !id(&variant.variant_id)
                || !text(&variant.title)
                || !variants.insert(&variant.variant_id)
            {
                return Err("command_source_variant_invalid");
            }
        }
        rule_actions.extend(rule.action_classes.iter());
    }
    if !mcp
        && extension.delegated_protection.is_none()
        && rule_actions != extension.action_classes.iter().collect()
    {
        return Err("command_source_rule_action_ownership_invalid");
    }
    Ok(())
}

pub(super) fn validate_relationships(
    documents: &[SourceDocument],
    mcp_ids: &BTreeSet<&str>,
) -> Result<(), &'static str> {
    if documents.is_empty() || documents.len() > 512 {
        return Err("command_source_catalog_bounds_invalid");
    }
    let mut extensions = BTreeMap::new();
    let mut permissions = BTreeMap::new();
    let mut capabilities = BTreeSet::new();
    let mut families = BTreeMap::new();
    for document in documents {
        validate(
            document,
            mcp_ids.contains(document.extension.extension_id.as_str()),
        )?;
        let extension = &document.extension;
        if extensions
            .insert(extension.extension_id.as_str(), extension)
            .is_some()
        {
            return Err("command_source_extension_duplicate");
        }
        for permission in &extension.permissions {
            if permissions
                .insert(permission.permission_id.as_str(), permission)
                .is_some()
            {
                return Err("command_source_permission_duplicate");
            }
            for capability in &permission.typed_capabilities {
                if !capability.is_ascii()
                    || !capabilities.insert(capability.trim().to_ascii_lowercase())
                {
                    return Err("command_source_typed_capability_duplicate_or_unsupported");
                }
            }
            if let Some(family) = &permission.family {
                if families
                    .insert(family, &extension.extension_id)
                    .is_some_and(|owner| owner != &extension.extension_id)
                {
                    return Err("command_source_family_owner_conflict");
                }
            }
        }
    }
    let mut aliases = BTreeSet::new();
    let mut extension_edges = BTreeMap::new();
    let mut permission_edges = BTreeMap::new();
    for extension in extensions.values() {
        for alias in &extension.aliases {
            if extensions.contains_key(alias.as_str()) || !aliases.insert(alias) {
                return Err("command_source_alias_collision");
            }
        }
        for conflict in &extension.conflicts {
            if !extensions
                .get(conflict.as_str())
                .is_some_and(|other| other.conflicts.contains(&extension.extension_id))
            {
                return Err("command_source_conflict_invalid");
            }
        }
        extension_edges.insert(
            extension.extension_id.as_str(),
            extension.dependencies.iter().map(String::as_str).collect(),
        );
        for permission in &extension.permissions {
            for conflict in &permission.conflicts {
                if conflict == &permission.permission_id
                    || !permissions.contains_key(conflict.as_str())
                {
                    return Err("command_source_permission_conflict_invalid");
                }
            }
            if permission
                .replacement_permission_id
                .as_deref()
                .is_some_and(|id| !permissions.contains_key(id))
            {
                return Err("command_source_permission_replacement_invalid");
            }
            permission_edges.insert(
                permission.permission_id.as_str(),
                permission
                    .dependencies
                    .iter()
                    .chain(&permission.implied_permissions)
                    .map(String::as_str)
                    .collect(),
            );
        }
    }
    acyclic(&extension_edges)?;
    acyclic(&permission_edges)
}

fn acyclic(edges: &BTreeMap<&str, Vec<&str>>) -> Result<(), &'static str> {
    fn visit<'a>(
        id: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        active: &mut BTreeSet<&'a str>,
        heights: &mut BTreeMap<&'a str, usize>,
        depth: usize,
    ) -> Result<usize, &'static str> {
        if let Some(height) = heights.get(id) {
            if depth + height > 32 {
                return Err("command_source_dependency_cycle_or_depth");
            }
            return Ok(*height);
        }
        if depth > 32 || !active.insert(id) {
            return Err("command_source_dependency_cycle_or_depth");
        }
        let children = edges.get(id).ok_or("command_source_dependency_missing")?;
        let mut height = 0;
        for child in children {
            height = height.max(1 + visit(child, edges, active, heights, depth + 1)?);
        }
        active.remove(id);
        heights.insert(id, height);
        Ok(height)
    }
    let mut active = BTreeSet::new();
    let mut heights = BTreeMap::new();
    for id in edges.keys() {
        visit(id, edges, &mut active, &mut heights, 0)?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn memoized_dependencies_cannot_hide_overlong_paths() {
        let ids: Vec<_> = (0..34).map(|index| format!("node{index:02}")).collect();
        let mut edges = BTreeMap::new();
        for (index, id) in ids.iter().enumerate() {
            edges.insert(
                id.as_str(),
                if index == 0 {
                    Vec::new()
                } else {
                    vec![ids[index - 1].as_str()]
                },
            );
        }
        assert_eq!(
            acyclic(&edges),
            Err("command_source_dependency_cycle_or_depth")
        );
        edges.remove(ids[33].as_str());
        assert!(acyclic(&edges).is_ok());
        edges.insert(ids[0].as_str(), vec![ids[32].as_str()]);
        assert_eq!(
            acyclic(&edges),
            Err("command_source_dependency_cycle_or_depth")
        );
    }
}
