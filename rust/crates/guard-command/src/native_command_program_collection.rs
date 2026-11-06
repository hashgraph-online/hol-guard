//! Compose independently admitted packs without an aggregate JSON envelope.
//! Selection, release authentication and transactional activation remain the
//! caller's responsibilities. Constructing this value grants no policy authority.
use super::*;

impl NativeCommandProgram {
    /// Combine a complete selected dependency closure of one-extension packs.
    /// Each input must already have passed bounded native pack admission. The
    /// resulting indexes and identities contain only the supplied policy set.
    pub(super) fn combine_admitted_packs(mut packs: Vec<Self>) -> Result<Self, &'static str> {
        if packs.is_empty() || packs.iter().any(|pack| pack.extensions.len() != 1) {
            return Err("native_command_pack_inventory_invalid");
        }
        packs.sort_by(|left, right| {
            left.extensions[0]
                .extension_id
                .cmp(&right.extensions[0].extension_id)
        });
        let mut extension_ids = BTreeSet::new();
        let mut permission_ids = BTreeSet::new();
        let mut rule_ids = BTreeSet::new();
        let mut mcp_inventory = source::McpInventory::default();
        for pack in &packs {
            for extension in &pack.extensions {
                if !extension_ids.insert(extension.extension_id.as_str()) {
                    return Err("native_command_extension_duplicate");
                }
                if let Some(mcp) = &extension.mcp {
                    let launch = &mcp.mcp_launch;
                    mcp_inventory.insert(&serde_json::json!({
                        "kind":launch.kind,"command":launch.command,
                        "package":launch.package,"url":launch.url,
                        "serverNames":launch.server_names,
                    }))?;
                }
                for permission in &extension.permissions {
                    if !permission_ids.insert(permission.permission_id.as_str()) {
                        return Err("native_command_permission_duplicate");
                    }
                }
            }
            for rule in &pack.rules {
                if rule.extension_index != 0
                    || !pack.extensions[0].permissions.iter().any(|permission| {
                        permission.permission_id == rule.permission_id
                            && permission.rule_ids.contains(&rule.rule_id)
                    })
                {
                    return Err("native_command_pack_rule_owner_invalid");
                }
                if !rule_ids.insert(rule.rule_id.as_str()) {
                    return Err("native_command_rule_duplicate");
                }
            }
        }
        for pack in &packs {
            for extension in &pack.extensions {
                if extension
                    .dependencies
                    .iter()
                    .any(|id| !extension_ids.contains(id.as_str()))
                {
                    return Err("native_command_extension_dependency_unknown");
                }
                for permission in &extension.permissions {
                    if permission
                        .dependencies
                        .iter()
                        .chain(&permission.implied_permissions)
                        .any(|id| !permission_ids.contains(id.as_str()))
                    {
                        return Err("native_command_permission_dependency_unknown");
                    }
                }
            }
        }
        let compatibility: BTreeSet<_> = packs
            .iter()
            .flat_map(|pack| &pack.rules)
            .filter(|rule| rule.matcher.is_none())
            .map(|rule| rule.rule_id.as_str())
            .collect();
        if compatibility
            != crate::command_compatibility::compatibility_rule_ids()
                .iter()
                .copied()
                .collect()
        {
            return Err("native_command_compatibility_inventory_mismatch");
        }
        let identities: Vec<_> = packs.iter().map(|pack| serde_json::json!({
            "extension":pack.extensions[0].extension_id,
            "program":pack.program_digest,"catalog":pack.catalog_digest,"trust":pack.trust_digest,
        })).collect();
        let program_digest = digest_value(
            b"hol-guard.active-command-program.v1\0",
            &serde_json::json!({
                "engine":env!("GUARD_COMMAND_SOURCE_IMPLEMENTATION"),"packs":identities,
            }),
        )?;
        let catalog_digest = digest_value(b"hol-guard.active-command-catalog.v1\0", &identities)?;
        let trust_digest = digest_value(b"hol-guard.active-command-trust.v1\0", &identities)?;
        let mut extensions = Vec::new();
        let mut rules = Vec::new();
        let mut nodes = Vec::new();
        let mut node_ids = Vec::new();
        let mut shared_nodes = BTreeMap::<String, usize>::new();
        let mut executable_index = BTreeMap::<String, Vec<usize>>::new();
        let mut keyword_index = BTreeMap::<String, Vec<usize>>::new();
        let mut unindexed = Vec::new();
        for pack in packs {
            let extension_offset = extensions.len();
            let rule_offset = rules.len();
            extension_offset
                .checked_add(pack.extensions.len())
                .ok_or("native_command_pack_index_invalid")?;
            rule_offset
                .checked_add(pack.rules.len())
                .ok_or("native_command_pack_index_invalid")?;
            if pack.node_ids.len() != pack.nodes.len() {
                return Err("native_command_pack_index_invalid");
            }
            let mut mapping = Vec::with_capacity(pack.node_ids.len());
            for id in &pack.node_ids {
                let next = shared_nodes.len();
                mapping.push(*shared_nodes.entry(id.clone()).or_insert(next));
            }
            for (local, mut node) in pack.nodes.into_iter().enumerate() {
                if mapping[local] < nodes.len() {
                    continue;
                }
                if mapping[local] != nodes.len() {
                    return Err("native_command_pack_index_invalid");
                }
                match &mut node.matcher {
                    Matcher::Any(children) | Matcher::All(children) => {
                        for index in children {
                            *index = mapping[*index];
                        }
                    }
                    Matcher::Pipeline(left, right) => {
                        *left = mapping[*left];
                        *right = mapping[*right];
                    }
                    _ => (),
                }
                nodes.push(node);
                node_ids.push(pack.node_ids[local].clone());
            }
            for mut rule in pack.rules {
                rule.extension_index += extension_offset;
                if let Some(index) = &mut rule.matcher {
                    *index = mapping[*index];
                }
                for (_, index) in &mut rule.variants {
                    *index = mapping[*index];
                }
                rules.push(rule);
            }
            for (key, values) in pack.executable_index {
                executable_index
                    .entry(key)
                    .or_default()
                    .extend(values.into_iter().map(|index| index + rule_offset));
            }
            for (key, values) in pack.keyword_index {
                keyword_index
                    .entry(key)
                    .or_default()
                    .extend(values.into_iter().map(|index| index + rule_offset));
            }
            unindexed.extend(pack.unindexed.into_iter().map(|index| index + rule_offset));
            extensions.extend(pack.extensions);
        }
        let rule_indices = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (rule.rule_id.clone(), index))
            .collect();
        let (extension_rule_indices, baseline_allow_permissions) =
            dispatch::admission_indexes(&extensions, &rules);
        Ok(Self {
            program_digest,
            catalog_digest,
            trust_digest,
            extensions,
            rules,
            nodes,
            node_ids,
            executable_index,
            keyword_index,
            unindexed,
            rule_indices,
            extension_rule_indices,
            baseline_allow_permissions,
        })
    }
}

#[cfg(test)]
#[path = "native_command_program_collection_tests.rs"]
mod tests;
