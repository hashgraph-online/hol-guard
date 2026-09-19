//! Validate and compile the packaged program once.

use super::*;

impl NativeCommandProgram {
    // Production callers cannot submit arbitrary program bytes: the executable
    // and its packaged artifact are one attested release identity.
    pub(super) fn from_packaged_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        Self::from_packaged_bytes_observed(bytes, |_| {})
    }

    // The no-op production observer is removed by monomorphization. Diagnostic
    // callers time these actual admission phases without maintaining a second
    // implementation of their validation or compilation work.
    pub(super) fn from_packaged_bytes_observed(
        bytes: &[u8],
        mut observe_phase: impl FnMut(&'static str),
    ) -> Result<Self, &'static str> {
        if bytes.len() > MAX_PROGRAM_BYTES {
            return Err("native_command_program_bytes_exceeded");
        }
        let mut value: Value =
            serde_json::from_slice(bytes).map_err(|_| "native_command_program_json_invalid")?;
        observe_phase("json_value_parse");
        let canonical =
            serde_json::to_vec(&value).map_err(|_| "native_command_program_json_invalid")?;
        if bytes != canonical && bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
            return Err("native_command_program_noncanonical");
        }
        let object = value
            .as_object_mut()
            .ok_or("native_command_program_shape_invalid")?;
        let digest = object
            .remove("program_digest")
            .ok_or("native_command_program_digest_missing")?;
        let expected_digest = digest_json_value(PROGRAM_DOMAIN, &value)?;
        if digest.as_str() != Some(&expected_digest) {
            return Err("native_command_program_digest_mismatch");
        }
        observe_phase("canonical_program_digest");
        value
            .as_object_mut()
            .ok_or("native_command_program_shape_invalid")?
            .insert("program_digest".into(), digest);
        // Consume the already strictly checked JSON value. Re-decoding the
        // complete artifact would retain two independent configuration trees.
        let raw: RawProgram =
            serde_json::from_value(value).map_err(|_| "native_command_program_contract_invalid")?;
        observe_phase("typed_program_decode");
        if raw.schema != PROGRAM_SCHEMA
            || raw.compiler_version != 1
            || raw.semantic_profile != "cpython-3.12-ucd15"
        {
            return Err("native_command_program_version_unsupported");
        }
        if [
            raw.authoring_semantics_digest.as_str(),
            &raw.catalog_digest,
            &raw.trust_digest,
            &raw.program_digest,
        ]
        .iter()
        .any(|value| !valid_digest(value))
            || raw.rules.len() > MAX_RULES
            || raw.nodes.len() > MAX_NODES
            || raw.extensions.len() > 512
            || raw.coverage.len() != raw.rules.len()
            || raw.matcher_families.len() > 64
        {
            return Err("native_command_program_bounds_invalid");
        }
        let extension_indices: BTreeMap<_, _> = raw
            .extensions
            .iter()
            .enumerate()
            .map(|(index, extension)| (extension.extension_id.clone(), index))
            .collect();
        if extension_indices.len() != raw.extensions.len() {
            return Err("native_command_extension_duplicate");
        }
        let mut permission_owners = BTreeMap::new();
        for (index, extension) in raw.extensions.iter().enumerate() {
            if !bounded_id(&extension.extension_id)
                || !bounded_id(&extension.version)
                || !matches!(
                    extension.trust_class.as_str(),
                    "first-party" | "trusted-library" | "external"
                )
                || extension.permissions.len() > 512
                || extension
                    .dependencies
                    .iter()
                    .any(|id| !extension_indices.contains_key(id))
            {
                return Err("native_command_extension_contract_invalid");
            }
            for permission in &extension.permissions {
                if !bounded_id(&permission.permission_id)
                    || permission_owners
                        .insert(permission.permission_id.clone(), index)
                        .is_some()
                {
                    return Err("native_command_permission_contract_invalid");
                }
            }
        }
        for extension in &raw.extensions {
            for permission in &extension.permissions {
                if permission
                    .dependencies
                    .iter()
                    .chain(&permission.implied_permissions)
                    .any(|id| !permission_owners.contains_key(id))
                {
                    return Err("native_command_permission_dependency_invalid");
                }
            }
        }
        let node_indices: BTreeMap<_, _> = raw
            .nodes
            .keys()
            .enumerate()
            .map(|(index, id)| (id.clone(), index))
            .collect();
        let mut nodes = Vec::with_capacity(raw.nodes.len());
        observe_phase("catalog_validation");
        for (id, node) in raw.nodes {
            let canonical =
                serde_json::to_vec(&node).map_err(|_| "native_command_encoding_failed")?;
            if !valid_digest(&id) || digest_canonical_bytes(NODE_DOMAIN, &canonical) != id {
                return Err("native_command_matcher_digest_mismatch");
            }
            nodes.push(compile_node(node, &node_indices)?);
        }
        let mut visit = vec![0_u8; nodes.len()];
        let mut heights = vec![0; nodes.len()];
        for index in 0..nodes.len() {
            validate_graph(index, &nodes, &mut visit, &mut heights, 0)?;
        }
        observe_phase("matcher_digest_compile");
        let mut rules = Vec::with_capacity(raw.rules.len());
        let mut ids = BTreeSet::new();
        let mut executable_index = BTreeMap::<String, Vec<usize>>::new();
        let mut keyword_index = BTreeMap::<String, Vec<usize>>::new();
        let mut unindexed = Vec::new();
        for (index, (rule, coverage)) in raw.rules.into_iter().zip(raw.coverage).enumerate() {
            let extension_index = *extension_indices
                .get(&rule.extension_id)
                .ok_or("native_command_rule_owner_missing")?;
            if !bounded_id(&rule.rule_id)
                || !ids.insert(rule.rule_id.clone())
                || permission_owners.get(&rule.permission_id) != Some(&extension_index)
                || rule.safe_variants.len() > 64
                || coverage.rule_id != rule.rule_id
                || !valid_digest(&coverage.matcher_contract_digest)
                || coverage.native_execution != "requires-runtime-admission"
                || coverage.translation
                    != if rule.matcher.is_some() {
                        "declarative-ir"
                    } else {
                        "compatibility-only"
                    }
                || coverage.safe_variants.len() != rule.safe_variants.len()
            {
                return Err("native_command_rule_coverage_invalid");
            }
            let mut variants = Vec::new();
            let mut variant_ids = BTreeSet::new();
            for (variant, manifest) in rule.safe_variants.into_iter().zip(coverage.safe_variants) {
                if !bounded_id(&variant.variant_id)
                    || !variant_ids.insert(variant.variant_id.clone())
                    || manifest.variant_id != variant.variant_id
                    || !valid_digest(&manifest.matcher_contract_digest)
                {
                    return Err("native_command_variant_coverage_invalid");
                }
                variants.push((
                    variant.variant_id,
                    *node_indices
                        .get(&variant.matcher)
                        .ok_or("native_command_node_missing")?,
                ));
            }
            let matcher = rule
                .matcher
                .map(|id| {
                    node_indices
                        .get(&id)
                        .copied()
                        .ok_or("native_command_node_missing")
                })
                .transpose()?;
            for executable in rule.candidate_executables {
                executable_index.entry(executable).or_default().push(index);
            }
            for keyword in rule.candidate_keywords {
                keyword_index.entry(keyword).or_default().push(index);
            }
            if rule.candidate_unindexed {
                unindexed.push(index);
            }
            rules.push(ProgramRule {
                rule_id: rule.rule_id,
                rule_version: rule.rule_version,
                extension_index,
                permission_id: rule.permission_id,
                baseline_floor: rule.baseline_floor,
                configurable: rule.configurable,
                default_mode: rule.default_mode,
                severity: rule.severity,
                risk_classes: rule.risk_classes,
                action_classes: rule.action_classes,
                matcher,
                variants,
            });
        }
        let compatibility_ids: BTreeSet<_> = crate::command_compatibility::compatibility_rule_ids()
            .iter()
            .copied()
            .collect();
        let catalog_compatibility: BTreeSet<_> = rules
            .iter()
            .filter(|rule| rule.matcher.is_none())
            .map(|rule| rule.rule_id.as_str())
            .collect();
        if compatibility_ids != catalog_compatibility {
            return Err("native_command_compatibility_inventory_mismatch");
        }
        let rule_indices = rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (rule.rule_id.clone(), index))
            .collect();
        observe_phase("rule_candidate_indexes");
        Ok(Self {
            rule_indices,
            program_digest: raw.program_digest,
            catalog_digest: raw.catalog_digest,
            trust_digest: raw.trust_digest,
            extensions: raw.extensions,
            rules,
            nodes,
            executable_index,
            keyword_index,
            unindexed,
        })
    }
}
