//! Compile authenticated controls once against the exact packaged catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use guard_contracts::{
    NativeCommandControlBindingV1, NativeCommandObservationBatchV1, NativeCommandObservationsV1,
    NativeCommandReceiptBindingV1, PreToolResultV1, NATIVE_COMMAND_OBSERVATIONS_SCHEMA,
    NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA,
};

use crate::native_command_control_projection::project_validated_layer;
use crate::native_command_program::{
    digest_value, packaged_command_program, NativeCommandProgram, ProgramRule,
};
use crate::CanonicalCommandV1;

#[derive(Debug)]
pub struct CompiledNativeCommandControls {
    program: Arc<NativeCommandProgram>,
    binding: NativeCommandControlBindingV1,
    active_extensions: BTreeSet<String>,
    blocked_extensions: BTreeSet<String>,
    blocked_permissions: BTreeSet<String>,
    explicitly_enabled_permissions: BTreeSet<String>,
    global_block: bool,
    rule_indices: BTreeMap<String, usize>,
}

impl CompiledNativeCommandControls {
    pub fn new(binding: &NativeCommandControlBindingV1) -> Result<Self, &'static str> {
        Self::for_program(binding, packaged_command_program()?)
    }

    // Production always supplies the packaged, attested program through new().
    // The crate-local seam also lets diagnostic tests vary real compiled
    // catalogs without duplicating any control admission or evaluation logic.
    pub(crate) fn for_program(
        binding: &NativeCommandControlBindingV1,
        program: Arc<NativeCommandProgram>,
    ) -> Result<Self, &'static str> {
        binding.validate()?;
        if binding.program_digest != program.program_digest
            || binding.catalog_digest != program.catalog_digest
            || binding.trust_digest != program.trust_digest
        {
            return Err("native_command_program_binding_mismatch");
        }
        let extension_indices: BTreeMap<_, _> = program
            .extensions
            .iter()
            .enumerate()
            .map(|(index, extension)| (extension.extension_id.as_str(), index))
            .collect();
        let permissions: BTreeMap<_, _> = program
            .extensions
            .iter()
            .flat_map(|extension| {
                extension.permissions.iter().map(move |permission| {
                    (permission.permission_id.as_str(), (extension, permission))
                })
            })
            .collect();
        let mut composed = BTreeMap::<(&str, &str), bool>::new();
        let mut locally_enabled = BTreeSet::new();
        let mut global_block = binding.health != "protected";
        for layer in &binding.layers {
            global_block |= layer.global_lockdown;
            for ((target_kind, target_id), disabled) in project_validated_layer(layer)? {
                let is_extension = target_kind == "extension";
                if (is_extension && !extension_indices.contains_key(target_id))
                    || (!is_extension && !permissions.contains_key(target_id))
                {
                    return Err("native_command_control_target_unknown");
                }
                composed
                    .entry((target_kind, target_id))
                    .and_modify(|previous| *previous |= disabled)
                    .or_insert(disabled);
                if is_extension && layer.kind == "local-admin" && !disabled {
                    locally_enabled.insert(target_id);
                }
            }
        }
        let mut active_extensions = BTreeSet::new();
        let mut blocked_extensions = BTreeSet::new();
        for extension in &program.extensions {
            let disabled =
                composed.get(&("extension", extension.extension_id.as_str())) == Some(&true);
            let active = extension.required
                || extension.trust_class != "external"
                || (locally_enabled.contains(extension.extension_id.as_str()) && !disabled);
            if active {
                active_extensions.insert(extension.extension_id.clone());
            }
            let mut pending = vec![extension.extension_id.as_str()];
            let mut visited = BTreeSet::new();
            while let Some(id) = pending.pop() {
                if !visited.insert(id) {
                    continue;
                }
                if composed.get(&("extension", id)) == Some(&true) {
                    blocked_extensions.insert(extension.extension_id.clone());
                }
                let index = *extension_indices
                    .get(id)
                    .ok_or("native_command_extension_dependency_unknown")?;
                pending.extend(
                    program.extensions[index]
                        .dependencies
                        .iter()
                        .map(String::as_str),
                );
            }
        }
        let mut blocked_permissions = BTreeSet::new();
        let mut explicitly_enabled_permissions = BTreeSet::new();
        for (id, (_, permission)) in &permissions {
            if binding.health == "protected"
                && permission.configurable
                && composed.get(&("permission", id)) == Some(&false)
            {
                explicitly_enabled_permissions.insert((*id).to_owned());
            }
            let mut pending = vec![*id];
            let mut visited = BTreeSet::new();
            while let Some(current) = pending.pop() {
                if !visited.insert(current) {
                    continue;
                }
                let (owner, dependent) = permissions
                    .get(current)
                    .ok_or("native_command_permission_dependency_unknown")?;
                if composed.get(&("permission", current)) == Some(&true)
                    || blocked_extensions.contains(&owner.extension_id)
                {
                    blocked_permissions.insert((*id).to_owned());
                }
                pending.extend(
                    dependent
                        .dependencies
                        .iter()
                        .chain(&dependent.implied_permissions)
                        .map(String::as_str),
                );
            }
        }
        let rule_indices = program
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| (rule.rule_id.clone(), index))
            .collect();
        Ok(Self {
            program,
            binding: binding.clone(),
            active_extensions,
            blocked_extensions,
            blocked_permissions,
            explicitly_enabled_permissions,
            global_block,
            rule_indices,
        })
    }

    pub fn apply(
        &self,
        command: &CanonicalCommandV1,
        mut result: PreToolResultV1,
        deadline: Option<Instant>,
    ) -> PreToolResultV1 {
        let batch = match self
            .program
            .observe(command, &self.active_extensions, deadline)
        {
            Ok(batch) => batch,
            Err(_) => {
                strengthen(
                    &mut result,
                    "block",
                    "native_command_extension_evaluation_failed",
                );
                NativeCommandObservationBatchV1 {
                    evaluation_error: Some("native_command_evaluation_failed".to_owned()),
                    ..Default::default()
                }
            }
        };
        let mut floor = if self.global_block { "block" } else { "allow" };
        let mut reason = if self.global_block {
            "native_command_control_authority_block"
        } else {
            "native_command_extension_review"
        };
        for observation in &batch.observations {
            if !observation.uncertainty_reasons.is_empty() {
                floor = "block";
                reason = "native_command_extension_uncertain";
            }
            if self.blocked_extensions.contains(&observation.extension_id) {
                floor = "block";
                reason = "native_command_extension_disabled";
            }
            if observation.effective_segment_indexes.is_empty() {
                continue;
            }
            let Some(index) = self.rule_indices.get(&observation.rule_id) else {
                floor = "block";
                reason = "native_command_extension_identity_invalid";
                continue;
            };
            let rule = &self.program.rules[*index];
            if self.blocked_permissions.contains(&rule.permission_id) {
                floor = "block";
                reason = "native_command_permission_disabled";
            }
            if !self
                .explicitly_enabled_permissions
                .contains(&rule.permission_id)
            {
                let candidate =
                    rule_floor(rule, self.program.extensions[rule.extension_index].required);
                if rank(candidate) > rank(floor) {
                    floor = candidate;
                }
            }
        }
        for observation in &batch.permission_observations {
            if !observation.uncertainty_reasons.is_empty() {
                floor = "block";
                reason = "native_command_extension_uncertain";
            }
            if self.blocked_extensions.contains(&observation.extension_id)
                || self
                    .blocked_permissions
                    .contains(&observation.permission_id)
            {
                floor = "block";
                reason = "native_command_permission_disabled";
            }
        }
        let observations_digest =
            match digest_value(b"hol-guard.native-command-observations.v1\0", &batch) {
                Ok(digest) => digest,
                Err(_) => {
                    strengthen(
                        &mut result,
                        "block",
                        "native_command_extension_evaluation_failed",
                    );
                    return result;
                }
            };
        let binding = NativeCommandReceiptBindingV1 {
            schema: NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA.to_owned(),
            program_digest: self.binding.program_digest.clone(),
            catalog_digest: self.binding.catalog_digest.clone(),
            trust_digest: self.binding.trust_digest.clone(),
            control_revision: self.binding.revision,
            managed_control_revision: self.binding.managed_revision,
            control_effective_digest: self.binding.effective_digest.clone(),
            observations_digest,
            observation_count: batch.observations.len() + batch.permission_observations.len(),
            uncertainty_count: batch
                .observations
                .iter()
                .filter(|observation| !observation.uncertainty_reasons.is_empty())
                .count()
                + batch
                    .permission_observations
                    .iter()
                    .filter(|observation| !observation.uncertainty_reasons.is_empty())
                    .count()
                + usize::from(batch.evaluation_error.is_some()),
        };
        result.command_extensions = Some(NativeCommandObservationsV1 {
            schema: NATIVE_COMMAND_OBSERVATIONS_SCHEMA.to_owned(),
            binding,
            observations: batch.observations,
            permission_observations: batch.permission_observations,
            evaluation_error: batch.evaluation_error,
        });
        strengthen(&mut result, floor, reason);
        result
    }
}

fn rule_floor(rule: &ProgramRule, required: bool) -> &'static str {
    if rule.is_compatibility_attribution_only() {
        return "allow";
    }
    if required {
        return if rule.severity == "critical" {
            "block"
        } else {
            "review"
        };
    }
    match rule.default_mode.as_str() {
        "disabled" => "allow",
        "monitor" => "warn",
        "review" | "required" => "review",
        _ => "block",
    }
}

fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

fn strengthen(result: &mut PreToolResultV1, action: &str, reason: &str) {
    if rank(action) > rank(&result.minimum_action) {
        result.minimum_action = action.to_owned();
        result.policy_action = action.to_owned();
        result.decision = if matches!(action, "allow" | "warn") {
            "allow"
        } else {
            "deny"
        }
        .to_owned();
        result.explicitly_benign = action == "allow";
        result.reason_code = reason.to_owned();
        result.reason = "HOL Guard requires the native command extension policy before this action can execute.".to_owned();
    }
}
