//! Compile authenticated controls once against the exact packaged catalog.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Instant;

use guard_contracts::{
    NativeCommandControlBindingV1, NativeCommandObservationBatchV1, NativeCommandObservationsV1,
    NativeCommandReceiptBindingV1, PreToolResultV1, NATIVE_COMMAND_OBSERVATIONS_SCHEMA,
    NATIVE_COMMAND_RECEIPT_BINDING_SCHEMA,
};

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
        // A never-enrolled device still gets packaged first-party protection.
        // It cannot opt in external code or carry any permission override.
        // The snapshot store rejects this baseline after a protected floor has
        // ever been retained, including across expiry, quarantine and restart.
        let initial_defaults = binding.health == "unenrolled"
            && binding.revision == 0
            && binding.managed_revision == 0
            && binding.layers.is_empty()
            && binding.authority.as_ref().is_some_and(|authority| {
                authority.epoch == 1
                    && authority.authority_key_id == "0".repeat(64)
                    && authority.recovery.is_none()
            });
        let mut global_block = binding.health != "protected" && !initial_defaults;
        for layer in &binding.layers {
            global_block |= layer.global_lockdown;
            for control in &layer.controls {
                let is_extension = control.target_kind == "extension";
                if (is_extension && !extension_indices.contains_key(control.target_id.as_str()))
                    || (!is_extension && !permissions.contains_key(control.target_id.as_str()))
                {
                    return Err("native_command_control_target_unknown");
                }
                let disabled = control.state == "disabled";
                let key = (control.target_kind.as_str(), control.target_id.as_str());
                composed
                    .entry(key)
                    .and_modify(|previous| *previous |= disabled)
                    .or_insert(disabled);
                if is_extension && layer.kind == "local-admin" && !disabled {
                    locally_enabled.insert(control.target_id.as_str());
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
        result: PreToolResultV1,
        deadline: Option<Instant>,
    ) -> PreToolResultV1 {
        self.apply_with_tool(Some(command), result, None, &[], deadline)
    }

    pub fn apply_with_tool(
        &self,
        command: Option<&CanonicalCommandV1>,
        mut result: PreToolResultV1,
        tool: Option<&str>,
        packages: &[String],
        deadline: Option<Instant>,
    ) -> PreToolResultV1 {
        let observed = match command {
            Some(command) => self
                .program
                .observe(command, &self.active_extensions, deadline),
            None => Ok(NativeCommandObservationBatchV1::default()),
        };
        let mut batch = match observed {
            Ok(batch) => batch,
            Err(_) => NativeCommandObservationBatchV1 {
                evaluation_error: Some("native_command_evaluation_failed".to_owned()),
                ..Default::default()
            },
        };
        let delegated_floor = if batch.evaluation_error.is_none() {
            match self.delegated_observations(command, tool, packages, &mut batch, deadline) {
                Ok(action) => action,
                Err(_) => {
                    batch = NativeCommandObservationBatchV1 {
                        evaluation_error: Some("native_command_evaluation_failed".into()),
                        ..Default::default()
                    };
                    "block"
                }
            }
        } else {
            "allow"
        };
        let mut floor = if self.global_block {
            "block"
        } else {
            delegated_floor
        };
        let mut reason = if self.global_block {
            "native_command_control_authority_block"
        } else if batch.evaluation_error.is_some() {
            "native_command_extension_evaluation_failed"
        } else if delegated_floor == "block" {
            "native_command_permission_disabled"
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
        if result.reason_code == "native_command_review_required"
            && result.minimum_action == "review"
            && result.action.bounded
            && !result.action.sensitive_target
            && floor == "allow"
            && binding.uncertainty_count == 0
            && command.is_some_and(|model| self.explicit_permissions_cover_command(model, &batch))
        {
            // Authenticated consent to every classified command segment can
            // settle the generic unknown-command floor, never an intrinsic risk.
            result.minimum_action = "allow".into();
            result.policy_action = "allow".into();
            result.decision = "allow".into();
            result.explicitly_benign = true;
            result.reason_code = "native_command_explicit_permission_allow".into();
            result.reason =
                "This command is allowed by its authenticated extension permissions.".into();
        }
        let evaluation_error = batch.evaluation_error.clone();
        result.command_extensions = Some(NativeCommandObservationsV1 {
            schema: NATIVE_COMMAND_OBSERVATIONS_SCHEMA.to_owned(),
            binding,
            observations: batch.observations,
            permission_observations: batch.permission_observations,
            evaluation_error: batch.evaluation_error,
        });
        if evaluation_error.is_some() && !self.global_block && rank(floor) < rank("block") {
            floor = "block";
            reason = "native_command_extension_evaluation_failed";
        }
        strengthen(&mut result, floor, reason);
        result
    }

    fn explicit_permissions_cover_command(
        &self,
        command: &CanonicalCommandV1,
        batch: &NativeCommandObservationBatchV1,
    ) -> bool {
        if command.confidence != "exact"
            || command.path_overridden
            || !command.wrapper_chain.is_empty()
            || command.segments.is_empty()
        {
            return false;
        }
        let mut covered = BTreeSet::new();
        for observation in &batch.observations {
            if observation.effective_segment_indexes.is_empty() {
                continue;
            }
            let Some(index) = self.rule_indices.get(&observation.rule_id) else {
                return false;
            };
            if !self
                .explicitly_enabled_permissions
                .contains(&self.program.rules[*index].permission_id)
            {
                return false;
            }
            covered.extend(observation.effective_segment_indexes.iter().copied());
        }
        // Delegated package-firewall ownership is not execution consent. Only
        // verified rule observations can cover a segment; an extra unclassified
        // command in a shell chain must retain its own review.
        (0..command.segments.len()).all(|index| covered.contains(&index))
    }
}

#[path = "native_command_delegated.rs"]
mod delegated;
pub(crate) use delegated::normalized_tool;

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
        result.reason = match reason {
            "native_command_extension_evaluation_failed" => {
                "HOL Guard could not evaluate the extension controls for this command. Check Guard diagnostics before retrying."
            }
            _ => "HOL Guard requires the native command extension policy before this action can execute.",
        }
        .to_owned();
    }
}

#[cfg(test)]
#[path = "native_command_controls_tests.rs"]
mod review_regressions;
