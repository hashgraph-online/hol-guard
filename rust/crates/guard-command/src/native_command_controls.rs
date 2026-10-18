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
    digest_value, packaged_command_program, CommandCandidateIndex, NativeCommandProgram,
};
use crate::CanonicalCommandV1;

#[path = "native_command_controls_admission.rs"]
mod admission;
#[path = "native_command_controls_risk.rs"]
mod risk;

#[derive(Debug)]
pub struct CompiledNativeCommandControls {
    program: Arc<NativeCommandProgram>,
    binding: NativeCommandControlBindingV1,
    active_extensions: BTreeSet<String>,
    candidate_index: CommandCandidateIndex,
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

    /// The authority health the bound control program reported.
    pub fn health(&self) -> &str {
        &self.binding.health
    }

    fn for_program_inner(
        binding: &NativeCommandControlBindingV1,
        program: Arc<NativeCommandProgram>,
        retain_inactive: bool,
    ) -> Result<Self, &'static str> {
        admission::validate_binding(binding, &program)?;
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
                let unknown = (is_extension
                    && !extension_indices.contains_key(control.target_id.as_str()))
                    || (!is_extension && !permissions.contains_key(control.target_id.as_str()));
                if unknown
                    && (!retain_inactive
                        || !admission::may_retain_inactive(control, &layer.kind, |owner| {
                            extension_indices.contains_key(owner)
                        }))
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
            candidate_index: CommandCandidateIndex::for_active(&program, &active_extensions),
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
        result: PreToolResultV1,
        tool: Option<&str>,
        packages: &[String],
        deadline: Option<Instant>,
    ) -> PreToolResultV1 {
        self.apply_with_tool_and_context(
            command,
            result,
            tool,
            packages,
            deadline,
            crate::pretool::PathContext::default(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn apply_with_tool_and_context(
        &self,
        command: Option<&CanonicalCommandV1>,
        mut result: PreToolResultV1,
        tool: Option<&str>,
        packages: &[String],
        deadline: Option<Instant>,
        context: crate::pretool::PathContext<'_>,
        environment: Option<&guard_contracts::GuardExecutionEnvironmentV1>,
    ) -> PreToolResultV1 {
        let observed = match command {
            Some(command) => self.observe_command(command, deadline, context, environment),
            None => Ok((NativeCommandObservationBatchV1::default(), None)),
        };
        let (mut batch, unmodeled) = match observed {
            Ok(observed) => observed,
            Err(_) => (
                NativeCommandObservationBatchV1 {
                    evaluation_error: Some("native_command_evaluation_failed".to_owned()),
                    ..Default::default()
                },
                None,
            ),
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
        // An uncertain observation may belong to any of its candidate owners,
        // so it takes the strongest of their floors and never less than review.
        // An unmodeled command already carries the floor of its possible owners.
        let mut uncertain_floor: Option<&'static str> = unmodeled;
        // Uncertainty about a Git rule the user explicitly allowed reviews only
        // when that Allow does not cover the whole command, or the command runs
        // in a repository Guard could not inspect (below).
        let mut enabled_uncertainty = false;
        for observation in &batch.observations {
            if !observation.uncertainty_reasons.is_empty() {
                let candidate = self.uncertain_candidate(&observation.rule_id);
                enabled_uncertainty |= candidate.is_none();
                if let Some(candidate) = candidate {
                    let candidate = if rank(candidate) < rank("review") {
                        "review"
                    } else {
                        candidate
                    };
                    if uncertain_floor.is_none_or(|current| rank(candidate) > rank(current)) {
                        uncertain_floor = Some(candidate);
                    }
                }
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
            // A ruleless permission has no declared floor to bound uncertainty.
            if !observation.uncertainty_reasons.is_empty() {
                uncertain_floor = Some("block");
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
        if floor::proof_owner_disabled(&self.blocked_extensions, command, context) {
            floor = "block";
            reason = "native_command_extension_disabled";
        }
        if let Some(candidate) = uncertain_floor {
            if rank(candidate) > rank(floor) {
                floor = candidate;
                reason = "native_command_extension_uncertain";
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
        let explicit_allow = floor == "allow"
            && self.explicit_allow(&result, &batch, command, context, enabled_uncertainty);
        if enabled_uncertainty && !explicit_allow && rank(floor) < rank("review") {
            floor = "review";
            reason = "native_command_extension_uncertain";
        }
        if explicit_allow && result.minimum_action != "allow" {
            precedence::settle_with_explicit_allow(&mut result);
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
        floor::explain_expired_deadline(&mut result, deadline);
        let global_lockdown = self
            .binding
            .layers
            .iter()
            .any(|layer| layer.global_lockdown);
        add_authority_repair_hint(&mut result, &self.binding.health, global_lockdown);
        result
    }

    fn explicit_permissions_cover_command(
        &self,
        command: &CanonicalCommandV1,
        batch: &NativeCommandObservationBatchV1,
        context: crate::pretool::PathContext<'_>,
    ) -> bool {
        if command.confidence != "exact"
            || command.path_overridden
            || !command.wrapper_chain.is_empty()
            || command.segments.is_empty()
        {
            return false;
        }
        let mut covered: BTreeSet<_> = crate::pretool::benign_command_segments(command, context)
            .into_iter()
            .collect();
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
                if observation
                    .effective_segment_indexes
                    .iter()
                    .all(|index| covered.contains(index))
                {
                    continue;
                }
                return false;
            }
            covered.extend(observation.effective_segment_indexes.iter().copied());
        }
        // GitHub permission-only owners run last so they never hide an
        // ungranted rule.
        covered.extend(self.github_granted_segments(&batch.permission_observations));
        // Delegated package-firewall ownership is not execution consent. Only
        // verified rule observations or the native benign proof can cover a
        // segment; an extra unclassified command retains its own review.
        (0..command.segments.len()).all(|index| covered.contains(&index))
    }
}

#[path = "native_command_delegated.rs"]
mod delegated;
pub(crate) use delegated::normalized_tool;

#[path = "native_command_controls_floor.rs"]
mod floor;
#[path = "native_command_controls_precedence.rs"]
mod precedence;
#[path = "native_command_unmodeled.rs"]
mod unmodeled;
use floor::{add_authority_repair_hint, rank, rule_floor, strengthen};
pub(crate) use unmodeled::{python_is_builtin_only, python_stdin, unread_file_interpreter};

#[cfg(test)]
#[path = "native_command_controls_tests.rs"]
mod review_regressions;

#[cfg(test)]
#[path = "native_command_uncertainty_tests.rs"]
mod uncertainty_regressions;

#[cfg(test)]
#[path = "native_command_precedence_tests.rs"]
mod precedence_regressions;

#[cfg(test)]
#[path = "native_command_compound_controls_tests.rs"]
mod compound_regressions;

#[cfg(test)]
#[path = "native_command_script_controls_tests.rs"]
mod script_regressions;

#[cfg(test)]
#[path = "native_command_powershell_tests.rs"]
mod powershell_regressions;

#[cfg(test)]
#[path = "native_command_read_permission_tests.rs"]
mod read_permission_regressions;
