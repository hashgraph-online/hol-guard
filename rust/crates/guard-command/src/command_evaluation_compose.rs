//! Composite command evaluation (`runtime/command_evaluation.py::evaluate_command`).
//!
//! Composition only: the individual `DecisionFactor` producers live in sibling
//! modules, and the shell-read floor factors arrive as an input because the
//! filesystem read model owns cwd/home resolution on the host edge.

use std::collections::BTreeSet;

use guard_contracts::NativeCommandControlBindingV1;
use serde_json::Value;

use crate::canonical_command::CanonicalCommand;
use crate::command_action_risk_classes::risk_classes_for_command_action;
use crate::command_contained_routine_candidates::contained_routine_candidate_factor;
use crate::command_critical_floors::command_critical_floor_factors;
use crate::command_decision_adapter::{
    command_uncertainties, decision_factors, extension_evidence_batch, extension_uncertainties,
    CompatRuleRef,
};
use crate::command_evaluation::{
    decision_action_floor, match_precedence_key, rule_floor, stronger_floor, CommandDecisionFloor,
    CompositeCommandEvaluation, OwnedCommandRuleMatch, UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS,
};
use crate::command_evaluation_controls::{
    authority_evidence, authority_failure_for_health, control_layers_from_binding,
};
use crate::command_evaluation_support::{
    github_capability_from_str, owned_match, sorted_uncertainties,
};
use crate::command_native_factors::{
    direct_github_permission_ids, explicit_permission_allow_factors, native_classification_factors,
};
use crate::command_verified_read_candidates::verified_read_candidate_factor;
use crate::command_workspace_write_candidates::workspace_write_candidate_factors;
use crate::effect_decision::{
    evaluate_effect_decision, DecisionFactor, EffectDecisionRequest, GuardAction,
    EFFECT_DECISION_SCHEMA_VERSION,
};
use crate::extension_control::{resolve_extension_controls, ControlSurface, ResolverFailureCode};
use crate::extension_evidence::ExtensionEvidenceBatch;
use crate::extension_trust::filter_inert_external_observations;
use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_workflow_authorization::{
    github_workflow_authorization_evidence, GitHubWorkflowAuthorizationV1,
};
use crate::native_command_catalog::CommandCatalog;
use crate::native_command_extension_evidence::observations_from_native_evidence;

const ERR_UNKNOWN_IDENTITY: &str = "native_command_extension_evidence_unknown_identity";

/// Inputs of one evaluation. `read_factors` is the host-computed
/// `shell_read_floor_factors` output.
pub struct CommandEvaluationInput<'a> {
    pub command: &'a CanonicalCommand,
    pub native_extension_evidence: &'a Value,
    pub registry: &'a CommandCatalog,
    pub binding: &'a NativeCommandControlBindingV1,
    pub compatibility_action_class: Option<&'a str>,
    pub compatibility_reason: Option<&'a str>,
    pub workflow_authorization: Option<&'a GitHubWorkflowAuthorizationV1>,
    pub read_factors: Vec<DecisionFactor>,
}

/// `evaluate_command`: evaluate every built-in rule without executing or
/// persisting the command.
pub fn evaluate_command(
    input: CommandEvaluationInput<'_>,
) -> Result<CompositeCommandEvaluation, &'static str> {
    let CommandEvaluationInput {
        command,
        native_extension_evidence,
        registry,
        binding,
        compatibility_action_class,
        compatibility_reason,
        workflow_authorization,
        read_factors,
    } = input;
    let control_layers = control_layers_from_binding(binding)?;
    let authority_failure = authority_failure_for_health(&binding.health)?;
    let authority = authority_evidence(binding);
    let observations = filter_inert_external_observations(
        registry,
        &observations_from_native_evidence(native_extension_evidence, registry, command, binding)?,
        &control_layers,
    );
    let mut selected = Vec::new();
    for observation in &observations {
        let effective: Vec<_> = observation
            .effective_evidence()
            .into_iter()
            .cloned()
            .collect();
        if effective.is_empty() {
            continue;
        }
        let extension = registry
            .get(&observation.extension_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        let rule = extension
            .rules
            .iter()
            .find(|rule| rule.rule_id == observation.rule_id)
            .ok_or(ERR_UNKNOWN_IDENTITY)?;
        selected.push((observation, extension, rule, effective));
    }
    // Compatibility labels are display metadata, not additional observations.
    let compatibility_rule: Option<CompatRuleRef> = compatibility_action_class.and_then(|class| {
        selected
            .iter()
            .find(|(_, _, rule, _)| rule.action_classes.iter().any(|item| item == class))
            .map(|(_, extension, rule, _)| CompatRuleRef {
                extension_required: extension.required,
                rule_severity: rule.severity.clone(),
                rule_default_mode: rule.default_mode.clone(),
                rule_id: rule.rule_id.clone(),
            })
    });
    let effective_compatibility_class = compatibility_action_class
        .filter(|class| compatibility_rule.is_some() || !registry.has_action_class_owner(class));

    let mut owned_matches: Vec<OwnedCommandRuleMatch> = Vec::new();
    for (observation, _extension, rule, evidence) in &selected {
        owned_matches.push(owned_match(
            registry,
            observation,
            rule,
            evidence.clone(),
            effective_compatibility_class,
            compatibility_reason,
            command,
        )?);
    }

    let extension_ids: Vec<String> = observations
        .iter()
        .map(|observation| observation.extension_id.clone())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let mut permission_id_set: BTreeSet<String> = owned_matches
        .iter()
        .filter_map(|owned| registry.permission_for_rule_id(&owned.rule.rule_id))
        .map(|permission| permission.permission_id.clone())
        .collect();
    permission_id_set.extend(direct_github_permission_ids(command));
    let permission_ids: Vec<String> = permission_id_set.into_iter().collect();
    let observation_ids: Vec<String> = observations
        .iter()
        .map(|observation| format!("{}:{}", observation.extension_id, observation.rule_id))
        .collect();
    let control_resolution = resolve_extension_controls(
        &control_layers,
        Some(registry),
        &extension_ids,
        &permission_ids,
        ControlSurface::CommandEvaluation,
        &observation_ids,
        authority_failure,
    );
    let explicitly_enabled_permissions: BTreeSet<String> = control_resolution
        .explicitly_enabled_permission_ids
        .iter()
        .cloned()
        .collect();
    let relaxable_enabled_permissions: BTreeSet<String> = if authority_failure.is_none() {
        explicitly_enabled_permissions
            .iter()
            .filter(|id| {
                registry
                    .permission(id)
                    .is_some_and(|permission| permission.configurable)
            })
            .cloned()
            .collect()
    } else {
        BTreeSet::new()
    };
    let explicitly_enabled_rule_ids: BTreeSet<String> = relaxable_enabled_permissions
        .iter()
        .filter_map(|id| registry.permission(id))
        .flat_map(|permission| permission.rule_ids.iter().cloned())
        .collect();

    // `max` keeps the first of equal keys.
    let controlling_match = owned_matches.iter().fold(
        None,
        |best: Option<&OwnedCommandRuleMatch>, owned| match best {
            Some(current) if match_precedence_key(owned) <= match_precedence_key(current) => {
                Some(current)
            }
            _ => Some(owned),
        },
    );
    let mut controlling_action_class = effective_compatibility_class.map(str::to_owned);
    let mut controlling_reason = if effective_compatibility_class.is_some() {
        compatibility_reason.map(str::to_owned)
    } else {
        None
    };
    if controlling_action_class.is_none() {
        if let Some(controlling) = controlling_match {
            controlling_action_class = controlling.action_class.clone();
            controlling_reason = Some(controlling.reason.clone());
        }
    }
    let authorization_evidence =
        github_workflow_authorization_evidence(workflow_authorization, &command.security_identity);
    let authorized_action_class = authorization_evidence.as_ref().map(|(_, class)| *class);
    let workflow_authorized_rule_ids: BTreeSet<String> = observations
        .iter()
        .filter(|observation| {
            authorized_action_class.is_some_and(|class| {
                observation.uncertainty_reasons.is_empty()
                    && observation
                        .rule_action_classes
                        .iter()
                        .any(|item| item == class)
            })
        })
        .map(|observation| observation.rule_id.clone())
        .collect();
    let mut minimum_action = CommandDecisionFloor::Allow;
    let native_explicitly_benign = native_extension_evidence.is_object()
        && command.confidence == "exact"
        && native_extension_evidence
            .get("minimum_action")
            .and_then(Value::as_str)
            == Some("allow")
        && native_extension_evidence.get("explicitly_benign") == Some(&Value::Bool(true));
    // Ownership by a default-disabled rule is not proof of safety. Only an
    // explicit native benign classification discharges an optional allow-floor
    // observation; required rule floors remain active.
    let native_benign_rule_ids: BTreeSet<String> = if native_explicitly_benign {
        owned_matches
            .iter()
            .filter(|owned| {
                rule_floor(owned) == CommandDecisionFloor::Allow
                    && observations.iter().any(|observation| {
                        observation.rule_id == owned.rule.rule_id
                            && observation.uncertainty_reasons.is_empty()
                    })
            })
            .map(|owned| owned.rule.rule_id.clone())
            .collect()
    } else {
        BTreeSet::new()
    };
    // Syntax-level benign classification does not bind a read/write executor,
    // filesystem boundary, or launch identity.
    let contained_routine_candidate = contained_routine_candidate_factor(command);
    let verified_read_candidate = verified_read_candidate_factor(command);
    let workspace_write_candidates = workspace_write_candidate_factors(command);
    let execution_proof_required = contained_routine_candidate.is_some()
        || verified_read_candidate.is_some()
        || !workspace_write_candidates.is_empty();
    let native_host_floor_exempt = native_explicitly_benign && !execution_proof_required;
    for owned in &owned_matches {
        let rule_id = &owned.rule.rule_id;
        if native_benign_rule_ids.contains(rule_id)
            || explicitly_enabled_rule_ids.contains(rule_id)
            || workflow_authorized_rule_ids.contains(rule_id)
        {
            continue;
        }
        minimum_action = stronger_floor(minimum_action, rule_floor(owned));
    }
    let compatibility_owned_rule_ids: BTreeSet<&String> = owned_matches
        .iter()
        .filter(|owned| owned.action_class.as_deref() == effective_compatibility_class)
        .map(|owned| &owned.rule.rule_id)
        .collect();
    let compatibility_explicitly_enabled = (!compatibility_owned_rule_ids.is_empty()
        && compatibility_owned_rule_ids
            .iter()
            .all(|id| explicitly_enabled_rule_ids.contains(*id)))
        || compatibility_rule
            .as_ref()
            .is_some_and(|rule| explicitly_enabled_rule_ids.contains(&rule.rule_id));
    let compatibility_workflow_authorized = !compatibility_owned_rule_ids.is_empty()
        && compatibility_owned_rule_ids
            .iter()
            .all(|id| workflow_authorized_rule_ids.contains(*id));
    if effective_compatibility_class.is_some()
        && !compatibility_explicitly_enabled
        && !compatibility_workflow_authorized
    {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    if command.confidence != "exact"
        && (effective_compatibility_class.is_some() || !owned_matches.is_empty())
    {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    let observation_uncertainties = extension_uncertainties(&observations);
    if !observation_uncertainties.is_empty() {
        // Disabled controls still resolve to block through control_resolution.
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    let evidence_batch = extension_evidence_batch(command, &observations)?;
    let mut effective_evidence_batch = ExtensionEvidenceBatch {
        evidence: evidence_batch
            .evidence
            .iter()
            .filter(|evidence| {
                let rule_id = &evidence.identity.rule_id;
                !native_benign_rule_ids.contains(rule_id)
                    && (!explicitly_enabled_rule_ids.contains(rule_id)
                        || !evidence.uncertainty_reasons.is_empty())
            })
            .cloned()
            .collect(),
    };
    // A native benign proof cannot establish the resolved target of a file
    // read, so secret-read floors remain active even for proven benign commands.
    let mut read_factors = read_factors;
    if native_host_floor_exempt {
        read_factors.retain(|factor| factor.reason_code == "critical.local-secret-read");
    }
    if authorization_evidence.is_some() {
        read_factors.retain(|factor| factor.reason_code == "critical.local-secret-read");
    }
    if !read_factors.is_empty() {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    let explicitly_allowed_github_capabilities: Vec<GitHubCommandCapability> =
        relaxable_enabled_permissions
            .iter()
            .filter_map(|id| registry.permission(id))
            .flat_map(|permission| permission.typed_capabilities.iter())
            .filter_map(|capability| github_capability_from_str(capability))
            .collect();
    let critical_floor_factors: Vec<DecisionFactor> = if native_host_floor_exempt {
        Vec::new()
    } else {
        command_critical_floor_factors(
            command,
            workflow_authorization,
            if command.confidence == "exact" {
                &explicitly_allowed_github_capabilities
            } else {
                &[]
            },
        )
    };
    let explicit_permission_allow_factors = explicit_permission_allow_factors(
        command,
        &control_layers,
        &relaxable_enabled_permissions,
        Some(&authority),
    );
    if authorized_action_class.is_some() {
        effective_evidence_batch.evidence.retain(|evidence| {
            !workflow_authorized_rule_ids.contains(&evidence.identity.rule_id)
                || !evidence.uncertainty_reasons.is_empty()
        });
    }
    if contained_routine_candidate.is_some() || verified_read_candidate.is_some() {
        minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Review);
    }
    for candidate in &workspace_write_candidates {
        let floor = if candidate.basis.action_floor == GuardAction::Block {
            CommandDecisionFloor::Block
        } else {
            CommandDecisionFloor::Review
        };
        minimum_action = stronger_floor(minimum_action, floor);
    }
    let baseline_decision_factors = decision_factors(&evidence_batch, None, None)?;
    let decision_compatibility_action_class = effective_compatibility_class.filter(|class| {
        !compatibility_explicitly_enabled && authorized_action_class != Some(*class)
    });
    let current_decision_factors = decision_factors(
        &effective_evidence_batch,
        decision_compatibility_action_class,
        compatibility_rule.as_ref(),
    )?;
    let native_factors = native_classification_factors(
        native_extension_evidence,
        command,
        !execution_proof_required,
    );
    // Authenticated consent is evidence for the current decision, not proof
    // that the same command is benign without the control layer.
    let baseline_native_factors: &[DecisionFactor] = if native_extension_evidence
        .get("reason_code")
        .and_then(Value::as_str)
        == Some("native_command_explicit_permission_allow")
    {
        &[]
    } else {
        &native_factors
    };
    let mut baseline_factors: Vec<DecisionFactor> = baseline_native_factors.to_vec();
    baseline_factors.extend(baseline_decision_factors);
    baseline_factors.extend(contained_routine_candidate.iter().cloned());
    baseline_factors.extend(verified_read_candidate.iter().cloned());
    baseline_factors.extend(workspace_write_candidates.iter().cloned());
    baseline_factors.extend(critical_floor_factors.iter().cloned());
    baseline_factors.extend(read_factors.iter().cloned());
    let baseline_uncertainties = sorted_uncertainties([
        &command_uncertainties(command, !owned_matches.is_empty()),
        &observation_uncertainties,
    ]);
    let decision_uncertainties = if effective_compatibility_class.is_none() {
        baseline_uncertainties.clone()
    } else {
        sorted_uncertainties([
            &command_uncertainties(command, true),
            &observation_uncertainties,
        ])
    };
    // Unavailable authority still fail-closes cataloged, destructive, or write
    // commands. Secret reads and unmatched PATH tools keep their review floor.
    let mut apply_control_fail_closed = false;
    if control_resolution.blocked {
        let authority_unavailable_only = !control_resolution.failures.is_empty()
            && control_resolution
                .failures
                .iter()
                .all(|failure| failure.code == ResolverFailureCode::AuthorityUnavailable);
        apply_control_fail_closed = !authority_unavailable_only
            || !extension_ids.is_empty()
            || minimum_action == CommandDecisionFloor::Block
            || !workspace_write_candidates.is_empty();
        let fail_closed_risk = |risk: &str| UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.contains(&risk);
        if !apply_control_fail_closed {
            apply_control_fail_closed = owned_matches.iter().any(|owned| {
                owned
                    .rule
                    .risk_classes
                    .iter()
                    .any(|risk| fail_closed_risk(risk))
            });
        }
        if !apply_control_fail_closed {
            if let Some(class) = effective_compatibility_class {
                apply_control_fail_closed = risk_classes_for_command_action(class)
                    .iter()
                    .any(|risk| fail_closed_risk(risk));
            }
        }
        if apply_control_fail_closed {
            minimum_action = stronger_floor(minimum_action, CommandDecisionFloor::Block);
        }
    }
    let mut factors: Vec<DecisionFactor> = native_factors;
    factors.extend(current_decision_factors);
    factors.extend(contained_routine_candidate);
    factors.extend(verified_read_candidate);
    factors.extend(workspace_write_candidates);
    factors.extend(critical_floor_factors);
    factors.extend(read_factors);
    if apply_control_fail_closed {
        factors.extend(control_resolution.factors.iter().cloned());
    }
    factors.extend(explicit_permission_allow_factors);
    let decision_plane = evaluate_effect_decision(&EffectDecisionRequest {
        factors,
        uncertainties: decision_uncertainties,
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })?;
    let baseline_decision = evaluate_effect_decision(&EffectDecisionRequest {
        factors: baseline_factors.clone(),
        uncertainties: baseline_uncertainties,
        schema_version: EFFECT_DECISION_SCHEMA_VERSION.to_owned(),
    })?;
    // The decision plane includes intrinsic native evidence and non-extension
    // factors absent from the rule-floor accumulator; consumers must receive
    // the strongest materialized floor.
    minimum_action = stronger_floor(
        minimum_action,
        decision_action_floor(decision_plane.action.as_str()),
    );
    Ok(CompositeCommandEvaluation {
        security_identity: command.security_identity.clone(),
        parse_confidence: command.confidence.clone(),
        uncertainty_reason: command.uncertainty_reason.clone(),
        controlling_rule_id: controlling_match.map(|owned| owned.rule.rule_id.clone()),
        matches: owned_matches,
        controlling_action_class,
        controlling_reason,
        minimum_action,
        extension_observations: observations,
        decision_plane,
        baseline_factors,
        baseline_decision,
        control_resolution,
    })
}
