//! Match and uncertainty helpers of the composite command evaluation.
//!
//! Split from `command_evaluation_compose` so the composition entry point stays
//! within the repository file-size guideline.

use std::collections::BTreeSet;

use crate::canonical_command::CanonicalCommand;
use crate::command_decision_adapter::extension_uncertainties;
use crate::command_evaluation::{
    CommandSafetyRule, NativeCommandExtensionObservation, OwnedCommandRuleMatch,
};
use crate::effect_decision::{DecisionFactor, UncertaintyKind};
use crate::extension_evidence::ExtensionEvidenceBatch;
use crate::github_capability_contract::GitHubCommandCapability;
use crate::native_command_catalog::{CatalogRule, CommandCatalog};

const ERR_UNKNOWN_IDENTITY: &str = "native_command_extension_evidence_unknown_identity";

pub(crate) fn github_capability_from_str(capability: &str) -> Option<GitHubCommandCapability> {
    GitHubCommandCapability::ALL
        .iter()
        .find(|candidate| candidate.as_str() == capability)
        .copied()
}

pub(crate) fn sorted_uncertainties(groups: [&[UncertaintyKind]; 2]) -> Vec<UncertaintyKind> {
    let mut items: Vec<UncertaintyKind> = Vec::new();
    for item in groups.into_iter().flatten() {
        if !items.contains(item) {
            items.push(*item);
        }
    }
    items.sort_by_key(|item| item.as_str());
    items
}

fn settles_docker_uncertainty(command: &CanonicalCommand) -> bool {
    command.confidence == "exact"
        && command
            .segments
            .iter()
            .all(crate::command_compatibility::docker_segment_settles_uncertainty)
}

/// Whether every segment of the command stays inside what its text proves.
/// Uncertainty evidence is unattributed (`segment:unknown`), so it settles
/// only when the whole command settles, never one named segment.
fn command_settles_uncertainty(command: &CanonicalCommand) -> bool {
    command.confidence == "exact"
        && !command.segments.is_empty()
        && command.segments.iter().all(|segment| {
            crate::command_compatibility::segment_settles_uncertainty(
                segment,
                crate::pretool::PathContext::default(),
            )
        })
}

pub(crate) fn effective_observation_uncertainties(
    command: &CanonicalCommand,
    observations: &[NativeCommandExtensionObservation],
    explicitly_enabled_rule_ids: &BTreeSet<String>,
) -> Vec<UncertaintyKind> {
    // Enforcement settles an enabled rule only when every segment of the
    // command stays inside its proof, so the counterfactual must demand the
    // same: an observation whose own segments settle still reviews here
    // when a peer segment steers, interprets, or changes authority.
    if !command_settles_uncertainty(command) {
        return extension_uncertainties(observations);
    }
    let filtered: Vec<_> = observations
        .iter()
        .filter(|observation| !explicitly_enabled_rule_ids.contains(&observation.rule_id))
        .cloned()
        .collect();
    extension_uncertainties(&filtered)
}

pub(crate) fn filter_effective_evidence_batch(
    command: &CanonicalCommand,
    evidence_batch: &ExtensionEvidenceBatch,
    native_benign_rule_ids: &BTreeSet<String>,
    explicitly_enabled_rule_ids: &BTreeSet<String>,
) -> ExtensionEvidenceBatch {
    ExtensionEvidenceBatch {
        evidence: evidence_batch
            .evidence
            .iter()
            .filter(|evidence| {
                let rule_id = &evidence.identity.rule_id;
                let enabled_uncertainty_settles = explicitly_enabled_rule_ids.contains(rule_id)
                    && command_settles_uncertainty(command);
                !native_benign_rule_ids.contains(rule_id)
                    && (!explicitly_enabled_rule_ids.contains(rule_id)
                        || (!evidence.uncertainty_reasons.is_empty()
                            && !enabled_uncertainty_settles))
            })
            .cloned()
            .collect(),
    }
}

pub(crate) fn current_critical_floor_factors(
    command: &CanonicalCommand,
    critical_floor_factors: &[DecisionFactor],
    explicitly_enabled_rule_ids: &BTreeSet<String>,
) -> Vec<DecisionFactor> {
    let mut current = critical_floor_factors.to_vec();
    if settles_docker_uncertainty(command)
        && explicitly_enabled_rule_ids.contains("command.container-runtime.docker-sensitive")
    {
        current.retain(|factor| factor.reason_code != "critical.container-state-read");
    }
    current
}

pub(crate) fn unavailable_authority_fail_closed(
    control_resolution: &crate::extension_control::ControlResolution,
    extension_ids: &[String],
    minimum_action: crate::command_evaluation::CommandDecisionFloor,
    workspace_write_candidates: &[DecisionFactor],
    owned_matches: &[OwnedCommandRuleMatch],
    effective_compatibility_class: Option<&str>,
) -> bool {
    if !control_resolution.blocked {
        return false;
    }
    let authority_unavailable_only = !control_resolution.failures.is_empty()
        && control_resolution.failures.iter().all(|failure| {
            failure.code == crate::extension_control::ResolverFailureCode::AuthorityUnavailable
        });
    let mut apply = !authority_unavailable_only
        || !extension_ids.is_empty()
        || minimum_action == crate::command_evaluation::CommandDecisionFloor::Block
        || !workspace_write_candidates.is_empty();
    let fail_closed_risk = |risk: &str| {
        crate::command_evaluation::UNAVAILABLE_AUTHORITY_FAIL_CLOSED_RISKS.contains(&risk)
    };
    if !apply {
        apply = owned_matches.iter().any(|owned| {
            owned
                .rule
                .risk_classes
                .iter()
                .any(|risk| fail_closed_risk(risk))
        });
    }
    if !apply {
        if let Some(class) = effective_compatibility_class {
            apply = crate::command_action_risk_classes::risk_classes_for_command_action(class)
                .iter()
                .any(|risk| fail_closed_risk(risk));
        }
    }
    apply
}

pub(crate) fn owned_match(
    registry: &CommandCatalog,
    observation: &NativeCommandExtensionObservation,
    rule: &CatalogRule,
    evidence: Vec<crate::command_evaluation::NativeMatcherEvidence>,
    effective_compatibility_class: Option<&str>,
    compatibility_reason: Option<&str>,
    command: &CanonicalCommand,
) -> Result<OwnedCommandRuleMatch, &'static str> {
    let extension = registry
        .get(&observation.extension_id)
        .ok_or(ERR_UNKNOWN_IDENTITY)?;
    let action_class = rule
        .action_classes
        .first()
        .cloned()
        .or_else(|| effective_compatibility_class.map(str::to_owned));
    let mut reason = rule.description.clone();
    if rule.compatibility_fallback {
        if let Some(compatibility) = compatibility_reason {
            reason = compatibility.to_owned();
        }
    }
    Ok(OwnedCommandRuleMatch {
        extension_id: extension.extension_id.clone(),
        extension_required: extension.required,
        extension_provenance_digest: String::new(),
        extension_trust_class: extension.trust_class.clone(),
        rule: CommandSafetyRule {
            rule_id: rule.rule_id.clone(),
            severity: rule.severity.clone(),
            risk_classes: rule.risk_classes.clone(),
            action_classes: rule.action_classes.clone(),
            description: rule.description.clone(),
            safer_alternatives: rule.safer_alternatives.clone(),
            default_mode: rule.default_mode.clone(),
            compatibility_fallback: rule.compatibility_fallback,
            rule_version: rule.rule_version.clone(),
        },
        action_class,
        reason,
        matcher_evidence: evidence,
        parse_confidence: command.confidence.clone(),
    })
}
