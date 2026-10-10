//! Match and uncertainty helpers of the composite command evaluation.
//!
//! Split from `command_evaluation_compose` so the composition entry point stays
//! within the repository file-size guideline.

use crate::canonical_command::CanonicalCommand;
use crate::command_evaluation::{
    CommandSafetyRule, NativeCommandExtensionObservation, OwnedCommandRuleMatch,
};
use crate::effect_decision::UncertaintyKind;
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
