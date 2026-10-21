//! Native monotonic command floors and their bounded recursive factor walk.
use crate::canonical_command::CanonicalCommand;
use crate::command_launcher_floors::{launcher_child_commands, MAX_LAUNCHER_CHILDREN};
use crate::effect_decision::{
    DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction, ProofRoute,
};
use crate::github_capability_contract::GitHubCommandCapability;
use crate::github_capability_interaction::github_capability_action_class;
use crate::github_command_capabilities::classify_github_cli;
use crate::github_workflow_authorization::{
    github_workflow_authorization_evidence, GitHubWorkflowAuthorizationV1,
};
use std::collections::BTreeMap;
#[path = "critical_floor_controls.rs"]
mod controls;
#[path = "critical_floor_rules.rs"]
mod rules;
#[path = "critical_floor_shell.rs"]
mod shell;
pub(crate) use controls::{guard_control_block_in_command, guard_control_block_in_launcher_text};
use rules::{critical_floor, executable_name, path_export_index};

/// `command_critical_floor_factors` (:79). The public entry dedupes factors
/// by `semantic_key` after the recursive walk.
pub fn command_critical_floor_factors(
    command: &CanonicalCommand,
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    explicitly_allowed_github_capabilities: &[GitHubCommandCapability],
) -> Vec<DecisionFactor> {
    let mut remaining = [MAX_LAUNCHER_CHILDREN];
    let factors = inner(
        command,
        authorization,
        explicitly_allowed_github_capabilities,
        0,
        &mut remaining,
    );
    // `tuple({factor.semantic_key: factor for factor in factors}.values())`
    // — insertion-ordered dedupe by semantic key; later duplicates replace.
    let mut map: BTreeMap<Vec<String>, DecisionFactor> = BTreeMap::new();
    let mut order: Vec<Vec<String>> = Vec::new();
    for factor in factors {
        let key = factor.semantic_key();
        if !map.contains_key(&key) {
            order.push(key.clone());
        }
        map.insert(key, factor);
    }
    order
        .into_iter()
        .map(|key| map.remove(&key).unwrap())
        .collect()
}

/// `_command_critical_floor_factors` (:105).
fn inner(
    command: &CanonicalCommand,
    authorization: Option<&GitHubWorkflowAuthorizationV1>,
    explicitly_allowed_github_capabilities: &[GitHubCommandCapability],
    depth: usize,
    remaining_launcher_children: &mut [usize; 1],
) -> Vec<DecisionFactor> {
    let mut factors: Vec<DecisionFactor> = Vec::new();
    let authorization_evidence =
        github_workflow_authorization_evidence(authorization, &command.security_identity);
    let mut authorized_action_class: Option<&'static str> = None;
    if let Some((proof, action_class)) = authorization_evidence {
        authorized_action_class = Some(action_class);
        let operation_id = command.security_identity.rsplit(':').next().unwrap_or("");
        factors.push(DecisionFactor {
            source: DecisionFactorSource::Authorization,
            reason_code: "github-workflow-capability".to_owned(),
            basis: DecisionBasis {
                action_floor: GuardAction::Allow,
                proof_route: Some(ProofRoute::WorkflowAuthorized),
            },
            segment_ref: None,
            operation_ref: Some(format!("operation:{operation_id}")),
            producer_ref: Some("runtime:github-workflow-authorization-v1".to_owned()),
            evidence_digest: None,
            assessment: None,
            proof: Some(proof),
        });
    }
    let path_export_index = path_export_index(command);
    if let Some(export_index) = path_export_index {
        factors.push(factor(
            command,
            export_index,
            GuardAction::RequireReapproval,
            "critical.path-provenance-drift",
        ));
    }
    for (index, segment) in command.segments.iter().enumerate() {
        let executable = executable_name(segment);
        let arguments = &segment.arguments;
        let windows_executable = segment
            .executable
            .as_deref()
            .unwrap_or("")
            .to_lowercase()
            .ends_with(".exe");
        if let Some(github_factor) = github_factor(
            command,
            index,
            &executable,
            arguments,
            authorized_action_class,
            explicitly_allowed_github_capabilities,
            depth > 0 || !command.wrapper_chain.is_empty(),
            windows_executable,
        ) {
            factors.push(github_factor);
        }
        if let Some((action, reason_code)) =
            critical_floor(command, segment, &executable, arguments)
        {
            factors.push(factor(command, index, action, reason_code));
        }
        let launcher_children = match launcher_child_commands(&executable, arguments) {
            Ok(children) => children,
            Err(reason) => {
                factors.push(factor(command, index, GuardAction::Block, reason));
                continue;
            }
        };
        if depth < 3 {
            for child in launcher_children {
                if remaining_launcher_children[0] == 0 {
                    factors.push(factor(
                        command,
                        index,
                        GuardAction::Block,
                        "critical.launcher-expansion-limit",
                    ));
                    break;
                }
                remaining_launcher_children[0] -= 1;
                factors.extend(inner(
                    &child,
                    None,
                    &[],
                    depth + 1,
                    remaining_launcher_children,
                ));
            }
        } else if !launcher_children.is_empty() {
            factors.push(factor(
                command,
                index,
                GuardAction::Block,
                "critical.launcher-depth-limit",
            ));
        }
    }
    factors
}

/// `_github_factor` (:175).
#[allow(clippy::too_many_arguments)]
fn github_factor(
    command: &CanonicalCommand,
    index: usize,
    executable: &str,
    arguments: &[String],
    authorized_action_class: Option<&'static str>,
    explicitly_allowed_capabilities: &[GitHubCommandCapability],
    indirect: bool,
    windows_executable: bool,
) -> Option<DecisionFactor> {
    if executable != "gh" {
        return None;
    }
    let assessment = classify_github_cli(arguments);
    let action_floor = assessment.action_floor();
    // An explicitly enabled `unknown` permission is the user's consent to
    // unverified GitHub commands, so Unknown suppresses like any other
    // capability the user allowed; without that enablement `.all()` fails
    // and the floor fires.
    if !indirect
        && action_floor != GuardAction::Block
        && assessment
            .capabilities
            .iter()
            .all(|capability| explicitly_allowed_capabilities.contains(capability))
    {
        return None;
    }
    if authorized_action_class.is_some()
        && action_floor != GuardAction::Allow
        && github_capability_action_class(&assessment).ok() == authorized_action_class
    {
        return None;
    }
    let indirect_routine_mutation = (indirect || windows_executable)
        && assessment.capabilities.iter().any(|capability| {
            matches!(
                capability,
                GitHubCommandCapability::RoutineMergeRemote
                    | GitHubCommandCapability::RoutineWorkflowRemote
            )
        });
    if action_floor == GuardAction::Allow && !indirect_routine_mutation {
        return None;
    }
    let mut effective_floor = action_floor;
    if (indirect || windows_executable) && effective_floor != GuardAction::Block {
        effective_floor = GuardAction::RequireReapproval;
    }
    Some(factor(
        command,
        index,
        effective_floor,
        "critical.github-cli",
    ))
}

/// `_factor` (:265).
fn factor(
    command: &CanonicalCommand,
    index: usize,
    action: GuardAction,
    reason_code: &str,
) -> DecisionFactor {
    let operation_id = command.security_identity.rsplit(':').next().unwrap_or("");
    DecisionFactor {
        source: DecisionFactorSource::Policy,
        reason_code: reason_code.to_owned(),
        basis: DecisionBasis {
            action_floor: action,
            proof_route: None,
        },
        segment_ref: Some(format!("segment:{index}")),
        operation_ref: Some(format!("operation:{operation_id}")),
        producer_ref: Some("runtime:command-critical-floors-v1".to_owned()),
        evidence_digest: None,
        assessment: None,
        proof: None,
    }
}
