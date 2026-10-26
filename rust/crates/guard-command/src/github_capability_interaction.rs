//! Rust port of `runtime/github_capability_interaction.py`.

use std::sync::LazyLock;

use crate::github_capability_contract::{
    github_capability_contract, GitHubCommandAssessment, GitHubCommandCapability,
};

/// `GITHUB_MAINTENANCE_ACTION_CLASS` (:9-12).
pub static GITHUB_MAINTENANCE_ACTION_CLASS: LazyLock<&'static str> = LazyLock::new(|| {
    match github_capability_contract(GitHubCommandCapability::MaintainRemote).action_class {
        Some(action_class) => action_class,
        None => panic!("GitHub maintenance capability is missing an action class"),
    }
});

/// `github_capability_requires_confirmation` (:15).
pub fn github_capability_requires_confirmation(assessment: &GitHubCommandAssessment) -> bool {
    assessment.action_floor() != crate::effect_decision::GuardAction::Allow
}

/// `github_capability_action_class` (:19). Mirrors the Python
/// `ValueError` fail-closed contract as `Result`.
pub fn github_capability_action_class(
    assessment: &GitHubCommandAssessment,
) -> Result<&'static str, String> {
    let capability = if assessment
        .capabilities
        .contains(&GitHubCommandCapability::AdminMergeRemote)
    {
        GitHubCommandCapability::AdminMergeRemote
    } else {
        assessment.capability
    };
    let action_class = github_capability_contract(capability).action_class;
    match action_class {
        Some(action_class) => Ok(action_class),
        None if !github_capability_requires_confirmation(assessment) => {
            Err("read-only GitHub capabilities do not have review action classes".to_owned())
        }
        None => Err("reviewed GitHub capability is missing an action class".to_owned()),
    }
}
