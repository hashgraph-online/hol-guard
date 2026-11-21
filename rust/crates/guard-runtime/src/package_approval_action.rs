//! The package approval's composed current action.
//!
//! Two actions come out of the same configuration. `compose_current_action`
//! decides the request and may leave the `package_script` risk setting out,
//! because an install proven to run no lifecycle scripts gives that setting
//! nothing to govern. `hashed_action` always folds it in, so the approval
//! token a user's Always allow is bound to does not move when Guard learns to
//! read a proof it could not read before.

use guard_command::action_lattice::most_restrictive_guard_action;
use guard_command::effect_decision::GuardAction;
use guard_contracts::PackageApprovalHashRequestV1;
use serde_json::Value;

use crate::package_approval_hash_op::field;

/// Whether this request is an install proven to run no lifecycle scripts.
///
/// The proof is the native command authority's, read over the redacted argv
/// the artifact carries. Redaction cuts a URL-bearing token at its first `?`
/// or `#`, which can hand the proof a flag the raw argv never carried:
/// `npm ci --ignore-scripts#https://host` redacts to exactly
/// `npm ci --ignore-scripts`, while npm reads the original token as an unknown
/// flag and runs lifecycle scripts. So the redacted argv's flags must still be
/// the raw argv's flags, which `metadata.flags` records from the raw tokens.
fn package_scripts_disabled(request: &PackageApprovalHashRequestV1) -> bool {
    let metadata = field(&request.artifact, "metadata");
    let Some(redacted_command) = field(metadata, "redacted_command").as_str() else {
        return false;
    };
    let Some(flags) = field(metadata, "flags").as_array() else {
        return false;
    };
    let mut raw_flags = Vec::with_capacity(flags.len());
    for flag in flags {
        let Some(flag) = flag.as_str() else {
            return false;
        };
        raw_flags.push(flag.to_owned());
    }
    guard_command::package_intent_common::redacted_command_keeps_flags(redacted_command, &raw_flags)
        && guard_command::pretool::no_script_install_command(redacted_command)
}

/// `most_restrictive_guard_action(policy_action, additional?, config actions…)`.
///
/// An install proven to run no lifecycle scripts has nothing for the
/// `package_script` risk setting to govern, so that setting alone is left out
/// of the composition. This is the package-approval half of
/// `policy_enforcement::package_scripts_disabled`, and it is just as narrow:
/// the evaluation's own action, the caller's additional action and a
/// configured artifact, publisher or harness override are all still folded in,
/// so a user's explicit package policy and every other floor still decide this
/// request.
pub(crate) fn compose_current_action(
    request: &PackageApprovalHashRequestV1,
    config_policy: &Value,
) -> GuardAction {
    compose(request, config_policy, package_scripts_disabled(request))
}

/// The action the approval-context token is built from.
///
/// This one never drops the `package_script` risk setting. The token stands
/// for the configuration a user approved under, not for what Guard can prove
/// about the install, so a release that teaches Guard the script-free proof
/// must not move it: `docs/guard/approval-invariant.md` keeps a saved Always
/// allow across an upgrade that only changes rules.
pub(crate) fn hashed_action(
    request: &PackageApprovalHashRequestV1,
    config_policy: &Value,
) -> GuardAction {
    compose(request, config_policy, false)
}

fn compose(
    request: &PackageApprovalHashRequestV1,
    config_policy: &Value,
    scripts_disabled: bool,
) -> GuardAction {
    let mut actions = vec![field(&request.evaluation, "policy_action").clone()];
    if let Some(additional) = request.additional_current_action.as_ref() {
        actions.push(additional.clone());
    }
    for key in ["effective_package_script_action", "resolved_override"] {
        if scripts_disabled && key == "effective_package_script_action" {
            continue;
        }
        let action = field(config_policy, key);
        if !action.is_null() {
            actions.push(action.clone());
        }
    }
    most_restrictive_guard_action(&actions, GuardAction::Block)
}

#[cfg(test)]
#[path = "package_approval_action_tests.rs"]
mod tests;
