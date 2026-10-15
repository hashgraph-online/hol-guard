use std::collections::BTreeSet;

use guard_contracts::{NativeCommandPermissionObservationV1, PreToolResultV1};

use crate::native_command_program::{NativeCommandProgram, ProgramRule};
use crate::CanonicalCommandV1;

/// A docker listing or container start the native proof admits carries no
/// container-runtime observation, so a disabled container-runtime extension,
/// or one that depends on it, still blocks the command here.
pub(super) fn proof_owner_disabled(
    blocked_extensions: &BTreeSet<String>,
    command: Option<&CanonicalCommandV1>,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    blocked_extensions.contains("command.container-runtime")
        && command.is_some_and(|command| {
            command.segments.iter().any(|segment| {
                crate::pretool::docker_reads::proven_segment(command, segment, context)
            })
        })
}

pub(super) fn rule_floor(rule: &ProgramRule, required: bool) -> &'static str {
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

/// Whether the packaged catalog lets `permission_id` proceed while the user
/// has not set it: enabled by default with an `allow` baseline floor.
pub(super) fn baseline_allows(program: &NativeCommandProgram, permission_id: &str) -> bool {
    program
        .extensions
        .iter()
        .flat_map(|extension| &extension.permissions)
        .any(|permission| {
            permission.permission_id == permission_id
                && permission.default_enabled
                && permission.baseline_floor == "allow"
        })
}

pub(super) fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}

pub(super) fn strengthen(result: &mut PreToolResultV1, action: &str, reason: &str) {
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
                "HOL Guard could not check this command against the installed extension controls, so it stays blocked. Split it into simpler commands, or ask the user to run `hol-guard doctor` if this keeps happening."
            }
            "native_command_extension_uncertain" => {
                "HOL Guard requires review because it could not match this command to its extension permissions."
            }
            _ => "HOL Guard requires the native command extension policy before this action can execute.",
        }
        .to_owned();
    }
}

/// Tell the user how to restore protection when an unhealthy local authority,
/// not an administrator lockdown, is what blocks every command. Acknowledging
/// a degraded authority keeps the block, so only recovery is suggested.
pub(super) fn add_authority_repair_hint(
    result: &mut PreToolResultV1,
    health: &str,
    global_lockdown: bool,
) {
    if global_lockdown || result.reason_code != "native_command_control_authority_block" {
        return;
    }
    if !matches!(
        health,
        "degraded-unacknowledged" | "degraded-acknowledged" | "tampered" | "recovery-required"
    ) {
        return;
    }
    result.reason.push_str(
        " Run `hol-guard command controls recover-authority` in a terminal to restore protection.",
    );
}

impl super::CompiledNativeCommandControls {
    /// Segments an enabled GitHub permission-only owner (a proven read, a
    /// static pull-request proposal or a routine review-thread resolution)
    /// covers. A permission the user has not set keeps its packaged baseline,
    /// so an `allow` baseline counts until the user disables it. A segment is
    /// covered only when every GitHub permission it needs is enabled, so
    /// `gh auth status` needs both its local and remote reads.
    pub(crate) fn github_granted_segments(
        &self,
        observations: &[NativeCommandPermissionObservationV1],
    ) -> BTreeSet<usize> {
        let enabled = |id: &str| {
            self.explicitly_enabled_permissions.contains(id)
                || (!self.blocked_permissions.contains(id) && baseline_allows(&self.program, id))
        };
        let (mut granted, mut withheld) = (BTreeSet::new(), BTreeSet::new());
        for item in observations {
            let id = &item.permission_id;
            if item.mcp_tool.is_some() || !id.starts_with("command.github.permission.") {
                continue;
            }
            let target = if item.uncertainty_reasons.is_empty() && enabled(id.as_str()) {
                &mut granted
            } else {
                &mut withheld
            };
            target.extend(item.matcher_evidence.iter().map(|e| e.segment_index));
        }
        granted.difference(&withheld).copied().collect()
    }
}
