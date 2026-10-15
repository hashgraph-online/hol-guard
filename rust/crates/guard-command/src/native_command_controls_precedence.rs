//! When a user's explicit extension Allow takes precedence over Rust's own
//! judgment of a command, and when uncertainty about an allowed Git rule still
//! reviews.

use guard_contracts::{NativeCommandObservationBatchV1, PreToolResultV1};

use super::{rule_floor, CompiledNativeCommandControls};
use crate::CanonicalCommandV1;

/// Rust judgments of a command's shape that a user's explicit extension Allow
/// may settle. Every other non-allow reason stays a floor, including helpers
/// that repository or global Git configuration would run.
const OVERRIDABLE_NATIVE_REASONS: &[&str] = &[
    "native_command_review_required",
    "native_destructive_command",
    "native_network_review",
    "native_package_review",
    "native_process_service_review",
    "native_process_service_dangerous",
];

impl CompiledNativeCommandControls {
    /// The floor an uncertain observation of `rule_id` contributes, or `None`
    /// for a Git rule the user explicitly allowed: that uncertainty reviews
    /// only when the Allow does not settle the command ([`Self::explicit_allow`]).
    pub(super) fn uncertain_candidate(&self, rule_id: &str) -> Option<&'static str> {
        let Some(index) = self.rule_indices.get(rule_id) else {
            return Some("block");
        };
        let rule = &self.program.rules[*index];
        let extension = &self.program.extensions[rule.extension_index];
        if !self
            .explicitly_enabled_permissions
            .contains(&rule.permission_id)
        {
            Some(rule_floor(rule, extension.required))
        } else if extension.extension_id == "command.git" {
            None
        } else {
            Some("review")
        }
    }

    /// Whether the user's authenticated Allow for every segment's extension
    /// permissions settles a command whose delegated floor is already allow.
    /// Guard self-protection, secret access and exfiltration, configured Git
    /// programs, disabled permissions and evaluation failures are fixed
    /// floors. Allowed Git uncertainty also needs every Git segment to run a
    /// built-in whose program options Guard holds, in a verified repository.
    pub(super) fn explicit_allow(
        &self,
        result: &PreToolResultV1,
        batch: &NativeCommandObservationBatchV1,
        command: Option<&CanonicalCommandV1>,
        context: crate::pretool::PathContext<'_>,
        enabled_uncertainty: bool,
    ) -> bool {
        batch.evaluation_error.is_none()
            && result.action.bounded
            && !result.action.sensitive_target
            && (result.minimum_action == "allow"
                || OVERRIDABLE_NATIVE_REASONS.contains(&result.reason_code.as_str()))
            && command.is_some_and(|model| {
                !crate::pretool::fixed_command_floor(model)
                    && (!enabled_uncertainty
                        || model
                            .segments
                            .iter()
                            .all(|segment| settles_git_uncertainty(segment, context)))
                    && self.explicit_permissions_cover_command(model, batch, context)
            })
    }
}

/// Whether a segment is not Git, or runs a Git built-in whose program options
/// Guard holds in a repository whose routes it verified.
fn settles_git_uncertainty(
    segment: &crate::CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    use crate::command_compatibility as compatibility;
    compatibility::basename(segment) != "git"
        || (compatibility::git_subcommand_settles_uncertainty(segment)
            && compatibility::git_repository_routes_verified(segment, context))
}

/// Records that the user's explicit Allow took precedence over Rust's review.
pub(super) fn settle_with_explicit_allow(result: &mut PreToolResultV1) {
    result.minimum_action = "allow".into();
    result.policy_action = "allow".into();
    result.decision = "allow".into();
    result.explicitly_benign = true;
    result.reason_code = "native_command_explicit_permission_allow".into();
    result.reason = "This command is allowed by its authenticated extension permissions.".into();
}
