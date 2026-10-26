//! When a user's explicit extension Allow takes precedence over Rust's own
//! judgment of a command, and when uncertainty about an allowed rule still
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
    /// for a rule the user explicitly allowed, whichever extension owns it:
    /// that uncertainty reviews only when the Allow does not settle the
    /// command ([`Self::explicit_allow`]).
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
        } else {
            None
        }
    }

    /// Whether `rule_id` by itself asks for nothing beyond allow: a rule the
    /// user explicitly allowed, or one whose packaged mode and permission
    /// leave the command where it already stands. A proof that lifts one
    /// rule's review uses this to tell the rules it is not lifting, so an
    /// ordinary read beside the reviewed step does not hold the proof back.
    pub(crate) fn rule_settles_at_allow(&self, rule_id: &str) -> bool {
        let Some(index) = self.rule_indices.get(rule_id) else {
            return false;
        };
        let rule = &self.program.rules[*index];
        let extension = &self.program.extensions[rule.extension_index];
        if self.blocked_extensions.contains(&extension.extension_id)
            || self.blocked_permissions.contains(&rule.permission_id)
        {
            return false;
        }
        self.explicitly_enabled_permissions
            .contains(&rule.permission_id)
            || rule_floor(rule, extension.required) == "allow"
    }

    /// Whether a ruleless permission observation asks for nothing beyond
    /// allow. Such an observation declares no floor of its own: it records
    /// that a segment touched the permission so a disabled extension or
    /// permission can still block the command, and nothing more. A proof
    /// that lifts one rule's review uses this to tell the permissions it is
    /// not lifting, so a Git plumbing read beside the reviewed step does not
    /// hold the proof back.
    pub(crate) fn permission_settles_at_allow(
        &self,
        extension_id: &str,
        permission_id: &str,
    ) -> bool {
        !self.blocked_extensions.contains(extension_id)
            && !self.blocked_permissions.contains(permission_id)
    }

    /// Whether the user's authenticated Allow for every segment's extension
    /// permissions settles a command whose delegated floor is already allow.
    /// Guard self-protection, secret access and exfiltration, configured Git
    /// programs, disabled permissions and evaluation failures are fixed
    /// floors. Allowed uncertainty also needs every segment to stay inside
    /// what its text proves ([`settles_enabled_uncertainty`]).
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
                            .all(|segment| settles_enabled_uncertainty(segment, context)))
                    && self.explicit_permissions_cover_command(
                        model,
                        &batch.observations,
                        &batch.permission_observations,
                        context,
                    )
            })
    }
}

/// Whether a segment's own shape stays inside what its text proves, so an
/// explicit Allow may settle uncertainty about it, whichever extension owns
/// the uncertain rule.
fn settles_enabled_uncertainty(
    segment: &crate::CommandSegmentV1,
    context: crate::pretool::PathContext<'_>,
) -> bool {
    crate::command_compatibility::segment_settles_uncertainty(segment, context)
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
