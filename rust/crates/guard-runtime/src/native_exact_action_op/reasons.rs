//! Stable once-only reason codes; they reach the dashboard as `once_only_reason`.

pub(super) const NO_COMMAND_IDENTITY: &str = "no_command_identity";
pub(super) const MUTABLE_LAUNCHER: &str = "mutable_launcher";
pub(super) const COMPOUND_COMMAND: &str = "compound_command";
pub(super) const GUARD_CONTROL: &str = "guard_control";
pub(super) const PACKAGE_ACTION: &str = "package_action";
pub(super) const NON_OVERRIDABLE: &str = "non_overridable";
pub(super) const UNPROVEN_LAUNCH: &str = "unproven_launch";
pub(super) const SENSITIVE_PATH: &str = "sensitive_path";
pub(super) const BROAD_SCOPE: &str = "broad_scope";
pub(super) const DESTRUCTIVE_COMMAND: &str = "destructive_command";
pub(super) const GIT_HELPER_CONFIG: &str = "git_helper_config";
pub(super) const SCRIPT_DELIVERY: &str = "script_execution_binding_unavailable";

/// A hook review carries one proved token or one recognized unavailable reason.
pub(super) fn review_identity(
    token: Option<String>,
    once_only_reason: Option<String>,
) -> (Option<String>, Option<String>) {
    match (token, once_only_reason) {
        (Some(token), None) => (Some(token), None),
        (None, Some(reason)) if is_review_reason(&reason) => (None, Some(reason)),
        _ => (None, Some(UNPROVEN_LAUNCH.to_owned())),
    }
}

fn is_review_reason(reason: &str) -> bool {
    matches!(
        reason,
        NO_COMMAND_IDENTITY
            | MUTABLE_LAUNCHER
            | COMPOUND_COMMAND
            | GUARD_CONTROL
            | PACKAGE_ACTION
            | NON_OVERRIDABLE
            | UNPROVEN_LAUNCH
            | SENSITIVE_PATH
            | BROAD_SCOPE
            | DESTRUCTIVE_COMMAND
            | GIT_HELPER_CONFIG
            | SCRIPT_DELIVERY
            | "node_package_manifest_unproven"
            | "node_package_entrypoint_unproven"
            | "node_package_exports_unproven"
            | "node_package_native_addon_unproven"
            | "node_runtime_package_mutation_unproven"
            | "runner_code_closure_unproven"
            | "python_runtime_module_unproven"
            | "python_runtime_bootstrap_unproven"
    )
}

/// Native action types for changes to Guard itself.
pub(super) const GUARD_CONTROL_ACTION_TYPES: [&str; 4] = [
    "guard_control",
    "guard-control",
    "guard_control_operation",
    "guard-control-operation",
];

/// A failed proof is not permission. The scope contract determines whether
/// any supported execution or recovery route exists for this reason.
pub(super) type Proof<T> = Result<T, &'static str>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_review_identity_keeps_one_proof_or_a_known_reason() {
        let token = Some("token".to_owned());
        let reason = Some(COMPOUND_COMMAND.to_owned());
        assert_eq!(review_identity(token.clone(), None), (token.clone(), None));
        assert_eq!(
            review_identity(None, reason.clone()),
            (None, reason.clone())
        );
        let unproven = (None, Some(UNPROVEN_LAUNCH.to_owned()));
        assert_eq!(review_identity(None, None), unproven);
        assert_eq!(review_identity(token, reason), unproven);
        assert_eq!(review_identity(None, Some("unrecognized".into())), unproven);
    }
}
