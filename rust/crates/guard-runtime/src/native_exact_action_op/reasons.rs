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
