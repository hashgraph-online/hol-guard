//! The verdict for a command whose settings a reviewed projection removed.
//!
//! Any program may read any name, so a setting that is not inert keeps the
//! command from settling below review on the host. The read-only profiles
//! are different: their launchers run the bare program under the restricted
//! environment allowlist, which drops every name it does not forward. A
//! setting that only carries data (`REPORT_DIR=/tmp/report vitest run`) never
//! reaches such a run, so the profile chosen for the command without it is
//! the profile for what runs. Search-path settings load code, temporary
//! directory settings are set by the profile itself, and a value with an
//! expansion (`$TMPDIR/x`) is only proved by the workspace sandbox, which
//! re-checks the raw text; none of them is data here.
use super::ReviewedProjection;
use guard_contracts::PreToolResultV1;

/// Profiles whose launchers filter the environment through the restricted
/// allowlist (`restricted_pytest::environment::filter`).
const FILTERED_PROFILES: [&str; 10] = [
    "native_bun_eval_readonly_containment_required",
    "native_git_readonly_containment_required",
    "native_node_build_output_containment_required",
    "native_node_eval_readonly_containment_required",
    "native_node_test_readonly_containment_required",
    "native_node_tool_readonly_containment_required",
    "native_package_test_readonly_containment_required",
    "native_pytest_readonly_containment_required",
    "native_python_eval_readonly_containment_required",
    "native_vitest_readonly_containment_required",
];

const MAX_DATA_CHARS: usize = 512;

/// The settings a reviewed projection removed that are not inert.
pub(super) struct Reviewed {
    /// The first one, a shape-checked variable name.
    pub(super) first: Option<String>,
    /// Whether every one is plain data the read-only profiles drop.
    pub(super) data_only: bool,
}

impl Default for Reviewed {
    fn default() -> Self {
        Self {
            first: None,
            data_only: true,
        }
    }
}

/// Record a reviewable setting; `search_path` is set for a setting that
/// picks where a toolchain finds its modules.
pub(super) fn record(reviewed: &mut Reviewed, name: &str, value: &str, search_path: bool) {
    reviewed.first.get_or_insert_with(|| name.to_owned());
    reviewed.data_only &= !search_path && plain_data(name, value);
}

fn plain_data(name: &str, value: &str) -> bool {
    !matches!(
        name.to_ascii_uppercase().as_str(),
        "NODE_PATH" | "TMPDIR" | "TMP" | "TEMP"
    ) && !crate::command_compatibility::credential_routing_environment_name(name)
        && !forwarded(name)
        && value.len() <= MAX_DATA_CHARS
        && !value.starts_with('-')
        && value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "/._+@:,%-".contains(character))
}

#[cfg(unix)]
fn forwarded(name: &str) -> bool {
    crate::forwarded_settings::forwarded_setting(name)
}

/// Without the restricted launchers every setting counts as forwarded.
#[cfg(not(unix))]
fn forwarded(_name: &str) -> bool {
    true
}

/// Joins the verdict of a [`ReviewedProjection`] with the unprojected
/// command's own intrinsic verdict, never below review unless a read-only
/// profile drops every removed setting itself.
pub(in crate::pretool::generic) fn join_reviewed(
    mut projected: PreToolResultV1,
    raw: PreToolResultV1,
    reviewed: &ReviewedProjection,
) -> PreToolResultV1 {
    projected.action.sensitive_target |= raw.action.sensitive_target;
    projected.action.bounded &= raw.action.bounded;
    if raw.reason_code != "native_command_review_required"
        && raw.reason_code != "native_command_extension_evaluation_failed"
        && rank(&raw.minimum_action) > rank(&projected.minimum_action)
    {
        projected.minimum_action = raw.minimum_action;
        projected.policy_action = raw.policy_action;
        projected.decision = raw.decision;
        projected.reason_code = raw.reason_code;
        projected.reason = raw.reason;
    }
    let dropped = reviewed.data_only
        && !projected.action.sensitive_target
        && FILTERED_PROFILES.contains(&projected.reason_code.as_str());
    // Protected execution would otherwise run the command without its settings.
    if rank(&projected.minimum_action) < rank("review")
        || (projected.minimum_action == "sandbox-required" && !dropped)
    {
        projected.minimum_action = "review".into();
        projected.policy_action = "review".into();
        projected.decision = "deny".into();
        projected.reason_code = "native_command_review_required".into();
        projected.reason = format!(
            "HOL Guard requires review because the {} setting can change how this command runs.",
            reviewed.setting
        );
    }
    projected.explicitly_benign = false;
    projected
}

fn rank(action: &str) -> u8 {
    match action {
        "allow" => 0,
        "warn" => 1,
        "review" => 2,
        "require-reapproval" => 3,
        "sandbox-required" => 4,
        _ => 5,
    }
}
