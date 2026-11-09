//! The composed current action: the `package_script` risk setting, the
//! script-free proof that exempts it, and the approval token that does not
//! move when it does.

use super::*;
use guard_contracts::{PackageApprovalHashRequestV1, PACKAGE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::json;

// ---------------------------------------------------------------------------
// The `package_script` risk setting and a frozen script-free install.
//
// `protection_posture = "protected"` resolves `package_script` to
// `require-reapproval`. Folding that into the composed action stopped
// `npm ci --ignore-scripts`, an install that runs no lifecycle script at all,
// on the install-protection route -- the one route that never sees the hook
// lane's `native_exact_safe_lockfile_install` allow.
// ---------------------------------------------------------------------------

/// A request whose `metadata.flags` is what the parser records from the raw
/// argv: `flag_tokens` over everything after the package manager.
fn request_for(command: &str, evaluation_action: &str) -> PackageApprovalHashRequestV1 {
    // Whitespace splitting, not a shell split: every command here is plain, and
    // `contained_execution::shlex_split` is `#[cfg(unix)]`.
    let tokens: Vec<String> = command.split_whitespace().map(str::to_owned).collect();
    let flags = guard_command::package_intent_common::flag_tokens(&tokens[1..]);
    serde_json::from_value(json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "package-script-setting",
        "guard_home": "/nonexistent",
        "kind": "current_action",
        "artifact": {"metadata": {
            "redacted_command": guard_command::package_intent_common::redacted_command(&tokens),
            "flags": flags,
        }},
        "evaluation": {"policy_action": evaluation_action},
    }))
    .unwrap()
}

fn composed(command: &str, evaluation_action: &str, config_policy: Value) -> GuardAction {
    compose_current_action(&request_for(command, evaluation_action), &config_policy)
}

#[test]
fn a_script_free_install_is_not_upgraded_by_the_package_script_setting() {
    assert_eq!(
        composed(
            "npm ci --ignore-scripts --no-audit --no-fund",
            "review",
            json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::Review,
        "an install that runs no lifecycle script has nothing for the \
         package_script setting to govern"
    );
}

#[test]
fn an_install_that_may_run_scripts_still_takes_the_package_script_setting() {
    assert_eq!(
        composed(
            "npm install left-pad",
            "review",
            json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::RequireReapproval,
    );
    // `--foreground-scripts` puts the lifecycle scripts back.
    assert_eq!(
        composed(
            "npm ci --ignore-scripts --foreground-scripts",
            "review",
            json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::RequireReapproval,
    );
}

#[test]
fn the_exemption_covers_only_the_package_script_setting() {
    // A configured artifact, publisher or harness override is the user's own
    // package policy and still decides the request.
    assert_eq!(
        composed(
            "npm ci --ignore-scripts",
            "review",
            json!({
                "effective_package_script_action": "warn",
                "resolved_override": "block",
            }),
        ),
        GuardAction::Block,
    );
    // So does the evaluation's own action.
    assert_eq!(
        composed(
            "npm ci --ignore-scripts",
            "require-reapproval",
            json!({"effective_package_script_action": "warn"}),
        ),
        GuardAction::RequireReapproval,
    );
}

#[test]
fn an_artifact_with_no_redacted_command_keeps_the_package_script_setting() {
    let request: PackageApprovalHashRequestV1 = serde_json::from_value(json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "package-script-setting",
        "guard_home": "/nonexistent",
        "kind": "current_action",
        "artifact": {},
        "evaluation": {"policy_action": "review"},
    }))
    .unwrap();
    assert_eq!(
        compose_current_action(
            &request,
            &json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::RequireReapproval,
    );
}

#[test]
fn a_flag_only_redaction_creates_proves_nothing() {
    // npm reads `--ignore-scripts#https://example.com` as an unknown flag and
    // runs lifecycle scripts. Redaction cuts the token at its `#`, so the
    // redacted argv reads `npm ci --ignore-scripts` on its own. The raw flags
    // the artifact records are what tell the two apart.
    let request = request_for("npm ci --ignore-scripts#https://example.com", "review");
    let metadata = field(&request.artifact, "metadata");
    assert_eq!(
        field(metadata, "redacted_command").as_str(),
        Some("npm ci --ignore-scripts"),
        "redaction is what creates the flag"
    );
    assert_eq!(
        compose_current_action(
            &request,
            &json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::RequireReapproval,
    );
}

#[test]
fn an_artifact_with_no_flags_keeps_the_package_script_setting() {
    let request: PackageApprovalHashRequestV1 = serde_json::from_value(json!({
        "schema": PACKAGE_AUTHORITY_REQUEST_SCHEMA,
        "request_id": "package-script-setting",
        "guard_home": "/nonexistent",
        "kind": "current_action",
        "artifact": {"metadata": {"redacted_command": "npm ci --ignore-scripts"}},
        "evaluation": {"policy_action": "review"},
    }))
    .unwrap();
    assert_eq!(
        compose_current_action(
            &request,
            &json!({"effective_package_script_action": "require-reapproval"}),
        ),
        GuardAction::RequireReapproval,
        "with no raw flags to check the redacted argv against, there is no proof"
    );
}

#[test]
fn the_exemption_does_not_move_the_approval_token() {
    // The token stands for the configuration the user approved under. An
    // upgrade that only teaches Guard the script-free proof must keep every
    // saved Always allow, so the hashed action still folds the setting in.
    let request = request_for("npm ci --ignore-scripts", "review");
    let config_policy = json!({"effective_package_script_action": "require-reapproval"});
    assert_eq!(
        compose_current_action(&request, &config_policy),
        GuardAction::Review,
    );
    assert_eq!(
        hashed_action(&request, &config_policy),
        GuardAction::RequireReapproval,
    );
}
