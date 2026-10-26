use super::{
    allowed_verdict, evaluate_hook_local_cli_rule_request, launch_env, review_verdict, RuleVerdict,
};
use crate::context_digest_package_scripts::package_json_scripts;
use guard_contracts::{HookLocalCliRuleRequestV1, HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};
use std::fs;
use std::path::Path;

const SCHEMA: &str = "
create table local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null
);
create table local_cli_command (
    cli_id text not null,
    command_id text not null,
    name text not null,
    usage text not null,
    description text not null,
    parent_id text
);
create table local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null
);
";

fn object(value: Value) -> Map<String, Value> {
    value.as_object().unwrap().clone()
}

fn scratch(label: &str) -> String {
    let root = std::env::temp_dir().join(format!(
        "hook-local-cli-rule-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::canonicalize(root).unwrap().to_str().unwrap().to_owned()
}

/// A workspace whose package scripts are a local CLI, and a Guard home whose
/// store holds the grant `state` for that CLI, or no grant row when `None`.
struct Case {
    workspace: String,
    guard_home: String,
    /// The CLI name a block names.
    name: String,
}

impl Case {
    fn new(label: &str, state: Option<&str>) -> Self {
        let workspace = scratch(&format!("{label}-work"));
        let guard_home = scratch(&format!("{label}-home"));
        fs::write(
            Path::new(&workspace).join("package.json"),
            br#"{"name": "demo", "scripts": {"build": "tsc"}}"#,
        )
        .unwrap();
        let identity = package_json_scripts("npm run build", &workspace, &workspace)
            .unwrap()
            .unwrap()
            .identity
            .unwrap();
        let connection =
            rusqlite::Connection::open(Path::new(&guard_home).join("guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        if let Some(state) = state {
            connection
                .execute(
                    "insert into local_cli_grant values (?1, ?2, ?3)",
                    [
                        identity.cli_id.as_str(),
                        identity.identity_hash.as_str(),
                        state,
                    ],
                )
                .unwrap();
        }
        Self {
            workspace,
            guard_home,
            name: identity.name,
        }
    }

    fn request(
        &self,
        mode: &str,
        command: &str,
        native_result: Value,
    ) -> HookLocalCliRuleRequestV1 {
        HookLocalCliRuleRequestV1 {
            schema: HOOK_LOCAL_CLI_RULE_REQUEST_SCHEMA.to_owned(),
            request_id: "rule-1".to_owned(),
            store_path: Path::new(&self.guard_home)
                .join("guard.db")
                .to_str()
                .unwrap()
                .to_owned(),
            guard_home: self.guard_home.clone(),
            mode: mode.to_owned(),
            payload: object(json!({ "tool_input": { "command": command } })),
            native_result: object(native_result),
            workspace: Some(self.workspace.clone()),
            home_dir: self.workspace.clone(),
            user_home: None,
            env: None,
        }
    }
}

fn allowed() -> Value {
    json!({ "decision": "allow", "minimum_action": "allow", "policy_action": "allow" })
}

fn review(reason_code: &str) -> Value {
    json!({
        "decision": "review",
        "minimum_action": "review",
        "policy_action": "review",
        "reason_code": reason_code,
        "action": { "action_type": "shell" },
    })
}

#[test]
fn a_custom_block_stops_an_allowed_launch() {
    let case = Case::new("block", Some("blocked"));
    assert_eq!(
        allowed_verdict(&case.request("allowed", "npm run build", allowed())),
        RuleVerdict::Blocked(case.name.clone())
    );
    // A command that launches no local CLI keeps the edge's allow.
    assert_eq!(
        allowed_verdict(&case.request("allowed", "pwd", allowed())),
        RuleVerdict::None
    );
    // Only an allowed command is checked here.
    assert_eq!(
        allowed_verdict(&case.request("allowed", "npm run build", review("x"))),
        RuleVerdict::None
    );
}

#[test]
fn without_a_block_rule_the_allowed_lane_reads_nothing() {
    let case = Case::new("allow-only", Some("allowed"));
    assert_eq!(
        allowed_verdict(&case.request("allowed", "npm run build", allowed())),
        RuleVerdict::None
    );
    let empty = Case::new("empty", None);
    assert_eq!(
        allowed_verdict(&empty.request("allowed", "npm run build", allowed())),
        RuleVerdict::None
    );
}

#[test]
fn a_custom_block_applies_to_any_review() {
    let case = Case::new("review-block", Some("blocked"));
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", review("network_target"))),
        RuleVerdict::Blocked(case.name.clone())
    );
    let mut reapproval = review("network_target");
    reapproval["policy_action"] = json!("require-reapproval");
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", reapproval)),
        RuleVerdict::Blocked(case.name.clone())
    );
    // A block decision is not a review, so no rule is read for it.
    let mut blocked = review("network_target");
    blocked["policy_action"] = json!("block");
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", blocked)),
        RuleVerdict::None
    );
}

#[test]
fn a_custom_allow_lifts_only_a_non_recognition_review() {
    let case = Case::new("review-allow", Some("allowed"));
    assert_eq!(
        review_verdict(&case.request(
            "review",
            "npm run build",
            review("native_command_review_required")
        )),
        RuleVerdict::Allowed
    );
    // A review with its own risk signal stands.
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", review("network_target"))),
        RuleVerdict::None
    );
    // So does one with no reason at all.
    let mut no_reason = review("native_command_review_required");
    no_reason.as_object_mut().unwrap().remove("reason_code");
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", no_reason)),
        RuleVerdict::None
    );
    // And one a broad grant may not override.
    let mut control = review("native_command_review_required");
    control["action"]["action_type"] = json!(["shell"]);
    assert_eq!(
        review_verdict(&case.request("review", "npm run build", control)),
        RuleVerdict::None
    );
}

#[test]
fn the_reply_names_the_verdict_and_refuses_an_unknown_mode() {
    let case = Case::new("reply", Some("blocked"));
    let reply =
        evaluate_hook_local_cli_rule_request(&case.request("allowed", "npm run build", allowed()))
            .unwrap();
    let reply: Value = serde_json::from_slice(&reply).unwrap();
    assert_eq!(reply["schema"], "guard-hook-local-cli-rule-result.v1");
    assert_eq!(reply["request_id"], "rule-1");
    assert_eq!(reply["status"], "ok");
    assert_eq!(reply["verdict"], "blocked");
    assert_eq!(reply["name"], json!(case.name));
    let error =
        evaluate_hook_local_cli_rule_request(&case.request("other", "npm run build", allowed()));
    assert_eq!(
        error,
        Err("native_hook_local_cli_rule_mode_invalid".to_owned())
    );
}

#[test]
fn the_launch_resolves_against_the_daemon_environment_it_was_sent() {
    let case = Case::new("launch-env", Some("blocked"));
    let mut request = case.request("allowed", "npm run build", allowed());
    // Without the daemon's environment the resident resolves against its own.
    assert!(launch_env(&request).is_none());
    request.user_home = Some("/daemon/home".to_owned());
    assert!(launch_env(&request).is_none());
    request.env = Some(
        [("PATH".to_owned(), "/daemon/bin".to_owned())]
            .into_iter()
            .collect(),
    );
    let sent = launch_env(&request).unwrap();
    assert_eq!(sent.user_home, "/daemon/home");
    assert_eq!(
        sent.env.get("PATH").map(String::as_str),
        Some("/daemon/bin")
    );
    // A package script launch reads the workspace, not `PATH`, so the
    // daemon's environment still finds its grant.
    assert_eq!(
        allowed_verdict(&request),
        RuleVerdict::Blocked(case.name.clone())
    );
}
