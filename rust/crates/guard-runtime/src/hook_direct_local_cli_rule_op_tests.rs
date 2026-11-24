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
            // The edge always sends the daemon's home and environment.
            user_home: Some(self.workspace.clone()),
            env: Some(
                std::env::var("PATH")
                    .map(|path| [("PATH".to_owned(), path)].into_iter().collect())
                    .unwrap_or_default(),
            ),
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
    // The review the workspace sandbox leaves for a program outside its
    // executable roots asks the same question, so it lifts too, rather than
    // running the allowed program in a sandbox with no network.
    assert_eq!(
        review_verdict(&case.request(
            "review",
            "npm run build",
            review("native_workspace_containment_executable_outside_roots")
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
    request.user_home = None;
    request.env = None;
    assert!(launch_env(&request).is_none());
    // Without the daemon's environment no launch past a package script is
    // resolved, never against the resident's own, so the check cannot
    // verify one.
    let mut unresolved = case.request("allowed", "pwd", allowed());
    unresolved.user_home = None;
    unresolved.env = None;
    assert_eq!(allowed_verdict(&unresolved), RuleVerdict::Unverified);
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

#[test]
fn a_cli_run_after_cd_reads_its_own_grant() {
    let read = |case: &Case, command: &str, reason: &str| {
        let parent = Path::new(&case.workspace)
            .parent()
            .unwrap()
            .to_str()
            .unwrap()
            .to_owned();
        let mut request = case.request("review", command, review(reason));
        request.payload.insert("cwd".to_owned(), json!(parent));
        review_verdict(&request)
    };
    let allowed = Case::new("after-cd", Some("allowed"));
    let ws = allowed.workspace.clone();
    let unrecognised = "native_command_review_required";
    assert_eq!(
        read(&allowed, &format!("cd {ws} && npm run build"), unrecognised),
        RuleVerdict::Allowed
    );
    // Any other step, a pipe, a redirect or `;` keeps the review.
    for command in [
        format!("cd {ws} && npm run build | tail -5"),
        format!("cd {ws} && npm run build && rm -rf dist"),
        format!("cd {ws} && npm run build > build.log"),
        format!("cd {ws} ; npm run build"),
        // Without the cd the parent launches nothing the user allowed.
        "npm run build".to_owned(),
    ] {
        assert_eq!(
            read(&allowed, &command, unrecognised),
            RuleVerdict::None,
            "{command}"
        );
    }
    // An allow lifts only a review due to non-recognition.
    assert_eq!(
        read(
            &allowed,
            &format!("cd {ws} && npm run build"),
            "network_target"
        ),
        RuleVerdict::None
    );
    let blocked = Case::new("after-cd-block", Some("blocked"));
    let ws = blocked.workspace.clone();
    assert_eq!(
        read(
            &blocked,
            &format!("cd {ws} && npm run build"),
            "network_target"
        ),
        RuleVerdict::Blocked(blocked.name.clone())
    );
}

#[cfg(unix)]
fn executable(path: &Path, content: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir_all(path.parent().unwrap()).unwrap();
    fs::write(path, content).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

/// The agent runs `bun` from a directory the daemon's own `PATH` lacks, and
/// its `PATH` also starts with Guard's package shim directory, whose `bun` is
/// a shell script that re-enters Guard. The grant for the script must still
/// match: the launch resolves against the agent's `PATH` the hook stamped,
/// less the shim directory.
#[cfg(unix)]
#[test]
fn a_script_grant_matches_the_runtime_on_the_agent_path_past_the_package_shim() {
    let case = Case::new("agent-path", None);
    let shim_dir = Path::new(&case.guard_home)
        .join("package-shims")
        .join("bin");
    executable(&shim_dir.join("bun"), b"#!/bin/sh\nexec false\n");
    let runtime_dir = Path::new(&case.workspace).join("runtime").join("bin");
    executable(&runtime_dir.join("bun"), b"\x7fELF runtime\n");
    fs::create_dir_all(Path::new(&case.workspace).join("tools")).unwrap();
    fs::write(
        Path::new(&case.workspace).join("tools").join("context.mjs"),
        b"console.log('context');\n",
    )
    .unwrap();
    let command = "bun ./tools/context.mjs --target app/items/page.tsx";
    let runtime_dir = runtime_dir.to_str().unwrap();
    let shim_dir = shim_dir.to_str().unwrap();
    // A system directory with no `bun`, so the host's own never answers.
    let system = Path::new(&case.workspace).join("system");
    fs::create_dir_all(&system).unwrap();
    let system = system.to_str().unwrap();

    // The grant the user saved for the script, as the runtime on their own
    // `PATH` identifies it.
    let agent_env = [("PATH".to_owned(), format!("{runtime_dir}:{system}"))]
        .into_iter()
        .collect();
    let granted = super::super::local_launch(
        command,
        &case.workspace,
        &case.workspace,
        Some(super::super::LaunchEnv {
            user_home: &case.workspace,
            env: &agent_env,
        }),
    )
    .unwrap()
    .expect("the runtime on the agent's PATH identifies the script");
    rusqlite::Connection::open(Path::new(&case.guard_home).join("guard.db"))
        .unwrap()
        .execute(
            "insert into local_cli_grant values (?1, ?2, 'allowed')",
            [granted.cli_id.as_str(), granted.identity_hash.as_str()],
        )
        .unwrap();

    let reviewed = |stamped: Option<String>| {
        let mut request = case.request("review", command, review("native_command_review_required"));
        // The daemon runs with a system `PATH` that holds no `bun`.
        request.env = Some(
            [("PATH".to_owned(), system.to_owned())]
                .into_iter()
                .collect(),
        );
        if let Some(path) = stamped {
            request.payload.insert(
                crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD.to_owned(),
                json!({ "path": path }),
            );
        }
        review_verdict(&request)
    };
    assert_eq!(
        reviewed(Some(format!("{shim_dir}:{runtime_dir}:{system}"))),
        RuleVerdict::Allowed
    );
    // Without the stamp the daemon's `PATH` finds no runtime to identify.
    assert_eq!(reviewed(None), RuleVerdict::None);
    // A `PATH` whose only `bun` is the shim identifies nothing either.
    assert_eq!(
        reviewed(Some(format!("{shim_dir}:{system}"))),
        RuleVerdict::None
    );
    // An entry the check cannot resolve keeps its place without bringing the
    // shims back.
    assert_eq!(
        reviewed(Some(format!(
            "~someone/bin:{shim_dir}:{runtime_dir}:{system}"
        ))),
        RuleVerdict::Allowed
    );
    // An empty stamped `PATH` is the agent's, not a reason to fall back to the
    // daemon's.
    assert_eq!(reviewed(Some(String::new())), RuleVerdict::None);

    // After `cd`, a relative entry names a directory under the new working
    // directory: there it is the shim directory, and is dropped.
    let parent = Path::new(&case.workspace).parent().unwrap();
    let home_name = Path::new(&case.guard_home).file_name().unwrap();
    let relative_shims = format!("../{}/package-shims/bin", home_name.to_str().unwrap());
    let mut after_cd = case.request(
        "review",
        &format!("cd {} && {command}", case.workspace),
        review("native_command_review_required"),
    );
    after_cd.env = Some(
        [("PATH".to_owned(), system.to_owned())]
            .into_iter()
            .collect(),
    );
    after_cd
        .payload
        .insert("cwd".to_owned(), json!(parent.to_str().unwrap()));
    after_cd.payload.insert(
        crate::hook_direct::EXECUTION_ENVIRONMENT_FIELD.to_owned(),
        json!({ "path": format!("{relative_shims}:{runtime_dir}:{system}") }),
    );
    assert_eq!(review_verdict(&after_cd), RuleVerdict::Allowed);
}
