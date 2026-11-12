//! A custom extension's allow for a script that starts `#!/usr/bin/env bash`,
//! read for a review the resident answers.
//!
//! The resident runs with only `HOME` and a temporary directory, so `env`
//! cannot find `bash` there. The daemon identifies the launch with its own
//! environment, which it publishes with the binding; the resident must read
//! the grant against that one, or the allowed script stays paused for review.

use super::*;
use crate::hook_direct::local_cli::{review_grant, LaunchEnv, RuleCheck};
use std::os::unix::fs::PermissionsExt;

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

/// A script outside the workspace, added as a custom extension by its full
/// path, and a Guard home whose store allows the identity the daemon derives
/// for it under `published`.
struct ScriptGrant {
    workspace: String,
    guard_home: String,
    payload: Map<String, Value>,
    published: BTreeMap<String, String>,
}

impl ScriptGrant {
    fn new(tag: &str) -> Self {
        let workspace = workspace(tag);
        let root = std::env::temp_dir().join(format!(
            "hg-saved-custom-grant-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(root.join("tools")).unwrap();
        std::fs::create_dir_all(root.join("guard")).unwrap();
        let root = root.canonicalize().unwrap();
        let script = root.join("tools/pr-approve-merge.sh");
        std::fs::write(&script, "#!/usr/bin/env bash\necho ok\n").unwrap();
        std::fs::set_permissions(&script, std::fs::Permissions::from_mode(0o755)).unwrap();
        let command = format!("{} 42 --dry-run", script.to_str().unwrap());
        let published = BTreeMap::from([
            ("HOME".to_owned(), workspace.clone()),
            ("PATH".to_owned(), std::env::var("PATH").unwrap()),
        ]);
        let found = crate::local_cli_identify::identify(&crate::local_cli_identify::Request {
            command_text: &command,
            cwd: &workspace,
            home_dir: Some(&workspace),
            user_home: &workspace,
            compound: false,
            env: &published,
            budget_ms: 2_000,
        })
        .unwrap();
        let identity = found.first().expect("the script is a local CLI");
        let guard_home = root.join("guard").to_str().unwrap().to_owned();
        let connection = Connection::open(root.join("guard/guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute(
                "insert into local_cli_grant values (?1, ?2, 'allowed')",
                params![identity.cli_id, identity.identity_hash],
            )
            .unwrap();
        let payload = json!({ "tool_input": { "command": command } })
            .as_object()
            .unwrap()
            .clone();
        Self {
            workspace,
            guard_home,
            payload,
            published,
        }
    }

    fn custom_grant(&self, environment: &BTreeMap<String, String>) -> Option<ReviewVerdict> {
        let binding = binding();
        let context = Context {
            harness: "cursor",
            payload: &self.payload,
            recorded_payload: &self.payload,
            workspace: &self.workspace,
            home_dir: &self.workspace,
            guard_home: &self.guard_home,
            binding: &binding,
            hint: None,
        };
        let result = json!({ "policy_action": "review" })
            .as_object()
            .unwrap()
            .clone();
        custom_grant(&context, &result, environment)
    }

    fn review_grant(&self, launch_env: Option<LaunchEnv<'_>>) -> Option<ReviewVerdict> {
        review_grant(&RuleCheck {
            payload: Some(&self.payload),
            harness: "cursor",
            workspace: &self.workspace,
            home_dir: &self.workspace,
            guard_home: &self.guard_home,
            recording_only: false,
            launch_env,
        })
    }
}

#[test]
fn the_grant_is_read_against_the_environment_the_daemon_published() {
    let script = ScriptGrant::new("published");
    assert_eq!(
        script.custom_grant(&script.published),
        Some(ReviewVerdict::Allowed)
    );
    // An environment whose `PATH` cannot find `bash` identifies no launch,
    // as it would not for the daemon either, so the review stands.
    let without_bash = BTreeMap::from([
        ("HOME".to_owned(), script.workspace.clone()),
        ("PATH".to_owned(), "/nonexistent".to_owned()),
    ]);
    assert_eq!(script.custom_grant(&without_bash), None);
    // A published environment without `HOME` names no home to resolve `~`
    // against, so the review stands rather than guessing one.
    let homeless = BTreeMap::from([("PATH".to_owned(), std::env::var("PATH").unwrap())]);
    assert_eq!(script.custom_grant(&homeless), None);
}

#[test]
fn a_launch_is_never_resolved_against_the_resident_environment() {
    let script = ScriptGrant::new("resident");
    let daemon = LaunchEnv {
        user_home: &script.workspace,
        env: &script.published,
    };
    assert_eq!(
        script.review_grant(Some(daemon)),
        Some(ReviewVerdict::Allowed)
    );
    // Without the daemon's environment the resident used to identify the
    // launch against its own. Its `PATH` is not the daemon's, so the
    // identity could differ from the one the user allowed.
    assert_eq!(script.review_grant(None), None);
}
