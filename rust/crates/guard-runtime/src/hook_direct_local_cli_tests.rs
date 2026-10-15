use super::{custom_rule_response, launch_cwd, launches_local_cli, pre_tool_command, RuleCheck};
use crate::context_digest_package_scripts::package_json_scripts;
use serde_json::{json, Map, Value};
use std::fs;

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
        "hook-direct-local-cli-{label}-{}",
        std::process::id()
    ));
    let _ = fs::remove_dir_all(&root);
    fs::create_dir_all(&root).unwrap();
    fs::canonicalize(root).unwrap().to_str().unwrap().to_owned()
}

#[test]
fn the_command_follows_the_daemon_field_order() {
    let payload = object(json!({
        "toolInput": { "cmd": "  ", "shellCommand": "make" },
        "arguments": { "command": "ls" },
        "command": "pwd",
    }));
    assert_eq!(pre_tool_command(&payload), Ok(Some("make")));
    let payload = object(json!({ "tool_input": {}, "arguments": { "command": "ls" } }));
    assert_eq!(pre_tool_command(&payload), Ok(Some("ls")));
    let payload = object(json!({ "tool_input": { "file_path": "/tmp/a" } }));
    assert_eq!(pre_tool_command(&payload), Ok(None));
}

#[test]
fn the_launch_directory_must_exist_and_be_absolute() {
    let workspace = scratch("cwd");
    let payload = object(json!({ "cwd": " " }));
    assert_eq!(
        launch_cwd(&payload, &workspace),
        Ok(Some(workspace.clone()))
    );
    let payload = object(json!({ "cwd": "relative/dir" }));
    assert_eq!(launch_cwd(&payload, &workspace), Ok(None));
    let payload = object(json!({ "cwd": format!("{workspace}/absent") }));
    assert_eq!(launch_cwd(&payload, &workspace), Ok(None));
}

/// A workspace whose package scripts are a local CLI, and a Guard home whose
/// store holds the rows `seed` writes for that CLI's id and identity hash.
struct Case {
    workspace: String,
    guard_home: String,
}

impl Case {
    fn new(label: &str, seed: &str) -> Self {
        let workspace = scratch(&format!("{label}-work"));
        let guard_home = scratch(&format!("{label}-home"));
        fs::write(
            format!("{workspace}/package.json"),
            br#"{"name": "demo", "scripts": {"build": "tsc", "db:migrate": "knex"}}"#,
        )
        .unwrap();
        let found = package_json_scripts("npm run build", &workspace, &workspace)
            .unwrap()
            .unwrap();
        let identity = found.identity.unwrap();
        let seed = seed
            .replace("{cli}", &identity.cli_id)
            .replace("{hash}", &identity.identity_hash);
        let connection = rusqlite::Connection::open(format!("{guard_home}/guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection.execute_batch(&seed).unwrap();
        Self {
            workspace,
            guard_home,
        }
    }

    fn check(
        &self,
        command: &str,
        recording_only: bool,
        own_shape: bool,
    ) -> Result<Option<Value>, ()> {
        let payload = object(json!({ "tool_input": { "command": command } }));
        let answered = json!({ "result": { "decision": "allow", "minimum_action": "allow" } });
        custom_rule_response(
            &answered,
            &RuleCheck {
                payload: Some(&payload),
                harness: "codex",
                workspace: &self.workspace,
                home_dir: &self.workspace,
                guard_home: &self.guard_home,
                recording_only,
                own_shape,
            },
        )
    }
}

const COMMANDS: &str = "
insert into local_cli_command values ('{cli}', 'build', 'build', 'build', 'tsc', null);
insert into local_cli_command values ('{cli}', 'db', 'db', 'db', 'db', null);
insert into local_cli_command values ('{cli}', 'db.migrate', 'migrate', 'db:migrate', 'knex', 'db');
";

#[test]
fn a_launch_without_a_blocking_grant_keeps_the_edge_response() {
    let none = Case::new("none", "");
    assert_eq!(none.check("npm run build", false, false), Ok(None));
    assert_eq!(none.check("pwd", false, false), Ok(None));
    let allowed = Case::new(
        "allowed",
        &format!(
            "insert into local_cli_grant values ('{{cli}}', '{{hash}}', 'allowed'); {COMMANDS} \
             insert into local_cli_command_grant values ('{{cli}}', 'db.migrate', 'block');"
        ),
    );
    assert_eq!(allowed.check("npm run build", false, false), Ok(None));
    let stale = Case::new(
        "stale",
        &format!(
            "insert into local_cli_grant values ('{{cli}}', '{}', 'blocked');",
            "f".repeat(64)
        ),
    );
    assert_eq!(stale.check("npm run build", false, false), Ok(None));
}

#[test]
fn only_a_command_that_launches_a_local_cli_reads_a_grant() {
    let case = Case::new("launches", "");
    let launches =
        |payload: Value| launches_local_cli(&object(payload), &case.workspace, &case.workspace);
    assert_eq!(
        launches(json!({ "tool_input": { "command": "npm run build" } })),
        Ok(true)
    );
    assert_eq!(
        launches(json!({ "tool_input": { "command": "pwd" } })),
        Ok(false)
    );
    assert_eq!(
        launches(json!({ "tool_input": { "file_path": "/tmp/a" } })),
        Ok(false)
    );
    assert_eq!(
        launches(json!({ "tool_input": { "command": "npm run build" }, "cwd": "relative" })),
        Ok(false)
    );
}

#[test]
fn a_blocking_grant_answers_with_the_daemon_block() {
    let blocked = Case::new(
        "blocked",
        "insert into local_cli_grant values ('{cli}', '{hash}', 'blocked');",
    );
    let response = blocked
        .check("npm run build", false, false)
        .unwrap()
        .unwrap();
    assert_eq!(response["approval_reuse_status"], "blocked");
    assert!(response
        .to_string()
        .contains("Your custom extension rules block this"));
    let watch = blocked
        .check("npm run build", true, false)
        .unwrap()
        .unwrap();
    assert!(watch.get("approval_reuse_status").is_none());
    assert_eq!(blocked.check("npm run build", false, true), Err(()));

    let command = Case::new(
        "command",
        &format!(
            "insert into local_cli_grant values ('{{cli}}', '{{hash}}', 'allowed'); {COMMANDS} \
             insert into local_cli_command_grant values ('{{cli}}', 'build', 'block');"
        ),
    );
    let response = command
        .check("npm run build", false, false)
        .unwrap()
        .unwrap();
    assert_eq!(response["approval_reuse_status"], "blocked");
}

#[test]
fn only_an_allowed_pre_tool_under_rules_is_checked() {
    let blocked = Case::new(
        "gate",
        "insert into local_cli_grant values ('{cli}', '{hash}', 'blocked');",
    );
    let payload = object(json!({ "tool_input": { "command": "npm run build" } }));
    let answer = |decision: &str, action: &str| json!({ "result": { "decision": decision, "minimum_action": action } });
    let gate = |answered: Value, payload: Option<&Map<String, Value>>, recording_only: bool| {
        gated(&blocked, &answered, payload, recording_only)
    };
    assert_eq!(
        gate(answer("allow", "warn"), Some(&payload), false),
        Ok(None)
    );
    assert_eq!(gate(answer("allow", "allow"), None, false), Ok(None));
    // Watch checks only an action the edge also decided to allow.
    assert_eq!(
        gate(answer("review", "allow"), Some(&payload), true),
        Ok(None)
    );
    assert!(matches!(
        gate(answer("allow", "allow"), Some(&payload), true),
        Ok(Some(_))
    ));
}

fn gated(
    case: &Case,
    answered: &Value,
    payload: Option<&Map<String, Value>>,
    recording_only: bool,
) -> Result<Option<Value>, ()> {
    custom_rule_response(
        answered,
        &RuleCheck {
            payload,
            harness: "codex",
            workspace: &case.workspace,
            home_dir: &case.workspace,
            guard_home: &case.guard_home,
            recording_only,
            own_shape: false,
        },
    )
}

#[test]
fn an_unreadable_store_defers() {
    let broken = Case::new("broken", "");
    fs::write(format!("{}/guard.db", broken.guard_home), b"not a database").unwrap();
    assert_eq!(broken.check("npm run build", false, false), Err(()));
}

#[test]
fn a_grant_the_resident_cannot_read_answers_as_unverified() {
    // A hash of the wrong type fails the resident's grant read after the
    // catalog read succeeds, which the daemon blocks as unverified.
    let damaged = Case::new(
        "damaged",
        "insert into local_cli_grant values ('{cli}', x'00', 'blocked');",
    );
    let response = damaged
        .check("npm run build", false, false)
        .unwrap()
        .unwrap();
    assert_eq!(response["approval_reuse_status"], "blocked");
    let text = response.to_string();
    assert!(
        text.contains("Guard could not check this command against your custom extension rules.")
    );
    assert!(text.contains("local_cli_extension_unverified"));
    let watch = damaged
        .check("npm run build", true, false)
        .unwrap()
        .unwrap();
    assert!(watch.get("approval_reuse_status").is_none());
    assert!(!watch.to_string().contains("local_cli_extension_unverified"));
    assert_eq!(damaged.check("npm run build", false, true), Err(()));
    assert_eq!(damaged.check("pwd", false, false), Ok(None));
}
