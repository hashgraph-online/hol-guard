//! `LocalCliHook` against a temporary `guard.db` built from the local CLI
//! schema the Python store recorded (`testdata/guard_store/local_cli_vectors.json`),
//! plus the command-id vectors recorded from the Python token step
//! (`testdata/local_cli_hook/record_vectors.py`).

use std::collections::{BTreeMap, BTreeSet};
use std::fs;

use guard_contracts::{
    GuardStoreRequestV1, LocalCliHookRequestV1, LocalCliIdentitySourceV1, LocalCliIdentityV1,
    PackageScriptCommandV1, GUARD_STORE_REQUEST_SCHEMA, LOCAL_CLI_HOOK_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::{json, Value};

use super::*;
use crate::guard_store_cmd_vectors_tests::temp_home;

const HOOK_VECTORS: &str = include_str!("../testdata/local_cli_hook/vectors.json");
const STORE_VECTORS: &str = include_str!("../testdata/guard_store/local_cli_vectors.json");
/// The tables the recorded schema leaves out: outbox digests the store op
/// finalizes, per-command states, and the schema marker.
const EXTRA_SCHEMA: &str = "
create table guard_review_outbox_events (
    stream_sequence integer primary key,
    payload_hash text not null default ''
);
create table local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null check (state in ('inherit', 'allow', 'review', 'block')),
    primary key (cli_id, command_id)
);
create table local_cli_schema_migration (
    singleton integer primary key check (singleton = 1),
    version integer not null,
    checksum text not null
);
";

struct Fixture {
    home: String,
    workspace: String,
    connection: Connection,
}

impl Fixture {
    fn new(tag: &str) -> Self {
        let home = temp_home(&format!("local-cli-hook-{tag}"));
        let workspace = home.join("work");
        fs::create_dir(&workspace).unwrap();
        fs::write(
            workspace.join("package.json"),
            br#"{"name": "demo", "scripts": {"build": "tsc", "db:migrate": "knex"}}"#,
        )
        .unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        let vectors: Value = serde_json::from_str(STORE_VECTORS).unwrap();
        for statement in vectors["schema_sql"].as_array().unwrap() {
            connection
                .execute_batch(statement.as_str().unwrap())
                .unwrap();
        }
        connection.execute_batch(EXTRA_SCHEMA).unwrap();
        connection
            .execute(
                "insert into local_cli_schema_migration values (1, 11, ?1)",
                [crate::local_store_read::schema_checksum(11)],
            )
            .unwrap();
        Self {
            home: home.to_string_lossy().into_owned(),
            workspace: workspace.to_string_lossy().into_owned(),
            connection,
        }
    }

    /// `guard.db` joined as a path: Windows reads `/` literally after the
    /// `\\?\` prefix that canonicalizing the temporary home leaves.
    fn store_path(&self) -> String {
        std::path::Path::new(&self.home)
            .join("guard.db")
            .to_string_lossy()
            .into_owned()
    }

    fn request(&self, command: &str, action: &str, grant_allowed: bool) -> LocalCliHookRequestV1 {
        LocalCliHookRequestV1 {
            schema: LOCAL_CLI_HOOK_REQUEST_SCHEMA.to_owned(),
            request_id: "hook-test".to_owned(),
            store_path: self.store_path(),
            guard_home: self.home.clone(),
            source: "test-source".to_owned(),
            busy_timeout_ms: 5_000,
            command: command.to_owned(),
            cwd: self.workspace.clone(),
            home_dir: Some(self.workspace.clone()),
            user_home: self.workspace.clone(),
            env: BTreeMap::new(),
            current_action: action.to_owned(),
            grant_allowed,
        }
    }

    fn identity(&self) -> LocalCliIdentityV1 {
        package_json_scripts("npm run build", &self.workspace, &self.workspace)
            .unwrap()
            .unwrap()
            .identity
            .unwrap()
    }

    fn grant(&self, cli_id: &str, hash: &str, state: &str) {
        self.connection
            .execute(
                "insert into local_cli_grant values (?1, ?2, ?3, 1, '2026-01-01T00:00:00Z')",
                params![cli_id, hash, state],
            )
            .unwrap();
    }

    fn command_grant(&self, cli_id: &str, command_id: &str, state: &str) {
        self.connection
            .execute(
                "insert into local_cli_command_grant values (?1, ?2, ?3)",
                params![cli_id, command_id, state],
            )
            .unwrap();
    }

    fn observations(&self) -> Vec<(String, String, String, i64)> {
        let mut statement = self
            .connection
            .prepare(
                "select cli_id, surface, source_path, observed_count \
                 from local_cli_observation order by cli_id",
            )
            .unwrap();
        statement
            .query_map([], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?))
            })
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn commands(&self, cli_id: &str) -> Vec<(String, String)> {
        let mut statement = self
            .connection
            .prepare(
                "select command_id, name from local_cli_command \
                 where cli_id = ?1 order by sort_index",
            )
            .unwrap();
        statement
            .query_map([cli_id], |row| Ok((row.get(0)?, row.get(1)?)))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn command_grants(&self, cli_id: &str) -> Vec<String> {
        let mut statement = self
            .connection
            .prepare(
                "select command_id from local_cli_command_grant \
                 where cli_id = ?1 order by command_id",
            )
            .unwrap();
        statement
            .query_map([cli_id], |row| row.get(0))
            .unwrap()
            .collect::<Result<_, _>>()
            .unwrap()
    }

    fn store(&self, method: &str, args: Value) -> Value {
        let request = GuardStoreRequestV1 {
            schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
            request_id: "hook-test".to_owned(),
            store_path: self.store_path(),
            guard_home: self.home.clone(),
            method: method.to_owned(),
            source: "test-source".to_owned(),
            busy_timeout_ms: 5_000,
            args: args.as_object().unwrap().clone(),
        };
        let bytes = crate::guard_store_op::evaluate_guard_store_request(&request).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }
}

fn launch(runner: Option<&str>, kind: &str, name: &str) -> Launch {
    Launch {
        cli_id: "local-cli.test".to_owned(),
        identity_hash: "0".repeat(64),
        name: name.to_owned(),
        kind: kind.to_owned(),
        runner: runner.map(str::to_owned),
        source: LocalCliIdentitySourceV1::RegistryPackage {
            name: name.to_owned(),
            package_name: name.to_owned(),
        },
    }
}

fn strings(values: &[&str]) -> Vec<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

fn catalog(values: &[&str]) -> BTreeSet<String> {
    values.iter().map(|value| (*value).to_owned()).collect()
}

#[test]
fn recorded_python_token_vectors_replay() {
    let vectors: Value = serde_json::from_str(HOOK_VECTORS).unwrap();
    assert_eq!(vectors["schema"], "guard-local-cli-hook-vectors.v1");
    let cases = vectors["vectors"].as_array().unwrap();
    assert!(cases.len() >= 40);
    for case in cases {
        let name = case["name"].as_str().unwrap();
        let arguments: Vec<String> = serde_json::from_value(case["arguments"].clone()).unwrap();
        let identity = launch(
            case["runner"].as_str(),
            case["kind"].as_str().unwrap(),
            case["identity_name"].as_str().unwrap(),
        );
        let tokens = command_tokens(&arguments, &identity);
        let expected: Vec<String> = serde_json::from_value(case["tokens"].clone()).unwrap();
        assert_eq!(tokens, expected, "{name}");
        let ids: BTreeSet<String> = serde_json::from_value(case["catalog"].clone()).unwrap();
        assert_eq!(
            match_command_id(&tokens, &ids),
            case["command_id"].as_str().unwrap(),
            "{name}"
        );
    }
}

#[test]
fn token_split_follows_runner_script_and_plain_launches() {
    let plain = launch(None, "executable", "tool");
    assert_eq!(
        command_tokens(&strings(&["deploy", "prod"]), &plain),
        strings(&["deploy", "prod"])
    );
    assert_eq!(
        command_tokens(&strings(&["deploy", "--force", "prod"]), &plain),
        strings(&["deploy"])
    );
    assert!(command_tokens(&strings(&["-v", "deploy"]), &plain).is_empty());
    assert_eq!(
        command_tokens(&strings(&["a", "b", "c", "d", "e"]), &plain),
        strings(&["a", "b", "c", "d"])
    );
    let script = launch(None, "script", "tool.py");
    assert_eq!(
        command_tokens(&strings(&["./bin/tool.py", "db"]), &script),
        strings(&["db"])
    );
    assert!(command_tokens(&strings(&["other.py", "db"]), &script).is_empty());
    let runner = launch(Some("npx"), "executable", "wrangler");
    assert_eq!(
        command_tokens(&strings(&["-y", "wrangler", "deploy"]), &runner),
        strings(&["deploy"])
    );
    assert!(command_tokens(&strings(&["--weird", "wrangler"]), &runner).is_empty());
}

#[test]
fn match_command_id_takes_the_longest_catalog_prefix() {
    let ids = catalog(&["root", "db", "db.migrate", "other"]);
    assert_eq!(match_command_id(&[], &ids), "root");
    assert_eq!(
        match_command_id(&strings(&["db", "migrate", "up"]), &ids),
        "db.migrate"
    );
    assert_eq!(match_command_id(&strings(&["db", "seed"]), &ids), "db");
    assert_eq!(match_command_id(&strings(&["status"]), &ids), "other");
}

#[test]
fn merged_commands_wrap_valid_distinct_scripts_in_root_and_other() {
    let command = |id: &str| PackageScriptCommandV1 {
        command_id: id.to_owned(),
        name: id.to_owned(),
        usage: id.to_owned(),
        description: id.to_owned(),
        parent_id: None,
    };
    let merged = merged_commands(
        "pnpm",
        &[
            command("build"),
            command("root"),
            command("build"),
            command("1bad"),
        ],
    );
    let ids: Vec<&str> = merged.iter().map(|item| item.command_id.as_str()).collect();
    assert_eq!(ids, ["root", "build", "other"]);
    assert_eq!(merged[0].name, "pnpm run");
    assert_eq!(merged[0].description, "Run pnpm run without a subcommand.");
    assert_eq!(merged[2].usage, "pnpm run …");
    let many: Vec<PackageScriptCommandV1> = (0..150)
        .map(|index| command(&format!("s{index}")))
        .collect();
    let merged = merged_commands("npm", &many);
    assert_eq!(merged.len(), MAX_COMMANDS);
    assert_eq!(merged.last().unwrap().command_id, "other");
}

#[test]
fn replace_commands_truncates_text_and_prunes_stale_grants() {
    let fixture = Fixture::new("replace");
    let cli_id = "local-cli.demo";
    fixture.command_grant(cli_id, "build", "block");
    fixture.command_grant(cli_id, "gone", "allow");
    let reply = fixture.store(
        "replace_local_cli_commands",
        json!({"cli_id": cli_id, "commands": [
            {"command_id": "root", "name": "é".repeat(130), "usage": "u".repeat(170),
             "description": "d".repeat(250), "parent_id": null},
            {"command_id": "build", "name": "build", "usage": "build", "description": "b",
             "parent_id": "root"},
        ]}),
    );
    assert_eq!(reply["status"], "ok", "{reply}");
    let rows = fixture.commands(cli_id);
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0].1.chars().count(), 120);
    let (usage, description): (String, String) = fixture
        .connection
        .query_row(
            "select usage, description from local_cli_command where command_id = 'root'",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap();
    assert_eq!((usage.len(), description.len()), (160, 240));
    assert_eq!(fixture.command_grants(cli_id), ["build"]);
    let reply = fixture.store(
        "replace_local_cli_commands",
        json!({"cli_id": cli_id, "commands": [
            {"command_id": "bad id", "name": "n", "usage": "u", "description": "d", "parent_id": null},
        ]}),
    );
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(
        fixture.commands(cli_id).len(),
        2,
        "a refused replace rolls back"
    );
}

#[test]
fn package_run_records_observation_and_catalog() {
    let fixture = Fixture::new("observe");
    let identity = fixture.identity();
    let request = fixture.request("npm run build", "allow", true);
    assert_eq!(run(&request), Ok("allow".to_owned()));
    let observations = fixture.observations();
    assert_eq!(observations.len(), 1);
    assert_eq!(observations[0].0, identity.cli_id);
    assert_eq!(observations[0].1, "package-scripts");
    assert!(observations[0].2.ends_with("package.json"));
    let ids: Vec<String> = fixture
        .commands(&identity.cli_id)
        .into_iter()
        .map(|(id, _)| id)
        .collect();
    assert_eq!(ids.first().map(String::as_str), Some("root"));
    assert_eq!(ids.last().map(String::as_str), Some("other"));
    assert!(ids.contains(&"build".to_owned()));
    assert_eq!(run(&request), Ok("allow".to_owned()));
    assert_eq!(fixture.observations()[0].3, 2);
}

#[test]
fn grants_refine_the_action_by_cli_and_command() {
    let fixture = Fixture::new("grant");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    assert_eq!(
        run(&fixture.request("npm run build", "review", true)),
        Ok("allow".to_owned())
    );
    fixture.command_grant(&identity.cli_id, "build", "block");
    assert_eq!(
        run(&fixture.request("npm run build", "review", true)),
        Ok("block".to_owned())
    );
}

#[test]
fn grant_lookups_off_still_record_the_observation() {
    let fixture = Fixture::new("no-grant");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    assert_eq!(
        run(&fixture.request("npm run build", "allow", false)),
        Ok("allow".to_owned())
    );
    assert_eq!(fixture.observations().len(), 1);
}

#[test]
fn a_non_refinable_action_is_never_changed() {
    let fixture = Fixture::new("non-refinable");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    assert_eq!(
        run(&fixture.request("npm run build", "block", true)),
        Ok("block".to_owned())
    );
    assert_eq!(fixture.observations().len(), 1);
}

#[test]
fn an_unreadable_grant_is_unverified() {
    let fixture = Fixture::new("unverified");
    fixture
        .connection
        .execute("update local_cli_schema_migration set version = 99", [])
        .unwrap();
    let request = fixture.request("npm run build", "allow", true);
    assert_eq!(run(&request), Ok("allow".to_owned()), "no block rule");
    fixture.command_grant("local-cli.other", "deploy", "block");
    assert_eq!(run(&request), Ok("review".to_owned()));
    assert_eq!(
        run(&fixture.request("npm run build", "warn", true)),
        Ok("review".to_owned())
    );
    assert_eq!(
        run(&fixture.request("npm run build", "require-reapproval", true)),
        Ok("require-reapproval".to_owned())
    );
}

#[test]
fn block_rule_probe_reads_both_tables_and_fails_closed() {
    let fixture = Fixture::new("probe");
    let request = fixture.request("true", "allow", true);
    assert!(!has_block_rules(&request));
    fixture.grant("local-cli.other", &"0".repeat(64), "blocked");
    assert!(has_block_rules(&request));
    let mut outside = request.clone();
    outside.store_path = "/nonexistent/guard.db".to_owned();
    assert!(has_block_rules(&outside));
}

#[test]
fn the_reply_binds_the_request_and_rejects_another_schema() {
    let fixture = Fixture::new("reply");
    let request = fixture.request("npm run build", "allow", true);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_hook_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], json!({"action": "allow"}));
    assert_eq!(reply["request_id"], "hook-test");
    assert!(reply["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    let mut other = request;
    other.schema = "other".to_owned();
    assert!(evaluate_local_cli_hook_request(&other).is_err());
}
