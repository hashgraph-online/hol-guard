//! Decision matrix against a temporary `guard.db` carrying the local CLI
//! schema that `store_local_cli_schema.py` creates.

use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use guard_contracts::{
    LocalCliGrantRequestV1, LocalCliIdentitySourceV1, LOCAL_CLI_GRANT_REQUEST_SCHEMA,
};
use rusqlite::{params, Connection};
use serde_json::Value;

use super::evaluate_local_cli_grant_request;

const CONTENT: &str = "abababababababababababababababababababababababababababababababab";
const SCHEMA: &str = "
create table local_cli_schema_migration (
    singleton integer primary key check (singleton = 1),
    version integer not null,
    checksum text not null
);
create table local_cli_grant (
    cli_id text primary key,
    identity_hash text not null,
    state text not null check (state in ('allowed', 'blocked')),
    revision integer not null check (revision >= 1),
    updated_at text not null
);
create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    kind text not null check (kind in ('executable', 'script')),
    name text not null,
    example_label text not null,
    observed_count integer not null check (observed_count >= 1),
    last_seen_at text not null,
    surface text not null default 'cli' check (surface in ('cli', 'mcp', 'package-scripts'))
);
create table local_cli_command (
    cli_id text not null,
    command_id text not null,
    name text not null,
    usage text not null,
    description text not null,
    parent_id text,
    sort_index integer not null check (sort_index >= 0),
    primary key (cli_id, command_id)
);
create table local_cli_command_grant (
    cli_id text not null,
    command_id text not null,
    state text not null check (state in ('inherit', 'allow', 'review', 'block')),
    primary key (cli_id, command_id)
);
";

static COUNTER: AtomicUsize = AtomicUsize::new(0);

struct Fixture {
    home: PathBuf,
    connection: Connection,
}

impl Fixture {
    fn new() -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let home = std::env::temp_dir().join(format!(
            "hol-guard-local-cli-grant-{}-{suffix}-{}",
            std::process::id(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&home).unwrap();
        let connection = Connection::open(home.join("guard.db")).unwrap();
        connection.execute_batch(SCHEMA).unwrap();
        connection
            .execute(
                "insert into local_cli_schema_migration values (1, 11, ?1)",
                [crate::local_store_read::schema_checksum(11)],
            )
            .unwrap();
        Self { home, connection }
    }

    fn grant(&self, identity: &Identity, state: &str, hash: Option<&str>) {
        self.connection
            .execute(
                "insert into local_cli_grant values (?1, ?2, ?3, 1, '2026-01-01T00:00:00Z')",
                params![identity.cli_id, hash.unwrap_or(&identity.hash), state],
            )
            .unwrap();
    }

    fn observe(&self, identity: &Identity, surface: &str) {
        self.connection
            .execute(
                "insert into local_cli_observation (cli_id, identity_hash, kind, name, \
                 example_label, observed_count, last_seen_at, surface) \
                 values (?1, ?2, 'script', 'n', 'n', 1, '2026-01-01T00:00:00Z', ?3)",
                params![identity.cli_id, identity.hash, surface],
            )
            .unwrap();
    }

    fn command(&self, identity: &Identity, command_id: &str, state: Option<&str>) {
        self.connection
            .execute(
                "insert into local_cli_command values (?1, ?2, ?2, ?2, 'd', null, 0)",
                params![identity.cli_id, command_id],
            )
            .unwrap();
        if let Some(state) = state {
            self.connection
                .execute(
                    "insert into local_cli_command_grant values (?1, ?2, ?3)",
                    params![identity.cli_id, command_id, state],
                )
                .unwrap();
        }
    }

    fn request(
        &self,
        source: &LocalCliIdentitySourceV1,
        action: &str,
        command_id: Option<&str>,
    ) -> LocalCliGrantRequestV1 {
        LocalCliGrantRequestV1 {
            schema: LOCAL_CLI_GRANT_REQUEST_SCHEMA.to_owned(),
            request_id: "grant-test".to_owned(),
            store_path: self.home.join("guard.db").to_string_lossy().into_owned(),
            guard_home: self.home.to_string_lossy().into_owned(),
            current_action: action.to_owned(),
            source: source.clone(),
            command_id: command_id.map(str::to_owned),
        }
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

struct Identity {
    cli_id: String,
    hash: String,
    source: LocalCliIdentitySourceV1,
}

fn package_json() -> Identity {
    let source = LocalCliIdentitySourceV1::PackageJson {
        manifest_path: "/work/app/package.json".to_owned(),
        content_sha256: CONTENT.to_owned(),
        package_name: "app".to_owned(),
    };
    derived(source)
}

fn registry() -> Identity {
    derived(LocalCliIdentitySourceV1::RegistryPackage {
        name: "cowsay".to_owned(),
        package_name: "cowsay".to_owned(),
    })
}

fn script() -> Identity {
    derived(LocalCliIdentitySourceV1::Script {
        entrypoint: serde_json::json!({
            "kind": "python-script", "status": "verified",
            "sha256": CONTENT, "path": "/opt/tools/cwv.py",
        }),
    })
}

fn derived(source: LocalCliIdentitySourceV1) -> Identity {
    let identity = crate::context_digest_local_cli::local_cli_identity(&source)
        .unwrap()
        .unwrap();
    Identity {
        cli_id: identity.cli_id,
        hash: identity.identity_hash,
        source,
    }
}

fn payload(fixture: &Fixture, identity: &Identity, action: &str, command: Option<&str>) -> Value {
    let request = fixture.request(&identity.source, action, command);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "ok", "{reply}");
    reply["payload"].clone()
}

fn state(fixture: &Fixture, identity: &Identity, action: &str, command: Option<&str>) -> String {
    payload(fixture, identity, action, command)["state"]
        .as_str()
        .unwrap()
        .to_owned()
}

#[test]
fn no_grant_row_matches_nothing() {
    let fixture = Fixture::new();
    let identity = script();
    assert_eq!(state(&fixture, &identity, "review", None), "none");
}

#[test]
fn allowed_grant_without_catalog_allows_and_reports_identity() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    let found = payload(&fixture, &identity, "review", None);
    assert_eq!(found["state"], "allowed");
    assert_eq!(found["cli_id"], identity.cli_id);
    assert_eq!(found["identity_hash"], identity.hash);
}

#[test]
fn blocked_grant_blocks_every_refinable_action() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    for action in ["allow", "review", "require-reapproval", "warn"] {
        assert_eq!(
            state(&fixture, &identity, action, None),
            "blocked",
            "{action}"
        );
    }
}

#[test]
fn other_actions_are_never_refined() {
    let fixture = Fixture::new();
    let allowed = script();
    fixture.grant(&allowed, "allowed", None);
    for action in ["block", "sandbox-required", "unknown", ""] {
        assert_eq!(state(&fixture, &allowed, action, None), "none", "{action}");
    }
    let fixture = Fixture::new();
    let blocked = script();
    fixture.grant(&blocked, "blocked", None);
    assert_eq!(state(&fixture, &blocked, "block", None), "none");
}

#[test]
fn identity_hash_mismatch_drops_both_grant_states() {
    for grant_state in ["allowed", "blocked"] {
        let fixture = Fixture::new();
        let identity = script();
        fixture.grant(&identity, grant_state, Some(&"0".repeat(64)));
        assert_eq!(state(&fixture, &identity, "review", None), "none");
    }
}

#[test]
fn command_block_beats_cli_allow_and_command_allow_applies() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "root", None);
    fixture.command(&identity, "deploy", Some("block"));
    fixture.command(&identity, "build", Some("allow"));
    fixture.command(&identity, "lint", Some("inherit"));
    assert_eq!(
        state(&fixture, &identity, "review", Some("deploy")),
        "blocked"
    );
    assert_eq!(
        state(&fixture, &identity, "review", Some("build")),
        "allowed"
    );
    assert_eq!(state(&fixture, &identity, "review", Some("lint")), "none");
    assert_eq!(state(&fixture, &identity, "review", Some("root")), "none");
    // An id missing from the request is the catch-all `other`.
    assert_eq!(state(&fixture, &identity, "review", None), "none");
}

#[test]
fn unknown_and_review_command_states_inherit() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "root", None);
    fixture
        .connection
        .execute(
            "insert into local_cli_command_grant values (?1, 'build', 'review')",
            params![identity.cli_id],
        )
        .unwrap();
    fixture.command(&identity, "build", None);
    assert_eq!(state(&fixture, &identity, "review", Some("build")), "none");
}

#[test]
fn command_allow_cannot_override_a_cli_block() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    fixture.command(&identity, "build", Some("allow"));
    assert_eq!(
        state(&fixture, &identity, "review", Some("build")),
        "blocked"
    );
}

#[test]
fn registry_packages_only_bind_blocks() {
    let fixture = Fixture::new();
    let identity = registry();
    fixture.grant(&identity, "allowed", None);
    assert_eq!(state(&fixture, &identity, "review", None), "none");
    fixture.command(&identity, "run", Some("allow"));
    assert_eq!(state(&fixture, &identity, "review", Some("run")), "none");
    fixture.command(&identity, "rm", Some("block"));
    assert_eq!(state(&fixture, &identity, "review", Some("rm")), "blocked");

    let fixture = Fixture::new();
    let identity = registry();
    fixture.grant(&identity, "blocked", None);
    assert_eq!(state(&fixture, &identity, "review", None), "blocked");
}

#[test]
fn package_scripts_inherit_allows_named_scripts_only() {
    let fixture = Fixture::new();
    let identity = package_json();
    fixture.grant(&identity, "allowed", None);
    fixture.observe(&identity, "package-scripts");
    fixture.command(&identity, "root", None);
    fixture.command(&identity, "other", None);
    fixture.command(&identity, "build", None);
    fixture.command(&identity, "deploy", Some("block"));
    assert_eq!(
        state(&fixture, &identity, "review", Some("build")),
        "allowed"
    );
    assert_eq!(state(&fixture, &identity, "review", Some("root")), "none");
    assert_eq!(state(&fixture, &identity, "review", Some("other")), "none");
    assert_eq!(state(&fixture, &identity, "review", None), "none");
    assert_eq!(
        state(&fixture, &identity, "review", Some("deploy")),
        "blocked"
    );
}

#[test]
fn inherit_does_not_allow_other_surfaces_or_unobserved_clis() {
    for surface in ["cli", "mcp"] {
        let fixture = Fixture::new();
        let identity = package_json();
        fixture.grant(&identity, "allowed", None);
        fixture.observe(&identity, surface);
        fixture.command(&identity, "build", None);
        assert_eq!(state(&fixture, &identity, "review", Some("build")), "none");
    }
    let fixture = Fixture::new();
    let identity = package_json();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&identity, "build", None);
    assert_eq!(state(&fixture, &identity, "review", Some("build")), "none");
}

#[test]
fn other_clis_rows_do_not_leak_across_cli_ids() {
    let fixture = Fixture::new();
    let identity = script();
    let neighbour = package_json();
    fixture.grant(&identity, "allowed", None);
    fixture.command(&neighbour, "build", Some("block"));
    fixture.command(&neighbour, "root", None);
    assert_eq!(
        state(&fixture, &identity, "review", Some("build")),
        "allowed"
    );
}

#[path = "local_cli_grant_op_store_tests.rs"]
mod store;
