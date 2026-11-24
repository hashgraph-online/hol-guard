//! Store, schema-marker and request-validation cases for `LocalCliGrantDecide`.

use super::*;
use crate::local_cli_grant_op::{grant_unset, Undecided};

#[test]
fn ungrantable_material_matches_nothing() {
    let fixture = Fixture::new();
    let source = LocalCliIdentitySourceV1::Script {
        entrypoint: serde_json::json!({"kind": "python-c", "status": "verified"}),
    };
    let request = fixture.request(&source, "review", None);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["payload"]["state"], "none");
    assert_eq!(reply["payload"]["cli_id"], Value::Null);
}

#[test]
fn missing_store_and_missing_tables_match_nothing() {
    let mut fixture = Fixture::new();
    let identity = script();
    // Windows refuses to delete a file a connection still holds open.
    drop(std::mem::replace(
        &mut fixture.connection,
        Connection::open_in_memory().unwrap(),
    ));
    fs::remove_file(fixture.home.join("guard.db")).unwrap();
    assert_eq!(state(&fixture, &identity, "review", None), "none");
    Connection::open(fixture.home.join("guard.db"))
        .unwrap()
        .execute_batch("create table unrelated (x integer)")
        .unwrap();
    assert_eq!(state(&fixture, &identity, "review", None), "none");
}

#[test]
fn newer_schema_fails_instead_of_guessing() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    fixture
        .connection
        .execute("update local_cli_schema_migration set version = 15", [])
        .unwrap();
    let request = fixture.request(&identity.source, "review", None);
    let reply: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    assert_eq!(reply["status"], "error");
    assert_eq!(reply["code"], "native_local_cli_grant_schema_unsupported");
    assert_eq!(reply["payload"], Value::Null);
}

#[test]
fn damaged_schema_marker_fails_instead_of_authorizing() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "allowed", None);
    assert_eq!(state(&fixture, &identity, "review", None), "allowed");
    for (version, checksum) in [
        (11, "checksum".to_owned()),
        (11, crate::local_store_read::schema_checksum(10)),
        (0, crate::local_store_read::schema_checksum(0)),
    ] {
        fixture
            .connection
            .execute(
                "update local_cli_schema_migration set version = ?1, checksum = ?2",
                rusqlite::params![version, checksum],
            )
            .unwrap();
        let request = fixture.request(&identity.source, "review", None);
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "error", "{version} {checksum}");
        assert_eq!(reply["code"], "native_local_cli_grant_schema_invalid");
        assert_eq!(reply["payload"], Value::Null);
    }
}

#[test]
fn store_path_must_be_guard_db_directly_under_home() {
    let fixture = Fixture::new();
    let identity = script();
    fixture.grant(&identity, "blocked", None);
    let other = Fixture::new();
    let mut cases = Vec::new();
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = other.home.join("guard.db").to_string_lossy().into_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = fixture.home.join("other.db").to_string_lossy().into_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = "guard.db".to_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.guard_home = "relative".to_owned();
    cases.push(request);
    let mut request = fixture.request(&identity.source, "review", None);
    request.store_path = fixture
        .home
        .join("..")
        .join(fixture.home.file_name().unwrap())
        .join("sub")
        .join("guard.db")
        .to_string_lossy()
        .into_owned();
    cases.push(request);
    for request in cases {
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["status"], "error", "{request:?}");
        assert_eq!(reply["code"], "native_local_cli_grant_path_invalid");
    }
}

#[test]
fn invalid_command_id_and_schema_are_rejected() {
    let fixture = Fixture::new();
    let identity = script();
    for bad in ["", "caf\u{e9}"] {
        let request = fixture.request(&identity.source, "review", Some(bad));
        let reply: Value =
            serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
        assert_eq!(reply["code"], "native_local_cli_grant_command_invalid");
    }
    let mut request = fixture.request(&identity.source, "review", None);
    request.schema = "wrong".to_owned();
    assert_eq!(
        evaluate_local_cli_grant_request(&request).unwrap_err(),
        "native_local_cli_grant_schema_mismatch"
    );
}

#[test]
fn reply_binds_to_the_request_digest() {
    let fixture = Fixture::new();
    let identity = script();
    let request = fixture.request(&identity.source, "review", None);
    let first: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&request).unwrap()).unwrap();
    let other = fixture.request(&identity.source, "warn", None);
    let second: Value =
        serde_json::from_slice(&evaluate_local_cli_grant_request(&other).unwrap()).unwrap();
    assert!(first["request_sha256"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_ne!(first["request_sha256"], second["request_sha256"]);
}

#[test]
fn an_allow_of_an_earlier_version_is_told_apart_from_no_decision() {
    let fixture = Fixture::new();
    let identity = script();
    let home = fixture.home.to_string_lossy().into_owned();
    let unset = |hash: &str| grant_unset(&home, &identity.cli_id, hash, &identity.source).unwrap();
    assert_eq!(unset(&identity.hash), Some(Undecided::Never));
    let older = "0".repeat(64);
    fixture.grant(&identity, "allowed", Some(&older));
    assert_eq!(unset(&older), None);
    assert_eq!(
        unset(&identity.hash),
        Some(Undecided::AllowedEarlierVersion)
    );
    // A block of an earlier version stays a plain setup review.
    fixture
        .connection
        .execute("update local_cli_grant set state = 'blocked'", [])
        .unwrap();
    assert_eq!(unset(&older), None);
    assert_eq!(unset(&identity.hash), Some(Undecided::Never));
}

fn runtime_script(kind: &str, content: &str) -> Identity {
    derived(LocalCliIdentitySourceV1::Script {
        entrypoint: serde_json::json!({
            "kind": kind, "status": "verified",
            "sha256": content, "path": "/opt/tools/scripts/context.mjs",
        }),
    })
}

#[test]
fn a_script_grant_covers_every_javascript_runtime_that_runs_the_file() {
    let fixture = Fixture::new();
    let node = runtime_script("node-script", CONTENT);
    fixture.grant(&node, "allowed", None);
    for kind in [
        "node-script",
        "bun-script",
        "bun.exe-script",
        "deno-script",
        "tsx-script",
        "ts-node.cmd-script",
    ] {
        let launch = runtime_script(kind, CONTENT);
        assert_eq!(launch.cli_id, node.cli_id, "{kind}");
        let found = payload(&fixture, &launch, "review", None);
        assert_eq!(found["state"], "allowed", "{kind}");
        assert_eq!(found["identity_hash"], launch.hash, "{kind}");
    }
    let home = fixture.home.to_string_lossy().into_owned();
    let bun = runtime_script("bun-script", CONTENT);
    assert_eq!(
        grant_unset(&home, &bun.cli_id, &bun.hash, &bun.source).unwrap(),
        None
    );
}

#[test]
fn a_block_recorded_under_one_javascript_runtime_binds_the_others() {
    let fixture = Fixture::new();
    let bun = runtime_script("bun-script", CONTENT);
    fixture.grant(&bun, "blocked", None);
    let node = runtime_script("node-script", CONTENT);
    assert_eq!(state(&fixture, &node, "review", None), "blocked");
}

#[test]
fn a_runtime_grant_stays_bound_to_the_file_content_and_language() {
    let fixture = Fixture::new();
    let node = runtime_script("node-script", CONTENT);
    fixture.grant(&node, "allowed", None);
    let changed = runtime_script("bun-script", &"b".repeat(64));
    assert_eq!(state(&fixture, &changed, "review", None), "none");
    let home = fixture.home.to_string_lossy().into_owned();
    assert_eq!(
        grant_unset(&home, &changed.cli_id, &changed.hash, &changed.source).unwrap(),
        Some(Undecided::AllowedEarlierVersion)
    );
    // Another language reading the same file is not one of the runtimes.
    let python = runtime_script("python-script", CONTENT);
    assert_eq!(python.cli_id, node.cli_id);
    assert_eq!(state(&fixture, &python, "review", None), "none");
}

#[test]
fn a_grant_recorded_under_a_typescript_runner_covers_node() {
    let fixture = Fixture::new();
    for kind in ["tsx-script", "ts-node-script"] {
        let runner = runtime_script(kind, CONTENT);
        fixture
            .connection
            .execute("delete from local_cli_grant", [])
            .unwrap();
        fixture.grant(&runner, "allowed", None);
        let node = runtime_script("node-script", CONTENT);
        assert_eq!(state(&fixture, &node, "review", None), "allowed", "{kind}");
    }
}
