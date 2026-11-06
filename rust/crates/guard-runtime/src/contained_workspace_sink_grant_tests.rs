//! The sink asks the store for the grant itself and refuses one that moved.

use super::*;
use crate::local_cli_hook_op::tests::Fixture;

fn sandboxed(fixture: &Fixture) -> LocalCliHookRequestV1 {
    let mut request = fixture.request("npm run build", "sandbox-required", true);
    request.current_reason_code = Some(WORKSPACE_REASON.to_owned());
    request
}

fn message(outcome: Outcome<impl std::fmt::Debug>) -> String {
    outcome.expect_err("refused").message
}

#[test]
fn an_allowed_grant_is_decided_and_an_unset_one_runs_the_base_sandbox() {
    let fixture = Fixture::new("sink-grant-allowed");
    let request = sandboxed(&fixture);
    assert_eq!(decided(&request).unwrap(), None);
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    let grant = decided(&request).unwrap().expect("the store's grant");
    assert_eq!(grant["identity_hash"], identity.identity_hash.as_str());
    let input = prepare_input(&grant);
    let mut keys: Vec<&str> = input
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(keys, ["capabilities", "identity_hash", "name"]);
    let expected = expected(&grant, "/").unwrap();
    assert_eq!(expected.identity_hash, identity.identity_hash);
    assert_eq!(expected.state_dir, None, "no state capability");
    assert_eq!(unchanged(&Some(grant), decided(&request)), Ok(()));
}

#[test]
fn a_blocked_cli_stops_the_run() {
    let fixture = Fixture::new("sink-grant-blocked");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "blocked");
    assert_eq!(message(decided(&sandboxed(&fixture))), GRANT_BLOCKED);
}

#[test]
fn a_store_that_cannot_be_asked_decides_no_grant() {
    let fixture = Fixture::new("sink-grant-unusable-store");
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    let usable = sandboxed(&fixture);
    let first = decided(&usable).unwrap();
    assert!(first.is_some(), "the store decides the grant");
    let mut unusable = usable.clone();
    unusable.store_path = "relative/guard.db".to_owned();
    // The base sandbox runs, as it does in the Python sink.
    assert_eq!(decided(&unusable).unwrap(), None);
    // A grant already decided cannot be confirmed by a store that went away.
    assert_eq!(
        message(unchanged(&first, decided(&unusable))),
        GRANT_CHANGED
    );
    assert_eq!(unchanged(&None, decided(&unusable)), Ok(()));
}

#[test]
fn a_tampered_or_revoked_grant_is_refused_before_launch() {
    let fixture = Fixture::new("sink-grant-tampered");
    let request = sandboxed(&fixture);
    let identity = fixture.identity();
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    let first = decided(&request).unwrap();
    // The grant the plan was prepared with differs from the store's now.
    for (field, value) in [
        ("identity_hash", json!("f".repeat(64))),
        ("capabilities", json!(["loopback-network"])),
        ("name", json!("lanectl")),
    ] {
        let mut tampered = first.clone().unwrap();
        tampered[field] = value;
        assert_eq!(
            message(unchanged(&Some(tampered), decided(&request))),
            GRANT_CHANGED,
            "{field}"
        );
    }
    // The state moved off `allowed` between plan and launch.
    fixture
        .connection
        .execute("update local_cli_grant set state = 'blocked'", [])
        .unwrap();
    assert_eq!(message(unchanged(&first, decided(&request))), GRANT_CHANGED);
    fixture
        .connection
        .execute("delete from local_cli_grant", [])
        .unwrap();
    assert_eq!(message(unchanged(&first, decided(&request))), GRANT_CHANGED);
    // A grant that appears only after planning is refused as well.
    fixture.grant(&identity.cli_id, &identity.identity_hash, "allowed");
    assert_eq!(message(unchanged(&None, decided(&request))), GRANT_CHANGED);
}

#[test]
fn the_expected_state_directory_follows_the_canonical_home() {
    let home = tempfile::tempdir().unwrap();
    let canonical = std::fs::canonicalize(home.path()).unwrap();
    let grant = json!({
        "identity_hash": "a".repeat(64),
        "name": "lanectl",
        "capabilities": ["loopback-network", "state-dir-read"],
    });
    let expected = expected(&grant, home.path().to_str().unwrap()).unwrap();
    assert_eq!(
        expected.state_dir.as_deref(),
        canonical.join(".lanectl").to_str()
    );
    let mut unsorted = grant;
    unsorted["capabilities"] = json!(["state-dir-read", "loopback-network"]);
    assert_eq!(
        message(super::expected(&unsorted, "/")),
        INVALID_PLAN.to_owned()
    );
}

fn private_home() -> (tempfile::TempDir, std::path::PathBuf) {
    let private = tempfile::tempdir().unwrap();
    let path = std::fs::canonicalize(private.path()).unwrap();
    std::fs::create_dir(path.join("home")).unwrap();
    (private, path)
}

fn state_grant(home: &std::path::Path, names: &[&str]) -> (ExpectedGrant, Value) {
    let expected = ExpectedGrant {
        identity_hash: "a".repeat(64),
        capabilities: names.iter().map(|name| (*name).to_owned()).collect(),
        state_dir: home.join(".lanectl").to_str().map(str::to_owned),
    };
    (expected, json!(names))
}

#[test]
fn the_state_directory_is_linked_where_home_looks_for_it() {
    let host = tempfile::tempdir().unwrap();
    let host = std::fs::canonicalize(host.path()).unwrap();
    let state = host.join(".lanectl");
    std::fs::create_dir(&state).unwrap();
    std::fs::write(state.join("session"), "saved").unwrap();
    std::fs::write(host.join("unrelated"), "private").unwrap();
    let (_keep, private) = private_home();
    let (expected, capabilities) = state_grant(&host, &["state-dir-read"]);
    link_state(&private, Some(&expected), &capabilities).unwrap();
    let linked = private.join("home/.lanectl");
    assert_eq!(std::fs::read_link(&linked).unwrap(), state);
    // The CLI reads and writes its state through the private `HOME`.
    assert_eq!(
        std::fs::read_to_string(linked.join("session")).unwrap(),
        "saved"
    );
    std::fs::write(linked.join("written"), "new").unwrap();
    assert!(state.join("written").is_file());
    // Nothing else of the real home is there.
    assert_eq!(std::fs::read_dir(private.join("home")).unwrap().count(), 1);
}

#[test]
fn no_state_link_without_a_state_capability_or_directory() {
    let host = tempfile::tempdir().unwrap();
    let host = std::fs::canonicalize(host.path()).unwrap();
    let (_keep, private) = private_home();
    let linked = private.join("home/.lanectl");
    // No state capability, though the directory exists.
    std::fs::create_dir(host.join(".lanectl")).unwrap();
    let (expected, capabilities) = state_grant(&host, &["loopback-network"]);
    link_state(&private, Some(&expected), &capabilities).unwrap();
    assert!(!linked.exists() && std::fs::symlink_metadata(&linked).is_err());
    // No grant at all.
    let (_, state_names) = state_grant(&host, &["state-dir-write"]);
    link_state(&private, None, &state_names).unwrap();
    assert!(std::fs::symlink_metadata(&linked).is_err());
    // A state directory that does not exist yet is left for the CLI to make.
    std::fs::remove_dir(host.join(".lanectl")).unwrap();
    let (expected, capabilities) = state_grant(&host, &["state-dir-write"]);
    link_state(&private, Some(&expected), &capabilities).unwrap();
    assert!(std::fs::symlink_metadata(&linked).is_err());
    // Nor is a link in the directory's place followed.
    std::os::unix::fs::symlink(&host, host.join(".lanectl")).unwrap();
    link_state(&private, Some(&expected), &capabilities).unwrap();
    assert!(std::fs::symlink_metadata(&linked).is_err());
}

#[test]
fn the_newest_loopback_denial_replaces_an_older_cause() {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection
        .execute_batch(
            "create table local_cli_observation (cli_id text, identity_hash text, \
             surface text, first_blocked_cause text); \
             insert into local_cli_observation values \
             ('lanectl', 'h1', 'cli', null), \
             ('lanectl', 'h2', 'cli', 'exec_outside_roots'), \
             ('lanectl', 'h3', 'cli', 'write_home_state'), \
             ('lanectl', 'h4', 'mcp', null);",
        )
        .unwrap();
    for hash in ["h1", "h2", "h3", "h4"] {
        keep_loopback_cause(&connection, "lanectl", hash).unwrap();
    }
    let causes: Vec<Option<String>> = connection
        .prepare("select first_blocked_cause from local_cli_observation order by identity_hash")
        .unwrap()
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect();
    assert_eq!(
        causes,
        [
            Some("connect_loopback".to_owned()),
            Some("connect_loopback".to_owned()),
            Some("connect_loopback".to_owned()),
            None,
        ]
    );
}

#[test]
fn a_grant_with_local_network_access_records_nothing() {
    let fixture = Fixture::new("sink-grant-loopback");
    let request = sandboxed(&fixture);
    let with = json!({"cli_id": "c", "identity_hash": "h", "capabilities": ["loopback-network"]});
    assert!(LoopbackNote::new(&request, Some(&with)).grant.is_none());
    let without = json!({"cli_id": "c", "identity_hash": "h", "capabilities": []});
    assert_eq!(
        LoopbackNote::new(&request, Some(&without)).grant,
        Some(("c", "h"))
    );
    assert!(LoopbackNote::new(&request, None).grant.is_none());
}
