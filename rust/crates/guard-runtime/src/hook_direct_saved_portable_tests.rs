use super::super::tests::{
    binding, local_store, sign_decision, ARTIFACT, SIGNED_AT, TOKEN, VALIDATED_BUNDLE,
};
use super::super::{saved_response, Context, HookDirectDefer, StoreShape};
use crate::project_identity::{resolve, PortableIdentity, PORTABLE_PROJECT_IDENTITY_PREFIX};
use rusqlite::{params, Connection, OpenFlags};
use serde_json::{json, Map, Value};

const REMOTE: &str = "https://github.com/example/hook.git";

/// A fresh canonical directory, a Git checkout cloned from `remote` when
/// one is named.
fn directory(tag: &str, remote: Option<&str>) -> String {
    let path = std::env::temp_dir().join(format!("hook-saved-ws-{}-{tag}", std::process::id()));
    let _ = std::fs::remove_dir_all(&path);
    std::fs::create_dir_all(&path).unwrap();
    if let Some(remote) = remote {
        let git = path.join(".git");
        std::fs::create_dir_all(git.join("logs")).unwrap();
        let config = format!("[remote \"origin\"]\n\turl = {remote}\n");
        std::fs::write(git.join("config"), config).unwrap();
        let zeros = "0".repeat(40);
        let head = "1".repeat(40);
        let log = format!("{zeros} {head} G <g@example.invalid> 1 +0000\tclone: from {remote}\n");
        std::fs::write(git.join("logs/HEAD"), log).unwrap();
    }
    let path = std::fs::canonicalize(&path).unwrap();
    path.to_str().unwrap().to_owned()
}

fn identity_of(workspace: &str) -> String {
    let PortableIdentity::Identity(identity) = resolve(workspace) else {
        panic!("the checkout resolves");
    };
    identity
}

/// A signed decision for the artifact, bound to `workspace` under `scope`.
fn decide(connection: &Connection, scope: &str, workspace: Option<&str>, action: &str) {
    connection
        .execute(
            "insert into policy_decisions (harness, scope, artifact_id, action, artifact_hash,
               workspace, source, created_at, updated_at)
             values ('claude-code', ?1, ?2, ?3, ?4, ?5, 'approval-gate', ?6, ?6)",
            params![scope, ARTIFACT, action, TOKEN, workspace, SIGNED_AT],
        )
        .unwrap();
    sign_decision(connection, connection.last_insert_rowid());
}

/// The daemon's saved response for the overridable review in `workspace`:
/// its reuse status, `None` when the review stands.
fn status(
    connection: &Connection,
    guard_home: &str,
    workspace: &str,
) -> Result<Option<Value>, HookDirectDefer> {
    let payload = Map::new();
    let binding = binding();
    let context = Context {
        harness: "claude-code",
        payload: &payload,
        recorded_payload: &payload,
        workspace,
        home_dir: "/home/user",
        guard_home,
        binding: &binding,
        hint: None,
    };
    let store = StoreShape {
        connection,
        harness: "claude-code",
        artifact_id: ARTIFACT,
    };
    let result = json!({
        "decision": "review",
        "policy_action": "review",
        "minimum_action": "review",
    });
    let result = result.as_object().unwrap();
    saved_response(&context, &store, result, TOKEN)
        .map(|response| response.map(|response| response["approval_reuse_status"].clone()))
}

fn store(tag: &str) -> (String, Connection) {
    let (path, connection) = local_store(tag);
    let guard_home = path.parent().unwrap().to_str().unwrap().to_owned();
    decide(&connection, "artifact", None, "allow");
    (guard_home, connection)
}

#[test]
fn a_portable_block_outranks_the_saved_allow_in_its_checkout() {
    let (home, connection) = store("portable-block");
    let checkout = directory("block", Some(REMOTE));
    let identity = identity_of(&checkout);
    assert_eq!(
        status(&connection, &home, &checkout),
        Ok(Some(json!("accepted")))
    );
    decide(&connection, "workspace", Some(&identity), "block");
    // The daemon composes the identity's block over the local allow, so the
    // workspace decision answers and the review stands.
    assert_eq!(status(&connection, &home, &checkout), Ok(None));
}

#[test]
fn a_portable_row_bound_elsewhere_is_read_by_no_lookup_of_this_workspace() {
    let (home, connection) = store("portable-elsewhere");
    let checkout = directory("elsewhere", Some(REMOTE));
    let plain = directory("plain", None);
    decide(
        &connection,
        "workspace",
        Some(&identity_of(&checkout)),
        "block",
    );
    // Every workspace selector the lookup binds is the probe's own, so a
    // workspace with no identity of its own reads none of the checkout's
    // rows and the local allow still answers.
    assert_eq!(
        status(&connection, &home, &plain),
        Ok(Some(json!("accepted")))
    );
    // A row under a third project's identity changes neither answer.
    let other = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "f".repeat(64));
    decide(&connection, "workspace", Some(&other), "block");
    assert_eq!(status(&connection, &home, &checkout), Ok(None));
    assert_eq!(
        status(&connection, &home, &plain),
        Ok(Some(json!("accepted")))
    );
}

#[test]
fn a_workspace_that_already_names_an_identity_reads_that_identity_alone() {
    let (home, connection) = store("portable-named");
    let identity = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "a".repeat(64));
    // `_portable_project_workspace` answers such a workspace with itself, so
    // the identity's own lookup is the whole composition and no local
    // authority is read beside it. The saved allow is a portable permission
    // the daemon strips, so the review stands instead of being reused.
    assert_eq!(status(&connection, &home, &identity), Ok(None));
    // The same workspace spelled with surrounding space is the same
    // identity: `_portable_project_workspace` strips before it compares.
    let padded = format!("  {identity}  ");
    assert_eq!(status(&connection, &home, &padded), Ok(None));
}

#[test]
fn a_local_row_an_identity_named_workspace_never_reads_does_not_stop_it() {
    let (path, connection) = local_store("portable-named-readonly");
    let home = path.parent().unwrap().to_str().unwrap().to_owned();
    decide(&connection, "artifact", None, "allow");
    let identity = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "b".repeat(64));
    let padded = format!("  {identity}  ");
    // An unsigned row only the local lookup of the padded workspace matches.
    // Reading it records an integrity audit event, which this store cannot
    // take, so running that lookup at all would stop the call.
    connection
        .execute(
            "insert into policy_decisions (harness, scope, artifact_id, action, artifact_hash,
               workspace, source, created_at, updated_at)
             values ('claude-code', 'workspace', ?1, 'allow', ?2, ?3, 'approval-gate', ?4, ?4)",
            params![ARTIFACT, TOKEN, padded, SIGNED_AT],
        )
        .unwrap();
    drop(connection);
    let readable = Connection::open_with_flags(&path, OpenFlags::SQLITE_OPEN_READ_ONLY).unwrap();
    assert_eq!(status(&readable, &home, &padded), Ok(None));
}

#[test]
fn an_identity_the_resident_does_not_resolve_exactly_defers() {
    let (home, connection) = store("portable-unknown");
    // `expanduser` rewrites a `~` name against the asking process's
    // environment, which the resident does not read, so the workspace
    // settles to no identity at all rather than to none being there, and the
    // saved lookup defers instead of composing a portable decision.
    let unresolved = "~/not-here";
    assert_eq!(resolve(unresolved), PortableIdentity::Unknown);
    assert_eq!(
        status(&connection, &home, unresolved),
        Err(HookDirectDefer::SavedDecision)
    );

    // A workspace under a directory that is not there is a different case:
    // `resolve(strict=False)` appends the names that do not exist to the
    // part that does, so it is read under the checkout above it.
    let checkout = directory("unknown", Some(REMOTE));
    assert!(matches!(
        resolve(&format!("{checkout}/not-here")),
        PortableIdentity::Identity(_)
    ));
}

/// The daemon's saved response in `workspace` while the validated bundle
/// carries the Cloud rule that blocks the artifact and `exceptions`.
fn status_under_bundle(
    connection: &Connection,
    guard_home: &str,
    workspace: &str,
    exceptions: Value,
) -> Result<Option<Value>, HookDirectDefer> {
    let rule = json!([
        "claude-code",
        "artifact",
        ARTIFACT,
        null,
        null,
        null,
        "block",
        "managed",
        "pkg-block",
        "policy-bundle",
        null
    ]);
    let bundle = json!({ "workspaceId": "workspace-1", "cloudExceptions": exceptions });
    let authority = (
        vec![rule.as_array().unwrap().clone()],
        bundle.as_object().cloned(),
    );
    VALIDATED_BUNDLE.with(|cell| *cell.borrow_mut() = Some(authority));
    let answered = status(connection, guard_home, workspace);
    VALIDATED_BUNDLE.with(|cell| *cell.borrow_mut() = None);
    answered
}

#[test]
fn a_cloud_exception_for_the_checkout_lifts_the_cloud_block_from_its_portable_lookup_too() {
    checkout_exception_lifts_the_cloud_block("policy-bundle");
}

/// A v2 bundle compiles to canonical rows and materializes no identities; its
/// exception still lifts them in the hook's own lookup.
#[test]
fn a_cloud_exception_lifts_a_v2_canonical_block_in_the_hook() {
    checkout_exception_lifts_the_cloud_block("policy-bundle-canonical");
}

fn checkout_exception_lifts_the_cloud_block(source: &str) {
    let (home, connection) = store(&format!("portable-exception-{source}"));
    let checkout = directory(&format!("exception-{source}"), Some(REMOTE));
    connection
        .execute(
            "insert into policy_decisions (harness, scope, artifact_id, action, reason, owner,
               source, created_at, updated_at)
             values ('claude-code', 'artifact', ?1, 'block', 'managed', 'pkg-block',
               ?3, ?2, ?2)",
            params![ARTIFACT, SIGNED_AT, source],
        )
        .unwrap();
    sign_decision(&connection, connection.last_insert_rowid());
    // The Cloud block outranks the saved allow, so the review stands.
    assert_eq!(
        status_under_bundle(&connection, &home, &checkout, json!([])),
        Ok(None)
    );
    // An exception approved for this checkout's working directory lifts the
    // Cloud block from both the local lookup and the lookup under the
    // checkout's portable identity, so the saved allow answers. Lifting the
    // portable lookup against the identity instead would keep the block
    // there, and the composition would keep the review standing.
    let exception = json!([{
        "exceptionId": "exception-checkout",
        "scope": "artifact",
        "harness": "claude-code",
        "artifactId": ARTIFACT,
        "workingDirectory": checkout,
        "owner": "owner@example.test",
        "expiresAt": "2099-01-01T00:00:00+00:00",
    }]);
    assert_eq!(
        status_under_bundle(&connection, &home, &checkout, exception),
        Ok(Some(json!("accepted")))
    );
}
