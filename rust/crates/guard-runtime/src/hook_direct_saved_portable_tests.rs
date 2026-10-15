use super::super::tests::{binding, local_store, sign_decision, ARTIFACT, SIGNED_AT, TOKEN};
use super::super::{saved_response, Context, HookDirectDefer, StoreShape};
use crate::project_identity::{resolve, PortableIdentity, PORTABLE_PROJECT_IDENTITY_PREFIX};
use rusqlite::{params, Connection};
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
fn a_portable_row_bound_elsewhere_defers() {
    let (home, connection) = store("portable-elsewhere");
    let checkout = directory("elsewhere", Some(REMOTE));
    let plain = directory("plain", None);
    decide(
        &connection,
        "workspace",
        Some(&identity_of(&checkout)),
        "block",
    );
    // A workspace with no identity reads no portable row.
    assert_eq!(
        status(&connection, &home, &plain),
        Err(HookDirectDefer::SavedDecision)
    );
    let other = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "f".repeat(64));
    decide(&connection, "workspace", Some(&other), "block");
    assert_eq!(
        status(&connection, &home, &checkout),
        Err(HookDirectDefer::SavedDecision)
    );
}

#[test]
fn an_identity_the_resident_does_not_resolve_exactly_defers() {
    let (home, connection) = store("portable-unknown");
    let checkout = directory("unknown", Some(REMOTE));
    let link = std::env::temp_dir().join(format!("hook-saved-link-{}", std::process::id()));
    let _ = std::fs::remove_file(&link);
    std::os::unix::fs::symlink(&checkout, &link).unwrap();
    // The daemon reads the link's own path; the resolver would follow it.
    let parent = std::fs::canonicalize(link.parent().unwrap()).unwrap();
    let link = parent.join(link.file_name().unwrap());
    let link = link.to_str().unwrap();
    assert_eq!(resolve(link), PortableIdentity::Unknown);
    assert_eq!(
        status(&connection, &home, link),
        Err(HookDirectDefer::SavedDecision)
    );
}
