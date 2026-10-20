//! The portable Git identity the relay's saved lookups compose with
//! (`mcp_relay_decide_saved.rs`), over real Git checkouts.

use super::*;
use crate::policy_decision_lookup_op::workspace_policy_key;
use crate::project_identity::PORTABLE_PROJECT_IDENTITY_PREFIX;

/// A fresh canonical directory, a Git checkout cloned from `remote` when
/// one is named.
fn directory(tag: &str, remote: Option<&str>) -> String {
    let path = std::env::temp_dir().join(format!("mcp-relay-ws-{}-{tag}", std::process::id()));
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

#[test]
fn a_workspace_row_bound_elsewhere_answers_as_a_miss() {
    let (home, connection) = guard_home("elsewhere");
    let workspace = directory("elsewhere", None);
    let other = workspace_policy_key(Some("/elsewhere")).unwrap();
    decide(
        &connection,
        "workspace",
        "block",
        Some(&other),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&workspace))),
            saved.answer(&policy_need(ARTIFACT, None)).is_ok(),
        )
    })
    .unwrap();
    // Every workspace selector the lookup binds is the probe's own, so
    // another workspace's row is read by neither lookup.
    assert_eq!(answers.0.unwrap()["decision"], Value::Null);
    assert!(answers.1);
}

#[test]
fn a_confined_workspace_row_answers_a_workspace_lookup() {
    let (home, connection) = guard_home("confined");
    let workspace = directory("confined", None);
    let key = workspace_policy_key(Some(&workspace)).unwrap();
    decide(
        &connection,
        "workspace",
        "block",
        Some(&key),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&workspace))),
            // A workspace whose identity is not resolved exactly defers.
            saved.answer(&policy_need(ARTIFACT, Some("relative/work"))),
        )
    })
    .unwrap();
    assert_eq!(answers.0.unwrap()["decision"]["action"], "block");
    assert_eq!(answers.1, Err(SAVED_PORTABLE));
}

#[test]
fn a_portable_row_answers_only_the_workspace_resolving_to_it() {
    let (home, connection) = guard_home("portable");
    let repository = directory("repository", Some("https://github.com/example/relay.git"));
    let plain = directory("plain", None);
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "block",
        Some(&identity),
        "approval-gate",
    );
    let grant = json!({"kind": "grant_lookup", "harness": HARNESS, "selector": ARTIFACT});
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&repository))),
            saved.answer(&policy_need(ARTIFACT, Some(&plain))),
            saved.answer(&policy_need(ARTIFACT, None)),
            saved.answer(&grant),
        )
    })
    .unwrap();
    // The portable block outranks the local miss, as the proxy composes it.
    assert_eq!(answers.0.unwrap()["decision"]["action"], "block");
    // Every other lookup binds its own workspace selectors, so none of them
    // reads the row and each answers as a miss.
    assert_eq!(answers.1.unwrap()["decision"], Value::Null);
    assert_eq!(answers.2.unwrap()["decision"], Value::Null);
    assert_eq!(answers.3.unwrap()["decision"], Value::Null);
    // A row under another project's identity leaves the checkout's own
    // answer as it was.
    let other = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "f".repeat(64));
    decide(
        &connection,
        "workspace",
        "block",
        Some(&other),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&repository))),
            saved.answer(&policy_need(ARTIFACT, Some(&plain))),
        )
    })
    .unwrap();
    assert_eq!(answers.0.unwrap()["decision"]["action"], "block");
    assert_eq!(answers.1.unwrap()["decision"], Value::Null);
}

/// `_portable_project_workspace` answers a workspace that already names a
/// portable identity with itself, and
/// `resolve_policy_decision_lookup` then returns that identity's
/// restrictive-only lookup alone, with no local authority beside it.
#[test]
fn a_workspace_that_already_names_an_identity_reads_that_identity_alone() {
    let (home, connection) = guard_home("portable-named");
    let identity = format!("{PORTABLE_PROJECT_IDENTITY_PREFIX}{}", "a".repeat(64));
    decide(
        &connection,
        "workspace",
        "allow",
        Some(&identity),
        "approval-gate",
    );
    let answers = read(&home, &binding(), |saved| {
        let saved = saved.expect("saved rows");
        (
            saved.answer(&policy_need(ARTIFACT, Some(&identity))),
            saved.answer(&policy_need(ARTIFACT, Some(&format!("  {identity}  ")))),
        )
    })
    .unwrap();
    // The identity's own allow is a portable permission, which never lowers
    // enforcement, and no local lookup carries it either.
    assert_eq!(answers.0.unwrap()["decision"], Value::Null);
    // The same identity, spelled with the space Python strips first.
    assert_eq!(answers.1.unwrap()["decision"], Value::Null);
}

/// The claim's fresh resolve (`after_claim`) reads saved lookups through
/// `store::saved` on the claim's write transaction, query-only, so a
/// portable block saved after the decision outranks the claimed local allow
/// there, and `postclaim` answers the fresh block instead of forwarding.
#[test]
fn a_portable_block_saved_before_the_claim_outranks_the_claimed_allow() {
    let (home, connection) = guard_home("claim");
    let repository = directory("claim", Some("https://github.com/example/claim.git"));
    let key = workspace_policy_key(Some(&repository)).unwrap();
    decide(
        &connection,
        "workspace",
        "allow",
        Some(&key),
        "approval-gate",
    );
    let need = policy_need(ARTIFACT, Some(&repository));
    let decided = read(&home, &binding(), |saved| {
        saved.expect("saved rows").answer(&need)
    });
    assert_eq!(decided.unwrap().unwrap()["decision"]["action"], "allow");
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "block",
        Some(&identity),
        "approval-gate",
    );
    let claim = Connection::open(home.join(crate::local_store_read::STORE_FILE_NAME)).unwrap();
    let transaction = claim.unchecked_transaction().unwrap();
    claim.execute_batch("PRAGMA query_only = ON").unwrap();
    let saved = store::saved(&claim, &binding(), home.to_str().unwrap(), HARNESS)
        .unwrap()
        .expect("saved rows");
    let fresh = saved.answer(&need).unwrap();
    assert_eq!(fresh["decision"]["action"], "block");
    drop(saved);
    drop(transaction);
}

#[test]
fn a_portable_allow_never_lowers_enforcement() {
    let (home, connection) = guard_home("portable-allow");
    let repository = directory("allow", Some("git@github.com:example/allow.git"));
    let crate::project_identity::PortableIdentity::Identity(identity) =
        crate::project_identity::resolve(&repository)
    else {
        panic!("the checkout resolves");
    };
    decide(
        &connection,
        "workspace",
        "allow",
        Some(&identity),
        "approval-gate",
    );
    let policy = read(&home, &binding(), |saved| {
        saved
            .expect("saved rows")
            .answer(&policy_need(ARTIFACT, Some(&repository)))
    })
    .unwrap()
    .unwrap();
    assert_eq!(policy["decision"], Value::Null);
}
