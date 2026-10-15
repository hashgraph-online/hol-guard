//! The memo answers exactly what a fresh evaluation answers, and only for
//! the subject it was made for.

use std::sync::atomic::{AtomicUsize, Ordering};

use guard_contracts::{
    LocalMcpServerMaterialV1, McpExtensionInputV1, McpToolPolicyObservationV1,
    McpToolPolicySubjectV1,
};
use serde_json::{json, Value};

use super::super::{evaluate_current, evaluate_pass, Ctx, Pass, Phase, Stop};
use super::{current, extension, PassMemo};
use crate::mcp_tool_policy_extension::extension_decision;

const VECTORS: &str =
    include_str!("../../../../tests/fixtures/mcp_tool_policy/parity_vectors.json");

static COUNTER: AtomicUsize = AtomicUsize::new(0);

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("parity vectors parse")
}

fn subject_of(doc: &Value, vector: &Value) -> McpToolPolicySubjectV1 {
    let key = vector["subject"].as_str().expect("subject key");
    serde_json::from_value(doc["subjects"][key].clone()).expect("subject parses")
}

/// A pass outcome in a comparable form.
fn outcome(pass: Result<Pass, Stop>) -> Value {
    match pass {
        Ok(Pass::Final(decision)) => json!({"final": decision.to_value()}),
        Ok(Pass::Claimed { row, .. }) => json!({"claimed": row}),
        Err(Stop::Need(need)) => json!({"need": need}),
        Err(Stop::Fail(code)) => json!({"fail": code}),
    }
}

fn pass(
    subject: &McpToolPolicySubjectV1,
    observations: &[McpToolPolicyObservationV1],
    memo: Option<&PassMemo<'_>>,
    claim: bool,
) -> Value {
    let ctx = Ctx {
        observations,
        lookup: None,
        memo,
    };
    outcome(evaluate_pass(&ctx, subject, Phase::Initial, claim))
}

#[test]
fn every_round_with_one_memo_matches_a_fresh_pass() {
    let doc = vectors();
    for vector in doc["vectors"].as_array().expect("vectors") {
        let name = vector["name"].as_str().unwrap_or("?");
        let subject = subject_of(&doc, vector);
        let claim = vector["claim_saved_approval"].as_bool().expect("claim");
        let observed: Vec<McpToolPolicyObservationV1> = vector["observations"]
            .as_array()
            .expect("observations")
            .iter()
            .map(|item| McpToolPolicyObservationV1 {
                need: item["need"].clone(),
                result: item["result"].clone(),
            })
            .collect();
        // One memo across every round, as the relay replays them.
        let memo = PassMemo::new(&subject);
        for index in 0..=observed.len() {
            let prefix = &observed[..index];
            assert_eq!(
                pass(&subject, prefix, Some(&memo), claim),
                pass(&subject, prefix, None, claim),
                "{name} round {index}"
            );
        }
    }
}

#[test]
fn a_memo_never_answers_for_another_subject() {
    let doc = vectors();
    let all = doc["vectors"].as_array().expect("vectors");
    let first = subject_of(&doc, &all[0]);
    let memo = PassMemo::new(&first);
    assert!(current(Some(&memo), &first).is_ok());
    // An equal copy, and one under a different config, evaluate afresh.
    let copy = first.clone();
    assert!(!memo.covers(&copy));
    let differs = all
        .iter()
        .map(|vector| subject_of(&doc, vector))
        .find(|other| {
            let (Ok(mine), Ok(theirs)) = (evaluate_current(&first), evaluate_current(other)) else {
                return false;
            };
            format!("{mine:?}") != format!("{theirs:?}")
        })
        .expect("a subject with another recommendation");
    assert_eq!(
        format!("{:?}", current(Some(&memo), &differs).map_err(|_| ())),
        format!("{:?}", evaluate_current(&differs).map_err(|_| ())),
    );
}

fn input(home: &std::path::Path) -> McpExtensionInputV1 {
    McpExtensionInputV1 {
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        harness: "codex".to_owned(),
        tool_name: "read_file".to_owned(),
        server: LocalMcpServerMaterialV1 {
            identity_hash: Some("a".repeat(64)),
            transport: Some("stdio".to_owned()),
            ..LocalMcpServerMaterialV1::default()
        },
        connection_identity_hash: None,
        tool_authority_hash: None,
        launcher_path: None,
        launcher_home: None,
        local_unavailable: false,
        server_identity: None,
        artifact_transport: None,
        server_name: None,
        contributed_tool_name: None,
        layers: Vec::new(),
        layers_unavailable: false,
    }
}

#[test]
fn the_extension_decision_is_read_once_per_memo() {
    let home = std::env::temp_dir().join(format!(
        "hol-guard-mcp-memo-{}-{}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    ));
    std::fs::create_dir_all(&home).unwrap();
    let home = home.canonicalize().unwrap();
    // A damaged schema marker with a grant row: the device's grants cannot
    // be verified, so an allowed call is held in review.
    let store = rusqlite::Connection::open(home.join("guard.db")).unwrap();
    store
        .execute_batch(
            "create table local_cli_grant (cli_id text);
             create table local_cli_schema_migration (singleton integer, version integer, checksum text);
             insert into local_cli_schema_migration values (1, 11, 'tampered');
             insert into local_cli_grant values ('one');",
        )
        .unwrap();
    drop(store);
    let doc = vectors();
    let mut subject = subject_of(&doc, &doc["vectors"][0]);
    subject.extension = Some(input(&home));
    let own = subject.extension.as_ref().expect("extension");
    let memo = PassMemo::new(&subject);
    let mut pinned = Vec::new();
    for action in ["allow", "review", "block"] {
        let answer = extension(Some(&memo), &subject, own, action);
        assert_eq!(answer, extension_decision(own, action), "{action}");
        pinned.push(answer);
    }
    // A store change within the call does not reach the memo; a new call
    // reads the store again.
    std::fs::remove_file(home.join("guard.db")).unwrap();
    for (action, answer) in ["allow", "review", "block"].iter().zip(&pinned) {
        assert_eq!(&extension(Some(&memo), &subject, own, action), answer);
        let fresh = PassMemo::new(&subject);
        assert_eq!(
            extension(Some(&fresh), &subject, own, action),
            extension_decision(own, action)
        );
    }
    // Another extension input is never answered from the memo.
    let other = input(&home);
    assert_eq!(
        extension(Some(&memo), &subject, &other, "allow"),
        extension_decision(&other, "allow")
    );
}
