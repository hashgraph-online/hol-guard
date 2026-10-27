use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlCommitV1};
use rusqlite::params;
use serde_json::{json, Value};

use super::layers::{layers_from_json, layers_to_json};
use super::records::{
    authenticated_record, private_hash, verify_record, SNAPSHOT_PURPOSE, TRANSITION_PURPOSE,
};
use super::tests::{anchor, catalog, local, run, Home, AT, KEY};
use crate::extension_control_proof::{mutation_digest, Mutation};

const LATER: &str = "2026-10-21T00:05:00+00:00";
const SOON: &str = "2026-10-21T00:04:59.999999+00:00";

fn view(health: &str, revision: i64) -> Value {
    json!({
        "health": health,
        "revision": revision,
        "catalog_digest": catalog('a'),
        "layers": [],
        "managed_revision": 0,
    })
}

/// `commit` with the digest its proof was granted for.
fn approved(mut commit: ExtensionControlCommitV1) -> ExtensionControlCommitV1 {
    let catalog = catalog('a');
    let layers = layers_from_json(&commit.layers_json).unwrap();
    commit.mutation_digest = mutation_digest(&Mutation {
        previous_revision: commit.expected_revision,
        catalog_digest: &catalog,
        layers: &layers,
        actor_id: &commit.actor_id,
        idempotency_key: &commit.idempotency_key,
        nonce: &commit.nonce,
    })
    .unwrap();
    commit
}

fn commit(revision: i64, expected_revision: i64) -> ExtensionControlCommitV1 {
    approved(ExtensionControlCommitV1 {
        actor_id: format!("actor-{revision}"),
        idempotency_key: format!("idem-{revision}"),
        nonce: format!("nonce-{revision}"),
        proof_id: format!("proof-{revision}"),
        mutation_digest: String::new(),
        layers_json: layers_to_json(&[local(&catalog('a'))]).unwrap(),
        expected_revision,
        pack_record_digest: None,
    })
}

fn commit_request(
    home: &Home,
    anchor_json: &str,
    current: Value,
    commit: ExtensionControlCommitV1,
) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json.to_owned()),
        view: Some(current),
        now: Some(LATER.to_owned()),
        commit: Some(commit),
        ..home.request("commit_plan", &catalog('a'))
    }
}

fn snapshot_digest(home: &Home, revision: i64) -> String {
    home.db
        .query_row(
            "select snapshot_digest from extension_control_authority_transition where revision = ?",
            params![revision],
            |row| row.get(0),
        )
        .unwrap()
}

fn refusal(result: &Value) -> &str {
    assert_eq!(result["fault"], json!("tampered"), "{result}");
    result["reason"].as_str().unwrap()
}

#[test]
fn commit_plan_seals_the_next_revision_on_the_committed_head() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let mut request = commit_request(&home, &head, view("protected", 1), commit(2, 1));
    request.commit.as_mut().unwrap().pack_record_digest = Some("p".repeat(64));
    let plan = &run(&request)["plan"];
    assert_eq!(plan["outcome"], json!("prepare"));
    assert_eq!(plan["revision"], json!(2));
    assert_eq!(plan["created_at"], json!(LATER));
    assert_eq!(plan["previous_digest"], json!(snapshot_digest(&home, 1)));
    assert_eq!(
        plan["hashes"]["nonce"],
        json!(private_hash("nonce-2", &KEY, "nonce"))
    );
    let sealed = |name: &str, purpose: &str| {
        let record = &plan[name];
        verify_record(
            record["json"].as_str().unwrap(),
            record["digest"].as_str().unwrap(),
            record["mac"].as_str().unwrap(),
            &KEY,
            purpose,
        )
        .unwrap()
    };
    let snapshot = sealed("snapshot", SNAPSHOT_PURPOSE);
    assert_eq!(snapshot["committed_at"], json!(LATER));
    assert_eq!(
        snapshot["command_pack_record_digest"],
        json!("p".repeat(64))
    );
    let transition = sealed("transition", TRANSITION_PURPOSE);
    assert_eq!(transition["snapshot_digest"], plan["snapshot"]["digest"]);
    assert_eq!(transition["phase"], json!("prepared"));
    assert_eq!(
        transition["idempotency_key_hash"],
        json!(private_hash("idem-2", &KEY, "idempotency"))
    );
}

#[test]
fn ordinary_control_writes_retain_the_bound_pack_without_a_new_activation() {
    let home = Home::new();
    let retained = "a".repeat(64);
    let head = home.commit_bound(
        1,
        &catalog('a'),
        &[local(&catalog('a'))],
        "committed",
        Some(&retained),
    );
    for replacement in [None, Some("b".repeat(64))] {
        let mut write = commit(2, 1);
        write.pack_record_digest = replacement.clone();
        let result = run(&commit_request(&home, &head, view("protected", 1), write));
        let plan = &result["plan"];
        assert_eq!(plan["outcome"], "prepare", "{result}");
        let payload = |name: &str, purpose: &str| {
            verify_record(
                plan[name]["json"].as_str().unwrap(),
                plan[name]["digest"].as_str().unwrap(),
                plan[name]["mac"].as_str().unwrap(),
                &KEY,
                purpose,
            )
            .unwrap()
        };
        let expected = replacement.as_ref().unwrap_or(&retained);
        assert_eq!(
            payload("snapshot", SNAPSHOT_PURPOSE)["command_pack_record_digest"],
            json!(expected)
        );
        assert_eq!(
            payload("transition", TRANSITION_PURPOSE)
                .get("command_pack_record_digest")
                .cloned(),
            replacement.map(Value::String)
        );
    }
}

#[test]
fn commit_plan_refuses_conflicts_and_replays() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let stale = run(&commit_request(
        &home,
        &head,
        view("protected", 1),
        commit(2, 0),
    ));
    assert_eq!(
        refusal(&stale),
        "extension control authority revision conflict"
    );
    let mut reused_nonce = commit(2, 1);
    reused_nonce.nonce = "nonce-1".to_owned();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 1),
            approved(reused_nonce)
        ))),
        "extension control authority nonce replay"
    );
    home.db
        .execute(
            "insert into extension_control_authority_proof values (?, ?, 1, ?, ?)",
            params![
                private_hash("proof-2", &KEY, "proof"),
                "m".repeat(64),
                AT,
                AT
            ],
        )
        .unwrap();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 1),
            commit(2, 1)
        ))),
        "extension control authority proof replay"
    );
    let unavailable = run(&commit_request(
        &home,
        &head,
        view("tampered", 0),
        commit(3, 0),
    ));
    assert_eq!(
        refusal(&unavailable),
        "extension control authority unavailable"
    );
}

#[test]
fn a_commit_a_read_finished_settles_its_grant_instead_of_being_refused_as_a_replay() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    // The call that prepared revision 2 sealed the anchor over it and died
    // before the row said so. A read met that sealed head and finished the
    // revision for it, leaving the grant the dead call reserved unspent.
    let head = home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    let granted = commit(2, 1);
    home.db
        .execute(
            "insert into extension_control_authority_proof values (?, ?, 2, ?, null)",
            params![
                private_hash("proof-2", &KEY, "proof"),
                &granted.mutation_digest,
                AT
            ],
        )
        .unwrap();

    // Its own retry settles the grant rather than being told it replayed a
    // commit that never returned to it.
    let settled = run(&commit_request(
        &home,
        &head,
        view("protected", 2),
        commit(2, 1),
    ));
    assert_eq!(settled["plan"]["outcome"], json!("finish"), "{settled}");
    assert_eq!(settled["plan"]["revision"], json!(2));
    assert_eq!(settled["plan"]["proof_recorded"], json!(true));

    // A grant already spent on that revision is the replay it always was.
    home.db
        .execute(
            "update extension_control_authority_proof set consumed_at = ?",
            params![AT],
        )
        .unwrap();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 2),
            commit(2, 1)
        ))),
        "extension control authority proof replay"
    );

    // An unspent grant that names another mutation never belonged to this
    // revision, whatever state the revision is in.
    home.db
        .execute(
            "update extension_control_authority_proof set mutation_digest = ?, consumed_at = null",
            params!["m".repeat(64)],
        )
        .unwrap();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 2),
            commit(2, 1)
        ))),
        "extension control authority proof state conflict"
    );
}

#[test]
fn commit_plan_seals_only_the_approved_mutation() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let mut other_layers = commit(2, 1);
    other_layers.layers_json = layers_to_json(&[]).unwrap();
    let mut other_revision = commit(2, 1);
    other_revision.expected_revision = 0;
    let mut other_nonce = commit(2, 1);
    other_nonce.nonce = "nonce-9".to_owned();
    let mut forged = commit(2, 1);
    forged.mutation_digest = "m".repeat(64);
    for changed in [other_layers, other_revision, other_nonce, forged] {
        assert_eq!(
            refusal(&run(&commit_request(
                &home,
                &head,
                view("protected", 1),
                changed
            ))),
            "extension control proof does not match mutation"
        );
    }
    let mut blank_actor = commit(2, 1);
    blank_actor.actor_id = " ".to_owned();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 1),
            blank_actor
        ))),
        "invalid extension control commit request"
    );
}

#[test]
fn commit_plan_rereads_once_before_giving_up_on_recovery() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let mut request = commit_request(&home, &head, view("recovery-required", 1), commit(2, 1));
    assert_eq!(run(&request)["plan"]["outcome"], json!("reread"));
    request.rollback_attempted = true;
    assert_eq!(
        refusal(&run(&request)),
        "extension control authority unavailable"
    );
}

#[test]
fn a_commit_waits_rather_than_take_another_requests_prepared_revision() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    // The read serves the committed view while that row waits, so the health
    // this request was handed says nothing about the revision above it. The
    // slot itself is what holds the commit back: a read that may roll the row
    // back runs first, and once one has, the row is a live transition this
    // request must not take.
    let mut request = commit_request(&home, &head, view("protected", 1), commit(3, 1));
    assert_eq!(run(&request)["plan"]["outcome"], json!("reread"));
    request.rollback_attempted = true;
    assert_eq!(
        refusal(&run(&request)),
        "extension control authority unavailable"
    );
}

#[test]
fn a_retry_resumes_its_own_prepared_transition() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    // The anchor never moved: the prepared row is discarded and retried.
    let abandoned = run(&commit_request(
        &home,
        &head,
        view("protected", 1),
        commit(2, 1),
    ));
    assert_eq!(abandoned["plan"]["outcome"], json!("abandon"));
    assert_eq!(abandoned["plan"]["proof_recorded"], json!(false));
    // The anchor moved to the prepared snapshot: the row is committed.
    let anchored = anchor(2, &snapshot_digest(&home, 2), "anchored");
    let resumed = run(&commit_request(
        &home,
        &anchored,
        view("recovery-required", 1),
        commit(2, 1),
    ));
    assert_eq!(resumed["plan"]["outcome"], json!("commit_pending"));
    assert_eq!(resumed["plan"]["revision"], json!(2));
    assert_eq!(resumed["plan"]["command_pack_record_digest"], Value::Null);
}

/// Reseals the prepared transition at `revision` so it binds `pack`.
fn bind_pack(home: &Home, revision: i64, pack: Value) {
    let text: String = home
        .db
        .query_row(
            "select transition_json from extension_control_authority_transition where revision = ?",
            params![revision],
            |row| row.get(0),
        )
        .unwrap();
    let Value::Object(mut transition) = serde_json::from_str(&text).unwrap() else {
        unreachable!("a sealed transition is an object");
    };
    transition.retain(|name, _| name != "authority_schema_version" && name != "purpose");
    transition.insert("command_pack_record_digest".to_owned(), pack);
    let (json, digest, mac) = authenticated_record(&transition, &KEY, TRANSITION_PURPOSE).unwrap();
    home.db
        .execute(
            "update extension_control_authority_transition \
             set transition_json = ?, transition_digest = ?, transition_mac = ? where revision = ?",
            params![json, digest, mac, revision],
        )
        .unwrap();
}

#[test]
fn resume_plan_names_the_pack_record_the_authenticated_transition_binds() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    let request = || ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor(2, &snapshot_digest(&home, 2), "anchored")),
        revision: Some(2),
        ..home.request("resume_plan", &catalog('a'))
    };
    bind_pack(&home, 2, json!("p".repeat(64)));
    let plan = &run(&request())["plan"];
    assert_eq!(plan["outcome"], json!("commit_pending"));
    assert_eq!(plan["command_pack_record_digest"], json!("p".repeat(64)));
    bind_pack(&home, 2, json!(7));
    assert_eq!(
        refusal(&run(&request())),
        "idempotent transition authentication mismatch"
    );
}

#[test]
fn a_retry_with_another_request_under_the_same_key_is_refused() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    let mut other = commit(2, 1);
    other.actor_id = "someone-else".to_owned();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 1),
            approved(other)
        ))),
        "idempotency key request mismatch"
    );
}

#[test]
fn a_recorded_proof_for_a_committed_transition_is_a_replay() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    let head = home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    // The grant names this request's own mutation and was spent on the
    // revision that is now committed, so asking again is a second use of a
    // commit that already returned.
    let granted = commit(2, 1);
    home.db
        .execute(
            "insert into extension_control_authority_proof values (?, ?, 2, ?, ?)",
            params![
                private_hash("proof-2", &KEY, "proof"),
                &granted.mutation_digest,
                AT,
                AT
            ],
        )
        .unwrap();
    assert_eq!(
        refusal(&run(&commit_request(
            &home,
            &head,
            view("protected", 2),
            commit(2, 1)
        ))),
        "extension control authority proof replay"
    );
}

fn rollback_request(
    home: &Home,
    anchor_json: &str,
    now: &str,
) -> ExtensionControlAuthorityRequestV1 {
    ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json.to_owned()),
        revision: Some(1),
        snapshot_digest: Some(snapshot_digest(home, 1)),
        now: Some(now.to_owned()),
        ..home.request("rollback_plan", &catalog('a'))
    }
}

#[test]
fn rollback_abandons_only_a_stale_unanchored_prepared_row() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    assert_eq!(
        run(&rollback_request(&home, &head, SOON))["plan"]["outcome"],
        json!("keep")
    );
    let stale = run(&rollback_request(&home, &head, LATER));
    assert_eq!(stale["plan"]["outcome"], json!("abandon"));
    assert_eq!(stale["plan"]["revision"], json!(2));
    let moved = anchor(1, &snapshot_digest(&home, 1), "anchored");
    assert_eq!(
        run(&rollback_request(&home, &moved, LATER))["plan"]["outcome"],
        json!("keep")
    );
}

/// A commit that failed before anchoring its own prepared row names it, so
/// the row goes at once instead of refusing every save for the retry window.
#[test]
fn rollback_abandons_the_callers_own_failed_row_without_waiting() {
    let home = Home::new();
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "prepared");
    let own: String = home
        .db
        .query_row(
            "select transition_digest from extension_control_authority_transition where revision = 2",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let outcome = |digest: &str, pin: &str| {
        run(&ExtensionControlAuthorityRequestV1 {
            own_transition_digest: Some(digest.to_owned()),
            ..rollback_request(&home, pin, SOON)
        })["plan"]["outcome"]
            .clone()
    };
    assert_eq!(outcome(own.as_str(), head.as_str()), json!("abandon"));
    // Another request's row is still kept for its own retry.
    assert_eq!(
        outcome("0".repeat(64).as_str(), head.as_str()),
        json!("keep")
    );
    // Naming the row never abandons one the anchor already moved onto.
    let moved = anchor(1, &snapshot_digest(&home, 1), "anchored");
    assert_eq!(outcome(own.as_str(), moved.as_str()), json!("keep"));
}

#[test]
fn resume_plan_finishes_a_committed_row_whose_final_anchor_was_lost() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[local(&catalog('a'))], "committed");
    let request = |revision: i64, anchor_json: String| ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(anchor_json),
        revision: Some(revision),
        ..home.request("resume_plan", &catalog('a'))
    };
    let anchored = anchor(2, &snapshot_digest(&home, 2), "anchored");
    assert_eq!(
        run(&request(2, anchored.clone()))["plan"]["outcome"],
        json!("finish")
    );
    assert_eq!(
        run(&request(3, anchored))["plan"]["outcome"],
        json!("absent")
    );
}

#[test]
fn history_lists_prior_committed_snapshots_newest_first() {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.commit(2, &catalog('a'), &[], "committed");
    let head = home.commit(3, &catalog('a'), &[local(&catalog('a'))], "committed");
    let request = |limit: i64| ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(head.clone()),
        view: Some(view("protected", 3)),
        limit: Some(limit),
        ..home.request("history", &catalog('a'))
    };
    let result = run(&request(20));
    let history = result["history"].clone();
    assert_eq!(history.as_array().map(Vec::len), Some(2), "{result}");
    assert_eq!(history[0]["revision"], json!(2));
    assert_eq!(history[0]["layers"], json!([]));
    assert_eq!(history[1]["revision"], json!(1));
    assert_eq!(history[1]["occurred_at"], json!(AT));
    assert_eq!(run(&request(1))["history"].as_array().unwrap().len(), 1);
    assert_eq!(
        refusal(&run(&request(51))),
        "invalid extension control history limit"
    );
}
