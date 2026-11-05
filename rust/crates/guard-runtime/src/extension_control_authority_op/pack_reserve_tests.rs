//! Pins the pack half of `commit_prepare`: the staged activation reserved
//! with the prepared row and installed by `resume`, and a draft refused by
//! name with nothing written when it does not match the protected floor, does
//! not extend the active slot or does not authenticate.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    ExtensionControlAuthorityRequestV1, ExtensionControlPackFinishV1, ExtensionControlPackReserveV1,
};
use serde_json::{json, Value};

use super::super::pack_finish::tests::{activation, floor, pack_tables, seal};
use super::super::plans_tests::{commit, view, LATER};
use super::super::tests::{anchor, catalog, local, run, with_cloud_events, Home, KEY};

struct Staged {
    home: Home,
    head: String,
    reserve: ExtensionControlPackReserveV1,
}

/// Revision 1 committed over a retained baseline, and an activation staged to
/// move the floor from 3.55.1 to 3.56.0.
fn staged() -> Staged {
    let home = with_cloud_events(Home::new());
    let head = home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    pack_tables(&home);
    let record = seal("activation", activation());
    let before = floor("3.55.1");
    let reserve = ExtensionControlPackReserveV1 {
        key_b64: Base64UrlUnpadded::encode_string(&KEY),
        floor: Some(before.clone()),
        record_json: record["record"].as_str().unwrap().to_owned(),
        record_digest: record["digest"].as_str().unwrap().to_owned(),
        record_mac: record["mac"].as_str().unwrap().to_owned(),
        lifecycle_before: before,
        lifecycle_after: floor("3.56.0"),
        admitted_at: 1500,
        ..ExtensionControlPackReserveV1::default()
    };
    Staged {
        home,
        head,
        reserve,
    }
}

fn prepare(staged: &Staged, reserve: ExtensionControlPackReserveV1) -> Value {
    let mut commit = commit(2, 1);
    commit.pack_record_digest = Some(staged.reserve.record_digest.clone());
    run(&ExtensionControlAuthorityRequestV1 {
        anchor_json: Some(staged.head.clone()),
        view: Some(view("protected", 1)),
        now: Some(LATER.to_owned()),
        commit: Some(commit),
        pack_reserve: Some(reserve),
        ..staged.home.request("commit_prepare", &catalog('a'))
    })
}

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

/// Nothing the refused commit would have written is left behind.
fn assert_unwritten(home: &Home) {
    for table in [
        "extension_control_authority_transition where revision = 2",
        "extension_control_authority_proof",
        "extension_command_pack_pending",
    ] {
        assert_eq!(
            count(home, &format!("select count(*) from {table}")),
            0,
            "{table}"
        );
    }
}

#[test]
fn commit_prepare_reserves_the_staged_activation_that_resume_installs() {
    let staged = staged();
    let reply = prepare(&staged, staged.reserve.clone());
    let plan = &reply["plan"];
    assert_eq!(plan["prepared"], json!(true), "{reply}");
    assert_eq!(
        count(
            &staged.home,
            "select count(*) from extension_command_pack_pending where control_revision = 2"
        ),
        1
    );
    let snapshot = plan["snapshot"]["digest"].as_str().unwrap();
    let resume = |floor: &str| {
        run(&ExtensionControlAuthorityRequestV1 {
            anchor_json: Some(anchor(2, snapshot, "anchored")),
            revision: Some(2),
            now: Some(LATER.to_owned()),
            proof_hash: plan["hashes"]["proof"].as_str().map(str::to_owned),
            pack_finish: Some(ExtensionControlPackFinishV1 {
                key_b64: staged.reserve.key_b64.clone(),
                floor: Some(floor.to_owned()),
                ..ExtensionControlPackFinishV1::default()
            }),
            ..staged.home.request("resume", &catalog('a'))
        })
    };
    let owed = resume(&staged.reserve.lifecycle_before);
    assert_eq!(
        owed["pack_floor_owed"]["after"],
        json!(staged.reserve.lifecycle_after),
        "{owed}"
    );
    let finished = resume(&staged.reserve.lifecycle_after);
    assert_eq!(finished["resumed"]["revision"], json!(2), "{finished}");
    let installed: String = staged
        .home
        .db
        .query_row(
            "select record_digest from extension_command_pack_activation where revision = 1",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(installed, staged.reserve.record_digest);
}

#[test]
fn commit_prepare_refuses_a_floor_the_activation_was_not_staged_against() {
    let staged = staged();
    let reserve = ExtensionControlPackReserveV1 {
        floor: Some(floor("3.57.0")),
        ..staged.reserve.clone()
    };
    let refused = prepare(&staged, reserve);
    assert_eq!(refused["fault"], json!("pack"), "{refused}");
    assert_eq!(
        refused["reason"],
        json!("pack_lifecycle_prepared_floor_conflict")
    );
    assert_unwritten(&staged.home);
}

#[test]
fn commit_prepare_refuses_an_activation_that_does_not_extend_the_active_slot() {
    let staged = staged();
    let reserve = ExtensionControlPackReserveV1 {
        previous_digest: Some("9".repeat(64)),
        ..staged.reserve.clone()
    };
    let refused = prepare(&staged, reserve);
    assert_eq!(refused["fault"], json!("pack"), "{refused}");
    assert_eq!(
        refused["reason"],
        json!("native_command_pack_activation_conflict")
    );
    assert_unwritten(&staged.home);
}

#[test]
fn commit_prepare_refuses_a_draft_that_does_not_authenticate_by_name() {
    let staged = staged();
    let reserve = ExtensionControlPackReserveV1 {
        record_mac: "0".repeat(64),
        ..staged.reserve.clone()
    };
    let refused = prepare(&staged, reserve);
    assert_eq!(refused["fault"], json!("pack"), "{refused}");
    assert_unwritten(&staged.home);
}
