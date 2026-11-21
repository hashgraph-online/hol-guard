//! Pins `clear_policy`: the plan names the epoch the clear moves to and
//! writes nothing, the clear lands only on the state the plan read, and a
//! clear that names a key it may not write is refused.

use std::collections::BTreeMap;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlPolicyClearV1};
use serde_json::{json, Value};

use super::super::managed_seals_tests::input;
use super::super::tests::{catalog, local, run, Home};

const NOW: &str = "2026-10-21T00:05:00+00:00";

/// Revision 1 committed, managed epoch 5 active, one remote and one local
/// decision, and a stored acknowledgement.
fn managed() -> Home {
    let home = Home::new();
    home.commit(1, &catalog('a'), &[local(&catalog('a'))], "committed");
    home.db
        .execute_batch(
            "drop table sync_state;
             create table sync_state (
                state_key text primary key, payload_json text not null, updated_at text not null);
             create table policy_decisions (artifact_id text not null, source text not null);
             insert into policy_decisions values ('remote', 'policy-bundle'), ('mine', 'local');",
        )
        .unwrap();
    let activation = run(&ExtensionControlAuthorityRequestV1 {
        managed_activation: Some(input()),
        ..home.request("seal_managed_activation", &catalog('a'))
    })["activation"]
        .clone();
    let revision = run(&ExtensionControlAuthorityRequestV1 {
        revision: Some(5),
        ..home.request("seal_managed_revision", &catalog('a'))
    })["state"]
        .clone();
    for (key, value) in [
        ("managed_controls_active", activation),
        ("managed_controls_revision", revision),
        ("managed_controls_negotiated_capabilities", json!(["a-cap"])),
        ("policy_bundle", json!({"bundleHash": "bundle-hash"})),
        ("policy_bundle_ack", json!({"status": "applied"})),
    ] {
        home.db
            .execute(
                "insert into sync_state values (?, ?, 't0')",
                rusqlite::params![key, value.to_string()],
            )
            .unwrap();
    }
    home
}

fn base(home: &Home) -> (i64, String) {
    home.db
        .query_row(
            "select revision, snapshot_digest from extension_control_authority_snapshot",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .unwrap()
}

fn clear(home: &Home, clear: ExtensionControlPolicyClearV1) -> Value {
    let (revision, digest) = base(home);
    run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        policy_clear: Some(ExtensionControlPolicyClearV1 {
            base_revision: Some(revision),
            base_snapshot_digest: Some(digest),
            ..clear
        }),
        ..home.request("clear_policy", &catalog('a'))
    })
}

fn payloads() -> BTreeMap<String, String> {
    BTreeMap::from([
        ("policy".to_owned(), "{}".to_owned()),
        ("cloud_exceptions".to_owned(), "[]".to_owned()),
        (
            "policy_bundle_ack".to_owned(),
            r#"{"status": "failed"}"#.to_owned(),
        ),
    ])
}

fn states(home: &Home) -> Vec<String> {
    let mut statement = home
        .db
        .prepare("select state_key from sync_state order by state_key")
        .unwrap();
    statement
        .query_map([], |row| row.get(0))
        .unwrap()
        .map(Result::unwrap)
        .collect()
}

fn count(home: &Home, sql: &str) -> i64 {
    home.db.query_row(sql, [], |row| row.get(0)).unwrap()
}

#[test]
fn the_plan_names_the_next_epoch_and_the_clear_writes_it() {
    let home = managed();
    let before = states(&home);
    let plan = clear(&home, ExtensionControlPolicyClearV1::default());
    assert_eq!(plan["managed_revision"], json!(6), "{plan}");
    let stored_ack = plan["stored_ack"].as_str().unwrap().to_owned();
    assert_eq!(states(&home), before);

    let cleared = clear(
        &home,
        ExtensionControlPolicyClearV1 {
            managed_revision: Some(6),
            stored_ack: Some(stored_ack),
            payloads: payloads(),
            ..ExtensionControlPolicyClearV1::default()
        },
    );
    assert_eq!(cleared["cleared"], json!(true), "{cleared}");
    assert_eq!(
        states(&home),
        [
            "cloud_exceptions",
            "managed_controls_revision",
            "policy",
            "policy_bundle_ack"
        ]
    );
    let ack: String = home
        .db
        .query_row(
            "select payload_json from sync_state where state_key = 'policy_bundle_ack'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    assert_eq!(ack, r#"{"status": "failed"}"#);
    let state: String = home
        .db
        .query_row(
            "select payload_json from sync_state where state_key = 'managed_controls_revision'",
            [],
            |row| row.get(0),
        )
        .unwrap();
    let verified = run(&ExtensionControlAuthorityRequestV1 {
        state: Some(serde_json::from_str(&state).unwrap()),
        ..home.request("managed_revision", &catalog('a'))
    });
    assert_eq!(verified["revision"], json!(6));
    assert_eq!(
        count(
            &home,
            "select count(*) from policy_decisions where source = 'local'"
        ),
        1
    );
    assert_eq!(count(&home, "select count(*) from policy_decisions"), 1);
}

#[test]
fn a_clear_over_state_the_plan_did_not_read_is_refused_with_nothing_written() {
    let home = managed();
    let plan = clear(&home, ExtensionControlPolicyClearV1::default());
    let stored_ack = plan["stored_ack"].as_str().map(str::to_owned);
    let before = states(&home);
    for stale in [
        ExtensionControlPolicyClearV1 {
            managed_revision: Some(5),
            stored_ack: stored_ack.clone(),
            ..ExtensionControlPolicyClearV1::default()
        },
        ExtensionControlPolicyClearV1 {
            managed_revision: Some(6),
            stored_ack: Some(r#"{"status": "pending"}"#.to_owned()),
            ..ExtensionControlPolicyClearV1::default()
        },
    ] {
        let refused = clear(&home, stale);
        assert_eq!(refused["fault"], json!("tampered"), "{refused}");
        assert_eq!(
            refused["reason"],
            json!("extension control authority changed during clear")
        );
    }
    let moved = run(&ExtensionControlAuthorityRequestV1 {
        now: Some(NOW.to_owned()),
        policy_clear: Some(ExtensionControlPolicyClearV1 {
            base_revision: Some(1),
            base_snapshot_digest: Some(catalog('d')),
            managed_revision: Some(6),
            stored_ack,
            ..ExtensionControlPolicyClearV1::default()
        }),
        ..home.request("clear_policy", &catalog('a'))
    });
    assert_eq!(
        moved["reason"],
        json!("extension control authority changed during clear")
    );
    assert_eq!(states(&home), before);
    assert_eq!(count(&home, "select count(*) from policy_decisions"), 2);
}

#[test]
fn a_clear_that_names_a_key_it_may_not_write_is_refused() {
    let home = managed();
    for (state_key, payload) in [("managed_controls_active", "{}"), ("policy", "not json")] {
        let refused = clear(
            &home,
            ExtensionControlPolicyClearV1 {
                payloads: BTreeMap::from([(state_key.to_owned(), payload.to_owned())]),
                ..ExtensionControlPolicyClearV1::default()
            },
        );
        assert_eq!(
            refused["reason"],
            json!("invalid policy clear request"),
            "{refused}"
        );
    }
}

#[test]
fn a_tampered_epoch_is_refused_and_no_managed_state_clears_at_zero() {
    let home = managed();
    home.db
        .execute(
            "update sync_state set payload_json = ? where state_key = 'managed_controls_revision'",
            [json!({"revision": 5, "authentication": {"record": "{}", "digest": "0", "mac": "0"}})
                .to_string()],
        )
        .unwrap();
    let refused = clear(&home, ExtensionControlPolicyClearV1::default());
    assert_eq!(
        refused["reason"],
        json!("invalid managed controls revision")
    );
    home.db
        .execute_batch("delete from sync_state where state_key like 'managed_controls_%'")
        .unwrap();
    let plan = clear(&home, ExtensionControlPolicyClearV1::default());
    assert_eq!(plan["managed_revision"], json!(0), "{plan}");
}
