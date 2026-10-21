//! Replays the Composio discovery vectors recorded from the original Python
//! writers (`testdata/guard_store/record_composio_catalog_vectors.py`), and
//! covers the three refusals the vectors cannot carry: the policy barrier the
//! resident asks for before it moves provider authority, a batch whose
//! connection no longer matches, and the stored-byte ceiling.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::{error_code, temp_home};
use crate::guard_store_local_cli_vectors_tests::{build_database, replay_vectors, run_step};

const COMPOSIO_VECTORS: &str =
    include_str!("../testdata/guard_store/composio_catalog_vectors.json");
const SCHEMA: &str = "guard-store-composio-catalog-vectors.v1";

struct Fixture {
    vectors: Value,
    home: std::path::PathBuf,
}

impl Fixture {
    /// Seeds `first_discovery`: one observed connection, no catalog yet.
    fn new(name: &str) -> Self {
        let vectors: Value = serde_json::from_str(COMPOSIO_VECTORS).unwrap();
        let scenario = scenario(&vectors, "first_discovery").clone();
        let home = temp_home(name);
        build_database(&home.join("guard.db"), &vectors, &scenario);
        Self { vectors, home }
    }

    fn step(&self, scenario_name: &str, index: usize) -> Value {
        scenario(&self.vectors, scenario_name)["steps"][index].clone()
    }

    fn run(&self, step: &Value) -> Value {
        run_step(
            &self.home,
            self.vectors["source"].as_str().unwrap(),
            self.vectors["now"].as_str().unwrap(),
            step,
        )
    }

    /// The stored revision of the one catalog row, for the repeated-slug case
    /// the vectors can only record against an empty catalog.
    fn action_revision(&self) -> i64 {
        Connection::open(self.home.join("guard.db"))
            .unwrap()
            .query_row(
                "select revision from local_mcp_provider_action",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn action_rows(&self) -> i64 {
        Connection::open(self.home.join("guard.db"))
            .unwrap()
            .query_row(
                "select count(*) from local_mcp_provider_action",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.home);
    }
}

fn scenario<'a>(vectors: &'a Value, name: &str) -> &'a Value {
    vectors["scenarios"]
        .as_array()
        .unwrap()
        .iter()
        .find(|scenario| scenario["name"] == name)
        .unwrap()
}

#[test]
fn replays_every_recorded_composio_catalog_scenario() {
    let compared_steps = replay_vectors(COMPOSIO_VECTORS, SCHEMA);
    assert!(compared_steps >= 18, "only {compared_steps} recorded steps");
}

/// Moving provider authority has to happen inside the native policy barrier.
/// The resident cannot reach the publishers that barrier notifies, so it
/// writes nothing and asks Python to close one first.
#[test]
fn an_authority_move_waits_for_the_policy_barrier() {
    let fixture = Fixture::new("composio-barrier");
    let mut open = fixture.step("first_discovery", 0);
    open["wire_args"]
        .as_object_mut()
        .unwrap()
        .remove("barrier_closed");
    let reply = fixture.run(&open);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], json!({ "need_barrier": true }));
    assert_eq!(
        fixture.action_rows(),
        0,
        "it wrote before the barrier closed"
    );

    let closed = fixture.step("first_discovery", 0);
    let reply = fixture.run(&closed);
    assert_eq!(reply["payload"], json!({ "authority_changed": true }));
    assert_eq!(fixture.action_rows(), 1);
}

/// A revision that leaves the authority where it is needs no barrier, so the
/// common refresh still costs one round trip.
#[test]
fn a_revision_without_an_authority_move_needs_no_barrier() {
    let fixture = Fixture::new("composio-no-barrier");
    fixture.run(&fixture.step("first_discovery", 0));
    let mut repeat = fixture.step("first_discovery", 1);
    repeat["wire_args"]
        .as_object_mut()
        .unwrap()
        .remove("barrier_closed");
    let reply = fixture.run(&repeat);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], json!({ "authority_changed": false }));
}

/// Metadata is held against the connection it was observed on. A cli_id that
/// no longer names that connection is refused before anything is written.
#[test]
fn metadata_for_another_connection_is_refused() {
    let fixture = Fixture::new("composio-mismatch");
    let mut moved = fixture.step("first_discovery", 0);
    moved["wire_args"]["cli_id"] = Value::from("local-cli.mcp-0000000000000000");
    let reply = fixture.run(&moved);
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["code"], error_code("ValueError"));
    assert_eq!(
        reply["payload"]["message"],
        "provider metadata connection changed"
    );
    assert_eq!(fixture.action_rows(), 0);
}

/// The catalog ceiling counts stored bytes, not actions, so one oversized
/// description reaches it. Python checks after the inserts and rolls the
/// transaction back; the refusal has to leave the catalog empty here too.
#[test]
fn an_oversized_catalog_is_refused_and_stores_nothing() {
    let fixture = Fixture::new("composio-capacity");
    let mut oversized = fixture.step("first_discovery", 0);
    oversized["wire_args"]["actions"][0]["description"] = Value::from("x".repeat(2_000_001));
    let reply = fixture.run(&oversized);
    assert_eq!(reply["status"], "error", "{reply}");
    assert_eq!(reply["code"], error_code("ValueError"));
    assert_eq!(
        reply["payload"]["message"],
        "provider metadata catalog capacity exceeded"
    );
    assert_eq!(fixture.action_rows(), 0);
}

/// Python upserts each action inside the loop that reads it, so a slug
/// repeated in one batch measures itself against the copy before it. The
/// pre-pass settles every revision before it writes anything, so it has to
/// carry those copies itself: a stored revision 1 followed by two further
/// authority moves in one batch has to land on 3, not 2.
#[test]
fn a_repeated_slug_counts_each_copy_against_the_one_before_it() {
    let fixture = Fixture::new("composio-repeated-slug");
    fixture.run(&fixture.step("first_discovery", 0));
    assert_eq!(fixture.action_revision(), 1);

    let mut batch = fixture.step("first_discovery", 0);
    let action = batch["wire_args"]["actions"][0].clone();
    let mut second = action.clone();
    second["toolkit"] = Value::from("slack-renamed");
    let mut third = action;
    third["description"] = Value::from("Synthetic metadata, revised again");
    batch["wire_args"]["actions"] = Value::from(vec![second, third]);
    let reply = fixture.run(&batch);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], json!({ "authority_changed": true }));
    assert_eq!(fixture.action_rows(), 1);
    assert_eq!(fixture.action_revision(), 3);
}
