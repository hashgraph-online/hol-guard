//! Replays the Composio discovery vectors recorded from the original Python
//! writers (`testdata/guard_store/record_composio_catalog_vectors.py`), and
//! covers the three refusals the vectors cannot carry: the policy barrier the
//! resident asks for before it moves provider authority, a batch whose
//! connection no longer matches, and the stored-byte ceiling.

use rusqlite::Connection;
use serde_json::{json, Value};

use crate::guard_store_cmd_vectors_tests::{error_code, temp_home};
use crate::guard_store_local_cli_vectors_tests::{build_database, replay_vectors, run_step};
use crate::local_store_read;

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

    /// Brings the store up to what a read expects of a migrated one: the
    /// schema marker, and the grant table a page left-joins for each action's
    /// state. The recorded writer vectors carry neither, because the writers
    /// read neither.
    fn migrate_for_reads(&self) {
        let connection = Connection::open(self.home.join("guard.db")).unwrap();
        connection
            .execute_batch(
                "create table if not exists local_cli_schema_migration (
                     singleton integer primary key check (singleton = 1),
                     version integer not null,
                     checksum text not null
                 );
                 create table if not exists local_mcp_provider_grant (
                     cli_id text not null,
                     identity_hash text not null,
                     tool_slug text not null,
                     state text not null check (state in ('review', 'block')),
                     updated_at text not null,
                     primary key (cli_id, identity_hash, tool_slug)
                 )",
            )
            .unwrap();
        connection
            .execute(
                "insert or replace into local_cli_schema_migration values (1, ?1, ?2)",
                rusqlite::params![
                    local_store_read::SUPPORTED_SCHEMA_VERSION,
                    local_store_read::schema_checksum(local_store_read::SUPPORTED_SCHEMA_VERSION),
                ],
            )
            .unwrap();
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

/// The writer's ceiling counts stored bytes, so a catalog at that ceiling can
/// still build a page the resident has to refuse as too large to frame. The
/// caller sees a refusal as the store being unavailable, with no page size it
/// could retry at, so the read stops short and names the offset to resume at.
#[test]
fn a_page_of_a_full_catalog_stays_inside_the_response_cap() {
    use guard_contracts::MAX_NATIVE_RESPONSE_BYTES;

    let fixture = Fixture::new("composio-page-budget");
    let mut batch = fixture.step("first_discovery", 0);
    let template = batch["wire_args"]["actions"][0].clone();
    // Forty actions just under 50,000 bytes each: inside the writer's
    // 2,000,000-byte ceiling, past what one reply can carry.
    let actions: Vec<Value> = (0..40)
        .map(|index| {
            let mut action = template.clone();
            action["tool_slug"] = Value::from(format!("SLACK_ACTION_{index:02}"));
            action["description"] = Value::from("d".repeat(49_800));
            action
        })
        .collect();
    batch["wire_args"]["actions"] = Value::from(actions);
    let reply = fixture.run(&batch);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(fixture.action_rows(), 40);
    fixture.migrate_for_reads();

    let read = json!({
        "method": "read_local_mcp_provider_actions",
        "wire_args": {
            "cli_id": batch["wire_args"]["cli_id"].clone(),
            "limit": 100,
            "offset": 0,
            "search": "",
            "expected_token": Value::Null,
        },
    });
    let reply = fixture.run(&read);
    assert_eq!(reply["status"], "ok", "{reply}");
    let encoded = serde_json::to_vec(&reply).unwrap().len();
    assert!(encoded <= MAX_NATIVE_RESPONSE_BYTES, "{encoded} bytes");
    let served = reply["payload"]["page"]["actions"]
        .as_array()
        .unwrap()
        .len();
    assert!(served > 0 && served < 40, "served {served} of 40 actions");
    assert_eq!(reply["payload"]["page"]["next_offset"], Value::from(served));
    assert_eq!(
        reply["payload"]["declarations"].as_array().unwrap().len(),
        served,
        "every action still carries its declaration"
    );

    let mut rest = read.clone();
    rest["wire_args"]["offset"] = Value::from(served);
    let reply = fixture.run(&rest);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(
        reply["payload"]["page"]["actions"]
            .as_array()
            .unwrap()
            .len(),
        40 - served,
        "the dropped actions come back on the next offset"
    );
}
