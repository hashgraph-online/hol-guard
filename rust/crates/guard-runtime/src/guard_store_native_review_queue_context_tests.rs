//! A connector-setup review's context, kept in the queue write that stored it.

use serde_json::{json, Map, Value};

use super::tests::{args, delegate, local_cli, looked_up, unrecognised};
use super::Delegated;

const OBSERVATION: &str = "
create table local_cli_observation (
    cli_id text primary key,
    identity_hash text not null,
    first_blocked_cause text,
    last_trigger_summary text,
    last_why_now text,
    last_harness text,
    last_workspace_label text,
    last_context_at text
);
insert into local_cli_observation (cli_id, identity_hash)
values ('local-cli.lanectl-1',
    'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa');
";

fn observed() -> rusqlite::Connection {
    let connection = rusqlite::Connection::open_in_memory().unwrap();
    connection.execute_batch(OBSERVATION).unwrap();
    connection
}

fn kept(connection: &rusqlite::Connection) -> Vec<Option<String>> {
    connection
        .query_row(
            "select first_blocked_cause, last_trigger_summary, last_why_now, last_harness, \
             last_workspace_label, last_context_at from local_cli_observation",
            [],
            |row| (0..6).map(|index| row.get(index)).collect(),
        )
        .unwrap()
}

fn connector_call() -> Map<String, Value> {
    unrecognised(json!({}))
}

fn lanectl() -> Value {
    let mut connector = local_cli();
    connector["cli_id"] = json!("local-cli.lanectl-1");
    connector["name"] = json!("lanectl");
    connector
}

fn connector_review(call: &Map<String, Value>) -> Delegated {
    looked_up(call, 10_000, lanectl()).unwrap()
}

fn connector_reply(summary: &str, why_now: &str) -> Value {
    json!({"row": {
        "request_id": "req1",
        "raw_command_text": "lanectl deploy staging",
        "trigger_summary": summary,
        "why_now": why_now,
    }})
}

#[test]
fn a_connector_review_keeps_its_context_with_the_row_it_stored() {
    let connection = observed();
    let delegated = connector_review(&connector_call());
    assert!(!delegated.args.contains_key("connector_lookup"));
    let refused = delegated.record_connector_context(
        &connection,
        &connector_reply("Runs a local CLI Guard has not seen.", "First use here."),
    );
    assert_eq!(refused, None);
    assert_eq!(
        kept(&connection),
        [
            Some("unrecognised_tool"),
            Some("Runs a local CLI Guard has not seen."),
            Some("First use here."),
            Some("claude-code"),
            Some("work"),
            Some("2026-10-29T00:00:00+00:00"),
        ]
        .map(|text| text.map(str::to_owned))
    );
}

#[test]
fn wording_that_repeats_an_argument_is_never_kept() {
    let connection = observed();
    let delegated = connector_review(&connector_call());
    // `staging` is an argument of the command; the program name is not.
    delegated.record_connector_context(
        &connection,
        &connector_reply("Deploys to staging.", "lanectl is new here."),
    );
    let kept = kept(&connection);
    assert_eq!(kept[1], None);
    assert_eq!(kept[2].as_deref(), Some("lanectl is new here."));
}

#[test]
fn a_review_without_a_connector_or_its_row_keeps_no_context() {
    let connection = observed();
    let reply = connector_reply("Runs a local CLI.", "First use here.");
    delegate(&args(json!({})))
        .unwrap()
        .record_connector_context(&connection, &reply);
    connector_review(&connector_call())
        .record_connector_context(&connection, &json!({"request_id": "req1"}));
    assert_eq!(kept(&connection), vec![None; 6]);
}

#[test]
fn the_first_cause_follows_the_review_reason() {
    for (reason_code, cause) in [
        (
            "native_workspace_containment_executable_outside_roots",
            Some("exec_outside_roots"),
        ),
        ("native_network_review", None),
    ] {
        let connection = observed();
        let mut call = connector_call();
        call["review"]["result"]["reason_code"] = json!(reason_code);
        connector_review(&call).record_connector_context(
            &connection,
            &connector_reply("Runs a local CLI.", "First use here."),
        );
        assert_eq!(kept(&connection)[0].as_deref(), cause);
    }
}

#[test]
fn a_context_the_store_refuses_leaves_the_review_as_it_was() {
    let connection = observed();
    let mut connector = lanectl();
    connector["cli_id"] = json!("not a local cli id");
    let delegated = looked_up(&connector_call(), 10_000, connector).unwrap();
    // The daemon logs the code; the review stays queued.
    let refused = delegated.record_connector_context(
        &connection,
        &connector_reply("Runs a local CLI.", "First use here."),
    );
    assert_eq!(refused, Some("native_guard_store_value_error"));
    assert_eq!(kept(&connection), vec![None; 6]);
}
