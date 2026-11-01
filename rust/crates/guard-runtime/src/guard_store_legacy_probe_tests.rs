//! The legacy Codex probe lookup against rows shaped as the hook evidence
//! writer stores them.

use std::path::Path;

use guard_contracts::{GuardStoreRequestV1, GUARD_STORE_REQUEST_SCHEMA};
use rusqlite::{params, Connection};
use serde_json::{json, Map, Value};

use super::{matching_receipt, prevented_attempt_digest, MAX_ROWS};
use crate::guard_store_cmd_vectors_tests::temp_home;
use crate::guard_store_db::Row;
use crate::native_decision_receipt::sealed_decision_id;

const VECTORS: &str = include_str!("../testdata/guard_store/native_receipt_vectors.json");
const KEY_ID: &str = "key-1";
const DIGEST: &str = "c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00c0ffee00";
const SINCE: &str = "2026-10-01T12:00:00+00:00";
const OCCURRED: &str = "2026-10-01T12:00:01.500000+00:00";
const RECORDED: &str = "2026-10-01T12:00:01.400000+00:00";

fn micros(text: &str) -> i128 {
    crate::guard_store_json::aware_epoch_micros(text).unwrap()
}

fn now() -> i128 {
    micros("2026-10-01T12:00:05+00:00")
}

/// A sealed codex `PreToolUse` receipt; `variant` keeps decision ids apart.
fn receipt(action: &str, variant: char) -> Value {
    let mut receipt = json!({
        "schema": "guard-native-hook-decision-receipt.v1",
        "version": 1,
        "authority": "rust",
        "decision_id": "",
        "request_id": "request-1",
        "request_digest": variant.to_string().repeat(64),
        "harness": "codex",
        "event_name": "PreToolUse",
        "payload_kind": "inline",
        "policy_generation": 1,
        "policy_digest": null,
        "rule_digest": null,
        "runtime_identity": "b".repeat(64),
        "decision": if action == "allow" { "allow" } else { "deny" },
        "model_output_action": "allow_original",
        "policy_action": action,
        "observed_policy_action": null,
        "reason_code": "policy_decision",
        "workspace_bound": false,
        "source_ref_external_allowed": false,
        "reviewed_output_sha256": null,
        "observe_mode": false,
        "deadline_budget_ms": null,
    });
    let parsed = crate::pyjson::parse(&receipt.to_string()).unwrap();
    receipt["decision_id"] = Value::from(sealed_decision_id(&parsed));
    receipt
}

/// One stored row as the probe's statement returns it.
fn row(receipt: &Value, activity: &[(&str, Value)]) -> Row {
    let mut row = receipt.as_object().unwrap().clone();
    for name in super::BOOL_FIELDS {
        let flag = row[name].as_bool().unwrap();
        row.insert(name.to_owned(), Value::from(i64::from(flag)));
    }
    row.insert("command_extensions_json".to_owned(), Value::Null);
    row.insert("recorded_at".to_owned(), Value::from(RECORDED));
    let action = receipt["policy_action"].clone();
    let permitted = matches!(action.as_str(), Some("allow" | "warn"));
    let mut fields: Map<String, Value> = [
        ("occurred_at", Value::from(OCCURRED)),
        ("policy_action", action),
        ("prompted", Value::from(0)),
        ("approval_reuse_status", Value::from("not-applicable")),
        (
            "execution_status",
            Value::from(if permitted {
                "allowed_unconfirmed"
            } else {
                "prevented"
            }),
        ),
    ]
    .into_iter()
    .map(|(name, value)| (name.to_owned(), value))
    .collect();
    for (name, value) in activity {
        fields.insert((*name).to_owned(), value.clone());
    }
    let digest = if permitted {
        DIGEST.to_owned()
    } else {
        prevented_attempt_digest(
            DIGEST,
            &fields["policy_action"],
            &receipt["decision_id"],
            false,
            &fields["approval_reuse_status"],
        )
    };
    for (name, value) in fields {
        row.insert(format!("activity_{name}"), value);
    }
    row.insert("correlation_digest".to_owned(), Value::from(digest));
    row
}

fn lookup(rows: Vec<Row>) -> Result<Value, String> {
    matching_receipt(rows, DIGEST, micros(SINCE), now()).map_err(|error| error.message())
}

#[test]
fn the_prevented_attempt_digest_is_the_shipped_wire_formula() {
    // `hashlib.sha256(json.dumps(["native-prevented-attempt-v1", "d", "block",
    // "r", False, "not-applicable"]).encode()).hexdigest()`.
    assert_eq!(
        prevented_attempt_digest(
            "d",
            &json!("block"),
            &json!("r"),
            false,
            &json!("not-applicable"),
        ),
        "39100f51064bd3629775852de50834719edc9ad33b47a19894e19f1aab064ca7"
    );
}

#[test]
fn a_fresh_permitted_or_prevented_receipt_is_found() {
    for action in ["allow", "warn", "block", "review"] {
        let receipt = receipt(action, 'a');
        assert_eq!(lookup(vec![row(&receipt, &[])]), Ok(receipt), "{action}");
    }
}

#[test]
fn a_row_for_another_request_is_skipped() {
    let mut other = row(&receipt("allow", 'a'), &[]);
    other.insert("correlation_digest".to_owned(), Value::from("0".repeat(64)));
    assert_eq!(lookup(vec![other]), Ok(Value::Null));
    // A denied attempt correlates only through its salted digest.
    let mut unsalted = row(&receipt("block", 'a'), &[]);
    unsalted.insert("correlation_digest".to_owned(), Value::from(DIGEST));
    assert_eq!(lookup(vec![unsalted]), Ok(Value::Null));
    let mut missing = row(&receipt("allow", 'a'), &[]);
    missing.insert("correlation_digest".to_owned(), Value::Null);
    assert_eq!(lookup(vec![missing]), Ok(Value::Null));
    assert_eq!(lookup(Vec::new()), Ok(Value::Null));
}

#[test]
fn matching_but_invalid_evidence_is_refused() {
    let allowed = receipt("allow", 'a');
    let mut cases: Vec<(&str, Row)> = vec![
        ("prompted", row(&allowed, &[("prompted", json!(1))])),
        (
            "reused",
            row(&allowed, &[("approval_reuse_status", json!("reused"))]),
        ),
        (
            "executed",
            row(&allowed, &[("execution_status", json!("prevented"))]),
        ),
        (
            "stale activity",
            row(
                &allowed,
                &[("occurred_at", json!("2026-10-01T11:59:59+00:00"))],
            ),
        ),
        (
            "future activity",
            row(
                &allowed,
                &[("occurred_at", json!("2026-10-01T12:00:06+00:00"))],
            ),
        ),
        (
            "naive activity",
            row(&allowed, &[("occurred_at", json!("2026-10-01T12:00:01"))]),
        ),
        (
            "long activity",
            row(
                &allowed,
                &[(
                    "occurred_at",
                    json!(format!("{OCCURRED}{}", " ".repeat(40))),
                )],
            ),
        ),
    ];
    for (name, value) in [
        ("recorded_at", json!("2026-10-01T11:59:59+00:00")),
        ("recorded_at", json!("2026-10-01T12:00:06+00:00")),
        ("recorded_at", json!("not a time")),
        ("runtime_identity", json!("0".repeat(64))),
        ("observe_mode", json!(2)),
        ("command_extensions_json", json!("{not json")),
        ("command_extensions_json", json!("x".repeat(2_049))),
    ] {
        let mut changed = row(&allowed, &[]);
        changed.insert(name.to_owned(), value);
        cases.push((name, changed));
    }
    for (field, value) in [
        ("harness", "claude-code"),
        ("payload_kind", "source_file_ref"),
    ] {
        let mut other = allowed.clone();
        other[field] = Value::from(value);
        let parsed = crate::pyjson::parse(&other.to_string()).unwrap();
        other["decision_id"] = Value::from(sealed_decision_id(&parsed));
        cases.push((field, row(&other, &[])));
    }
    let mut observed = allowed.clone();
    observed["observe_mode"] = Value::Bool(true);
    let parsed = crate::pyjson::parse(&observed.to_string()).unwrap();
    observed["decision_id"] = Value::from(sealed_decision_id(&parsed));
    cases.push(("observe mode", row(&observed, &[])));
    // The activity says warn while the receipt says allow.
    let mut relabelled = row(&allowed, &[]);
    relabelled.insert("activity_policy_action".to_owned(), json!("warn"));
    cases.push(("activity policy", relabelled));
    for (name, case) in cases {
        assert_eq!(
            lookup(vec![case]),
            Err("legacy_probe_receipt_invalid".to_owned()),
            "{name}"
        );
    }
}

#[test]
fn two_receipts_for_one_request_are_ambiguous() {
    let rows = vec![
        row(&receipt("block", 'a'), &[]),
        row(&receipt("block", 'b'), &[]),
    ];
    assert_eq!(
        lookup(rows),
        Err("legacy_probe_receipt_ambiguous".to_owned())
    );
}

#[test]
fn a_busy_window_is_capped_instead_of_choosing_the_newest_row() {
    let unrelated = {
        let mut row = row(&receipt("allow", 'a'), &[]);
        row.insert("correlation_digest".to_owned(), Value::from("0".repeat(64)));
        row
    };
    let mut rows = vec![unrelated; MAX_ROWS];
    assert_eq!(lookup(rows.clone()), Ok(Value::Null));
    rows.push(row(&receipt("allow", 'a'), &[]));
    assert_eq!(
        lookup(rows),
        Err("legacy_probe_receipt_capacity".to_owned())
    );
}

fn build_database(path: &Path) {
    let vectors: Value = serde_json::from_str(VECTORS).unwrap();
    let connection = Connection::open(path).unwrap();
    connection
        .execute_batch(vectors["schema_sql"][0].as_str().unwrap())
        .unwrap();
    connection
        .execute_batch(
            "create table command_activity (activity_id text primary key, harness text, \
             hook_phase text, proof_level text, receipt_link_status text, occurred_at text, \
             policy_action text, prompted integer, approval_reuse_status text, \
             execution_status text, receipt_id text);
             create table command_activity_correlations (activity_id text, harness text, \
             kind text, key_id text, digest text);
             create table guard_review_outbox_events (stream_sequence integer primary key, \
             payload_hash text not null default '');",
        )
        .unwrap();
}

/// Store `row` as the writer would: the receipt, its activity and the
/// request correlation, all at `occurred_at`.
fn store(connection: &Connection, activity_id: &str, key_id: &str, row: &Row) {
    let columns: Vec<&String> = row
        .keys()
        .filter(|name| !name.starts_with("activity_") && *name != "correlation_digest")
        .collect();
    let values: Vec<rusqlite::types::Value> = columns
        .iter()
        .map(|name| match &row[*name] {
            Value::Null => rusqlite::types::Value::Null,
            Value::Number(number) => rusqlite::types::Value::Integer(number.as_i64().unwrap()),
            Value::String(text) => rusqlite::types::Value::Text(text.clone()),
            other => panic!("{other}"),
        })
        .collect();
    let names: Vec<&str> = columns.iter().map(|name| name.as_str()).collect();
    connection
        .execute(
            &format!(
                "insert into native_hook_decision_receipts ({}) values ({})",
                names.join(","),
                vec!["?"; names.len()].join(",")
            ),
            rusqlite::params_from_iter(values),
        )
        .unwrap();
    connection
        .execute(
            "insert into command_activity values (?, 'codex', 'pre', 'pre_hook', 'linked', ?, ?, 0, \
             'not-applicable', ?, ?)",
            params![
                activity_id,
                row["activity_occurred_at"].as_str(),
                row["activity_policy_action"].as_str(),
                row["activity_execution_status"].as_str(),
                row["decision_id"].as_str(),
            ],
        )
        .unwrap();
    connection
        .execute(
            "insert into command_activity_correlations values (?, 'codex', 'request', ?, ?)",
            params![activity_id, key_id, row["correlation_digest"].as_str()],
        )
        .unwrap();
}

fn read(home: &Path, since: &str) -> Value {
    read_within(home, since, 5_000)
}

fn read_within(home: &Path, since: &str, budget_ms: i64) -> Value {
    let mut args = Map::new();
    args.insert("key_id".to_owned(), json!(KEY_ID));
    args.insert("digest".to_owned(), json!(DIGEST));
    args.insert("since".to_owned(), json!(since));
    args.insert("budget_ms".to_owned(), json!(budget_ms));
    let request = GuardStoreRequestV1 {
        schema: GUARD_STORE_REQUEST_SCHEMA.to_owned(),
        request_id: "legacy-probe".to_owned(),
        store_path: home.join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.to_string_lossy().into_owned(),
        method: "read_legacy_codex_probe_receipt".to_owned(),
        source: "guard".to_owned(),
        busy_timeout_ms: 5000,
        args,
    };
    serde_json::from_slice(&crate::guard_store_op::evaluate_guard_store_request(&request).unwrap())
        .unwrap()
}

#[test]
fn the_store_op_reads_the_request_from_writer_shaped_rows() {
    let home = temp_home("legacy-probe");
    build_database(&home.join("guard.db"));
    let connection = Connection::open(home.join("guard.db")).unwrap();
    let wanted = receipt("block", 'a');
    store(&connection, "activity-1", KEY_ID, &row(&wanted, &[]));
    // Another installation key's row with the same digest never matches.
    store(
        &connection,
        "activity-2",
        "key-2",
        &row(&receipt("allow", 'b'), &[]),
    );
    drop(connection);

    let reply = read(&home, SINCE);
    assert_eq!(reply["status"], "ok", "{reply}");
    assert_eq!(reply["payload"], wanted);

    // Activity before the launch boundary is outside the statement's window.
    let later = read(&home, "2026-10-01T12:00:02+00:00");
    assert_eq!(later["payload"], Value::Null, "{later}");

    let naive = read(&home, "2026-10-01T12:00:00");
    assert_eq!(naive["code"], "native_guard_store_value_error", "{naive}");
    assert_eq!(naive["payload"]["message"], "legacy_probe_identity_invalid");

    // A spent or unbounded admission budget never starts the lookup.
    for budget_ms in [0, 60_001] {
        let refused = read_within(&home, SINCE, budget_ms);
        assert_eq!(
            refused["code"], "native_guard_store_value_error",
            "{refused}"
        );
        assert_eq!(
            refused["payload"]["message"],
            "legacy_probe_identity_invalid"
        );
    }
    let _ = std::fs::remove_dir_all(&home);
}
