//! Parity with the Python startup generation decision, recorded by
//! `testdata/policy_integrity_generation/record_vectors.py`, plus the request
//! failures that have no Python counterpart.

use base64ct::{Base64UrlUnpadded, Encoding};
use guard_contracts::{
    PolicyIntegrityGenerationRequestV1, PolicyIntegrityReconcileRequestV1,
    PolicyIntegrityReconcileTallyV1, PolicyIntegrityRowsRequestV1,
    POLICY_INTEGRITY_RECONCILE_FEATURE, POLICY_INTEGRITY_RECONCILE_MAX_ROWS,
    POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
};
use rusqlite::{params_from_iter, types::Value as SqlValue, Connection};
use serde_json::{json, Value};

use super::{decide, reconcile, ROW_COLUMNS};
use crate::policy_integrity_rows_op::evaluate;

const VECTORS: &str = include_str!("../testdata/policy_integrity_generation/vectors.json");

fn vectors() -> Value {
    serde_json::from_str(VECTORS).expect("vectors json")
}

fn key() -> Vec<u8> {
    (0u8..32).collect()
}

fn key_id() -> String {
    vectors()["integrity_key_id"]
        .as_str()
        .expect("key id")
        .to_owned()
}

fn sql_value(value: &Value) -> SqlValue {
    match value {
        Value::Null => SqlValue::Null,
        Value::String(text) => SqlValue::Text(text.clone()),
        Value::Number(number) if number.is_i64() => SqlValue::Integer(number.as_i64().unwrap()),
        Value::Number(number) => SqlValue::Real(number.as_f64().unwrap()),
        other => panic!("unexpected row value {other}"),
    }
}

/// A Guard home whose `guard.db` holds `rows` in `policy_decisions`.
fn home_with_rows(rows: &[Value]) -> tempfile::TempDir {
    let home = tempfile::tempdir().unwrap();
    let connection = Connection::open(home.path().join("guard.db")).unwrap();
    connection
        .execute(
            &format!("create table policy_decisions ({})", ROW_COLUMNS.join(", ")),
            [],
        )
        .unwrap();
    let placeholders = vec!["?"; ROW_COLUMNS.len()].join(", ");
    let insert = format!(
        "insert into policy_decisions ({}) values ({placeholders})",
        ROW_COLUMNS.join(", ")
    );
    for row in rows {
        let values = ROW_COLUMNS.iter().map(|column| sql_value(&row[*column]));
        connection
            .execute(&insert, params_from_iter(values))
            .unwrap();
    }
    home
}

fn generation_request(
    home: &tempfile::TempDir,
    trusted_state: Value,
) -> PolicyIntegrityGenerationRequestV1 {
    PolicyIntegrityGenerationRequestV1 {
        store_path: home.path().join("guard.db").to_string_lossy().into_owned(),
        guard_home: home.path().to_string_lossy().into_owned(),
        trusted_state,
    }
}

#[test]
fn python_vectors_match() {
    let vectors = vectors();
    let cases = vectors["cases"].as_array().expect("cases");
    assert!(cases.len() >= 25, "vector set unexpectedly small");
    for case in cases {
        let name = case["name"].as_str().expect("name");
        let home = home_with_rows(case["rows"].as_array().expect("rows"));
        let request = generation_request(&home, case["trusted_state"].clone());
        let outcome =
            decide(&request, &key(), &key_id()).unwrap_or_else(|code| panic!("{name}: {code}"));
        assert_eq!(
            serde_json::to_value(&outcome).expect("outcome json"),
            case["expected"],
            "{name}"
        );
    }
}

#[test]
fn rows_op_answers_the_generation_section() {
    let vectors = vectors();
    let case = &vectors["cases"][0];
    let home = home_with_rows(case["rows"].as_array().unwrap());
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "request_id": "unit",
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&key()),
        "integrity_key_id": vectors["integrity_key_id"],
        "verify": [],
        "sign": [],
        "generation": serde_json::to_value(generation_request(&home, case["trusted_state"].clone())).unwrap(),
    }))
    .unwrap();
    let payload = serde_json::to_value(evaluate(&request).unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({"verify": [], "sign": [], "generation": case["expected"]})
    );
}

#[test]
fn rows_op_without_generation_omits_the_section() {
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "verify": [],
        "sign": [],
    }))
    .unwrap();
    let payload = serde_json::to_value(evaluate(&request).unwrap()).unwrap();
    assert_eq!(payload, json!({"verify": [], "sign": []}));
}

#[test]
fn generation_without_key_fails_the_request() {
    let home = home_with_rows(&[]);
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "verify": [],
        "sign": [],
        "generation": serde_json::to_value(generation_request(&home, json!({
            "cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1
        }))).unwrap(),
    }))
    .unwrap();
    assert_eq!(
        evaluate(&request),
        Err("native_policy_integrity_key_unavailable")
    );
}

#[test]
fn unnormalized_trusted_state_is_refused() {
    let home = home_with_rows(&[]);
    for state in [
        json!({"cutover_complete": false, "generation": 3, "pending_generation": 2, "version": 1}),
        json!({"cutover_complete": false, "generation": 3, "version": 1}),
        json!({"cutover_complete": false, "generation": -1, "pending_generation": null, "version": 1}),
        json!({"cutover_complete": 0, "generation": 3, "pending_generation": null, "version": 1}),
        json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 2}),
        json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1, "extra": 1}),
    ] {
        assert_eq!(
            decide(&generation_request(&home, state.clone()), &key(), &key_id()),
            Err("native_policy_integrity_state_invalid"),
            "{state}"
        );
    }
}

#[test]
fn store_outside_home_or_missing_is_refused() {
    let home = home_with_rows(&[]);
    let other = home_with_rows(&[]);
    let state = json!({"cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1});
    let mut request = generation_request(&other, state.clone());
    request.guard_home = home.path().to_string_lossy().into_owned();
    assert_eq!(
        decide(&request, &key(), &key_id()),
        Err("native_policy_integrity_store_path_invalid")
    );
    let empty = tempfile::tempdir().unwrap();
    assert_eq!(
        decide(&generation_request(&empty, state), &key(), &key_id()),
        Err("native_policy_integrity_store_unavailable")
    );
}

/// The vector case `name`, which the reconcile tests reuse for its rows and
/// trusted state.
fn case_named(name: &str) -> Value {
    vectors()["cases"]
        .as_array()
        .expect("cases")
        .iter()
        .find(|case| case["name"] == name)
        .unwrap_or_else(|| panic!("no vector case named {name}"))
        .clone()
}

fn reconcile_request(case: &Value) -> PolicyIntegrityReconcileRequestV1 {
    PolicyIntegrityReconcileRequestV1 {
        trusted_state: case["trusted_state"].clone(),
        rows: case["rows"].as_array().expect("rows").clone(),
        carried: None,
        decide: true,
    }
}

fn decided(request: &PolicyIntegrityReconcileRequestV1) -> Value {
    reconcile(request, &key(), &key_id())
        .expect("reconcile")
        .next_state
        .expect("next_state")
}

fn reconciled(name: &str) -> Value {
    let case = case_named(name);
    reconcile(&reconcile_request(&case), &key(), &key_id())
        .unwrap_or_else(|code| panic!("{name}: {code}"))
        .next_state
        .unwrap_or_else(|| panic!("{name}: no next_state"))
}

/// Every pending-generation outcome the Python reconcile produced, over the
/// same rows, now decided natively. Unlike the startup decision these keep
/// `cutover_complete` as the store trusts it: only the pending generation is
/// resolved here.
#[test]
fn reconcile_decides_the_pending_generation() {
    let trusted =
        json!({"cutover_complete": false, "generation": 3, "pending_generation": 4, "version": 1});
    let cut_over_at_pending = json!({"cutover_complete": true, "generation": 4, "pending_generation": null, "version": 1});
    let pending_abandoned = json!({
        "cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1
    });
    for (name, expected) in [
        ("pending_all_at_pending", &cut_over_at_pending),
        ("pending_all_at_current", &pending_abandoned),
        ("pending_mixed", &trusted),
        ("pending_tampered", &trusted),
        ("pending_legacy_unsigned", &trusted),
        ("pending_legacy_v1_current_valid", &pending_abandoned),
        ("pending_legacy_v1_only", &trusted),
        ("pending_legacy_v1_pending_signed", &trusted),
        ("no_local_rows_pending", &cut_over_at_pending),
    ] {
        assert_eq!(&reconciled(name), expected, "{name}");
    }
}

/// A completed cutover still adopts the pending generation, and a state with
/// no pending generation is returned untouched.
#[test]
fn reconcile_leaves_a_state_with_nothing_pending_alone() {
    assert_eq!(
        reconciled("pending_cutover_done"),
        json!({"cutover_complete": true, "generation": 4, "pending_generation": null, "version": 1})
    );
    for name in [
        "steady_current",
        "newer_single_generation",
        "legacy_v1_no_pending",
    ] {
        let case = case_named(name);
        assert_eq!(&reconciled(name), &case["trusted_state"], "{name}");
    }
}

/// The caller's query decides which rows travel: a row the store would have
/// excluded is still counted when the caller ships it.
#[test]
fn reconcile_judges_exactly_the_rows_it_is_given() {
    let case = case_named("pending_all_at_pending");
    let mut request = reconcile_request(&case);
    request.rows.truncate(1);
    assert_eq!(
        decided(&request),
        json!({"cutover_complete": true, "generation": 4, "pending_generation": null, "version": 1})
    );
    request.rows.clear();
    assert_eq!(
        decided(&request),
        json!({"cutover_complete": true, "generation": 4, "pending_generation": null, "version": 1})
    );
}

/// A store too large for one request sends its rows in chunks, carrying the
/// counters forward, and settles on the same generation as a single request.
#[test]
fn reconcile_folds_chunked_rows_into_the_same_decision() {
    for name in [
        "pending_all_at_pending",
        "pending_all_at_current",
        "pending_mixed",
        "pending_legacy_unsigned",
    ] {
        let case = case_named(name);
        let whole = reconcile_request(&case);
        assert!(whole.rows.len() > 1, "{name}: needs several rows");
        let mut carried = None;
        for (index, row) in whole.rows.iter().enumerate() {
            let last = index == whole.rows.len() - 1;
            let outcome = reconcile(
                &PolicyIntegrityReconcileRequestV1 {
                    trusted_state: whole.trusted_state.clone(),
                    rows: vec![row.clone()],
                    carried,
                    decide: last,
                },
                &key(),
                &key_id(),
            )
            .unwrap_or_else(|code| panic!("{name}: {code}"));
            if last {
                assert_eq!(outcome.next_state, Some(reconciled(name)), "{name}");
                assert_eq!(outcome.tally, None, "{name}");
            } else {
                assert_eq!(outcome.next_state, None, "{name}");
                carried = Some(outcome.tally.unwrap_or_else(|| panic!("{name}: no tally")));
            }
        }
    }
}

/// Counters that no fold could have produced are refused rather than decided
/// on, so a caller cannot talk the resident into a generation by arithmetic.
#[test]
fn reconcile_refuses_impossible_carried_counters() {
    let case = case_named("pending_mixed");
    for carried in [
        PolicyIntegrityReconcileTallyV1 {
            rows: 1,
            pending_candidates: 2,
            ..Default::default()
        },
        PolicyIntegrityReconcileTallyV1 {
            rows: 2,
            pending_candidates: 1,
            pending_valid: 2,
            ..Default::default()
        },
        PolicyIntegrityReconcileTallyV1 {
            rows: 2,
            pending_candidates: 2,
            pending_valid: 2,
            current_valid: 1,
            ..Default::default()
        },
    ] {
        let mut request = reconcile_request(&case);
        request.carried = Some(carried);
        assert_eq!(
            reconcile(&request, &key(), &key_id()),
            Err("native_policy_integrity_tally_invalid")
        );
    }
}

#[test]
fn reconcile_refuses_an_unusable_request() {
    let case = case_named("pending_mixed");
    let mut request = reconcile_request(&case);
    request.trusted_state =
        json!({"cutover_complete": false, "generation": 3, "pending_generation": 2, "version": 1});
    assert_eq!(
        reconcile(&request, &key(), &key_id()),
        Err("native_policy_integrity_state_invalid")
    );
    let mut request = reconcile_request(&case);
    request.rows.push(json!("not a row"));
    assert_eq!(
        reconcile(&request, &key(), &key_id()),
        Err("native_policy_integrity_row_invalid")
    );
    let mut request = reconcile_request(&case);
    request.rows = vec![case["rows"][0].clone(); POLICY_INTEGRITY_RECONCILE_MAX_ROWS + 1];
    assert_eq!(
        reconcile(&request, &key(), &key_id()),
        Err("native_policy_integrity_rows_too_many_items")
    );
}

/// The reply's `reconcile` section is the op's answer, and the digest covers
/// the section so a reply cannot be replayed onto a different one.
#[test]
fn rows_op_answers_the_reconcile_section() {
    assert!(crate::resident_op_features::RESIDENT_OP_FEATURES
        .contains(&POLICY_INTEGRITY_RECONCILE_FEATURE));
    let case = case_named("pending_all_at_current");
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "request_id": "unit",
        "integrity_key_b64": Base64UrlUnpadded::encode_string(&key()),
        "integrity_key_id": vectors()["integrity_key_id"],
        "verify": [],
        "sign": [],
        "reconcile": serde_json::to_value(reconcile_request(&case)).unwrap(),
    }))
    .unwrap();
    let payload = serde_json::to_value(evaluate(&request).unwrap()).unwrap();
    assert_eq!(
        payload,
        json!({
            "verify": [],
            "sign": [],
            "reconcile": {"next_state": {
                "cutover_complete": false, "generation": 3, "pending_generation": null, "version": 1
            }},
        })
    );
}

#[test]
fn reconcile_without_key_fails_the_request() {
    let case = case_named("pending_mixed");
    let request: PolicyIntegrityRowsRequestV1 = serde_json::from_value(json!({
        "schema": POLICY_INTEGRITY_ROWS_REQUEST_SCHEMA,
        "verify": [],
        "sign": [],
        "reconcile": serde_json::to_value(reconcile_request(&case)).unwrap(),
    }))
    .unwrap();
    assert_eq!(
        evaluate(&request),
        Err("native_policy_integrity_key_unavailable")
    );
}
