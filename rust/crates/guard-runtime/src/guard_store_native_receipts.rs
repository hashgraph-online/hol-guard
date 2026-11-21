//! `store_native_decision_receipts.record_native_decision_receipt`.
//!
//! The receipt crosses the wire as the JSON text the caller holds, not as a
//! structure the transport has already reshaped: its decision ID commits to a
//! canonical encoding of its own fields, so those bytes have to reach the
//! validator unchanged. `pyjson::parse` returns the value `json.loads` would,
//! and `native_decision_receipt::valid` is the ported validator.
//!
//! Python detaches the receipt after validating it — `json.loads(json.dumps(
//! validated))` — because its caller still holds the nested `command_extensions`
//! mapping and could mutate it between the check and the insert. Here the
//! receipt is parsed from text this op owns and nothing else can reach, so
//! there is nothing to detach from.

use rusqlite::Connection;
use serde_json::Value;

use crate::guard_store_args::Args;
use crate::guard_store_db::{exec, placeholders, StoreError, StoreResult};
use crate::native_decision_receipt::{dumps_sorted, valid};
use crate::pyjson::{self, PyVal};

/// `raise ValueError("native decision receipt is invalid")`.
fn invalid() -> StoreError {
    StoreError::Value("native decision receipt is invalid".to_owned())
}

/// The columns both tables share, in the order `row` binds them. The prompt
/// table adds `prompt_risk_classes_json` after `recorded_at`, as the Python
/// statement builds it.
const COLUMNS: &str = "decision_id, schema, version, authority, request_id, \
                       request_digest, harness, event_name, payload_kind, \
                       policy_generation, policy_digest, rule_digest, \
                       runtime_identity, decision, model_output_action, \
                       policy_action, observed_policy_action, reason_code, \
                       workspace_bound, source_ref_external_allowed, \
                       reviewed_output_sha256, observe_mode, deadline_budget_ms, \
                       command_extensions_json, recorded_at";

pub(crate) fn record_native_decision_receipt(
    connection: &Connection,
    args: &Args<'_>,
) -> StoreResult<Value> {
    let receipt = pyjson::parse(args.str("receipt")?).map_err(|_| invalid())?;
    if !valid(&receipt) {
        return Err(invalid());
    }
    let mut params = row(&receipt, args.str("now")?);
    let (table, columns) = if text(&receipt, "event_name") == Some("UserPromptSubmit") {
        // Python writes `validated.get("prompt_risk_classes", [])`, so a prompt
        // receipt that declared none still gets a row rather than a null.
        let classes = receipt
            .get("prompt_risk_classes")
            .cloned()
            .unwrap_or_else(|| PyVal::List(Vec::new()));
        params.push(Value::from(dumps_sorted(&classes, true)));
        (
            "native_prompt_decision_receipts",
            format!("{COLUMNS}, prompt_risk_classes_json"),
        )
    } else {
        ("native_hook_decision_receipts", COLUMNS.to_owned())
    };
    exec(
        connection,
        &format!(
            "insert or ignore into {table} ({columns}) values ({})",
            placeholders(params.len())
        ),
        &params,
    )?;
    Ok(Value::Null)
}

/// The bound parameters, in the order `COLUMNS` names them.
fn row(receipt: &PyVal, now: &str) -> Vec<Value> {
    vec![
        string_value(receipt, "decision_id"),
        string_value(receipt, "schema"),
        number_value(receipt, "version"),
        string_value(receipt, "authority"),
        string_value(receipt, "request_id"),
        string_value(receipt, "request_digest"),
        string_value(receipt, "harness"),
        string_value(receipt, "event_name"),
        string_value(receipt, "payload_kind"),
        number_value(receipt, "policy_generation"),
        string_value(receipt, "policy_digest"),
        string_value(receipt, "rule_digest"),
        string_value(receipt, "runtime_identity"),
        string_value(receipt, "decision"),
        string_value(receipt, "model_output_action"),
        string_value(receipt, "policy_action"),
        string_value(receipt, "observed_policy_action"),
        string_value(receipt, "reason_code"),
        flag_value(receipt, "workspace_bound"),
        flag_value(receipt, "source_ref_external_allowed"),
        string_value(receipt, "reviewed_output_sha256"),
        flag_value(receipt, "observe_mode"),
        number_value(receipt, "deadline_budget_ms"),
        match receipt.get("command_extensions") {
            Some(binding) => Value::from(dumps_sorted(binding, true)),
            None => Value::Null,
        },
        Value::from(now),
    ]
}

fn text<'a>(receipt: &'a PyVal, name: &str) -> Option<&'a str> {
    receipt.get(name).and_then(PyVal::as_str)
}

fn string_value(receipt: &PyVal, name: &str) -> Value {
    text(receipt, name).map_or(Value::Null, Value::from)
}

/// `version` is checked with `== 1`, which a bool or a float can satisfy, so
/// the stored cell keeps whichever of the three Python would have bound. The
/// validator bounds the two true integers inside `i64`, so no digit string
/// reaching here can be too long to fit.
fn number_value(receipt: &PyVal, name: &str) -> Value {
    match receipt.get(name) {
        Some(PyVal::Int(digits)) => digits.parse::<i64>().map_or(Value::Null, Value::from),
        Some(PyVal::Bool(flag)) => Value::from(*flag),
        Some(PyVal::Float(number)) => Value::from(*number),
        _ => Value::Null,
    }
}

/// `int(cast_bool(...))`: the validator has already refused anything but a
/// bool in these three fields.
fn flag_value(receipt: &PyVal, name: &str) -> Value {
    Value::from(i64::from(matches!(
        receipt.get(name),
        Some(PyVal::Bool(true))
    )))
}
