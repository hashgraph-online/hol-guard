//! Guard connect state: the pairing record, the sync milestones and their
//! proof document. Python passes every instant and the request identifier; the
//! status vocabulary, the request-expiry transition and the proof merge are
//! decided here. Connect state is display data for the connect flow, never an
//! authority input.

use rusqlite::Connection;
use serde::de::{Deserialize, Deserializer, MapAccess, Visitor};
use serde_json::{Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_connect_effective as effective;
use crate::guard_store_db::{exec, query_one, text, StoreError, StoreResult};
use crate::guard_store_json::{dumps_default, epoch_micros, py_repr_str, py_str, py_strip};

pub(crate) const STATE_VERSION: &str = "guard-connect-state.v1";
const STATUSES: [&str; 4] = ["waiting", "connected", "retry_required", "expired"];
const MILESTONES: [&str; 6] = [
    "waiting_for_browser",
    "first_sync_pending",
    "first_sync_succeeded",
    "first_sync_failed",
    "sync_not_available",
    "expired",
];
const COLUMNS: &str = "request_id, sync_url, allowed_origin, status, milestone, reason, \
     created_at, updated_at, expires_at, completed_at, proof_json";

pub(crate) fn handles(method: &str) -> bool {
    matches!(
        method,
        "guard_connect_latest_state"
            | "guard_connect_effective_state"
            | "guard_connect_record_pairing"
            | "guard_connect_record_sync_result"
    )
}

/// The two reads; they write only when an expiry must be persisted.
pub(crate) fn is_state_read(method: &str) -> bool {
    matches!(
        method,
        "guard_connect_latest_state" | "guard_connect_effective_state"
    )
}

pub(crate) fn dispatch(connection: &Connection, method: &str, args: &Args) -> StoreResult<Value> {
    match method {
        "guard_connect_latest_state" => Ok(latest_state(connection, Some(args.str("now")?))?
            .map_or(Value::Null, |state| state.into_value())),
        "guard_connect_effective_state" => effective::effective_state(connection, args),
        "guard_connect_record_pairing" => record_pairing(connection, args),
        "guard_connect_record_sync_result" => record_sync_result(connection, args),
        _ => Err(StoreError::Invalid("native_guard_store_method_unknown")),
    }
}

/// A JSON object that keeps key order, as `json.loads` does for a `dict`.
#[derive(Clone, Default)]
pub(crate) struct Proof(Vec<(String, Value)>);

impl<'de> Deserialize<'de> for Proof {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        struct Ordered;
        impl<'de> Visitor<'de> for Ordered {
            type Value = Proof;
            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON object")
            }
            fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Proof, A::Error> {
                let mut proof = Proof::default();
                while let Some((key, value)) = map.next_entry::<String, Value>()? {
                    proof.set(&key, value);
                }
                Ok(proof)
            }
        }
        deserializer.deserialize_map(Ordered)
    }
}

impl Proof {
    /// `_coerce_proof`: anything that is not a JSON object is an empty proof.
    pub(crate) fn parse(text: &str) -> Self {
        serde_json::from_str(text).unwrap_or_default()
    }

    pub(crate) fn get(&self, key: &str) -> Option<&Value> {
        self.0
            .iter()
            .find(|(name, _)| name == key)
            .map(|(_, value)| value)
    }

    pub(crate) fn set(&mut self, key: &str, value: Value) {
        match self.0.iter_mut().find(|(name, _)| name == key) {
            Some(entry) => entry.1 = value,
            None => self.0.push((key.to_owned(), value)),
        }
    }

    pub(crate) fn set_default(&mut self, key: &str, value: Value) {
        if self.get(key).is_none() {
            self.set(key, value);
        }
    }

    pub(crate) fn to_value(&self) -> Value {
        Value::Object(self.0.iter().cloned().collect())
    }

    /// `json.dumps(proof)`: insertion order, default separators, ASCII only.
    pub(crate) fn dumps(&self) -> StoreResult<String> {
        let mut out = String::from("{");
        for (index, (key, value)) in self.0.iter().enumerate() {
            if index > 0 {
                out.push_str(", ");
            }
            let encoded = dumps_default(&Value::String(key.clone()))
                .zip(dumps_default(value))
                .ok_or(StoreError::Invalid("native_guard_store_args_invalid"))?;
            out.push_str(&encoded.0);
            out.push_str(": ");
            out.push_str(&encoded.1);
        }
        out.push('}');
        Ok(out)
    }
}

/// A stored connect state with its proof in stored key order.
pub(crate) struct State {
    pub(crate) fields: Map<String, Value>,
    pub(crate) proof: Proof,
}

impl State {
    fn from_row(row: &crate::guard_store_db::Row) -> Self {
        let cell = |name: &str| row.get(name).and_then(py_str).unwrap_or_default();
        let opt = |name: &str| match row.get(name) {
            None | Some(Value::Null) => Value::Null,
            Some(value) => Value::from(py_str(value).unwrap_or_default()),
        };
        let proof = Proof::parse(text(row, "proof_json"));
        let status = cell("status");
        let mut fields = Map::new();
        for name in [
            "request_id",
            "sync_url",
            "allowed_origin",
            "status",
            "milestone",
            "created_at",
            "updated_at",
            "expires_at",
        ] {
            fields.insert(name.to_owned(), Value::from(cell(name)));
        }
        fields.insert("reason".to_owned(), opt("reason"));
        fields.insert("completed_at".to_owned(), opt("completed_at"));
        fields.insert("proof".to_owned(), proof.to_value());
        fields.insert("version".to_owned(), Value::from(STATE_VERSION));
        fields.insert(
            "poll_after_ms".to_owned(),
            Value::from(if status == "waiting" { 1500 } else { 0 }),
        );
        Self { fields, proof }
    }

    pub(crate) fn text(&self, name: &str) -> &str {
        self.fields.get(name).and_then(Value::as_str).unwrap_or("")
    }

    pub(crate) fn into_value(self) -> Value {
        Value::Object(self.fields)
    }
}

/// `_parse_timestamp` reports the text it handed to `fromisoformat`, which has
/// a trailing `Z` already rewritten to `+00:00`.
fn invalid_isoformat<T>(value: &str) -> StoreResult<T> {
    let seen = value
        .strip_suffix('Z')
        .map_or_else(|| value.to_owned(), |head| format!("{head}+00:00"));
    Err(StoreError::Value(format!(
        "Invalid isoformat string: {}",
        py_repr_str(&seen)
    )))
}

/// ISO instants as `datetime.fromisoformat` reads them, which also accepts a
/// comma as the fractional-second separator.
fn instant(value: &str) -> StoreResult<i128> {
    epoch_micros(&value.replace(',', ".")).map_or_else(|| invalid_isoformat(value), Ok)
}

/// Whether a state read has an expiry to persist. Only a waiting request past
/// its expiry writes; every other read stays lock-free. An unparseable
/// instant reports a write so the read raises the same error as before.
pub(crate) fn read_persists_expiry(connection: &Connection, args: &Args) -> StoreResult<bool> {
    let Some(row) = query_one(
        connection,
        "select status, milestone, expires_at from guard_connect_states \
         order by updated_at desc limit 1",
        &[],
    )?
    else {
        return Ok(false);
    };
    if text(&row, "status") != "waiting" || text(&row, "milestone") != "waiting_for_browser" {
        return Ok(false);
    }
    let now = args.str("now")?;
    Ok(match (instant(text(&row, "expires_at")), instant(now)) {
        (Ok(expires_at), Ok(now)) => expires_at <= now,
        _ => true,
    })
}

/// `load_connect_state`: reads one state; a waiting request past its expiry is
/// marked expired (with its pairing request) inside the same transaction.
pub(crate) fn load_state(
    connection: &Connection,
    request_id: &str,
    now: Option<&str>,
) -> StoreResult<Option<State>> {
    let sql = format!("select {COLUMNS} from guard_connect_states where request_id = ?");
    let params = [Value::from(request_id)];
    let Some(row) = query_one(connection, &sql, &params)? else {
        return Ok(None);
    };
    let state = State::from_row(&row);
    let Some(now) = now else {
        return Ok(Some(state));
    };
    if state.text("status") != "waiting" || state.text("milestone") != "waiting_for_browser" {
        return Ok(Some(state));
    }
    let expires_at = instant(state.text("expires_at"))?;
    if expires_at > instant(now)? {
        return Ok(Some(state));
    }
    exec(
        connection,
        "update guard_connect_states set status = 'expired', milestone = 'expired', \
         reason = 'request_expired', updated_at = ? where request_id = ?",
        &[Value::from(now), Value::from(request_id)],
    )?;
    exec(
        connection,
        "update guard_connect_requests set status = 'expired' \
         where request_id = ? and status = 'pending'",
        &params,
    )?;
    Ok(query_one(connection, &sql, &params)?.map(|row| State::from_row(&row)))
}

pub(crate) fn latest_state(
    connection: &Connection,
    now: Option<&str>,
) -> StoreResult<Option<State>> {
    let row = query_one(
        connection,
        "select request_id from guard_connect_states order by updated_at desc limit 1",
        &[],
    )?;
    match row {
        Some(row) => load_state(connection, text(&row, "request_id"), now),
        None => Ok(None),
    }
}

fn record_pairing(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let (request_id, now) = (args.str("request_id")?, args.str("now")?);
    let mut proof = Proof::default();
    proof.set("pairing_completed_at", Value::from(now));
    proof.set("first_synced_at", Value::Null);
    proof.set("receipts_stored", Value::from(0));
    proof.set("inventory_items", Value::from(0));
    proof.set("runtime_session_id", Value::Null);
    proof.set("runtime_session_synced_at", Value::Null);
    exec(
        connection,
        "insert into guard_connect_states (request_id, sync_url, allowed_origin, status, \
           milestone, reason, created_at, updated_at, expires_at, completed_at, proof_json) \
         values (?, ?, ?, 'connected', 'first_sync_pending', null, ?, ?, ?, ?, ?)",
        &[
            Value::from(request_id),
            Value::from(args.str("sync_url")?),
            Value::from(args.str("allowed_origin")?),
            Value::from(now),
            Value::from(now),
            Value::from(now),
            Value::from(now),
            Value::from(proof.dumps()?),
        ],
    )?;
    Ok(load_state(connection, request_id, Some(now))?
        .map_or_else(|| Value::Object(Map::new()), State::into_value))
}

/// `coerce_non_negative_int` over a decoded JSON value.
fn non_negative(value: Option<&Value>) -> Value {
    let count = match value {
        Some(Value::Number(number)) => number.as_i64().map(|n| n.max(0)),
        Some(Value::String(text)) => py_strip(text).parse::<i64>().ok().map(|n| n.max(0)),
        _ => None,
    };
    Value::from(count.unwrap_or(0))
}

fn merge_sync_payload(proof: &mut Proof, payload: &Map<String, Value>) {
    if let Some(value) = payload.get("synced_at") {
        proof.set("first_synced_at", value.clone());
    }
    if let Some(value) = payload.get("receipts_stored") {
        proof.set("receipts_stored", non_negative(Some(value)));
    }
    if payload.contains_key("inventory_tracked") || payload.contains_key("inventory") {
        let value = payload
            .get("inventory_tracked")
            .or_else(|| payload.get("inventory"));
        proof.set("inventory_items", non_negative(value));
    }
    for (source, target) in [
        ("runtime_session_id", "runtime_session_id"),
        ("runtime_session_synced_at", "runtime_session_synced_at"),
    ] {
        if let Some(value) = payload.get(source) {
            proof.set(target, value.clone());
        }
    }
}

fn persist_result(
    connection: &Connection,
    request_id: &str,
    args: &Args,
    now: &str,
) -> StoreResult<Value> {
    let (status, milestone) = (args.str("status")?, args.str("milestone")?);
    if !STATUSES.contains(&status) {
        return crate::guard_store_db::value_error("invalid_connect_state_status");
    }
    if !MILESTONES.contains(&milestone) {
        return crate::guard_store_db::value_error("invalid_connect_state_milestone");
    }
    let Some(mut state) = load_state(connection, request_id, Some(now))? else {
        return crate::guard_store_db::value_error("connect_state_not_found");
    };
    if let Some(payload) = args.opt_object("sync_payload")? {
        merge_sync_payload(&mut state.proof, payload);
    }
    exec(
        connection,
        "update guard_connect_states set status = ?, milestone = ?, reason = ?, \
         updated_at = ?, proof_json = ? where request_id = ?",
        &[
            Value::from(status),
            Value::from(milestone),
            args.opt_str("reason")?.map_or(Value::Null, Value::from),
            Value::from(now),
            Value::from(state.proof.dumps()?),
            Value::from(request_id),
        ],
    )?;
    Ok(load_state(connection, request_id, Some(now))?
        .map_or_else(|| Value::Object(Map::new()), State::into_value))
}

fn record_sync_result(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let now = args.str("now")?;
    let supplied = args.opt_str("request_id")?;
    let explicit = supplied.map(py_strip).filter(|id| !id.is_empty());
    let latest = match explicit {
        Some(id) => load_state(connection, id, Some(now))?,
        None => {
            let row = query_one(
                connection,
                "select request_id from guard_connect_states \
                 where status in ('connected', 'retry_required') \
                 order by updated_at desc limit 1",
                &[],
            )?;
            let Some(row) = row else {
                return Ok(Value::Null);
            };
            load_state(connection, text(&row, "request_id"), Some(now))?
        }
    };
    let Some(latest) = latest else {
        return Ok(Value::Null);
    };
    let status = latest.text("status");
    if !matches!(status, "connected" | "retry_required") {
        return Ok(latest.into_value());
    }
    if supplied.is_none() && status != "connected" {
        return Ok(latest.into_value());
    }
    persist_result(connection, latest.text("request_id"), args, now)
}

#[cfg(test)]
mod instant_tests {
    use super::instant;

    #[test]
    fn comma_and_period_fractions_are_the_same_instant() {
        assert_eq!(
            instant("2025-01-01T00:00:00,123456+00:00").ok(),
            instant("2025-01-01T00:00:00.123456+00:00").ok()
        );
        assert!(instant("2025-01-01T00:00:00,123456+00:00").is_ok());
        assert!(instant("not a time").is_err());
    }
}
