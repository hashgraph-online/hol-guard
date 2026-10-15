//! Atomic continuation lease and durable evidence finalization.
use crate::guard_store_db::{exec, query_one, runtime_error, value_error, StoreError, StoreResult};
use rusqlite::{Connection, OpenFlags, TransactionBehavior};
use serde_json::{json, Value};

fn string<'a>(args: &'a Value, key: &str) -> StoreResult<&'a str> {
    args[key]
        .as_str()
        .ok_or(StoreError::Invalid("continuation_argument_invalid"))
}
pub(crate) fn claim_check(args: &Value) -> Value {
    let row = &args["row"];
    let claim = &args["claim_id"];
    if !claim.is_null() {
        if row["state"] == "completed" {
            return json!({"allowed":false});
        }
        if row.is_null() || row["state"] != "claimed" || row["claim_id"] != *claim {
            return json!({"error":"continuation claim ownership changed before finalization"});
        }
    }
    json!({"allowed":row.is_null() || row["state"] != "completed" || row["evidence_id"].is_null() || row["evidence_id"] == args["evidence_id"]})
}
pub(crate) fn evaluate(args: &Value) -> super::runner_authority_op::KindResult {
    match run(args) {
        Ok(value) => Ok(value),
        Err(StoreError::Runtime(message)) => {
            Ok(json!({"error":message,"exception":"RuntimeError"}))
        }
        Err(StoreError::Value(message)) => Ok(json!({"error":message,"exception":"ValueError"})),
        Err(StoreError::Sqlite(error)) => {
            let class = sqlite_exception(&error);
            let code = if let rusqlite::Error::SqliteFailure(code, _) = &error {
                Some(code.extended_code)
            } else {
                None
            };
            let prefix = code.and_then(|code| {
                [
                    "SQLITE_OK",
                    "SQLITE_ERROR",
                    "SQLITE_INTERNAL",
                    "SQLITE_PERM",
                    "SQLITE_ABORT",
                    "SQLITE_BUSY",
                    "SQLITE_LOCKED",
                    "SQLITE_NOMEM",
                    "SQLITE_READONLY",
                    "SQLITE_INTERRUPT",
                    "SQLITE_IOERR",
                    "SQLITE_CORRUPT",
                    "SQLITE_NOTFOUND",
                    "SQLITE_FULL",
                    "SQLITE_CANTOPEN",
                    "SQLITE_PROTOCOL",
                    "SQLITE_EMPTY",
                    "SQLITE_SCHEMA",
                    "SQLITE_TOOBIG",
                    "SQLITE_CONSTRAINT",
                    "SQLITE_MISMATCH",
                    "SQLITE_MISUSE",
                    "SQLITE_NOLFS",
                    "SQLITE_AUTH",
                    "SQLITE_FORMAT",
                    "SQLITE_RANGE",
                    "SQLITE_NOTADB",
                    "SQLITE_NOTICE",
                    "SQLITE_WARNING",
                ]
                .get((code & 0xff) as usize)
                .copied()
            });
            Ok(
                json!({"exception":class,"error":error.to_string(),"sqlite_errorcode":code,"sqlite_errorname_prefix":prefix}),
            )
        }
        Err(_) => Err("native_runner_authority_continuation_store_unavailable"),
    }
}
fn sqlite_exception(error: &rusqlite::Error) -> &'static str {
    // CPython Modules/_sqlite/util.c selects by the primary SQLite result code.
    let rusqlite::Error::SqliteFailure(code, _) = error else {
        return "sqlite3.DatabaseError";
    };
    match code.extended_code & 0xff {
        2 | 12 => "sqlite3.InternalError",
        7 => "MemoryError",
        1 | 3 | 4 | 5 | 6 | 8 | 9 | 10 | 13 | 14 | 15 | 16 | 17 => "sqlite3.OperationalError",
        18 => "sqlite3.DataError",
        19 | 20 => "sqlite3.IntegrityError",
        21 | 25 => "sqlite3.InterfaceError",
        _ => "sqlite3.DatabaseError",
    }
}
fn wake_database_key(path: &str) -> String {
    if let Some(unc) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{unc}")
    } else {
        path.strip_prefix(r"\\?\").unwrap_or(path).to_owned()
    }
}
fn run(args: &Value) -> StoreResult<Value> {
    let home = string(args, "guard_home")?;
    let path = crate::local_store_read::require_store_path(string(args, "store_path")?, home)
        .map_err(|_| StoreError::Invalid("continuation_store_path_invalid"))?;
    let canonical = std::fs::canonicalize(&path)
        .map_err(|_| StoreError::Invalid("continuation_store_path_invalid"))?;
    let database_key = wake_database_key(&canonical.to_string_lossy());
    let mut connection = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_WRITE | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    connection.busy_timeout(std::time::Duration::from_millis(
        args["busy_timeout_ms"]
            .as_u64()
            .unwrap_or(1000)
            .clamp(1, 10000),
    ))?;
    let material = if !args["approval_decision"].is_null() {
        let home = std::path::Path::new(home);
        let resolved = std::fs::canonicalize(home).unwrap_or_else(|_| home.to_path_buf());
        let mut secrets = crate::encrypted_secret_store::EncryptedFileSecretStore::new(&resolved);
        crate::policy_integrity_resolver::resolve_integrity_state(&mut secrets, &resolved).0
    } else {
        None
    };
    let tx = connection.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let output = match string(args, "call")? {
        "store_claim" => claim(&tx, args)?,
        "store_finalize" => {
            if !args["approval_decision"].is_null() {
                let Some(material) = material else {
                    return Ok(json!({"finalized":false}));
                };
                if !crate::continuation_grants::consume(
                    &tx,
                    string(args, "request_id")?,
                    &args["approval_decision"],
                    string(args, "now")?,
                    material.raw_key.as_slice(),
                    &material.key_id,
                )? {
                    return Ok(json!({"finalized":false}));
                }
            }
            finalize(&tx, args)?
        }
        _ => return Err(StoreError::Invalid("continuation_call_invalid")),
    };
    if output.get("finalized") == Some(&Value::Bool(false)) {
        return Ok(output);
    }
    let changes = tx.total_changes();
    tx.commit()?;
    let mut output = output;
    output["database_key"] = json!(database_key);
    output["outbox_generation"] = if changes > 0 {
        let exists = query_one(&connection,"select name from sqlite_master where type='table' and name='guard_review_outbox_wake_state'",&[])?;
        if exists.is_some() {
            query_one(
                &connection,
                "select generation from guard_review_outbox_wake_state where singleton=1",
                &[],
            )?
            .and_then(|row| row.get("generation").cloned())
            .unwrap_or(json!(0))
        } else {
            json!(0)
        }
    } else {
        Value::Null
    };
    Ok(output)
}
fn claim(connection: &Connection, args: &Value) -> StoreResult<Value> {
    let now = string(args, "now")?;
    if crate::guard_store_json::add_seconds_isoformat(now, 0).is_none() {
        return value_error(&format!(
            "Invalid isoformat string: {}",
            crate::guard_store_json::py_repr_str(now)
        ));
    }
    if !crate::continuation_authority_op::has_time_zone(now) {
        return value_error("continuation claim timestamp must be timezone-aware");
    }
    let seconds = args["lease_seconds"]
        .as_f64()
        .ok_or(StoreError::Invalid("continuation_lease_invalid"))?;
    if seconds <= 0.0 {
        return value_error("continuation claim lease must be positive");
    }
    let micros = (seconds * 1_000_000.0).round_ties_even();
    if !micros.is_finite() || micros < i64::MIN as f64 || micros >= i64::MAX as f64 {
        return value_error("continuation claim lease is out of range");
    }
    let expiry = crate::guard_store_json::add_seconds_isoformat(now, micros as i64)
        .ok_or(StoreError::Invalid("continuation_time_invalid"))?;
    let keys = [
        args["request_id"].clone(),
        args["offer_hash"].clone(),
        args["action"].clone(),
    ];
    if let Some(row) = query_one(connection,"select state, lease_expires_at from guard_continuation_claims where request_id = ? and offer_hash = ? and action = ?",&keys)? {
        if matches!(row.get("state").and_then(Value::as_str),Some("completed"|"waiting")) {return Ok(json!({"claim_id":Value::Null}));}
        if row.get("state").and_then(Value::as_str) == Some("claimed") {
            if let Some(value) = row.get("lease_expires_at").filter(|v|!v.is_null()) {
                let text = crate::guard_store_json::py_str(value).ok_or(StoreError::Invalid("continuation_lease_invalid"))?;
                if crate::guard_store_json::add_seconds_isoformat(&text,0).is_none() {
                    return value_error(&format!("Invalid isoformat string: {}",crate::guard_store_json::py_repr_str(&text)));
                }
                if crate::continuation_authority_op::has_time_zone(&text) && guard_contracts::utc_timestamp_micros(&text).zip(guard_contracts::utc_timestamp_micros(now)).is_some_and(|(end,start)|end > start) {return Ok(json!({"claim_id":Value::Null}));}
            }
        }
    }
    let claim_id = string(args, "new_claim_id")?;
    exec(connection,"insert into guard_continuation_claims (request_id,offer_hash,action,state,claimed_at,lease_expires_at,claim_id,evidence_id) values (?,?,?,'claimed',?,?,?,null) on conflict(request_id,offer_hash,action) do update set state='claimed',claimed_at=excluded.claimed_at,lease_expires_at=excluded.lease_expires_at,claim_id=excluded.claim_id,evidence_id=null",
        &[keys[0].clone(),keys[1].clone(),keys[2].clone(),json!(now),json!(expiry),json!(claim_id)])?;
    Ok(json!({"claim_id":claim_id}))
}
fn finalize(connection: &Connection, args: &Value) -> StoreResult<Value> {
    let request_id = string(args, "request_id")?;
    let now = string(args, "now")?;
    let row = query_one(connection,"select state,claim_id,evidence_id from guard_continuation_claims where request_id = ? and offer_hash = ? and action = ?",
        &[json!(request_id),args["offer_hash"].clone(),args["action"].clone()])?;
    let check = claim_check(
        &json!({"row":row,"claim_id":args["claim_id"],"evidence_id":args["evidence_id"]}),
    );
    if let Some(error) = check["error"].as_str() {
        return runtime_error(error);
    }
    if check["allowed"] != true {
        return Ok(json!({"finalized":false}));
    }
    persist_resume(connection, args)?;
    exec(connection,"insert into guard_continuation_claims (request_id,offer_hash,action,state,claimed_at,lease_expires_at,claim_id,evidence_id) values (?,?,?,?,?,null,null,?) on conflict(request_id,offer_hash,action) do update set state=excluded.state,claimed_at=excluded.claimed_at,lease_expires_at=null,claim_id=null,evidence_id=excluded.evidence_id",
        &[json!(request_id),args["offer_hash"].clone(),args["action"].clone(),json!(if args["terminal"] == true {"completed"} else {"waiting"}),json!(now),args["evidence_id"].clone()])?;
    for event in args["events"]
        .as_array()
        .ok_or(StoreError::Invalid("continuation_events_invalid"))?
    {
        if event.as_array().is_none_or(|items| items.len() != 2) {
            return Err(StoreError::Invalid("continuation_event_invalid"));
        }
        let name = event[0]
            .as_str()
            .ok_or(StoreError::Invalid("continuation_event_invalid"))?;
        if effect(connection, args, name)? {
            exec(
                connection,
                "insert into guard_events (event_name,payload_json,occurred_at) values (?,?,?)",
                &[
                    json!(name),
                    json!(crate::guard_store_json::dumps_default(&event[1])
                        .ok_or(StoreError::Invalid("continuation_event_invalid"))?),
                    json!(now),
                ],
            )?;
        }
    }
    if args["terminal"] == true && effect(connection, args, "review.outbox.terminal")? {
        let result = &args["resume_update"];
        let status = result["continuation_status"].as_str().unwrap_or("");
        let correlation = result["continuation_evidence"][0]["correlationId"]
            .as_str()
            .unwrap_or("");
        if [
            status,
            correlation,
            result["continuation_capability"].as_str().unwrap_or(""),
            result["continuation_reason"].as_str().unwrap_or(""),
            result["continuation_completed_at"].as_str().unwrap_or(""),
        ]
        .contains(&"")
        {
            return value_error("terminal continuation result is incomplete");
        }
        if !matches!(
            status,
            "resumed"
                | "already_resumed"
                | "manual_retry_required"
                | "blocked_not_resumed"
                | "unsupported"
                | "failed"
        ) {
            return value_error("terminal continuation status is invalid");
        }
        let Some(request) = query_one(
            connection,
            "select oauth_source from approval_requests where request_id = ?",
            &[json!(request_id)],
        )?
        else {
            return value_error("terminal continuation request is missing");
        };
        let result = json!({"action":args["action"],"capability":result["continuation_capability"],"completedAt":result["continuation_completed_at"],"correlationId":correlation,"evidenceId":args["evidence_id"],"reason":result["continuation_reason"],"status":status});
        crate::guard_store_outbox_append::append_request_snapshot_event_with_continuation(
            connection,
            request_id,
            request["oauth_source"].as_str().unwrap_or("None"),
            &format!("review.continuation.{status}"),
            now,
            None,
            false,
            Some(&result),
        )?;
    }
    Ok(json!({"finalized":true}))
}
fn effect(connection: &Connection, args: &Value, name: &str) -> StoreResult<bool> {
    let evidence = string(args, "evidence_id")?;
    let hash = guard_policy_snapshot::digest_bytes(format!("{evidence}\0{name}").as_bytes());
    Ok(exec(connection,"insert or ignore into guard_continuation_effects (effect_key,request_id,evidence_id,event_name,created_at) values (?,?,?,?,?)",
        &[json!(hash),args["request_id"].clone(),json!(evidence),json!(name),args["now"].clone()])? != 0)
}
fn persist_resume(connection: &Connection, args: &Value) -> StoreResult<()> {
    let seed = &args["resume_seed"];
    let update = &args["resume_update"];
    let now = &args["now"];
    exec(connection,"insert into guard_request_resumes (request_id,operation_id,harness,resolution_action,strategy,supported,status,thread_id,reason,message,last_error,attempt_count,created_at,updated_at,last_attempt_at,sent_at) values (?,?,?,null,?,?,'pending',?,null,null,null,0,?,?,null,null) on conflict(request_id) do update set operation_id=excluded.operation_id,harness=excluded.harness,strategy=excluded.strategy,supported=excluded.supported,thread_id=coalesce(excluded.thread_id,guard_request_resumes.thread_id),updated_at=excluded.updated_at",
        &[args["request_id"].clone(),seed["operation_id"].clone(),seed["harness"].clone(),seed["strategy"].clone(),json!(i64::from(seed["supported"] == true)),seed["thread_id"].clone(),now.clone(),now.clone()])?;
    let fields = [
        "resolution_action",
        "strategy",
        "supported",
        "status",
        "reason",
        "message",
        "last_error",
        "attempt_count",
        "last_attempt_at",
        "sent_at",
        "continuation_contract_version",
        "continuation_capability",
        "continuation_status",
        "continuation_reason",
        "continuation_evidence",
        "continuation_offer_hash",
        "continuation_action",
        "continuation_completed_at",
        "continuation_cancelled_at",
    ];
    let mut values: Vec<Value> = fields.iter().map(|k| update[*k].clone()).collect();
    if !values[2].is_null() {
        values[2] = json!(i64::from(values[2] == true));
    }
    if !values[14].is_null() {
        values[14] = json!(crate::guard_store_json::dumps_sorted(&values[14])
            .ok_or(StoreError::Invalid("continuation_evidence_invalid"))?);
    }
    values.push(now.clone());
    values.push(args["request_id"].clone());
    exec(connection,"update guard_request_resumes set resolution_action=?,strategy=coalesce(?,strategy),supported=coalesce(?,supported),status=?,reason=?,message=?,last_error=?,attempt_count=?,last_attempt_at=?,sent_at=?,continuation_contract_version=coalesce(?,continuation_contract_version),continuation_capability=coalesce(?,continuation_capability),continuation_status=coalesce(?,continuation_status),continuation_reason=coalesce(?,continuation_reason),continuation_evidence_json=coalesce(?,continuation_evidence_json),continuation_offer_hash=coalesce(?,continuation_offer_hash),continuation_action=coalesce(?,continuation_action),continuation_completed_at=coalesce(?,continuation_completed_at),continuation_cancelled_at=coalesce(?,continuation_cancelled_at),updated_at=? where request_id=?",&values)?;
    let operation = &args["operation_update"];
    if !operation.is_null() {
        let mut metadata = operation["metadata"]
            .as_object()
            .cloned()
            .unwrap_or_default();
        let mut retained = false;
        if let Some(row) = query_one(
            connection,
            "select metadata_json from guard_operations where operation_id = ?",
            &[operation["operation_id"].clone()],
        )? {
            let existing = row["metadata_json"]
                .as_str()
                .map(crate::continuation_metadata::legacy_value)
                .unwrap_or(Value::Null);
            retained = crate::continuation_lineage::preserve(&existing, &mut metadata)?;
        }
        exec(connection,"update guard_operations set status=?,metadata_json=?,updated_at=? where operation_id=?",&[operation["status"].clone(),json!(crate::continuation_metadata::serialize(json!(metadata),&args["metadata_nonfinite"],retained)?),now.clone(),operation["operation_id"].clone()])?;
    }
    Ok(())
}

#[cfg(test)]
#[path = "continuation_store_tests.rs"]
mod tests;
