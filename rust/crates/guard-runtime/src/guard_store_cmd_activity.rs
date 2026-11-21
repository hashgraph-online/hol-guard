//! Transactional persistence of command activity evidence: one logical
//! command with its rule hits, correlations, optional invocation preview and
//! shadow observation, rolled up in the same transaction.

use rusqlite::Connection;
use serde_json::{json, Map, Value};

use crate::guard_store_args::Args;
use crate::guard_store_cmd_lifecycle::recover;
use crate::guard_store_cmd_rollups::record_insert;
use crate::guard_store_cmd_wire::{
    column_values, row_equals, rows_equal, text_of, Evidence, ACTIVITY_COLUMNS,
    CORRELATION_COLUMNS, MATCH_COLUMNS, SHADOW_COLUMNS,
};
use crate::guard_store_db::{exec, query_all, query_one, value_error, StoreError, StoreResult};

const INVALID: StoreError = StoreError::Invalid("native_guard_store_args_invalid");

fn insert_rows(connection: &Connection, sql: &str, rows: &[Vec<Value>]) -> StoreResult<()> {
    for row in rows {
        exec(connection, sql, row)?;
    }
    Ok(())
}

fn shadow_cohorts(shadow: &Map<String, Value>) -> StoreResult<Vec<Vec<Value>>> {
    let id = shadow.get("activity_id").cloned().unwrap_or(Value::Null);
    Ok(shadow
        .get("cohorts")
        .and_then(Value::as_array)
        .ok_or(INVALID)?
        .iter()
        .enumerate()
        .map(|(ordinal, cohort)| vec![id.clone(), Value::from(ordinal), cohort.clone()])
        .collect())
}

/// Insert one shadow observation; `false` for an exact replay.
fn record_shadow(connection: &Connection, shadow: &Map<String, Value>) -> StoreResult<bool> {
    let activity_id = text_of(shadow, "activity_id")?;
    let values = column_values(shadow, &SHADOW_COLUMNS)?;
    let cohorts = shadow_cohorts(shadow)?;
    let existing = query_one(
        connection,
        "select * from command_activity_shadow_evaluations where activity_id = ?",
        &[Value::from(activity_id)],
    )?;
    if let Some(existing) = existing {
        let persisted = query_all(
            connection,
            "select * from command_activity_shadow_cohorts where activity_id = ? order by ordinal",
            &[Value::from(activity_id)],
        )?;
        if !row_equals(&existing, &SHADOW_COLUMNS, &values)
            || !rows_equal(&persisted, &["activity_id", "ordinal", "cohort"], &cohorts)
        {
            return value_error("command shadow replay conflicts with persisted evidence");
        }
        return Ok(false);
    }
    exec(
        connection,
        "insert into command_activity_shadow_evaluations ( \
         activity_id, occurred_at, authoritative_action, current_action, current_disposition, \
         proposed_action, proposed_disposition, comparison, proposal_version, \
         evaluator_schema_version, control_generation, sample_basis_points, schema_version \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &values,
    )?;
    insert_rows(
        connection,
        "insert into command_activity_shadow_cohorts (activity_id, ordinal, cohort) \
         values (?, ?, ?)",
        &cohorts,
    )?;
    Ok(true)
}

fn require_exact_replay(
    connection: &Connection,
    evidence: &Evidence,
    existing: &Map<String, Value>,
) -> StoreResult<()> {
    let id = [Value::from(evidence.activity_id()?)];
    let matches = query_all(
        connection,
        "select * from command_activity_matches where activity_id = ? order by ordinal",
        &id,
    )?;
    let correlations = query_all(
        connection,
        "select * from command_activity_correlations where activity_id = ? order by kind",
        &id,
    )?;
    let effects = query_all(
        connection,
        "select * from command_activity_match_effects where activity_id = ? \
         order by ordinal, effect_class",
        &id,
    )?;
    let same = row_equals(existing, &ACTIVITY_COLUMNS, &evidence.activity_values()?)
        && rows_equal(&matches, &MATCH_COLUMNS, &evidence.match_values()?)
        && rows_equal(
            &effects,
            &["activity_id", "ordinal", "effect_class"],
            &evidence.effect_values()?,
        )
        && rows_equal(
            &correlations,
            &CORRELATION_COLUMNS,
            &evidence.correlation_values()?,
        );
    if same {
        Ok(())
    } else {
        value_error("conflicting command activity replay")
    }
}

fn record_new(
    connection: &Connection,
    evidence: &Evidence,
    shadow: Option<&Map<String, Value>>,
    shadow_succeeded: bool,
    preview: Option<&str>,
) -> StoreResult<()> {
    exec(
        connection,
        "insert into command_activity ( \
         activity_id, occurred_at, harness, hook_phase, execution_status, \
         proof_level, policy_action, decision_reason_code, controlling_rule_id, \
         parse_confidence, uncertainty_class, match_count, prompted, \
         approval_reuse_status, receipt_link_status, receipt_id, \
         evaluation_latency_bucket, persistence_latency_bucket, schema_version \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &evidence.activity_values()?,
    )?;
    if let Some(preview) = preview {
        exec(
            connection,
            "insert into command_activity_invocation (activity_id, invocation_preview) values (?, ?)",
            &[Value::from(evidence.activity_id()?), Value::from(preview)],
        )?;
    }
    insert_rows(
        connection,
        "insert into command_activity_matches ( \
         activity_id, ordinal, extension_id, extension_version, rule_id, \
         rule_version, match_class, severity, default_floor, \
         safe_variant_id, schema_version \
         ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        &evidence.match_values()?,
    )?;
    insert_rows(
        connection,
        "insert into command_activity_match_effects (activity_id, ordinal, effect_class) \
         values (?, ?, ?)",
        &evidence.effect_values()?,
    )?;
    insert_rows(
        connection,
        "insert into command_activity_correlations (activity_id, kind, harness, key_id, digest) \
         values (?, ?, ?, ?, ?)",
        &evidence.correlation_values()?,
    )?;
    if let Some(shadow) = shadow {
        record_shadow(connection, shadow)?;
    }
    let rule_hits = evidence
        .matches
        .iter()
        .map(|item| {
            Ok((
                text_of(item, "extension_id")?.to_owned(),
                text_of(item, "rule_id")?.to_owned(),
            ))
        })
        .collect::<StoreResult<Vec<_>>>()?;
    record_insert(connection, evidence.activity, &rule_hits)?;
    recover(connection, "command")?;
    if shadow.is_some() || shadow_succeeded {
        recover(connection, "shadow")?;
    }
    Ok(())
}

fn shadow_arg<'a>(args: &Args<'a>) -> StoreResult<Option<&'a Map<String, Value>>> {
    args.opt_object("shadow")
}

pub(crate) fn record_command_activity(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let evidence = Evidence::from_args(args)?;
    let shadow = shadow_arg(args)?;
    let preview = args.opt_str("invocation_preview")?;
    let id = [Value::from(evidence.activity_id()?)];
    if let Some(existing) = query_one(
        connection,
        "select * from command_activity where activity_id = ?",
        &id,
    )? {
        require_exact_replay(connection, &evidence, &existing)?;
        if let Some(shadow) = shadow {
            let present = query_one(
                connection,
                "select 1 as present from command_activity_shadow_evaluations where activity_id = ?",
                &[Value::from(text_of(shadow, "activity_id")?)],
            )?;
            if present.is_none() {
                return value_error("command shadow replay is missing persisted evidence");
            }
            record_shadow(connection, shadow)?;
        }
        return Ok(json!(false));
    }
    let rolled = query_one(
        connection,
        "select 1 as present from command_activity_rollup_membership where activity_id = ?",
        &id,
    )?;
    if rolled.is_some() {
        return Ok(json!(false));
    }
    record_new(
        connection,
        &evidence,
        shadow,
        args.flag("shadow_evaluation_succeeded")?,
        preview,
    )?;
    Ok(json!(true))
}

/// Exercise the real write path, then roll it back to a savepoint.
pub(crate) fn probe_persistence(connection: &Connection, args: &Args) -> StoreResult<Value> {
    let evidence = Evidence::from_args(args)?;
    let shadow = shadow_arg(args)?;
    let succeeded = args.flag("shadow_evaluation_succeeded")?;
    connection.execute_batch("savepoint command_activity_repair_probe")?;
    if let Err(error) = record_new(connection, &evidence, shadow, succeeded, None) {
        connection.execute_batch(
            "rollback to command_activity_repair_probe; release command_activity_repair_probe",
        )?;
        return Err(error);
    }
    connection.execute_batch(
        "rollback to command_activity_repair_probe; release command_activity_repair_probe",
    )?;
    recover(connection, "command")?;
    if shadow.is_some() || succeeded {
        recover(connection, "shadow")?;
    }
    Ok(Value::Null)
}
