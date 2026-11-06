//! `record_migration`: `_record_catalog_migrated_event_once`, written by the
//! resident.
//!
//! A protected read reports a catalog migration whose event the store does
//! not hold yet. The caller settles the migration's provenance outside any
//! store transaction, then asks the resident to record it. The resident takes
//! the migration from the committed head again inside one immediate
//! transaction, so the event is written once and only for the migration the
//! store actually holds.

use std::cell::RefCell;

use guard_contracts::{ExtensionControlAuthorityRequestV1, ExtensionControlMigrationRecordV1};
use serde_json::{json, Value};

use super::layers::layers_from_json;
use super::migrate::event_rows;
use super::records::{degraded, query_row, row_int, row_str, tampered, Res};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};

const INVALID: &str = "invalid extension control migration event request";

pub(super) fn record_migration_op(
    request: &ExtensionControlAuthorityRequestV1,
) -> Result<Value, String> {
    let Some(connection) = open_writer(request)? else {
        return Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    };
    let ctx = Ctx {
        connection: &connection,
        key: None,
        request,
        events: RefCell::new(Vec::new()),
    };
    Ok(immediate(&connection, || ctx.record_migration())
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

impl Ctx<'_> {
    fn record_migration(&self) -> Res<Value> {
        let (Some(revision), Some(catalog_digest), Some(occurred_at), Some(record)) = (
            self.request.revision,
            self.request.catalog_digest.as_deref(),
            self.request.now.as_deref(),
            self.request.migration_record.as_ref(),
        ) else {
            return Err(tampered(INVALID));
        };
        let unrecorded = || Ok(json!({ "recorded": false }));
        let Some(snapshot) = query_row(
            self.connection,
            "select revision, catalog_digest, layers_json from extension_control_authority_snapshot \
             where singleton = 1",
            [],
        )?
        else {
            return unrecorded();
        };
        if row_int(&snapshot, "revision")? != revision
            || row_str(&snapshot, "catalog_digest")? != catalog_digest
        {
            return unrecorded();
        }
        let layers = layers_from_json(&row_str(&snapshot, "layers_json")?)?;
        let Some(event) = self.catalog_migrated_backfill(revision, catalog_digest, &layers)? else {
            return unrecorded();
        };
        let retired_target_ids = event["retired_targets"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(Value::as_str)
            .map(str::to_owned)
            .collect();
        let rows = event_rows(
            (
                event["previous_revision"]
                    .as_i64()
                    .ok_or_else(|| tampered(INVALID))?,
                revision,
            ),
            (
                event["previous_catalog_digest"]
                    .as_str()
                    .ok_or_else(|| tampered(INVALID))?,
                catalog_digest,
            ),
            &layers,
            &ExtensionControlMigrationRecordV1 {
                retired_target_ids,
                ..record.clone()
            },
        )?;
        self.insert_migration_events(&rows, occurred_at)?;
        Ok(json!({ "recorded": true }))
    }
}

#[cfg(test)]
#[path = "migration_event_tests.rs"]
mod tests;
