//! `list_extension_control_authority_history`: the authenticated, privacy-safe
//! snapshots committed before the current one, for the current catalog.

use rusqlite::params;
use serde_json::{json, Value};

use super::layers::{
    layers_from_json, layers_to_values, validate_layers, validate_serialized_layers,
};
use super::records::{query_rows, row_int, row_str, tampered, Phase, Res, Row};
use super::{Ctx, View, PROTECTED};

const MAX_HISTORY_LIMIT: i64 = 50;

fn entry(row: &Row, catalog_digest: &str) -> Res<Value> {
    let layers_json = row_str(row, "layers_json")?;
    validate_serialized_layers(&layers_json)?;
    let layers = layers_from_json(&layers_json)?;
    validate_layers(&layers, catalog_digest)?;
    let occurred_at = match row.get("committed_at") {
        Some(rusqlite::types::Value::Null) => None,
        _ => Some(row_str(row, "committed_at")?).filter(|text| !text.is_empty()),
    };
    Ok(json!({
        "revision": row_int(row, "revision")?,
        "previous_revision": row_int(row, "previous_revision")?,
        "occurred_at": match occurred_at {
            Some(text) => text,
            None => row_str(row, "created_at")?,
        },
        "catalog_digest": catalog_digest,
        "layers": layers_to_values(&layers),
    }))
}

impl Ctx<'_> {
    /// `history`: the caller read `view` under the lease it still holds.
    pub(super) fn history(&self) -> Res<Value> {
        let limit = self
            .request
            .limit
            .filter(|limit| (1..=MAX_HISTORY_LIMIT).contains(limit))
            .ok_or_else(|| tampered("invalid extension control history limit"))?;
        let catalog_digest = self.catalog_digest()?;
        let current = View::from_value(self.request.view.as_ref())?;
        if current.health != PROTECTED {
            return Err(tampered("extension control history unavailable"));
        }
        if current.revision <= 0 {
            return Ok(json!({ "history": [] }));
        }
        let key = self.require_key()?;
        let anchor = self
            .request
            .anchor_json
            .as_deref()
            .map(|text| super::records::parse_anchor(text, key))
            .transpose()?;
        let Some(anchor) = anchor.filter(|anchor| {
            anchor.phase == Phase::Committed && anchor.revision == current.revision
        }) else {
            return Err(tampered("extension control history anchor mismatch"));
        };
        self.validate_transition_chain(current.revision, &anchor.snapshot_digest)?;
        let rows = query_rows(
            self.connection,
            "select * from extension_control_authority_transition
             where phase = ? and catalog_digest = ? and revision < ?
             order by revision desc limit ?",
            params![
                Phase::Committed.as_str(),
                catalog_digest,
                current.revision,
                limit
            ],
        )?;
        let history = rows
            .iter()
            .map(|row| entry(row, catalog_digest))
            .collect::<Res<Vec<_>>>()?;
        Ok(json!({ "history": history }))
    }
}
