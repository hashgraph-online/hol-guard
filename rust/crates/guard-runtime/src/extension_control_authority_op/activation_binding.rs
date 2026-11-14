//! The catalog of the command-pack activation the authority head is sealed to.
//!
//! A runtime reading with a catalog other than the stored one may migrate the
//! head to its own. When that runtime is an older install still running
//! beside an upgraded one, the migration moves the head off the catalog its
//! own pack activation names, and the next installed upgrade, which plans
//! from the activation, finds a source it cannot migrate. The read uses this
//! binding to keep the head on the activation's catalog.

use serde_json::Value;

use super::records::{canonical, query_row, row_text, sha256_hex, snapshot_pack_binding, Res};
use super::Ctx;

impl Ctx<'_> {
    /// The activation's catalog, when the stored head's sealed pack binding
    /// names the exact activation record on disk. `None` when the head binds
    /// no pack, the store has no activation, or the record is another one.
    pub(super) fn bound_activation_catalog(&self) -> Res<Option<String>> {
        let Some(snapshot) = self.snapshot_row()? else {
            return Ok(None);
        };
        let Some(bound) = snapshot_pack_binding(&snapshot, self.require_key()?)? else {
            return Ok(None);
        };
        let has_activation = query_row(
            self.connection,
            "select 1 as present from sqlite_master where type = 'table' \
             and name = 'extension_command_pack_activation'",
            [],
        )?
        .is_some();
        if !has_activation {
            return Ok(None);
        }
        let Some(row) = query_row(
            self.connection,
            "select record_json, record_digest from extension_command_pack_activation \
             where singleton = 1",
            [],
        )?
        else {
            return Ok(None);
        };
        // The snapshot seal authenticates the digest; the digest authenticates
        // the canonical record it was computed over.
        let record = row_text(&row, "record_json")?;
        if row_text(&row, "record_digest")? != bound || sha256_hex(&record) != bound {
            return Ok(None);
        }
        let Ok(value) = serde_json::from_str::<Value>(&record) else {
            return Ok(None);
        };
        if canonical(&value).ok().as_deref() != Some(record.as_str()) {
            return Ok(None);
        }
        Ok(value
            .get("catalog_digest")
            .and_then(Value::as_str)
            .map(str::to_owned))
    }
}
