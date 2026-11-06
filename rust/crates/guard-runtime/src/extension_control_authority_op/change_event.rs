//! `queue_change`: explicit recovery's change event, queued by the resident.
//!
//! Once `recover_extension_control_authority` has confirmed the committed
//! head and read it back protected, the change that head records is queued
//! as a cloud event, from that revision's committed row, inside one immediate
//! transaction. The read may have migrated the catalog past that head since,
//! so the snapshot is not required to name it still.

use std::cell::RefCell;

use guard_contracts::ExtensionControlAuthorityRequestV1;
use rusqlite::params;
use serde_json::{json, Value};

use super::records::{degraded, query_row, tampered, Phase, Res};
use super::resume::immediate;
use super::writes::open_writer;
use super::{fault_value, Ctx, STORE_UNAVAILABLE};

const HEAD_MISMATCH: &str = "extension control transition head mismatch";

pub(super) fn queue_change_op(
    request: &ExtensionControlAuthorityRequestV1,
    key: Option<&[u8]>,
) -> Result<Value, String> {
    let Some(connection) = open_writer(request)? else {
        return Ok(fault_value(&degraded(STORE_UNAVAILABLE), Vec::new()));
    };
    let ctx = Ctx {
        connection: &connection,
        key,
        request,
        events: RefCell::new(Vec::new()),
    };
    Ok(ctx
        .queue_committed_change()
        .unwrap_or_else(|fault| fault_value(&fault, Vec::new())))
}

impl Ctx<'_> {
    fn queue_committed_change(&self) -> Res<Value> {
        let revision = self
            .request
            .revision
            .filter(|revision| *revision > 0)
            .ok_or_else(|| tampered(HEAD_MISMATCH))?;
        immediate(self.connection, || {
            let row = query_row(
                self.connection,
                "select * from extension_control_authority_transition
                 where revision = ? and phase = ?",
                params![revision, Phase::Committed.as_str()],
            )?
            .ok_or_else(|| tampered("committed transition missing"))?;
            self.queue_change_event(&row)
        })?;
        Ok(json!({"queued": revision}))
    }
}

#[cfg(test)]
#[path = "change_event_tests.rs"]
mod tests;
