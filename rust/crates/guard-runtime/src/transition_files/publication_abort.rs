//! The failure path of a Codex hook config write, ported from the `except`
//! block of `CodexHarnessAdapter._write_authenticated_hook_config_owned`.
//!
//! Once the publication record exists, the durable inverse undoes it: the
//! config must still be the original or this writer's bytes and inode, or the
//! record is marked as a config conflict so a later recovery cannot restore
//! its participants over a replaced file. Request fields: `home`, `config`,
//! `prepared`, `original`, `written`, `original_identity`,
//! `written_identity` and `operation_id`. Answer: `{"durable": bool}`, plus
//! `rollback_error` when the inverse itself failed. A config conflict is the
//! fault.

use serde_json::{json, Value};

use super::inspect::decode;
use super::publication::{self, path_present, Call};
use super::publication_io::require_unchanged_for_rollback;
use super::Step;

pub(super) fn abort(call: &mut Call<'_>) -> Step<Value> {
    let home = call.home()?;
    let prepared = call.args.get("prepared").and_then(Value::as_bool) == Some(true);
    let durable = prepared || path_present(&Call::record_path(&home));
    if !durable {
        return Ok(json!({ "durable": false }));
    }
    let original = decode(call.args.get("original"))?;
    let written = decode(call.args.get("written"))?.unwrap_or_default();
    let unchanged = require_unchanged_for_rollback(
        &call.path("config")?,
        original.as_deref(),
        &written,
        call.args.get("original_identity").unwrap_or(&Value::Null),
        call.args.get("written_identity").unwrap_or(&Value::Null),
    );
    if let Err(conflict) = unchanged {
        // Persist the ownership refusal even for matching bytes.
        publication::mark_conflict(call)?;
        return Err(conflict);
    }
    Ok(match super::publication_commit::recover(call) {
        Ok(_) => json!({ "durable": true }),
        Err(fault) => json!({ "durable": true, "rollback_error": fault.to_json() }),
    })
}
