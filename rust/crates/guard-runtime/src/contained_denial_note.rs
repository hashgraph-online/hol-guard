//! `contained_denial_note` runner-authority kind: the note a failed
//! workspace-contained run gets when its output names a denial.
//!
//! The Python sandboxes ask here so their note comes from the same reading the
//! native sink gives its own output, in [`crate::contained_workspace_sink_denial`].
//!
//! - `{"outputs": [str, ...]}`, each output base64 encoded so bytes that are
//!   not UTF-8 reach the reader unchanged, answers
//!   `{"note": str | null, "loopback_denied": bool}`: the note for the
//!   outputs read in order, and whether a line names a blocked connection to
//!   this machine.

use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};

use crate::contained_workspace_sink_denial::{denial_note, loopback_denied};
use crate::runner_authority_detector::args_object;
use crate::runner_authority_op::{KindResult, ERR_INVALID};

pub(crate) fn dispatch(args: &Value) -> KindResult {
    let outputs = args_object(args)?
        .get("outputs")
        .and_then(Value::as_array)
        .ok_or(ERR_INVALID)?
        .iter()
        .map(|output| {
            output
                .as_str()
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .ok_or(ERR_INVALID)
        })
        .collect::<Result<Vec<Vec<u8>>, _>>()?;
    let outputs: Vec<&[u8]> = outputs.iter().map(Vec::as_slice).collect();
    Ok(json!({
        "note": denial_note(&outputs),
        "loopback_denied": loopback_denied(&outputs),
    }))
}

#[cfg(test)]
#[path = "contained_denial_note_tests.rs"]
mod tests;
