//! Per-call context of a workflow-capability operation: the connection, the
//! signing key, the injected clock, and the external control blob. The blob
//! lives in the caller's credential store, so every write is recorded in
//! order and handed back for the caller to persist; reads see the writes
//! already made during the same call.

use base64ct::{Base64, Encoding};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, Row};

use crate::guard_store_wfcap_error::{cap, WfError, WfResult};

pub(crate) struct Ctx<'a> {
    pub conn: &'a Connection,
    pub key: Vec<u8>,
    pub key_id: String,
    pub now: String,
    blob: Option<String>,
    writes: Vec<String>,
    post_commit: Vec<String>,
}

impl<'a> Ctx<'a> {
    /// `_require_store_key` plus the injected clock and blob.
    pub(crate) fn new(
        conn: &'a Connection,
        key_b64: Option<&str>,
        key_id: Option<&str>,
        now: &str,
        blob: Option<&str>,
    ) -> WfResult<Self> {
        let (Some(key_b64), Some(key_id)) = (key_b64, key_id) else {
            return cap("capability_key_unavailable");
        };
        let Ok(key) = Base64::decode_vec(key_b64) else {
            return cap("capability_key_unavailable");
        };
        Ok(Self {
            conn,
            key,
            key_id: key_id.to_owned(),
            now: now.to_owned(),
            blob: blob.map(str::to_owned),
            writes: Vec::new(),
            post_commit: Vec::new(),
        })
    }

    /// `_load_workflow_capability_control`.
    pub(crate) fn load_control(&self) -> Option<&str> {
        self.blob.as_deref()
    }

    /// `_store_workflow_capability_control`: recorded, assumed accepted.
    pub(crate) fn store_control(&mut self, encoded: String) {
        self.blob = Some(encoded.clone());
        self.writes.push(encoded);
    }

    /// A control write that follows the database commit.
    pub(crate) fn store_control_post_commit(&mut self, encoded: String) {
        self.blob = Some(encoded.clone());
        self.post_commit.push(encoded);
    }

    /// The writes before the database commit and the ones after it.
    pub(crate) fn into_writes(self) -> (Vec<String>, Vec<String>) {
        (self.writes, self.post_commit)
    }
}

/// Python `str(row[index])` for a non-null column.
pub(crate) fn text_at(row: &Row<'_>, index: usize) -> WfResult<String> {
    Ok(optional_text_at(row, index)?.unwrap_or_else(|| "None".to_owned()))
}

/// A nullable column: `None` for SQL NULL, otherwise `str(value)`.
pub(crate) fn optional_text_at(row: &Row<'_>, index: usize) -> WfResult<Option<String>> {
    Ok(match row.get_ref(index)? {
        ValueRef::Null => None,
        ValueRef::Integer(value) => Some(value.to_string()),
        ValueRef::Real(value) => Some(value.to_string()),
        ValueRef::Text(bytes) | ValueRef::Blob(bytes) => {
            Some(String::from_utf8_lossy(bytes).into_owned())
        }
    })
}

/// Python `int(row[index])`.
pub(crate) fn int_at(row: &Row<'_>, index: usize) -> WfResult<i64> {
    match row.get_ref(index)? {
        ValueRef::Integer(value) => Ok(value),
        ValueRef::Text(bytes) => std::str::from_utf8(bytes)
            .ok()
            .and_then(|text| text.trim().parse().ok())
            .ok_or_else(|| WfError::Runtime("invalid literal for int()".to_owned())),
        _ => Err(WfError::Runtime(
            "int() argument must be a number".to_owned(),
        )),
    }
}
