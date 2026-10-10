//! Paging for `PolicyBundleAuthority` results that can outgrow one resident
//! response.
//!
//! Resident responses are capped at `MAX_NATIVE_RESPONSE_BYTES`. A valid bundle
//! can expand into more decision rows than that (one reason repeated across
//! every location, harness and family), and a canonical payload can grow when
//! it is embedded in a JSON string. The caller therefore asks for one page at a
//! time by `offset`; every page reports the `total` and the `next` offset, so
//! the full document is still produced from one deterministic computation.

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::policy_bundle_op::{Fail, Handled};
use crate::policy_bundle_py::Obj;

/// Largest serialized size of one page of rows or text, well under the cap.
pub(crate) const PAGE_BYTES: usize = 1_000_000;
/// Text bytes per canonical-payload page; JSON string escaping at most doubles
/// ASCII text, so an escaped page stays inside `PAGE_BYTES`.
const TEXT_PAGE_BYTES: usize = 480_000;

/// The requested start of the page; absent means the first page.
pub(crate) fn page_offset(input: &Obj) -> Result<usize, Fail> {
    match input.get("offset") {
        None | Some(Value::Null) => Ok(0),
        Some(value) => value
            .as_u64()
            .and_then(|offset| usize::try_from(offset).ok())
            .ok_or(Fail::Invalid),
    }
}

/// One page of `rows` starting at `offset`.
///
/// A page always holds at least one row so progress is guaranteed; a single row
/// is bounded by the 2 MiB bundle limit it was derived from.
pub(crate) fn page_rows(rows: &[Value], offset: usize) -> Handled {
    if offset > rows.len() {
        return Err(Fail::Invalid);
    }
    let mut size: usize = 0;
    let mut end = offset;
    while let Some(row) = rows.get(end) {
        let row_bytes = serde_json::to_vec(row).map_or(usize::MAX, |bytes| bytes.len() + 1);
        if end > offset && size.saturating_add(row_bytes) > PAGE_BYTES {
            break;
        }
        size = size.saturating_add(row_bytes);
        end += 1;
    }
    let next = (end < rows.len()).then_some(end);
    Ok(json!({ "decisions": &rows[offset..end], "total": rows.len(), "next": next }))
}

/// One page of the UTF-8 text `bytes` starting at the byte `offset`, plus the
/// digest of the whole text so the caller can check the reassembly.
pub(crate) fn page_text(bytes: Vec<u8>, offset: usize) -> Handled {
    let text = String::from_utf8(bytes).map_err(|_| Fail::from("invalid_json_value"))?;
    if offset > text.len() || !text.is_char_boundary(offset) {
        return Err(Fail::Invalid);
    }
    let mut end = text.len().min(offset.saturating_add(TEXT_PAGE_BYTES));
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    let next = (end < text.len()).then_some(end);
    Ok(json!({
        "value": &text[offset..end],
        "total": text.len(),
        "next": next,
        "sha256": hex::encode(Sha256::digest(text.as_bytes())),
    }))
}
