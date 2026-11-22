//! `build_policy_bundle_decisions` for the `bundle_candidate` query: every
//! page of the policy-bundle authority's `build_decisions` verdict, asked
//! in process, with the codes `native_policy_bundle` turns its failures into.

use guard_contracts::{PolicyBundleAuthorityRequestV1, POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA};
use serde_json::{json, Map, Value};

use super::UNAVAILABLE;

/// The code the authority answers an input it cannot read with.
const AUTHORITY_INVALID: &str = "native_policy_bundle_authority_invalid";
/// `policy_bundle_chunks`: the bundle travels as bounded text chunks.
const CHUNK_CHARS: usize = 100_000;
const MAX_DOCUMENT_CHARS: usize = 3 * 1024 * 1024;
const LIMIT_BYTES: &str = "limit_bytes";
const MAX_PAGES: usize = 4_096;

/// The persisted-decision field maps the bundle authorizes on this device,
/// or the rejection code: the authority's own code when it refuses the
/// bundle, else `native_policy_bundle_unavailable` for an answer that cannot
/// be trusted.
pub(super) fn materialized_rows(
    bundle: &Map<String, Value>,
    device_id: &str,
    device_name: &str,
) -> Result<Vec<Value>, String> {
    let bundle_chunks = chunks(bundle).ok_or_else(|| LIMIT_BYTES.to_owned())?;
    let unavailable = || UNAVAILABLE.to_owned();
    let mut rows = Vec::new();
    let mut offset: u64 = 0;
    let mut total: Option<Value> = None;
    for _ in 0..MAX_PAGES {
        let page = authority(json!({
            "bundle_chunks": bundle_chunks,
            "device_id": device_id,
            "device_name": device_name,
            "offset": offset,
        }))?;
        let items = page
            .get("decisions")
            .and_then(Value::as_array)
            .filter(|items| items.iter().all(Value::is_object))
            .ok_or_else(unavailable)?;
        if total
            .as_ref()
            .is_some_and(|total| page.get("total") != Some(total))
        {
            return Err(unavailable());
        }
        total = page.get("total").cloned();
        rows.extend(items.iter().cloned());
        match page.get("next") {
            Some(Value::Null) | None => {
                let complete = total.as_ref().and_then(Value::as_u64) == Some(rows.len() as u64);
                return if complete {
                    Ok(rows)
                } else {
                    Err(unavailable())
                };
            }
            Some(next) => match next.as_u64() {
                Some(next) if next > offset => offset = next,
                _ => return Err(unavailable()),
            },
        }
    }
    Err(unavailable())
}

/// `policy_bundle_chunks`; `None` past the document limit.
fn chunks(bundle: &Map<String, Value>) -> Option<Vec<String>> {
    let text = serde_json::to_string(bundle).ok()?;
    let chars: Vec<char> = text.chars().collect();
    if chars.len() > MAX_DOCUMENT_CHARS {
        return None;
    }
    Some(
        chars
            .chunks(CHUNK_CHARS)
            .map(|chunk| chunk.iter().collect())
            .collect(),
    )
}

/// One `build_decisions` page. A refusal carries the authority's code; an
/// answer that is not `ok` is the authority failing to serve the request.
fn authority(input: Value) -> Result<Map<String, Value>, String> {
    let request = PolicyBundleAuthorityRequestV1 {
        schema: POLICY_BUNDLE_AUTHORITY_REQUEST_SCHEMA.to_owned(),
        request_id: "resident-bundle-candidate".to_owned(),
        kind: "build_decisions".to_owned(),
        input,
    };
    let result = guard_policy_bundle::evaluate_with_payload_hasher(
        &request,
        crate::policy_bundle_payload_hash::payload_hash,
    );
    if result.status != "ok" || result.code != "ok" {
        let invalid = result.code == AUTHORITY_INVALID;
        return Err(if invalid {
            AUTHORITY_INVALID
        } else {
            UNAVAILABLE
        }
        .to_owned());
    }
    let Value::Object(result) = result.result else {
        return Err(UNAVAILABLE.to_owned());
    };
    match result.get("error") {
        Some(Value::String(code)) => Err(code.clone()),
        Some(_) => Err(UNAVAILABLE.to_owned()),
        None => Ok(result),
    }
}
