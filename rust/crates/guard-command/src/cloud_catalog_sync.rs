//! Negotiated v2 transfer plan and acknowledgement.
//!
//! The handshake signal, the advertised wire limits and the upload origin are
//! judged here against this build's own constants. Python moves bytes between
//! the resident and the configured endpoint; it never re-derives this verdict.
use super::*;

const CAPABILITY_V2: &str = "extension-catalog.v2";
const UPLOAD_PATH: &str = "/api/guard/runtime/extension-catalog/sync-v2";
const SESSION_PATH: &str = "/api/guard/runtime/sessions/sync";
const SCHEMA_V2: &str = "guard.extension-catalog-sync.v2";

fn exact(value: &Value, fields: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == fields.len() && fields.iter().all(|key| object.contains_key(*key))
    })
}

fn advertises(capabilities: &Value) -> bool {
    capabilities
        .as_array()
        .is_some_and(|values| values.iter().any(|value| value == CAPABILITY_V2))
}

fn limits_match(limits: &Value) -> bool {
    let expected = [
        ("maxPageEntries", MAX_PAGE_ENTRIES),
        ("maxPageBytes", MAX_PAGE),
        ("maxEntryBytes", MAX_ENTRY),
        ("maxPages", MAX_PAGES),
        ("maxTotalBytes", MAX_TOTAL),
    ];
    limits.as_object().is_some_and(|object| {
        object.len() == expected.len()
            && expected
                .iter()
                .all(|(key, value)| object.get(*key).and_then(Value::as_u64) == Some(*value as u64))
    })
}

/// Keep the configured origin and query; a negotiated host is never trusted.
fn upload_url(session_url: &str, upload_path: &Value) -> Result<String> {
    if upload_path != UPLOAD_PATH {
        return Err(Error::Invalid);
    }
    let url = url::Url::parse(session_url).map_err(|_| Error::Invalid)?;
    if url.scheme() != "https"
        || url.host_str().is_none()
        || !url.username().is_empty()
        || url.password().is_some()
        || url.fragment().is_some()
        || url.path() != SESSION_PATH
    {
        return Err(Error::Invalid);
    }
    let mut upload = url.clone();
    upload.set_path(UPLOAD_PATH);
    Ok(upload.to_string())
}

/// Judge the negotiated handshake against the observed view and return the plan.
pub fn plan(manifest: &Value, request: &Value) -> Result<Value> {
    let expected = &manifest["catalogDigest"];
    let session = &request["session_payload"];
    if !advertises(&session["managedControlsCapabilities"])
        || session["extensionCatalogViewDigest"] != *expected
        || session["extensionCatalogEnforcementDigest"] != manifest["enforcementCatalogDigest"]
        || session["extensionCatalogGeneratedAt"] != manifest["generatedAt"]
    {
        return Err(Error::Invalid);
    }
    let signal = &request["runtime_response"]["extensionCatalogSync"];
    let known = signal["catalogKnown"].as_bool().ok_or(Error::Invalid)?;
    let required = signal["uploadRequired"].as_bool().ok_or(Error::Invalid)?;
    if !exact(
        signal,
        &[
            "protocolVersion",
            "catalogDigest",
            "catalogKnown",
            "uploadRequired",
            "uploadPath",
            "limits",
        ],
    ) || signal["protocolVersion"] != CAPABILITY_V2
        || signal["catalogDigest"] != *expected
        || known == required
        || !limits_match(&signal["limits"])
    {
        return Err(Error::Invalid);
    }
    let url = upload_url(
        request["runtime_sync_url"].as_str().ok_or(Error::Invalid)?,
        &signal["uploadPath"],
    )?;
    Ok(json!({
        "upload_url": url,
        "catalog_known": known,
        "expected_digest": expected,
        "page_count": manifest["pageCount"],
        "request_budget": MAX_PAGE + 1024,
    }))
}

/// Accept an upload acknowledgement only when it binds the observed digest.
pub fn ack(manifest: &Value, request: &Value) -> Result<Value> {
    let value = &request["response"];
    let complete = value["complete"].as_bool().ok_or(Error::Invalid)?;
    if !exact(
        value,
        &["schemaVersion", "catalogDigest", "accepted", "complete"],
    ) || value["schemaVersion"] != SCHEMA_V2
        || value["catalogDigest"] != manifest["catalogDigest"]
        || value["accepted"] != Value::Bool(true)
        || (request["completing"] == Value::Bool(true) && !complete)
    {
        return Err(Error::Invalid);
    }
    Ok(json!({ "complete": complete }))
}
