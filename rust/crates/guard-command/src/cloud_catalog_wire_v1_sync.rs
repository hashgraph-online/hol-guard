//! Cloud v1 Extension catalog negotiation: which summary a runtime session
//! reports, whether the catalog is uploaded, the digest-bound upload URL, and
//! whether the upload acknowledgement binds the catalog. The adapter reports
//! what it observed and moves bytes; every verdict is judged here against this
//! build's own constants. Requests are stateless: the adapter repeats the
//! session and handshake with the catalog observation it was asked for.
use super::{exact_fields, invalid, protocol, Outcome, MAX_PAYLOAD_BYTES};
use serde_json::{json, Value};
use std::net::Ipv6Addr;

const UPLOAD_PATH: &str = "/api/guard/runtime/extension-catalog/sync";
const ACK_SCHEMA: &str = "guard.extension-catalog-sync.v1";
/// Cloud enforces the catalog and the request body limits separately; the body
/// is the catalog plus a small idempotency wrapper.
const MAX_BODY_BYTES: u64 = MAX_PAYLOAD_BYTES as u64 + 16_384;
const HANDSHAKE_FIELDS: [&str; 4] = [
    "catalogDigest",
    "catalogKnown",
    "uploadRequired",
    "uploadPath",
];
const ACK_FIELDS: [&str; 7] = [
    "schemaVersion",
    "accepted",
    "catalogDigest",
    "alreadyKnown",
    "deviceCount",
    "firstSeenAt",
    "lastSeenAt",
];

/// What the adapter saw when it asked its catalog factory for a catalog.
enum Observed {
    /// Nothing built yet; the verdict may still need a catalog.
    Missing,
    Limit,
    Unavailable,
    /// A failure that is not a Cloud limit and not a missing runtime.
    Failed,
    /// A catalog was built. A probe reports no measurements; an upload that
    /// arrives without them is refused rather than assumed to fit.
    Built {
        digest: Option<String>,
        catalog_bytes: Option<u64>,
        body_bytes: Option<u64>,
    },
}

fn observation(value: &Value) -> Outcome<Observed> {
    if value.is_null() {
        return Ok(Observed::Missing);
    }
    match value["outcome"].as_str() {
        Some("limit") => Ok(Observed::Limit),
        Some("unavailable") => Ok(Observed::Unavailable),
        Some("failed") => Ok(Observed::Failed),
        Some("built") => Ok(Observed::Built {
            digest: value["catalog_digest"].as_str().map(str::to_owned),
            catalog_bytes: value["catalog_bytes"].as_u64(),
            body_bytes: value["body_bytes"].as_u64(),
        }),
        _ => invalid("Invalid Extension catalog observation"),
    }
}

fn downgraded(reason: &str) -> Value {
    json!({
        "managedControlsCapabilities": [],
        "extension_catalog_sync_status": "downgraded",
        "extension_catalog_sync_reason": reason,
    })
}

fn done(summary: Value, upload_url: Option<String>) -> Outcome<Value> {
    Ok(json!({"decision": "done", "summary": summary, "upload_url": upload_url}))
}

fn need_catalog(purpose: &str, generated_at: &str, digest: Option<&str>) -> Outcome<Value> {
    Ok(json!({
        "decision": "need_catalog",
        "purpose": purpose,
        "generated_at": generated_at,
        "idempotency_key": digest.map(|digest| format!("catalog:{digest}")),
    }))
}

/// Split an optional leading scheme the way the URL grammar does: ASCII letter
/// first, then letters, digits, `+`, `-` or `.`, ended by the first colon.
fn split_scheme(url: &str) -> (String, &str) {
    let Some(colon) = url.find(':').filter(|index| *index > 0) else {
        return (String::new(), url);
    };
    let candidate = &url[..colon];
    let valid = candidate.starts_with(|c: char| c.is_ascii_alphabetic())
        && candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '-' | '.'));
    if valid {
        (candidate.to_ascii_lowercase(), &url[colon + 1..])
    } else {
        (String::new(), url)
    }
}

/// A bracketed host is an IPv6 literal with an optional zone, or an IPvFuture
/// literal (`v`, hex digits, a dot, then at least one character).
fn bracketed_literal_is_valid(host: &str) -> bool {
    if let Some(future) = host.strip_prefix('v') {
        return future.split_once('.').is_some_and(|(version, address)| {
            !version.is_empty()
                && version.chars().all(|c| c.is_ascii_hexdigit())
                && !address.is_empty()
        });
    }
    match host.split_once('%') {
        Some((address, zone)) => {
            !zone.is_empty() && !zone.contains('%') && address.parse::<Ipv6Addr>().is_ok()
        }
        None => host.parse::<Ipv6Addr>().is_ok(),
    }
}

/// Unbalanced or otherwise invalid brackets are refused rather than guessed at.
fn bracketed_host_is_valid(netloc: &str) -> bool {
    match (netloc.find('['), netloc.find(']')) {
        (None, None) => true,
        (Some(open), Some(close)) if open < close => {
            bracketed_literal_is_valid(&netloc[open + 1..close])
        }
        _ => false,
    }
}

/// Keep the configured scheme, authority and query; replace the path and drop
/// the fragment. A negotiated host or path is never trusted, and a URL without
/// a scheme and an authority is refused instead of becoming a relative URL.
fn upload_url(runtime_sync_url: &str) -> Outcome<String> {
    let refused = || protocol("Invalid Extension catalog upload URL");
    // Leading control characters and spaces are trimmed; tabs and line breaks
    // are removed anywhere, as URL parsers do.
    let cleaned: String = runtime_sync_url
        .trim_start_matches(|c: char| c <= ' ')
        .chars()
        .filter(|c| !matches!(*c, '\t' | '\r' | '\n'))
        .collect();
    let (scheme, rest) = split_scheme(&cleaned);
    let Some(authority_and_rest) = rest.strip_prefix("//") else {
        return refused();
    };
    let end = authority_and_rest
        .find(&['/', '?', '#'][..])
        .unwrap_or(authority_and_rest.len());
    let (netloc, rest) = authority_and_rest.split_at(end);
    if scheme.is_empty() || netloc.is_empty() || !bracketed_host_is_valid(netloc) {
        return refused();
    }
    let without_fragment = rest.split('#').next().unwrap_or_default();
    let query = without_fragment
        .split_once('?')
        .map_or("", |(_, query)| query);
    let mut url = format!("{scheme}://{netloc}{UPLOAD_PATH}");
    if !query.is_empty() {
        url.push('?');
        url.push_str(query);
    }
    Ok(url)
}

/// Judge one runtime session's catalog negotiation.
pub fn handshake(request: &Value) -> Outcome<Value> {
    let session = &request["session"];
    let Some(fallback_generated_at) = request["fallback_generated_at"].as_str() else {
        return invalid("Invalid Extension catalog handshake request");
    };
    let observed = observation(&request["catalog"])?;
    let Some(digest) = session["extensionCatalogDigest"].as_str() else {
        if session.get("extensionCatalogViewDigest").is_some() {
            return done(
                json!({
                    "managedControlsCapabilities": [],
                    "extension_catalog_sync_status": "unsupported",
                    "extension_catalog_sync_reason": "complete_catalog_exceeds_cloud_v1_limits",
                }),
                None,
            );
        }
        // Posture advertises capabilities without a digest only when the
        // catalog build failed; name the Cloud limit when that was the cause.
        if session.get("managedControlsCapabilities").is_none() {
            return done(json!({}), None);
        }
        return match observed {
            Observed::Missing => need_catalog("probe", fallback_generated_at, None),
            Observed::Limit => done(downgraded("catalog_upload_exceeds_cloud_limit"), None),
            _ => done(json!({}), None),
        };
    };
    let handshake = &request["handshake"];
    if handshake.is_null() {
        return done(downgraded("catalog_handshake_unavailable"), None);
    }
    let bound = exact_fields(handshake, &HANDSHAKE_FIELDS)
        && handshake["catalogDigest"].as_str() == Some(digest)
        && handshake["uploadPath"] == UPLOAD_PATH;
    let (Some(known), Some(upload_required)) = (
        handshake["catalogKnown"].as_bool(),
        handshake["uploadRequired"].as_bool(),
    ) else {
        return protocol("Invalid Extension catalog handshake response");
    };
    if !bound || known == upload_required {
        return protocol("Invalid Extension catalog handshake response");
    }
    if known {
        return done(
            json!({
                "extension_catalog_sync_status": "already_known",
                "extension_catalog_sync_digest": digest,
            }),
            None,
        );
    }
    let generated_at = session["updatedAt"]
        .as_str()
        .filter(|value| !value.is_empty())
        .unwrap_or(fallback_generated_at);
    match observed {
        Observed::Missing => need_catalog("upload", generated_at, Some(digest)),
        Observed::Limit => done(downgraded("catalog_upload_exceeds_cloud_limit"), None),
        Observed::Unavailable => done(downgraded("catalog_runtime_unavailable"), None),
        Observed::Failed => invalid("Invalid Extension catalog observation"),
        Observed::Built {
            digest: built,
            catalog_bytes,
            body_bytes,
        } => {
            if built.as_deref() != Some(digest) {
                return protocol("Extension catalog changed during runtime synchronization");
            }
            let (Some(catalog_bytes), Some(body_bytes)) = (catalog_bytes, body_bytes) else {
                return invalid("Invalid Extension catalog observation");
            };
            if catalog_bytes > MAX_PAYLOAD_BYTES as u64 || body_bytes > MAX_BODY_BYTES {
                return done(downgraded("catalog_upload_exceeds_cloud_limit"), None);
            }
            let Some(runtime_sync_url) = request["runtime_sync_url"].as_str() else {
                return invalid("Invalid Extension catalog handshake request");
            };
            done(
                json!({
                    "extension_catalog_sync_status": "uploaded",
                    "extension_catalog_sync_digest": digest,
                }),
                Some(upload_url(runtime_sync_url)?),
            )
        }
    }
}

fn non_empty_text(value: &Value) -> bool {
    value.as_str().is_some_and(|text| !text.is_empty())
}

/// Accept an upload acknowledgement only when it binds the uploaded digest.
pub fn sync_ack(request: &Value) -> Outcome<Value> {
    let Some(expected) = request["expected_digest"].as_str() else {
        return invalid("Invalid Extension catalog sync request");
    };
    let response = &request["response"];
    if !(exact_fields(response, &ACK_FIELDS)
        && response["schemaVersion"] == ACK_SCHEMA
        && response["accepted"] == true
        && response["catalogDigest"].as_str() == Some(expected)
        && response["alreadyKnown"].is_boolean()
        && response["deviceCount"]
            .as_u64()
            .is_some_and(|count| count >= 1)
        && non_empty_text(&response["firstSeenAt"])
        && non_empty_text(&response["lastSeenAt"]))
    {
        return protocol("Invalid Extension catalog sync response");
    }
    Ok(json!({"accepted": true}))
}
