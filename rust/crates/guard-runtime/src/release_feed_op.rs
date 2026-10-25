//! Native projection of the published release feed.
//!
//! The daemon's I/O-only adapter fetches the public release archive from the
//! portal and hands the raw bytes here. This module is the only place a
//! release becomes renderable: it validates the untrusted payload, keeps the
//! fields the dashboard shows, drops everything else, bounds every count and
//! string, and re-serializes a data-only projection. It never fetches, never
//! writes guard state, and never executes anything derived from the payload.
//!
//! The projection is an allowlist, not `deny_unknown_fields`: the portal may
//! add fields to its public schemas without breaking installed clients, while
//! an unknown field still never reaches the dashboard.

use serde::Deserialize;
use serde_json::{json, Map, Value};

#[path = "release_feed_fields.rs"]
mod release_feed_fields;

use release_feed_fields::*;

pub const RELEASE_FEED_FEATURE: &str = "release-feed-projection-v1";
pub const RELEASE_FEED_REQUEST_SCHEMA: &str = "guard-release-feed-project-request.v1";
pub const RELEASE_FEED_RESULT_SCHEMA: &str = "guard-release-feed-project-result.v1";
pub const RELEASE_INDEX_SCHEMA: &str = "guard-release-client-index/v1";
pub const RELEASE_DETAIL_SCHEMA: &str = "guard-release-detail/v1";

/// Upstream bytes accepted in one projection (the adapter bounds its own read).
const MAX_BODY_BYTES: usize = 262_144;
/// Maximum upstream JSON nesting depth accepted by the validator.
const MAX_JSON_DEPTH: usize = 12;
/// Releases carried by one index page (mirrors the portal page-size cap).
const MAX_RELEASES: usize = 50;
/// Change items rendered for one release.
const MAX_CHANGES: usize = 200;
/// Credited contributors rendered for one release.
const MAX_ROSTER: usize = 500;
/// Downloadable assets rendered for one release.
const MAX_ASSETS: usize = 50;
const MAX_URL_CHARS: usize = 2_048;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReleaseFeedProjectRequest {
    pub schema: String,
    /// `index` or `detail`: which upstream document the body holds.
    pub kind: String,
    /// Raw upstream JSON text (the adapter already bounded its size).
    pub body: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FeedError {
    Request,
    Body,
    Payload,
}

impl FeedError {
    fn code(self) -> &'static str {
        match self {
            Self::Request => "release_feed_request_invalid",
            Self::Body => "release_feed_body_invalid",
            Self::Payload => "release_feed_payload_invalid",
        }
    }

    fn http_status(self) -> u16 {
        match self {
            Self::Request | Self::Body => 400,
            // The upstream answered, but with something the dashboard cannot
            // honestly render; that is an upstream failure, not a local one.
            Self::Payload => 502,
        }
    }
}

fn error_frame(error: FeedError) -> Value {
    json!({
        "schema": RELEASE_FEED_RESULT_SCHEMA,
        "outcome": "error",
        "http_status": error.http_status(),
        "etag": Value::Null,
        "body": Value::Null,
        "error_code": error.code(),
    })
}

fn project_coverage(object: &Map<String, Value>) -> Result<Value, FeedError> {
    let coverage = object
        .get("coverage")
        .and_then(Value::as_object)
        .ok_or(FeedError::Payload)?;
    let verified_at = match coverage.get("verifiedAt") {
        Some(Value::Null) | None => Value::Null,
        Some(Value::String(raw)) => match iso_instant(raw) {
            Some(instant) => Value::String(instant),
            None => return Err(FeedError::Payload),
        },
        _ => return Err(FeedError::Payload),
    };
    Ok(json!({
        "attributionState": enum_value(
            coverage,
            "attributionState",
            &["complete", "in-progress", "unknown"],
        )?,
        "historyCoverage": enum_value(coverage, "historyCoverage", &["complete", "partial"])?,
        "verifiedAt": verified_at,
    }))
}

/// Fields every release surface carries, summary row and detail alike.
fn project_release_identity(object: &Map<String, Value>) -> Result<Map<String, Value>, FeedError> {
    let mut projected = Map::new();
    projected.insert(
        "slug".to_owned(),
        json!(required_line(object, "slug", 128)?),
    );
    projected.insert(
        "rawTag".to_owned(),
        json!(required_line(object, "rawTag", 128)?),
    );
    projected.insert(
        "channel".to_owned(),
        json!(enum_value(object, "channel", &["stable", "preview"])?),
    );
    projected.insert(
        "train".to_owned(),
        json!(required_line(object, "train", 32)?),
    );
    projected.insert(
        "versionLabel".to_owned(),
        json!(required_line(object, "versionLabel", 64)?),
    );
    projected.insert(
        "title".to_owned(),
        json!(required_prose_line(object, "title", 200)?),
    );
    projected.insert(
        "publishedAt".to_owned(),
        json!(required_instant(object, "publishedAt")?),
    );
    projected.insert("coverage".to_owned(), project_coverage(object)?);
    Ok(projected)
}

fn project_summary_row(value: &Value) -> Result<Value, FeedError> {
    let object = object_at(value)?;
    let mut projected = project_release_identity(object)?;
    let path = field_str(object, "path")
        .and_then(release_path)
        .ok_or(FeedError::Payload)?;
    projected.insert("path".to_owned(), json!(path));
    projected.insert(
        "isRecommended".to_owned(),
        match object.get("isRecommended") {
            Some(Value::Bool(flag)) => Value::Bool(*flag),
            _ => return Err(FeedError::Payload),
        },
    );
    Ok(Value::Object(projected))
}

fn project_change_item(value: &Value) -> Result<Value, FeedError> {
    let object = object_at(value)?;
    Ok(json!({
        "id": required_line(object, "id", 200)?,
        "kind": enum_value(
            object,
            "kind",
            &["added", "changed", "fixed", "security", "removed", "other"],
        )?,
        "summary": field_str(object, "summary")
            .and_then(|summary| multi_line(summary, 2_000))
            .filter(|summary| !summary.is_empty())
            .ok_or(FeedError::Payload)?,
        "evidenceUrl": optional_https(object, "evidenceUrl"),
    }))
}

fn project_roster_entry(value: &Value) -> Result<Value, FeedError> {
    let object = object_at(value)?;
    let github_numeric_id = object
        .get("githubNumericId")
        .and_then(Value::as_i64)
        .filter(|id| *id > 0)
        .ok_or(FeedError::Payload)?;
    let login = match object.get("login") {
        Some(Value::Null) | None => Value::Null,
        Some(Value::String(raw)) => Value::String(single_line(raw, 64).ok_or(FeedError::Payload)?),
        _ => return Err(FeedError::Payload),
    };
    let roles = object
        .get("roles")
        .and_then(Value::as_array)
        .ok_or(FeedError::Payload)?;
    if roles.is_empty() || roles.len() > 16 {
        return Err(FeedError::Payload);
    }
    let mut projected_roles = Vec::with_capacity(roles.len());
    for role in roles {
        let role = role
            .as_str()
            .and_then(|role| single_line(role, 64))
            .ok_or(FeedError::Payload)?;
        projected_roles.push(Value::String(role));
    }
    Ok(json!({
        "creditId": required_line(object, "creditId", 128)?,
        "githubNumericId": github_numeric_id,
        "login": login,
        "type": enum_value(
            object,
            "type",
            &["human", "organization", "automation", "unresolved"],
        )?,
        "roles": projected_roles,
        "verificationMethod": enum_value(
            object,
            "verificationMethod",
            &[
                "pull-request-author",
                "verified-direct-commit-author",
                "verified-coauthor",
            ],
        )?,
        "evidenceUrl": optional_https(object, "evidenceUrl"),
    }))
}

fn project_asset(value: &Value) -> Result<Option<Value>, FeedError> {
    let object = object_at(value)?;
    let name = required_line(object, "name", 200)?;
    // A download link that is not plain https is dropped: the dashboard shows
    // the assets it can honestly offer, never a link it would refuse to open.
    let Some(url) = field_str(object, "url").and_then(https_url) else {
        return Ok(None);
    };
    Ok(Some(json!({ "name": name, "url": url })))
}

fn project_comparison(object: &Map<String, Value>) -> Result<Value, FeedError> {
    let comparison = object
        .get("comparison")
        .and_then(Value::as_object)
        .ok_or(FeedError::Payload)?;
    match comparison.get("available") {
        Some(Value::Bool(true)) => Ok(json!({
            "available": true,
            "predecessorSlug": required_line(comparison, "predecessorSlug", 128)?,
            "predecessorRawTag": required_line(comparison, "predecessorRawTag", 128)?,
        })),
        Some(Value::Bool(false)) => Ok(json!({
            "available": false,
            "reason": enum_value(
                comparison,
                "reason",
                &["unverified-predecessor", "first-release"],
            )?,
        })),
        _ => Err(FeedError::Payload),
    }
}

fn project_source_notes(object: &Map<String, Value>) -> Result<Value, FeedError> {
    let Some(notes) = object.get("sourceNotes") else {
        return Ok(Value::Null);
    };
    if notes.is_null() {
        return Ok(Value::Null);
    }
    let notes = notes.as_object().ok_or(FeedError::Payload)?;
    let text = field_str(notes, "text")
        .and_then(|text| multi_line(text, 20_000))
        .ok_or(FeedError::Payload)?;
    Ok(json!({
        "scope": enum_value(notes, "scope", &["exact_release", "train_overview"])?,
        "text": text,
    }))
}

fn project_index(parsed: &Value) -> Result<Value, FeedError> {
    let document = object_at(parsed)?;
    if field_str(document, "schemaVersion") != Some(RELEASE_INDEX_SCHEMA) {
        return Err(FeedError::Payload);
    }
    let releases = document
        .get("releases")
        .and_then(Value::as_array)
        .ok_or(FeedError::Payload)?;
    if releases.len() > MAX_RELEASES {
        return Err(FeedError::Payload);
    }
    let mut projected = Vec::with_capacity(releases.len());
    let mut seen_slugs: Vec<String> = Vec::with_capacity(releases.len());
    for release in releases {
        let row = project_summary_row(release)?;
        let slug = row
            .get("slug")
            .and_then(Value::as_str)
            .ok_or(FeedError::Payload)?;
        if seen_slugs.iter().any(|seen| seen == slug) {
            return Err(FeedError::Payload);
        }
        seen_slugs.push(slug.to_owned());
        projected.push(row);
    }
    let page = bounded_count(document, "page")?;
    let page_size = bounded_count(document, "pageSize")?;
    let returned = i64::try_from(projected.len()).map_err(|_| FeedError::Payload)?;
    if page < 1 || page_size < 1 || returned > page_size {
        return Err(FeedError::Payload);
    }
    Ok(json!({
        "kind": "index",
        "page": page,
        "pageSize": page_size,
        "total": bounded_count(document, "total")?,
        "totalPages": bounded_count(document, "totalPages")?,
        "generatedAt": required_instant(document, "generatedAt")?,
        "releases": projected,
    }))
}

fn project_detail(parsed: &Value) -> Result<Value, FeedError> {
    let document = object_at(parsed)?;
    if field_str(document, "schemaVersion") != Some(RELEASE_DETAIL_SCHEMA) {
        return Err(FeedError::Payload);
    }
    let mut projected = project_release_identity(document)?;
    projected.insert("kind".to_owned(), json!("detail"));
    projected.insert(
        "summary".to_owned(),
        json!(field_str(document, "summary")
            .and_then(|summary| multi_line(summary, 8_000))
            .ok_or(FeedError::Payload)?),
    );
    projected.insert("comparison".to_owned(), project_comparison(document)?);

    let changes = document
        .get("changes")
        .and_then(Value::as_array)
        .ok_or(FeedError::Payload)?;
    if changes.len() > MAX_CHANGES {
        return Err(FeedError::Payload);
    }
    let mut projected_changes = Vec::with_capacity(changes.len());
    for change in changes {
        projected_changes.push(project_change_item(change)?);
    }
    projected.insert("changes".to_owned(), Value::Array(projected_changes));

    let roster = document
        .get("roster")
        .and_then(Value::as_array)
        .ok_or(FeedError::Payload)?;
    if roster.len() > MAX_ROSTER {
        return Err(FeedError::Payload);
    }
    let mut projected_roster = Vec::with_capacity(roster.len());
    for entry in roster {
        projected_roster.push(project_roster_entry(entry)?);
    }
    projected.insert("roster".to_owned(), Value::Array(projected_roster));

    let mut projected_assets = Vec::new();
    if let Some(assets) = document.get("assets") {
        let assets = assets.as_array().ok_or(FeedError::Payload)?;
        if assets.len() > MAX_ASSETS {
            return Err(FeedError::Payload);
        }
        for asset in assets {
            if let Some(projected_asset) = project_asset(asset)? {
                projected_assets.push(projected_asset);
            }
        }
    }
    projected.insert("assets".to_owned(), Value::Array(projected_assets));
    projected.insert("sourceNotes".to_owned(), project_source_notes(document)?);
    Ok(Value::Object(projected))
}

/// Validate the upstream release document and project the renderable body.
/// Returns the resident result frame as encoded bytes; the Python adapter
/// writes `body` verbatim and never interprets a release.
pub fn evaluate_release_feed_project(
    request: &ReleaseFeedProjectRequest,
) -> Result<Vec<u8>, String> {
    let frame = match evaluate_release_feed_frame(request) {
        Ok(frame) => frame,
        Err(error) => error_frame(error),
    };
    serde_json::to_vec(&frame).map_err(|error| error.to_string())
}

fn evaluate_release_feed_frame(request: &ReleaseFeedProjectRequest) -> Result<Value, FeedError> {
    if request.schema != RELEASE_FEED_REQUEST_SCHEMA {
        return Err(FeedError::Request);
    }
    if request.body.len() > MAX_BODY_BYTES {
        return Err(FeedError::Request);
    }
    let parsed: Value = match serde_json::from_str(&request.body) {
        Ok(parsed) => parsed,
        Err(_) => return Err(FeedError::Body),
    };
    if json_depth(&parsed) > MAX_JSON_DEPTH {
        return Err(FeedError::Body);
    }
    let projection = match request.kind.as_str() {
        "index" => project_index(&parsed)?,
        "detail" => project_detail(&parsed)?,
        _ => return Err(FeedError::Request),
    };
    let body = serde_json::to_string(&projection).map_err(|_| FeedError::Payload)?;
    Ok(json!({
        "schema": RELEASE_FEED_RESULT_SCHEMA,
        "outcome": "ok",
        "http_status": 200,
        "etag": Value::Null,
        "body": body,
        "error_code": Value::Null,
    }))
}

#[cfg(test)]
#[path = "release_feed_op_tests.rs"]
mod release_feed_op_tests;
