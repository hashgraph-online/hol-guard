//! Request grammar for [`crate::catalog_read_model`]: route, query, cursor and
//! `If-None-Match` parsing. Every input is size-bounded and allowlisted; the
//! Python transport forwards these strings without interpreting them.

use percent_encoding::percent_decode_str;
use sha2::{Digest, Sha256};

use crate::catalog_read_model::CatalogReadError;

pub(crate) const DEFAULT_PAGE_ITEMS: usize = 50;
pub(crate) const MAX_PAGE_ITEMS: usize = 100;
pub(crate) const MAX_ROUTE_BYTES: usize = 512;
pub(crate) const MAX_RAW_QUERY_BYTES: usize = 2048;
pub(crate) const MAX_QUERY_TEXT_CHARS: usize = 256;
pub(crate) const MAX_FILTER_VALUE_BYTES: usize = 128;
pub(crate) const MAX_EXTENSION_ID_BYTES: usize = 128;
pub(crate) const MAX_IF_NONE_MATCH_BYTES: usize = 2048;
pub(crate) const MAX_IF_NONE_MATCH_TAGS: usize = 32;
/// `v1.` + 16-hex snapshot + `.` + ≤6-digit offset + `.` + 32-hex check.
pub(crate) const MAX_CURSOR_BYTES: usize = 3 + 16 + 1 + 6 + 1 + 32;
const MAX_CURSOR_OFFSET: usize = 999_999;
const CURSOR_DOMAIN: &[u8] = b"guard-catalog-read-cursor-v1\0";

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum CatalogRoute {
    Index,
    /// Catalog-wide permission search across every extension.
    PermissionSearch,
    Extension(String),
    Permissions(String),
    Rules(String),
    McpTools(String),
}

impl CatalogRoute {
    pub(crate) fn parse(route: &str) -> Result<Self, CatalogReadError> {
        if route.len() > MAX_ROUTE_BYTES {
            return Err(CatalogReadError::RouteNotFound);
        }
        let parts: Vec<&str> = route.split('/').collect();
        match parts.as_slice() {
            ["index"] => Ok(Self::Index),
            ["permissions"] => Ok(Self::PermissionSearch),
            ["extensions", id] => Ok(Self::Extension(extension_id(id)?)),
            ["extensions", id, "permissions"] => Ok(Self::Permissions(extension_id(id)?)),
            ["extensions", id, "rules"] => Ok(Self::Rules(extension_id(id)?)),
            ["extensions", id, "mcp-tools"] => Ok(Self::McpTools(extension_id(id)?)),
            _ => Err(CatalogReadError::RouteNotFound),
        }
    }

    /// The cursor binding for paginated resources.
    pub(crate) fn resource_key(&self) -> String {
        match self {
            Self::Index => "index".to_owned(),
            Self::PermissionSearch => "permission-search".to_owned(),
            Self::Extension(id) => format!("extension:{id}"),
            Self::Permissions(id) => format!("permissions:{id}"),
            Self::Rules(id) => format!("rules:{id}"),
            Self::McpTools(id) => format!("mcp-tools:{id}"),
        }
    }

    fn allowed_keys(&self) -> &'static [&'static str] {
        match self {
            Self::Index => &[
                "limit",
                "cursor",
                "q",
                "source",
                "trust_class",
                "risk_class",
                "surface",
            ],
            Self::PermissionSearch => &["limit", "cursor", "q"],
            Self::Extension(_) => &[],
            Self::Permissions(_) | Self::Rules(_) | Self::McpTools(_) => &["limit", "cursor"],
        }
    }
}

/// IDs are IDs, never paths: lowercase ASCII identifiers only.
fn extension_id(raw: &str) -> Result<String, CatalogReadError> {
    let valid = !raw.is_empty()
        && raw.len() <= MAX_EXTENSION_ID_BYTES
        && raw.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'-' | b'_')
        })
        && !raw.starts_with('.')
        && !raw.contains("..");
    if valid {
        Ok(raw.to_owned())
    } else {
        Err(CatalogReadError::RouteNotFound)
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct CatalogFilter {
    /// Lowercased search text.
    pub(crate) q: Option<String>,
    pub(crate) source: Option<String>,
    pub(crate) trust_class: Option<String>,
    pub(crate) risk_class: Option<String>,
    pub(crate) surface: Option<String>,
}

impl CatalogFilter {
    /// Canonical, unambiguous binding for cursors: each value is
    /// length-prefixed so no two filters share an encoding.
    pub(crate) fn binding_key(&self) -> String {
        let field = |value: &Option<String>| match value {
            Some(text) => format!("{}:{text}", text.len()),
            None => "-".to_owned(),
        };
        format!(
            "q={};source={};trust_class={};risk_class={};surface={}",
            field(&self.q),
            field(&self.source),
            field(&self.trust_class),
            field(&self.risk_class),
            field(&self.surface)
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CatalogQuery {
    pub(crate) limit: usize,
    pub(crate) cursor: Option<String>,
    pub(crate) filter: CatalogFilter,
}

impl CatalogQuery {
    pub(crate) fn parse(route: &CatalogRoute, raw: &str) -> Result<Self, CatalogReadError> {
        if raw.len() > MAX_RAW_QUERY_BYTES {
            return Err(CatalogReadError::QueryInvalid);
        }
        let mut query = Self {
            limit: DEFAULT_PAGE_ITEMS,
            cursor: None,
            filter: CatalogFilter::default(),
        };
        let mut seen: Vec<&str> = Vec::new();
        for pair in raw.split('&').filter(|pair| !pair.is_empty()) {
            let (key, value) = pair.split_once('=').ok_or(CatalogReadError::QueryInvalid)?;
            let Some(key) = route
                .allowed_keys()
                .iter()
                .copied()
                .find(|allowed| *allowed == key)
            else {
                return Err(CatalogReadError::QueryInvalid);
            };
            if seen.contains(&key) {
                return Err(CatalogReadError::QueryInvalid);
            }
            seen.push(key);
            let value = decode_component(value)?;
            match key {
                "limit" => query.limit = parse_limit(&value)?,
                "cursor" => query.cursor = Some(bounded_cursor(value)?),
                "q" => query.filter.q = search_text(&value)?,
                "source" => query.filter.source = Some(filter_token(value)?),
                "trust_class" => query.filter.trust_class = Some(filter_token(value)?),
                "risk_class" => query.filter.risk_class = Some(filter_token(value)?),
                "surface" => query.filter.surface = Some(filter_token(value)?),
                _ => return Err(CatalogReadError::QueryInvalid),
            }
        }
        Ok(query)
    }
}

fn decode_component(raw: &str) -> Result<String, CatalogReadError> {
    let spaced = raw.replace('+', " ");
    percent_decode_str(&spaced)
        .decode_utf8()
        .map(|text| text.into_owned())
        .map_err(|_| CatalogReadError::QueryInvalid)
}

fn parse_limit(value: &str) -> Result<usize, CatalogReadError> {
    let canonical = !value.is_empty()
        && value.len() <= 3
        && value.bytes().all(|b| b.is_ascii_digit())
        && !value.starts_with('0');
    let limit: usize = if canonical {
        value.parse().map_err(|_| CatalogReadError::QueryInvalid)?
    } else {
        return Err(CatalogReadError::QueryInvalid);
    };
    if (1..=MAX_PAGE_ITEMS).contains(&limit) {
        Ok(limit)
    } else {
        Err(CatalogReadError::QueryInvalid)
    }
}

fn bounded_cursor(value: String) -> Result<String, CatalogReadError> {
    if value.is_empty() || value.len() > MAX_CURSOR_BYTES {
        return Err(CatalogReadError::CursorInvalid);
    }
    Ok(value)
}

fn search_text(value: &str) -> Result<Option<String>, CatalogReadError> {
    if value.chars().count() > MAX_QUERY_TEXT_CHARS || value.chars().any(char::is_control) {
        return Err(CatalogReadError::QueryInvalid);
    }
    let trimmed = value.trim();
    Ok((!trimmed.is_empty()).then(|| trimmed.to_lowercase()))
}

fn filter_token(value: String) -> Result<String, CatalogReadError> {
    let valid = !value.is_empty()
        && value.len() <= MAX_FILTER_VALUE_BYTES
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'));
    if valid {
        Ok(value)
    } else {
        Err(CatalogReadError::QueryInvalid)
    }
}

/// A snapshot-bound continuation. The check binds snapshot, resource, filter
/// and offset; it is integrity, not authorization — every page is
/// reauthenticated by the transport and every offset is bounds-checked.
pub(crate) fn encode_cursor(
    snapshot_id: &str,
    resource_key: &str,
    filter_key: &str,
    offset: usize,
) -> String {
    format!(
        "v1.{}.{offset}.{}",
        snapshot_tag(snapshot_id),
        cursor_check(snapshot_id, resource_key, filter_key, offset)
    )
}

/// Decode a cursor to an offset. A well-formed cursor from another snapshot
/// is `SnapshotExpired`; any other mismatch is `CursorInvalid`.
pub(crate) fn decode_cursor(
    cursor: &str,
    snapshot_id: &str,
    resource_key: &str,
    filter_key: &str,
) -> Result<usize, CatalogReadError> {
    let parts: Vec<&str> = cursor.split('.').collect();
    let ["v1", tag, offset, check] = parts.as_slice() else {
        return Err(CatalogReadError::CursorInvalid);
    };
    let offset_valid = !offset.is_empty()
        && offset.len() <= 6
        && offset.bytes().all(|b| b.is_ascii_digit())
        && (*offset == "0" || !offset.starts_with('0'));
    if !offset_valid || !is_lower_hex(tag, 16) || !is_lower_hex(check, 32) {
        return Err(CatalogReadError::CursorInvalid);
    }
    let offset: usize = offset
        .parse()
        .map_err(|_| CatalogReadError::CursorInvalid)?;
    if offset > MAX_CURSOR_OFFSET {
        return Err(CatalogReadError::CursorInvalid);
    }
    if *tag != snapshot_tag(snapshot_id) {
        return Err(CatalogReadError::SnapshotExpired);
    }
    if *check != cursor_check(snapshot_id, resource_key, filter_key, offset) {
        return Err(CatalogReadError::CursorInvalid);
    }
    Ok(offset)
}

fn snapshot_tag(snapshot_id: &str) -> String {
    hex_prefix(&Sha256::digest(snapshot_id.as_bytes()), 16)
}

fn cursor_check(snapshot_id: &str, resource_key: &str, filter_key: &str, offset: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(CURSOR_DOMAIN);
    for part in [snapshot_id, resource_key, filter_key, &offset.to_string()] {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex_prefix(&hasher.finalize(), 32)
}

fn is_lower_hex(text: &str, len: usize) -> bool {
    text.len() == len && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}

pub(crate) fn hex_prefix(bytes: &[u8], chars: usize) -> String {
    let mut out = String::with_capacity(chars);
    for byte in bytes {
        if out.len() >= chars {
            break;
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out.truncate(chars);
    out
}

/// The strong ETag for exact response bytes.
pub(crate) fn etag_for(body: &[u8]) -> String {
    format!("\"cr1-{}\"", hex_prefix(&Sha256::digest(body), 32))
}

/// RFC 9110 `If-None-Match` weak comparison. Malformed or oversized headers
/// never match, so the full representation is sent.
pub(crate) fn if_none_match_matches(header: Option<&str>, etag: &str) -> bool {
    let Some(header) = header else {
        return false;
    };
    if header.len() > MAX_IF_NONE_MATCH_BYTES {
        return false;
    }
    let header = header.trim();
    if header == "*" {
        return true;
    }
    let target = opaque_tag(etag);
    let mut count = 0;
    let mut matched = false;
    for member in header.split(',') {
        count += 1;
        if count > MAX_IF_NONE_MATCH_TAGS {
            return false;
        }
        let member = member.trim();
        let member = member.strip_prefix("W/").unwrap_or(member);
        if !is_entity_tag(member) {
            return false;
        }
        matched |= Some(member) == target;
    }
    matched
}

fn opaque_tag(etag: &str) -> Option<&str> {
    let tag = etag.strip_prefix("W/").unwrap_or(etag);
    is_entity_tag(tag).then_some(tag)
}

fn is_entity_tag(tag: &str) -> bool {
    tag.len() >= 2
        && tag.starts_with('"')
        && tag.ends_with('"')
        && tag[1..tag.len() - 1]
            .bytes()
            .all(|b| b == 0x21 || (0x23..=0x7e).contains(&b))
}
