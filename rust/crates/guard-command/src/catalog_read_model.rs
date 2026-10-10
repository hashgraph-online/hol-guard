//! Rust-owned catalog read model (ADR 0014).
//!
//! One immutable snapshot per process is built from the embedded
//! `command-catalog.v1.json`, after its canonical digest is re-verified and
//! it is bound to the live native program. The snapshot pre-encodes every
//! allowlisted projection as HTML-safe JSON once, so a request only selects,
//! pages and concatenates bytes. Index pages, extension details and
//! permission/rule collection pages, snapshot-bound cursors and ETag
//! evaluation all live here; the daemon transport forwards raw request
//! strings and writes the returned body verbatim.
//!
//! The read model is static metadata. It never reads or changes effective
//! control state, trust, managed revisions or hook decisions.

use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

use crate::catalog_read_projection::{extension_entry, ExtensionEntry};
use crate::catalog_read_query::{
    decode_cursor, encode_cursor, etag_for, hex_prefix, if_none_match_matches, CatalogFilter,
    CatalogQuery, CatalogRoute, MAX_CURSOR_BYTES,
};
use crate::native_command_catalog::{embedded_catalog_bytes, packaged_command_catalog};

#[path = "catalog_read_search.rs"]
mod search;
use search::matches_filter;

pub const CATALOG_READ_CAPABILITY: &str = "catalog-read-model-v1";
pub const CATALOG_READ_REQUEST_SCHEMA: &str = "guard-catalog-read-request.v1";
pub const CATALOG_READ_RESULT_SCHEMA: &str = "guard-catalog-read-result.v1";
pub const CATALOG_INDEX_SCHEMA: &str = "guard.daemon.catalog-index.v2";
pub const CATALOG_EXTENSION_SCHEMA: &str = "guard.daemon.catalog-extension.v2";
pub const CATALOG_PERMISSIONS_SCHEMA: &str = "guard.daemon.catalog-permissions.v2";
pub const CATALOG_RULES_SCHEMA: &str = "guard.daemon.catalog-rules.v2";
pub const CATALOG_MCP_TOOLS_SCHEMA: &str = "guard.daemon.catalog-mcp-tools.v2";
pub const CATALOG_PERMISSION_SEARCH_SCHEMA: &str = "guard.daemon.catalog-permission-search.v2";
/// Uncompressed bytes per response, envelope included, counted after
/// HTML-safe escaping — the exact bytes the daemon writes.
pub const MAX_CATALOG_PAGE_BYTES: usize = 262_144;
/// Aggregate encoded-projection budget for the one retained snapshot. No
/// prior snapshot is retained: the catalog is immutable per native binary.
pub const MAX_CATALOG_SNAPSHOT_ENCODED_BYTES: usize = 16_000_000;
const MAX_CATALOG_EXTENSIONS: usize = 512;
/// Changes to projections, envelopes or page limits must change this so
/// snapshot IDs, cursors and ETags from older layouts stop validating.
const READ_MODEL_VERSION: &str = "catalog-read-model-v1;page=50/100/262144;index=2;search=1";
const SNAPSHOT_DOMAIN: &[u8] = b"guard-catalog-read-snapshot-v1\0";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CatalogReadError {
    RequestInvalid,
    QueryInvalid,
    CursorInvalid,
    RouteNotFound,
    ExtensionNotFound,
    SnapshotExpired,
    SnapshotMismatch,
    ItemExceedsPageBudget,
    Unavailable,
}

impl CatalogReadError {
    pub fn code(self) -> &'static str {
        match self {
            Self::RequestInvalid => "catalog_request_invalid",
            Self::QueryInvalid => "catalog_query_invalid",
            Self::CursorInvalid => "catalog_cursor_invalid",
            Self::RouteNotFound => "catalog_route_not_found",
            Self::ExtensionNotFound => "catalog_extension_not_found",
            Self::SnapshotExpired => "catalog_snapshot_expired",
            Self::SnapshotMismatch => "catalog_snapshot_mismatch",
            Self::ItemExceedsPageBudget => "catalog_item_exceeds_page_budget",
            Self::Unavailable => "catalog_read_model_unavailable",
        }
    }

    pub fn http_status(self) -> u16 {
        match self {
            Self::RequestInvalid | Self::QueryInvalid | Self::CursorInvalid => 400,
            Self::RouteNotFound | Self::ExtensionNotFound => 404,
            Self::SnapshotExpired => 409,
            Self::ItemExceedsPageBudget => 500,
            Self::SnapshotMismatch | Self::Unavailable => 503,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReadRequestV1 {
    pub schema: String,
    /// Route suffix after `/v2/extension-controls/catalog/`.
    pub route: String,
    /// Raw query string, without `?`.
    pub query: String,
    pub if_none_match: Option<String>,
    /// The `catalog_digest` of the registry the daemon serves.
    pub expected_catalog_digest: String,
}

#[derive(Debug, Serialize, PartialEq, Eq)]
pub struct CatalogReadResultV1 {
    pub schema: &'static str,
    pub outcome: &'static str,
    pub http_status: u16,
    pub etag: Option<String>,
    /// HTML-safe JSON text, written verbatim by the transport.
    pub body: Option<String>,
    pub error_code: Option<&'static str>,
}

impl CatalogReadResultV1 {
    fn error(error: CatalogReadError) -> Self {
        Self {
            schema: CATALOG_READ_RESULT_SCHEMA,
            outcome: "error",
            http_status: error.http_status(),
            etag: None,
            body: None,
            error_code: Some(error.code()),
        }
    }
}

/// One immutable, validated catalog snapshot with pre-encoded projections.
#[derive(Debug)]
pub struct CatalogReadSnapshot {
    snapshot_id: String,
    catalog_digest: String,
    extensions: Vec<ExtensionEntry>,
    encoded_bytes: usize,
}

/// The process-wide snapshot. `OnceLock` gives concurrent first readers one
/// shared build; nothing is locked while a response is written.
pub fn packaged_catalog_read_snapshot() -> Result<&'static CatalogReadSnapshot, &'static str> {
    static SNAPSHOT: OnceLock<Result<CatalogReadSnapshot, &'static str>> = OnceLock::new();
    SNAPSHOT
        .get_or_init(|| {
            let bound = packaged_command_catalog()?;
            let snapshot = CatalogReadSnapshot::from_catalog_bytes(embedded_catalog_bytes())?;
            if snapshot.catalog_digest != bound.catalog_digest {
                return Err("catalog_read_model_digest_mismatch");
            }
            Ok(snapshot)
        })
        .as_ref()
        .map_err(|error| *error)
}

/// Resident entry point: never panics, never returns a partial body.
pub fn evaluate_catalog_read(request: &CatalogReadRequestV1) -> CatalogReadResultV1 {
    match packaged_catalog_read_snapshot() {
        Ok(snapshot) => snapshot.read(request),
        Err(_) => CatalogReadResultV1::error(CatalogReadError::Unavailable),
    }
}

impl CatalogReadSnapshot {
    pub fn from_catalog_bytes(bytes: &[u8]) -> Result<Self, &'static str> {
        let envelope: Value =
            serde_json::from_slice(bytes).map_err(|_| "catalog_read_model_invalid_json")?;
        let catalog_digest = envelope
            .get("catalog_digest")
            .and_then(Value::as_str)
            .filter(|digest| is_sha256_hex(digest))
            .ok_or("catalog_read_model_missing_digest")?
            .to_owned();
        let catalog = envelope
            .get("catalog")
            .and_then(Value::as_array)
            .ok_or("catalog_read_model_missing_catalog")?;
        if catalog.len() > MAX_CATALOG_EXTENSIONS {
            return Err("catalog_read_model_extension_limit");
        }
        // Same canonical form as `GeneratedCommandCatalog.catalog_digest`:
        // sorted keys, compact separators, raw UTF-8.
        let canonical = serde_json::to_vec(catalog).map_err(|_| "catalog_read_model_encode")?;
        if hex_prefix(&Sha256::digest(&canonical), 64) != catalog_digest {
            return Err("catalog_read_model_digest_mismatch");
        }
        let snapshot_id = snapshot_id_for(&catalog_digest);
        let mut extensions = catalog
            .iter()
            .map(extension_entry)
            .collect::<Result<Vec<_>, _>>()?;
        extensions.sort_by(|left, right| left.id.cmp(&right.id));
        if extensions.windows(2).any(|pair| pair[0].id == pair[1].id) {
            return Err("catalog_read_model_duplicate_extension");
        }
        // Permission IDs are control targets, so they are unique catalog-wide.
        let mut permission_ids = std::collections::BTreeSet::new();
        if !extensions
            .iter()
            .flat_map(|entry| &entry.permission_ids)
            .all(|id| permission_ids.insert(id.as_str()))
        {
            return Err("catalog_read_model_duplicate_permission");
        }
        let encoded_bytes = extensions.iter().map(ExtensionEntry::encoded_bytes).sum();
        if encoded_bytes > MAX_CATALOG_SNAPSHOT_ENCODED_BYTES {
            return Err("catalog_read_model_snapshot_budget_exceeded");
        }
        Ok(Self {
            snapshot_id,
            catalog_digest,
            extensions,
            encoded_bytes,
        })
    }

    pub fn snapshot_id(&self) -> &str {
        &self.snapshot_id
    }

    pub fn catalog_digest(&self) -> &str {
        &self.catalog_digest
    }

    /// Encoded projection bytes retained by this snapshot.
    pub fn encoded_bytes(&self) -> usize {
        self.encoded_bytes
    }

    pub fn read(&self, request: &CatalogReadRequestV1) -> CatalogReadResultV1 {
        match self.render(request) {
            Ok(body) => {
                let etag = etag_for(&body);
                if if_none_match_matches(request.if_none_match.as_deref(), &etag) {
                    return CatalogReadResultV1 {
                        schema: CATALOG_READ_RESULT_SCHEMA,
                        outcome: "not_modified",
                        http_status: 304,
                        etag: Some(etag),
                        body: None,
                        error_code: None,
                    };
                }
                match String::from_utf8(body) {
                    Ok(body) => CatalogReadResultV1 {
                        schema: CATALOG_READ_RESULT_SCHEMA,
                        outcome: "ok",
                        http_status: 200,
                        etag: Some(etag),
                        body: Some(body),
                        error_code: None,
                    },
                    Err(_) => CatalogReadResultV1::error(CatalogReadError::Unavailable),
                }
            }
            Err(error) => CatalogReadResultV1::error(error),
        }
    }

    fn render(&self, request: &CatalogReadRequestV1) -> Result<Vec<u8>, CatalogReadError> {
        if request.schema != CATALOG_READ_REQUEST_SCHEMA
            || !is_sha256_hex(&request.expected_catalog_digest)
        {
            return Err(CatalogReadError::RequestInvalid);
        }
        if request.expected_catalog_digest != self.catalog_digest {
            return Err(CatalogReadError::SnapshotMismatch);
        }
        let route = CatalogRoute::parse(&request.route)?;
        let query = CatalogQuery::parse(&route, &request.query)?;
        match &route {
            CatalogRoute::Index => self.index_page(&route, &query),
            CatalogRoute::PermissionSearch => self.permission_search_page(&route, &query),
            CatalogRoute::Extension(id) => self.detail(self.extension(id)?),
            CatalogRoute::Permissions(id) => {
                let entry = self.extension(id)?;
                self.collection(
                    CATALOG_PERMISSIONS_SCHEMA,
                    entry,
                    &entry.permissions,
                    &route,
                    &query,
                )
            }
            CatalogRoute::Rules(id) => {
                let entry = self.extension(id)?;
                self.collection(CATALOG_RULES_SCHEMA, entry, &entry.rules, &route, &query)
            }
            CatalogRoute::McpTools(id) => {
                let entry = self.extension(id)?;
                self.collection(
                    CATALOG_MCP_TOOLS_SCHEMA,
                    entry,
                    &entry.mcp_tools,
                    &route,
                    &query,
                )
            }
        }
    }

    fn extension(&self, id: &str) -> Result<&ExtensionEntry, CatalogReadError> {
        self.extensions
            .binary_search_by(|entry| entry.id.as_str().cmp(id))
            .map(|index| &self.extensions[index])
            .map_err(|_| CatalogReadError::ExtensionNotFound)
    }

    fn index_page(
        &self,
        route: &CatalogRoute,
        query: &CatalogQuery,
    ) -> Result<Vec<u8>, CatalogReadError> {
        let items: Vec<&[u8]> = self
            .extensions
            .iter()
            .filter(|entry| matches_filter(entry, &query.filter))
            .map(|entry| &*entry.index_item)
            .collect();
        let prefix = format!(
            "{{\"schema_version\":\"{CATALOG_INDEX_SCHEMA}\",\"snapshot_id\":\"{}\",\
             \"native_catalog_digest\":\"{}\",\"limit\":{},\"total_count\":{},\"items\":[",
            self.snapshot_id,
            self.catalog_digest,
            query.limit,
            items.len()
        );
        self.page(prefix, &items, route, query)
    }

    fn collection(
        &self,
        schema: &str,
        entry: &ExtensionEntry,
        collection: &[Box<[u8]>],
        route: &CatalogRoute,
        query: &CatalogQuery,
    ) -> Result<Vec<u8>, CatalogReadError> {
        let prefix = format!(
            "{{\"schema_version\":\"{schema}\",\"snapshot_id\":\"{}\",\
             \"native_catalog_digest\":\"{}\",\"extension_id\":\"{}\",\"limit\":{},\
             \"total_count\":{},\"items\":[",
            self.snapshot_id,
            self.catalog_digest,
            entry.id,
            query.limit,
            collection.len()
        );
        let items: Vec<&[u8]> = collection.iter().map(|item| &**item).collect();
        self.page(prefix, &items, route, query)
    }

    /// Byte-aware page: complete items only, envelope counted, worst-case
    /// cursor reserved so the final body never exceeds the budget.
    fn page(
        &self,
        prefix: String,
        items: &[&[u8]],
        route: &CatalogRoute,
        query: &CatalogQuery,
    ) -> Result<Vec<u8>, CatalogReadError> {
        let resource_key = route.resource_key();
        let filter_key = query.filter.binding_key();
        let offset = match &query.cursor {
            Some(cursor) => {
                let offset = decode_cursor(cursor, &self.snapshot_id, &resource_key, &filter_key)?;
                if offset == 0 || offset >= items.len() {
                    return Err(CatalogReadError::CursorInvalid);
                }
                offset
            }
            None => 0,
        };
        let suffix_reserve = "],\"next_cursor\":\"\"}".len() + MAX_CURSOR_BYTES;
        let budget = MAX_CATALOG_PAGE_BYTES
            .checked_sub(prefix.len() + suffix_reserve)
            .ok_or(CatalogReadError::ItemExceedsPageBudget)?;
        let mut used = 0usize;
        let mut count = 0usize;
        for item in &items[offset..] {
            let added = item.len() + usize::from(count > 0);
            if count == query.limit || used + added > budget {
                break;
            }
            used += added;
            count += 1;
        }
        if count == 0 && offset < items.len() {
            return Err(CatalogReadError::ItemExceedsPageBudget);
        }
        let next = offset + count;
        let mut body = Vec::with_capacity(prefix.len() + used + suffix_reserve);
        body.extend_from_slice(prefix.as_bytes());
        for (position, item) in items[offset..next].iter().enumerate() {
            if position > 0 {
                body.push(b',');
            }
            body.extend_from_slice(item);
        }
        body.extend_from_slice(b"],\"next_cursor\":");
        if next < items.len() {
            let cursor = encode_cursor(&self.snapshot_id, &resource_key, &filter_key, next);
            body.push(b'"');
            body.extend_from_slice(cursor.as_bytes());
            body.push(b'"');
        } else {
            body.extend_from_slice(b"null");
        }
        body.push(b'}');
        if body.len() > MAX_CATALOG_PAGE_BYTES {
            return Err(CatalogReadError::ItemExceedsPageBudget);
        }
        Ok(body)
    }

    fn detail(&self, entry: &ExtensionEntry) -> Result<Vec<u8>, CatalogReadError> {
        let mut body = format!(
            "{{\"schema_version\":\"{CATALOG_EXTENSION_SCHEMA}\",\"snapshot_id\":\"{}\",\
             \"native_catalog_digest\":\"{}\",\"extension\":",
            self.snapshot_id, self.catalog_digest
        )
        .into_bytes();
        body.extend_from_slice(&entry.detail);
        let mut collections = format!(
            ",\"collections\":{{\"permissions\":{{\"total_count\":{}}},\
             \"rules\":{{\"total_count\":{}}}",
            entry.permissions.len(),
            entry.rules.len(),
        );
        // Mirror whether the source declares `mcp_tools` at all.
        if entry.has_mcp_tools {
            collections.push_str(&format!(
                ",\"mcp_tools\":{{\"total_count\":{}}}",
                entry.mcp_tools.len()
            ));
        }
        collections.push_str("}}");
        body.extend_from_slice(collections.as_bytes());
        if body.len() > MAX_CATALOG_PAGE_BYTES {
            return Err(CatalogReadError::ItemExceedsPageBudget);
        }
        Ok(body)
    }
}

fn snapshot_id_for(catalog_digest: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(SNAPSHOT_DOMAIN);
    hasher.update(catalog_digest.as_bytes());
    hasher.update(b"\0");
    hasher.update(READ_MODEL_VERSION.as_bytes());
    format!("cs1-{}", hex_prefix(&hasher.finalize(), 32))
}

fn is_sha256_hex(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
}
