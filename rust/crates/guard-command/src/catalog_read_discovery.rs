//! Integrity-bound discovery metadata only. The daemon supplies a root digest
//! obtained from its authenticated factory, never a caller-selected file path.
//! Each scan retains one index page, one extension and one response page.
use super::*;
use crate::native_command_program::source::{read_pack_blob, PackObjectRef};
#[cfg(test)]
use std::path::Path;
use std::path::PathBuf;

pub const CAPABILITY: &str = "catalog-read-discovery-v2";
const OBJECT_BYTES: usize = 65_536;
const MAX_EXTENSIONS: usize = 100_000;
const MAX_MATCHES: usize = 999_999; // existing cursor wire format

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CatalogReadRequestV2 {
    pub guard_home: PathBuf,
    pub discovery_root: String,
    pub read: CatalogReadRequestV1,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Root {
    schema: String,
    authority: String,
    count: usize,
    first: PackObjectRef,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Page {
    schema: String,
    entries: Vec<(String, PackObjectRef)>,
    next: Option<PackObjectRef>,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, CatalogReadError> {
    let value: Value = serde_json::from_slice(bytes).map_err(|_| CatalogReadError::Unavailable)?;
    // Exact canonical encoding rejects duplicate keys, whitespace, nonfinite
    // numbers and alternative encodings before any typed interpretation.
    if serde_json::to_vec(&value).map_err(|_| CatalogReadError::Unavailable)? != bytes {
        return Err(CatalogReadError::Unavailable);
    }
    serde_json::from_value(value).map_err(|_| CatalogReadError::Unavailable)
}

#[cfg(test)]
fn object(directory: &Path, digest: &str) -> Result<Vec<u8>, &'static str> {
    if !is_sha256_hex(digest) {
        return Err("catalog_discovery_digest_invalid");
    }
    crate::catalog_prepare::read_cache_object(directory, digest)
}

#[cfg(test)]
fn blob(directory: &Path, reference: &PackObjectRef) -> Result<Vec<u8>, CatalogReadError> {
    read_pack_blob(reference, &mut |digest| object(directory, digest))
        .map_err(|_| CatalogReadError::Unavailable)
}

fn cached_blob(
    reader: &crate::catalog_prepare::CacheReader,
    reference: &PackObjectRef,
) -> Result<Vec<u8>, CatalogReadError> {
    read_pack_blob(reference, &mut |digest| reader.read_pinned(digest))
        .map_err(|_| CatalogReadError::Unavailable)
}

pub fn evaluate(request: &CatalogReadRequestV2) -> CatalogReadResultV1 {
    read_result(render(request), &request.read)
}

fn render(request: &CatalogReadRequestV2) -> Result<Vec<u8>, CatalogReadError> {
    let read = &request.read;
    if read.schema != CATALOG_READ_REQUEST_SCHEMA
        || !is_sha256_hex(&read.expected_catalog_digest)
        || !is_sha256_hex(&request.discovery_root)
        || !request.guard_home.is_absolute()
    {
        return Err(CatalogReadError::RequestInvalid);
    }
    let route = CatalogRoute::parse(&read.route)?;
    let query = CatalogQuery::parse(&route, &read.query)?;
    let directory = request
        .guard_home
        .join("native-runtime/catalog-discovery/objects");
    let reader = crate::catalog_prepare::CacheReader::new(&directory)
        .map_err(|_| CatalogReadError::Unavailable)?;
    let bytes = reader
        .read(&request.discovery_root)
        .map_err(|_| CatalogReadError::Unavailable)?;
    if hex_prefix(&Sha256::digest(&bytes), 64) != request.discovery_root {
        return Err(CatalogReadError::Unavailable);
    }
    let root: Root = decode(&bytes)?;
    if root.schema != "guard.catalog-discovery.v1"
        || !is_sha256_hex(&root.authority)
        || root.count == 0
        || root.count > MAX_EXTENSIONS
    {
        return Err(CatalogReadError::Unavailable);
    }
    let snapshot_id = snapshot_id_for(&format!(
        "discovery-v2:{}:{}",
        request.discovery_root, read.expected_catalog_digest
    ));
    let snapshot = CatalogReadSnapshot {
        snapshot_id,
        catalog_digest: read.expected_catalog_digest.clone(),
        extensions: Vec::new(),
        encoded_bytes: 0,
    };
    let resource = route.resource_key();
    let filter = query.filter.binding_key();
    let offset = match &query.cursor {
        Some(cursor) => {
            let offset = decode_cursor(cursor, &snapshot.snapshot_id, &resource, &filter)?;
            if offset == 0 {
                return Err(CatalogReadError::CursorInvalid);
            }
            offset
        }
        None => 0,
    };
    let mut selection = Selection::new(offset, query.limit);
    let mut detail = None;
    let mut previous = String::new();
    let mut seen = 0;
    let mut pages = 0;
    let mut next = Some(root.first);
    while let Some(reference) = next {
        pages += 1;
        if pages > root.count
            || reference.expanded_length > OBJECT_BYTES
            || reference.kind != "data"
        {
            return Err(CatalogReadError::Unavailable);
        }
        let page: Page = decode(&cached_blob(&reader, &reference)?)?;
        if page.schema != "guard.catalog-discovery-page.v1"
            || page.entries.is_empty()
            || page.entries.len() > 64
        {
            return Err(CatalogReadError::Unavailable);
        }
        for (id, reference) in page.entries {
            seen += 1;
            if id <= previous
                || seen > root.count
                || CatalogRoute::parse(&format!("extensions/{id}")).is_err()
            {
                return Err(CatalogReadError::Unavailable);
            }
            previous = id.clone();
            let wanted = match &route {
                CatalogRoute::Index | CatalogRoute::PermissionSearch => true,
                CatalogRoute::Extension(target)
                | CatalogRoute::Permissions(target)
                | CatalogRoute::Rules(target)
                | CatalogRoute::McpTools(target) => target == &id,
            };
            if !wanted {
                continue;
            }
            let value: Value = decode(&cached_blob(&reader, &reference)?)?;
            let entry = extension_entry(&value).map_err(|_| CatalogReadError::Unavailable)?;
            if entry.id != id {
                return Err(CatalogReadError::Unavailable);
            }
            match &route {
                CatalogRoute::Index => {
                    if matches_filter(&entry, &query.filter) {
                        selection.push(&entry.index_item)?;
                    }
                }
                CatalogRoute::PermissionSearch => {
                    for (item, text) in entry.permissions.iter().zip(&entry.permission_search) {
                        if query
                            .filter
                            .q
                            .as_deref()
                            .unwrap_or("")
                            .split_whitespace()
                            .all(|term| text.contains(term))
                        {
                            selection.push(item)?;
                        }
                    }
                }
                _ => detail = Some(entry),
            }
        }
        next = page.next;
    }
    if seen != root.count {
        return Err(CatalogReadError::Unavailable);
    }
    reader.finish().map_err(|_| CatalogReadError::Unavailable)?;
    match route {
        CatalogRoute::Index | CatalogRoute::PermissionSearch => {
            selection.finish(&snapshot, &route, &query)
        }
        _ => {
            let entry = detail.ok_or(CatalogReadError::ExtensionNotFound)?;
            let one = CatalogReadSnapshot {
                extensions: vec![entry],
                ..snapshot
            };
            one.render(read)
        }
    }
}

/// Conservative envelope reserve keeps retained item bytes below one page.
/// A byte-full page remains closed while the scan continues to validate EOF
/// and count all matches (including matches on unloaded extensions).
struct Selection {
    offset: usize,
    limit: usize,
    total: usize,
    bytes: usize,
    closed: bool,
    items: Vec<Box<[u8]>>,
}

impl Selection {
    fn new(offset: usize, limit: usize) -> Self {
        Self {
            offset,
            limit,
            total: 0,
            bytes: 0,
            closed: false,
            items: Vec::new(),
        }
    }

    fn push(&mut self, item: &[u8]) -> Result<(), CatalogReadError> {
        self.total += 1;
        if self.total > MAX_MATCHES {
            return Err(CatalogReadError::ItemExceedsPageBudget);
        }
        if self.total <= self.offset || self.closed {
            return Ok(());
        }
        let added = item.len() + usize::from(!self.items.is_empty());
        if self.items.len() == self.limit || self.bytes + added > MAX_CATALOG_PAGE_BYTES - 1024 {
            self.closed = true;
            if self.items.is_empty() {
                return Err(CatalogReadError::ItemExceedsPageBudget);
            }
        } else {
            self.items.push(item.into());
            self.bytes += added;
        }
        Ok(())
    }

    fn finish(
        self,
        snapshot: &CatalogReadSnapshot,
        route: &CatalogRoute,
        query: &CatalogQuery,
    ) -> Result<Vec<u8>, CatalogReadError> {
        if query.cursor.is_some() && self.offset >= self.total {
            return Err(CatalogReadError::CursorInvalid);
        }
        let schema = if *route == CatalogRoute::Index {
            CATALOG_INDEX_SCHEMA
        } else {
            CATALOG_PERMISSION_SEARCH_SCHEMA
        };
        let mut body = format!(
            "{{\"schema_version\":\"{schema}\",\"snapshot_id\":\"{}\",\"native_catalog_digest\":\"{}\",\"limit\":{},\"total_count\":{},\"items\":[",
            snapshot.snapshot_id, snapshot.catalog_digest, query.limit, self.total
        ).into_bytes();
        for (index, item) in self.items.iter().enumerate() {
            if index > 0 {
                body.push(b',');
            }
            body.extend_from_slice(item);
        }
        body.extend_from_slice(b"],\"next_cursor\":");
        let next = self.offset + self.items.len();
        if next < self.total {
            let cursor = encode_cursor(
                &snapshot.snapshot_id,
                &route.resource_key(),
                &query.filter.binding_key(),
                next,
            );
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
}

#[cfg(test)]
#[path = "catalog_read_discovery_tests.rs"]
mod tests;
