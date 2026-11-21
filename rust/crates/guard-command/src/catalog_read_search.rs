//! Filtering for the catalog read model: index filters and the catalog-wide
//! permission search behind `permissions?q=` (ADR 0014).

use super::{
    CatalogFilter, CatalogQuery, CatalogReadError, CatalogReadSnapshot, CatalogRoute,
    ExtensionEntry, CATALOG_PERMISSION_SEARCH_SCHEMA,
};

impl CatalogReadSnapshot {
    /// Permissions from every extension, in index order (extension ID, then
    /// catalog source order). `q` keeps a permission only when every
    /// whitespace-separated term occurs in its search text.
    pub(super) fn permission_search_page(
        &self,
        route: &CatalogRoute,
        query: &CatalogQuery,
    ) -> Result<Vec<u8>, CatalogReadError> {
        let terms: Vec<&str> = query
            .filter
            .q
            .as_deref()
            .map(|text| text.split_whitespace().collect())
            .unwrap_or_default();
        let items: Vec<&[u8]> = self
            .extensions
            .iter()
            .flat_map(|entry| entry.permissions.iter().zip(&entry.permission_search))
            .filter(|(_, text)| terms.iter().all(|term| text.contains(term)))
            .map(|(item, _)| &**item)
            .collect();
        let prefix = format!(
            "{{\"schema_version\":\"{CATALOG_PERMISSION_SEARCH_SCHEMA}\",\"snapshot_id\":\"{}\",\
             \"native_catalog_digest\":\"{}\",\"limit\":{},\"total_count\":{},\"items\":[",
            self.snapshot_id,
            self.catalog_digest,
            query.limit,
            items.len()
        );
        self.page(prefix, &items, route, query)
    }
}

pub(super) fn matches_filter(entry: &ExtensionEntry, filter: &CatalogFilter) -> bool {
    filter
        .source
        .as_ref()
        .is_none_or(|value| *value == entry.source)
        && filter
            .surface
            .as_ref()
            .is_none_or(|value| entry.surface.as_ref() == Some(value))
        && filter
            .trust_class
            .as_ref()
            .is_none_or(|value| *value == entry.trust_class)
        && filter
            .risk_class
            .as_ref()
            .is_none_or(|value| entry.risk_classes.contains(value))
        && filter
            .q
            .as_ref()
            .is_none_or(|text| entry.search_text.contains(text.as_str()))
}
