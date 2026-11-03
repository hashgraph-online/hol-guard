//! The catalog a preview reads: the resolver projection plus the labels,
//! rules and conflicts the preview reports, looked up exactly as the Python
//! catalog looks them up.

use std::collections::{BTreeSet, HashMap};

use guard_command::extension_control::ControlClosure;
use guard_contracts::{
    ExtensionControlPreviewExtensionV1, ExtensionControlPreviewPermissionV1,
    ExtensionControlPreviewRegistryV1, ExtensionControlRegistryExtensionV1,
    ExtensionControlRegistryPermissionV1, ExtensionControlRegistryV1,
};

use crate::extension_control_op::{normalize, RequestRegistry};

use super::MAX_RELATIONSHIP_IDS;

/// The resolver projection of a preview catalog. The preview never asks
/// whether an extension is active, so no trust class travels.
pub(super) fn resolver_projection(
    registry: &ExtensionControlPreviewRegistryV1,
) -> ExtensionControlRegistryV1 {
    ExtensionControlRegistryV1 {
        catalog_digest: registry.catalog_digest.clone(),
        extensions: registry
            .extensions
            .iter()
            .map(|extension| ExtensionControlRegistryExtensionV1 {
                extension_id: extension.extension_id.clone(),
                aliases: extension.aliases.clone(),
                dependencies: extension.dependencies.clone(),
                required: false,
                trust_class: None,
            })
            .collect(),
        permissions: registry
            .permissions
            .iter()
            .map(|permission| ExtensionControlRegistryPermissionV1 {
                permission_id: permission.permission_id.clone(),
                extension_id: permission.extension_id.clone(),
                dependencies: permission.dependencies.clone(),
                implied_permissions: permission.implied_permissions.clone(),
            })
            .collect(),
    }
}

/// What each catalog permission and each changed extension pulls in,
/// resolved once against the catalog. Every resolution of a preview compares
/// these against its own layers instead of walking the catalog again.
pub(super) struct Closures {
    /// One per catalog permission, in catalog order.
    pub(super) permissions: Vec<ControlClosure>,
    /// One per distinct changed extension, by canonical id.
    pub(super) extensions: Vec<(String, ControlClosure)>,
}

/// Catalog lookups for the preview. Extensions resolve through the resolver
/// registry (normalized id or alias) to their canonical entry; permissions
/// through their normalized id.
pub(super) struct PreviewCatalog<'a> {
    pub(super) registry: &'a ExtensionControlPreviewRegistryV1,
    resolver: &'a RequestRegistry<'a>,
    extensions: HashMap<&'a str, &'a ExtensionControlPreviewExtensionV1>,
    permissions: HashMap<&'a str, &'a ExtensionControlPreviewPermissionV1>,
}

impl<'a> PreviewCatalog<'a> {
    /// `resolver` was built from `registry`'s projection, which already
    /// rejected duplicate extension and permission ids.
    pub(super) fn new(
        registry: &'a ExtensionControlPreviewRegistryV1,
        resolver: &'a RequestRegistry<'a>,
    ) -> Self {
        Self {
            registry,
            resolver,
            extensions: registry
                .extensions
                .iter()
                .map(|extension| (extension.extension_id.as_str(), extension))
                .collect(),
            permissions: registry
                .permissions
                .iter()
                .map(|permission| (permission.permission_id.as_str(), permission))
                .collect(),
        }
    }

    pub(super) fn resolver(&self) -> &'a RequestRegistry<'a> {
        self.resolver
    }

    pub(super) fn extension(
        &self,
        extension_id: &str,
    ) -> Option<&'a ExtensionControlPreviewExtensionV1> {
        let canonical = self.resolver.lookup(extension_id)?;
        self.extensions
            .get(canonical.extension_id.as_str())
            .copied()
    }

    pub(super) fn permission(
        &self,
        permission_id: &str,
    ) -> Option<&'a ExtensionControlPreviewPermissionV1> {
        self.permissions
            .get(normalize(permission_id).as_str())
            .copied()
    }

    /// The closure of every catalog permission and of each named extension.
    /// `None` once the closures hold more than `max_entries` entries in all,
    /// before the walk has gone further than that.
    pub(super) fn closures(
        &self,
        extension_ids: &[String],
        max_entries: usize,
    ) -> Option<Closures> {
        let mut entries = 0usize;
        let mut within_budget = |closure: &ControlClosure| {
            entries = entries.saturating_add(closure.size());
            entries <= max_entries
        };
        let mut permissions = Vec::with_capacity(self.registry.permissions.len());
        for permission in &self.registry.permissions {
            let ids = [permission.permission_id.clone()];
            let closure = ControlClosure::of(self.resolver, &[], &ids);
            if !within_budget(&closure) {
                return None;
            }
            permissions.push(closure);
        }
        let mut seen: BTreeSet<&str> = BTreeSet::new();
        let mut extensions = Vec::new();
        for extension_id in extension_ids {
            if !seen.insert(extension_id.as_str()) {
                continue;
            }
            let closure =
                ControlClosure::of(self.resolver, std::slice::from_ref(extension_id), &[]);
            if !within_budget(&closure) {
                return None;
            }
            extensions.push((extension_id.clone(), closure));
        }
        Some(Closures {
            permissions,
            extensions,
        })
    }

    /// Rules owned by the named permissions, sorted and bounded.
    pub(super) fn rule_ids_for_permissions(&self, permission_ids: &[String]) -> Vec<String> {
        let rule_ids: BTreeSet<&str> = permission_ids
            .iter()
            .filter_map(|permission_id| self.permission(permission_id))
            .flat_map(|permission| permission.rule_ids.iter().map(String::as_str))
            .collect();
        bounded(rule_ids.into_iter().map(str::to_owned))
    }

    /// Extensions owning the named permissions, sorted and bounded.
    pub(super) fn extension_ids_for_permissions(&self, permission_ids: &[String]) -> Vec<String> {
        let extension_ids: BTreeSet<&str> = permission_ids
            .iter()
            .filter_map(|permission_id| self.permission(permission_id))
            .map(|permission| permission.extension_id.as_str())
            .collect();
        bounded(extension_ids.into_iter().map(str::to_owned))
    }

    /// The extension and every extension it transitively depends on, by
    /// canonical id. The walk is depth-first from the end of the pending list
    /// and stops once the bound is reached, as the Python walk did.
    pub(super) fn extension_dependency_ids(&self, extension_id: &str) -> Vec<String> {
        let mut resolved: BTreeSet<String> = BTreeSet::new();
        let mut pending = vec![extension_id.to_owned()];
        while resolved.len() < MAX_RELATIONSHIP_IDS {
            let Some(current) = pending.pop() else {
                break;
            };
            let Some(extension) = self.extension(&current) else {
                continue;
            };
            if !resolved.insert(extension.extension_id.clone()) {
                continue;
            }
            pending.extend(extension.dependencies.iter().cloned());
        }
        resolved.into_iter().collect()
    }
}

/// The first `MAX_RELATIONSHIP_IDS` of an already ordered sequence.
pub(super) fn bounded(values: impl IntoIterator<Item = String>) -> Vec<String> {
    values.into_iter().take(MAX_RELATIONSHIP_IDS).collect()
}

/// `values` sorted (duplicates kept) and bounded.
pub(super) fn sorted_bounded(values: &[String]) -> Vec<String> {
    let mut sorted = values.to_vec();
    sorted.sort();
    sorted.truncate(MAX_RELATIONSHIP_IDS);
    sorted
}

/// The union of `values` and `extra`, sorted, deduplicated and bounded.
pub(super) fn union_bounded<'v>(
    values: impl IntoIterator<Item = &'v String>,
    extra: impl IntoIterator<Item = &'v String>,
) -> Vec<String> {
    let union: BTreeSet<&String> = values.into_iter().chain(extra).collect();
    bounded(union.into_iter().cloned())
}
