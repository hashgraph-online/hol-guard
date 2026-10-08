//! `command-catalog.v1.json` — catalog metadata layer mirroring
//! `generated_command_catalog.py`'s `GeneratedCommandCatalog`.
//!
//! The packaged `native-command-program.v1.json` carries only the compiled
//! matcher graph and the rule/extension fields the resident evaluator needs.
//! It intentionally drops the human-facing metadata (`description`,
//! `safer_alternatives`, `compatibility_fallback`, `aliases`) that the Python
//! `GeneratedCommandCatalog` exposes for `to_dict()` output and floor helpers.
//! Both artifacts share `catalog_digest`/`program_digest`, so this module binds
//! the catalog to the live [`NativeCommandProgram`] and provides the same
//! normalized lookup surface (`get`, `get_rule`, `permission`, …).

use std::collections::BTreeMap;
use std::sync::{Arc, OnceLock};

use serde::Deserialize;

use crate::native_command_program::packaged_command_program;

#[cfg(not(guard_source_bootstrap))]
const EMBEDDED_CATALOG: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/command-catalog.v1.json"));
// The bootstrap shadow lib (guard-command-build) produces no packaged output;
// an empty slice keeps `include_bytes!` valid and `from_embedded` fails closed
// exactly like the `EMBEDDED_PROGRAM` bootstrap path.
#[cfg(guard_source_bootstrap)]
const EMBEDDED_CATALOG: &[u8] = &[];

/// One rule's metadata — the fields `GeneratedCommandRule` exposes that the
/// compiled `ProgramRule` does not carry.
#[derive(Debug, Deserialize, PartialEq)]
pub struct CatalogRule {
    pub rule_id: String,
    pub rule_version: String,
    pub severity: String,
    pub risk_classes: Vec<String>,
    pub action_classes: Vec<String>,
    pub description: String,
    pub safer_alternatives: Vec<String>,
    pub default_mode: String,
    pub compatibility_fallback: bool,
    pub title: Option<String>,
    pub family: Option<String>,
    pub matcher_kind: Option<String>,
    pub matcher_contract_digest: Option<String>,
    /// Known safe variants — `GeneratedCommandRule.safe_variants`; the
    /// wire-evidence validator rejects `variant_id`s not present here.
    #[serde(default)]
    pub safe_variants: Vec<CatalogSafeVariant>,
}

/// One catalog safe variant — only `variant_id` is read by the evidence
/// validator; the remaining fields are display metadata bound by the
/// catalog digest.
#[derive(Debug, Deserialize, PartialEq)]
pub struct CatalogSafeVariant {
    pub variant_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub matcher_kind: Option<String>,
    #[serde(default)]
    pub matcher_contract_digest: Option<String>,
}

/// One permission's metadata — `GeneratedCommandPermission`.
#[derive(Debug, Deserialize, PartialEq)]
pub struct CatalogPermission {
    pub permission_id: String,
    pub extension_id: String,
    pub action_classes: Vec<String>,
    pub baseline_floor: String,
    pub configurable: bool,
    pub default_enabled: bool,
    pub dependencies: Vec<String>,
    pub implied_permissions: Vec<String>,
    pub rule_ids: Vec<String>,
    pub typed_capabilities: Vec<String>,
    pub description: String,
    pub deprecated: bool,
}

/// One extension's metadata — `GeneratedCommandExtension`.
#[derive(Debug, Deserialize, PartialEq)]
pub struct CatalogExtension {
    pub extension_id: String,
    pub version: String,
    pub source: String,
    pub required: bool,
    pub trust_class: String,
    #[serde(default)]
    pub aliases: Vec<String>,
    /// `dependencies` — resolver extension-closure input.
    #[serde(default)]
    pub dependencies: Vec<String>,
    pub rules: Vec<CatalogRule>,
    pub permissions: Vec<CatalogPermission>,
}

/// The read-only metadata catalog + normalized relationship indexes,
/// mirroring `GeneratedCommandCatalog`.
#[derive(Debug)]
pub struct CommandCatalog {
    pub catalog_digest: String,
    pub program_digest: String,
    pub extensions: Vec<CatalogExtension>,
    /// extension_id + aliases → extension index.
    by_extension_id: BTreeMap<String, usize>,
    /// normalized rule_id → extension's rule index path.
    by_rule_id: BTreeMap<String, usize>,
    /// normalized permission_id → permission index.
    by_permission_id: BTreeMap<String, usize>,
    /// normalized rule_id → permission index.
    permission_by_rule_id: BTreeMap<String, usize>,
    /// normalized action_class → rule index (first non-fallback).
    rule_by_action_class: BTreeMap<String, usize>,
    /// normalized action_class → permission index.
    permission_by_action_class: BTreeMap<String, usize>,
    /// normalized typed_capability → permission index.
    permission_by_capability: BTreeMap<String, usize>,
}

impl CommandCatalog {
    fn from_embedded() -> Result<Self, &'static str> {
        #[derive(Deserialize)]
        struct Wrapper {
            catalog: Vec<CatalogExtension>,
            catalog_digest: String,
            program_digest: String,
        }
        let wrapper: Wrapper = serde_json::from_slice(EMBEDDED_CATALOG)
            .map_err(|_| "command_catalog_decode_failed")?;
        let mut extensions = wrapper.catalog;
        extensions.sort_by(|a, b| a.extension_id.cmp(&b.extension_id));

        // Flatten rules in the same order the Python catalog does: extensions
        // sorted by extension_id, then each extension's rules in declared
        // order.
        let mut rule_entries: Vec<(usize, usize)> = Vec::new();
        for (extension_index, ext) in extensions.iter().enumerate() {
            for (rule_index, _) in ext.rules.iter().enumerate() {
                rule_entries.push((extension_index, rule_index));
            }
        }

        let mut by_extension_id: BTreeMap<String, usize> = BTreeMap::new();
        for (index, ext) in extensions.iter().enumerate() {
            by_extension_id.insert(ext.extension_id.clone(), index);
            for alias in &ext.aliases {
                by_extension_id.insert(alias.clone(), index);
            }
        }

        let mut by_rule_id: BTreeMap<String, usize> = BTreeMap::new();
        let mut by_permission_id: BTreeMap<String, usize> = BTreeMap::new();
        let mut permission_by_rule_id: BTreeMap<String, usize> = BTreeMap::new();
        let mut rule_by_action_class: BTreeMap<String, usize> = BTreeMap::new();
        let mut permission_by_action_class: BTreeMap<String, usize> = BTreeMap::new();
        let mut permission_by_capability: BTreeMap<String, usize> = BTreeMap::new();

        for (flat_rule, (extension_index, rule_index)) in rule_entries.iter().enumerate() {
            let rule = &extensions[*extension_index].rules[*rule_index];
            by_rule_id.insert(rule.rule_id.trim().to_lowercase(), flat_rule);
            if rule.compatibility_fallback {
                for action in &rule.action_classes {
                    rule_by_action_class.insert(action.trim().to_lowercase(), flat_rule);
                }
            }
        }
        let mut permissions: Vec<_> = extensions
            .iter()
            .flat_map(|ext| ext.permissions.iter())
            .enumerate()
            .collect();
        permissions.sort_by(|(_, left), (_, right)| left.permission_id.cmp(&right.permission_id));
        for (permission_index, permission) in permissions {
            by_permission_id.insert(
                permission.permission_id.trim().to_lowercase(),
                permission_index,
            );
            for rule_id in &permission.rule_ids {
                permission_by_rule_id.insert(rule_id.trim().to_lowercase(), permission_index);
            }
            for action in &permission.action_classes {
                permission_by_action_class
                    .entry(action.trim().to_lowercase())
                    .or_insert(permission_index);
            }
            for capability in &permission.typed_capabilities {
                permission_by_capability.insert(capability.trim().to_lowercase(), permission_index);
            }
        }

        Ok(Self {
            catalog_digest: wrapper.catalog_digest,
            program_digest: wrapper.program_digest,
            extensions,
            by_extension_id,
            by_rule_id,
            by_permission_id,
            permission_by_rule_id,
            rule_by_action_class,
            permission_by_action_class,
            permission_by_capability,
        })
    }

    /// Resolve an extension by `extension_id` or any of its `aliases`
    /// (GeneratedCommandCatalog.get).
    pub fn get(&self, extension_id: &str) -> Option<&CatalogExtension> {
        self.by_extension_id
            .get(extension_id)
            .map(|index| &self.extensions[*index])
    }

    /// Flat rule lookup by normalized rule_id (GeneratedCommandCatalog.get_rule).
    pub fn get_rule(&self, rule_id: &str) -> Option<(&CatalogExtension, &CatalogRule)> {
        let flat = *self.by_rule_id.get(&rule_id.trim().to_lowercase())?;
        let (extension_index, rule_index) = self.flat_rule_ref(flat)?;
        Some((
            &self.extensions[extension_index],
            &self.extensions[extension_index].rules[rule_index],
        ))
    }

    /// Permission lookup by normalized permission_id (GeneratedCommandCatalog.permission).
    pub fn permission(&self, permission_id: &str) -> Option<&CatalogPermission> {
        let index = *self
            .by_permission_id
            .get(&permission_id.trim().to_lowercase())?;
        self.permissions_flat().get(index).copied()
    }

    /// Permission owning a rule_id (GeneratedCommandCatalog.permission_for_rule_id).
    pub fn permission_for_rule_id(&self, rule_id: &str) -> Option<&CatalogPermission> {
        let index = *self
            .permission_by_rule_id
            .get(&rule_id.trim().to_lowercase())?;
        self.permissions_flat().get(index).copied()
    }

    /// First non-fallback rule for an action_class (rule_for_action_class).
    pub fn rule_for_action_class(
        &self,
        action_class: &str,
    ) -> Option<(&CatalogExtension, &CatalogRule)> {
        let flat = *self
            .rule_by_action_class
            .get(&action_class.trim().to_lowercase())?;
        let (extension_index, rule_index) = self.flat_rule_ref(flat)?;
        Some((
            &self.extensions[extension_index],
            &self.extensions[extension_index].rules[rule_index],
        ))
    }

    /// Permission for an action_class (permission_for_action_class).
    pub fn permission_for_action_class(&self, action_class: &str) -> Option<&CatalogPermission> {
        let index = *self
            .permission_by_action_class
            .get(&action_class.trim().to_lowercase())?;
        self.permissions_flat().get(index).copied()
    }

    /// Permission for a typed capability (permission_for_typed_capability).
    pub fn permission_for_typed_capability(&self, capability: &str) -> Option<&CatalogPermission> {
        let index = *self
            .permission_by_capability
            .get(&capability.trim().to_lowercase())?;
        self.permissions_flat().get(index).copied()
    }

    fn flat_rule_ref(&self, flat: usize) -> Option<(usize, usize)> {
        let mut offset = 0;
        for (extension_index, ext) in self.extensions.iter().enumerate() {
            if flat < offset + ext.rules.len() {
                return Some((extension_index, flat - offset));
            }
            offset += ext.rules.len();
        }
        None
    }

    fn permissions_flat(&self) -> Vec<&CatalogPermission> {
        self.extensions
            .iter()
            .flat_map(|ext| ext.permissions.iter())
            .collect()
    }
}

/// Load the packaged catalog once, bound to the live native program's digests.
/// Mismatched digests fail closed — the metadata layer is only valid for the
/// compiled program it was generated with.
pub fn packaged_command_catalog() -> Result<Arc<CommandCatalog>, &'static str> {
    static CATALOG: OnceLock<Result<Arc<CommandCatalog>, &'static str>> = OnceLock::new();
    CATALOG
        .get_or_init(|| {
            let catalog = CommandCatalog::from_embedded().map(Arc::new)?;
            let program = packaged_command_program()?;
            if catalog.catalog_digest != program.catalog_digest
                || catalog.program_digest != program.program_digest
            {
                return Err("command_catalog_program_digest_mismatch");
            }
            Ok(catalog)
        })
        .clone()
}
