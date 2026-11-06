//! Read only a selected closure from an independently authenticated release.
use super::*;

/// Caller-selected admission limits, independent of source format budgets.
/// Counts apply before interning, bounding temporary as well as retained work.
#[derive(Clone, Copy)]
pub struct PackAdmissionBudget {
    pub packs: usize,
    pub program_bytes: usize,
    pub rules: usize,
    pub nodes: usize,
}

impl PackAdmissionBudget {
    /// Resident control-path limits. These do not alter any legacy format cap.
    pub const fn resident() -> Self {
        Self {
            packs: 32768,
            program_bytes: 512 * 1024 * 1024,
            rules: 131072,
            nodes: 1048576,
        }
    }
}

fn charge(remaining: &mut usize, amount: usize) -> Result<(), &'static str> {
    *remaining = remaining
        .checked_sub(amount)
        .ok_or("native_command_pack_budget_exceeded")?;
    Ok(())
}

impl NativeCommandProgram {
    /// Construct a collection from exact integrity-bound pack bytes. The caller
    /// must authenticate `expected_root` and authorize the complete selection
    /// before publishing this value. A cache-owned digest is never authority.
    /// Fetch runs during admission, never during command evaluation.
    pub fn from_integrity_bound_packs(
        root: &[u8],
        expected_root: &str,
        selected: &BTreeSet<String>,
        budget: PackAdmissionBudget,
        fetch: impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
    ) -> Result<Self, &'static str> {
        Self::from_integrity_bound_packs_catalog(root, expected_root, selected, budget, fetch, None)
    }

    pub(super) fn from_integrity_bound_packs_catalog(
        root: &[u8],
        expected_root: &str,
        selected: &BTreeSet<String>,
        mut budget: PackAdmissionBudget,
        fetch: impl FnMut(&str) -> Result<Vec<u8>, &'static str>,
        mut catalog: Option<&mut Vec<crate::native_command_catalog::CatalogExtension>>,
    ) -> Result<Self, &'static str> {
        if selected.is_empty() || selected.iter().any(|id| !bounded_id(id)) {
            return Err("native_command_pack_selection_invalid");
        }
        charge(&mut budget.packs, selected.len())?;
        let mut reader = source::PackReleaseReuse::from_bytes(root, expected_root, fetch)?;
        let mut packs = Vec::with_capacity(selected.len());
        for id in selected {
            let value = reader
                .read(id, None)?
                .ok_or("native_command_pack_selection_missing")?;
            if let Some(catalog) = catalog.as_mut() {
                let bytes = canonical_json_bytes(&value.catalog)
                    .map_err(|_| "command_catalog_decode_failed")?;
                charge(&mut budget.program_bytes, bytes.len())?;
                let entries: Vec<crate::native_command_catalog::CatalogExtension> =
                    serde_json::from_slice(&bytes).map_err(|_| "command_catalog_decode_failed")?;
                if entries.len() != 1 || entries[0].extension_id != *id {
                    return Err("native_command_pack_inventory_invalid");
                }
                catalog.extend(entries);
            }
            let extensions = value.program["extensions"]
                .as_array()
                .filter(|extensions| extensions.len() == 1)
                .ok_or("native_command_pack_inventory_invalid")?;
            if extensions[0]["extension_id"] != *id {
                return Err("native_command_pack_inventory_invalid");
            }
            // Complete dependency ownership is checked at composition. Allow
            // only this pack's declared references during partial admission.
            let mut permissions = BTreeSet::new();
            for permission in extensions[0]["permissions"]
                .as_array()
                .ok_or("native_command_permission_contract_invalid")?
            {
                let identity = permission["permission_id"]
                    .as_str()
                    .ok_or("native_command_permission_contract_invalid")?;
                permissions.insert(identity.to_owned());
                for field in ["dependencies", "implied_permissions"] {
                    for reference in permission[field]
                        .as_array()
                        .ok_or("native_command_permission_contract_invalid")?
                    {
                        permissions.insert(
                            reference
                                .as_str()
                                .ok_or("native_command_permission_contract_invalid")?
                                .to_owned(),
                        );
                    }
                }
            }
            charge(
                &mut budget.rules,
                value.program["rules"]
                    .as_array()
                    .ok_or("native_command_program_shape_invalid")?
                    .len(),
            )?;
            charge(
                &mut budget.nodes,
                value.program["nodes"]
                    .as_object()
                    .ok_or("native_command_program_shape_invalid")?
                    .len(),
            )?;
            let bytes = canonical_json_bytes(&value.program)
                .map_err(|_| "native_command_program_json_invalid")?;
            charge(&mut budget.program_bytes, bytes.len())?;
            packs.push(Self::from_bytes_observed(
                &bytes,
                &mut |_| {},
                Some((selected, &permissions)),
            )?);
        }
        Self::combine_admitted_packs(packs)
    }
}
