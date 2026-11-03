//! Untrusted cache representation. Authority comes from the independent
//! expected collection identity, checked after complete native admission.
use super::*;
use source::PackObjectRef;
use std::path::Path;

const PAGE_BYTES: usize = 64 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CachedSet {
    schema: String,
    release: PackObjectRef,
    selection: PackObjectRef,
    selected_count: usize,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SelectionPage {
    schema: String,
    ids: Vec<String>,
    next: Option<PackObjectRef>,
}

fn decode<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, &'static str> {
    let value: Value =
        serde_json::from_slice(bytes).map_err(|_| "native_command_pack_cache_invalid")?;
    let canonical =
        canonical_json_bytes(&value).map_err(|_| "native_command_pack_cache_invalid")?;
    if bytes != canonical && bytes.strip_suffix(b"\n") != Some(canonical.as_slice()) {
        return Err("native_command_pack_cache_noncanonical");
    }
    serde_json::from_value(value).map_err(|_| "native_command_pack_cache_invalid")
}

fn read(path: &Path) -> Result<Vec<u8>, &'static str> {
    guard_secure_fs::read_bounded(path, PAGE_BYTES)
        .map(|value| value.bytes)
        .map_err(|_| "native_command_pack_cache_read_failed")
}

impl NativeCommandProgram {
    pub fn from_pack_cache(
        directory: &Path,
        expected_program: &str,
        budget: PackAdmissionBudget,
    ) -> Result<Self, &'static str> {
        Self::from_pack_cache_catalog(directory, expected_program, budget, None)
    }

    pub(crate) fn from_pack_cache_catalog(
        directory: &Path,
        expected_program: &str,
        budget: PackAdmissionBudget,
        catalog: Option<&mut Vec<crate::native_command_catalog::CatalogExtension>>,
    ) -> Result<Self, &'static str> {
        if !valid_digest(expected_program) {
            return Err("native_command_pack_cache_identity_invalid");
        }
        let set: CachedSet = decode(&read(
            &directory
                .join("sets")
                .join(format!("{expected_program}.json")),
        )?)?;
        if set.schema != "guard.command-pack-cache.v1"
            || set.selected_count == 0
            || set.selected_count > budget.packs
        {
            return Err("native_command_pack_cache_invalid");
        }
        let mut fetch = |digest: &str| {
            if !valid_digest(digest) {
                return Err("native_command_pack_cache_identity_invalid");
            }
            read(&directory.join("objects").join(format!("{digest}.json")))
        };
        let mut selected = BTreeSet::new();
        let mut visited = BTreeSet::new();
        let mut next = Some(set.selection);
        let mut previous = String::new();
        while let Some(reference) = next {
            if !visited.insert(reference.sha256.clone())
                || visited.len() > set.selected_count
                || reference.expanded_length > PAGE_BYTES
            {
                return Err("native_command_pack_selection_invalid");
            }
            let page: SelectionPage = decode(&source::read_pack_blob(&reference, &mut fetch)?)?;
            if page.schema != "guard.command-pack-selection-page.v1"
                || page.ids.is_empty()
                || page.ids.len() > 64
            {
                return Err("native_command_pack_selection_invalid");
            }
            for id in page.ids {
                if !bounded_id(&id) || id <= previous || selected.len() >= set.selected_count {
                    return Err("native_command_pack_selection_invalid");
                }
                previous.clone_from(&id);
                selected.insert(id);
            }
            next = page.next;
        }
        if selected.len() != set.selected_count
            || set.release.expanded_length > PAGE_BYTES
            || set.release.kind != "data"
        {
            return Err("native_command_pack_selection_invalid");
        }
        if DEFAULT_COMMAND_PACK_IDS
            .split(',')
            .filter(|id| !id.is_empty())
            .any(|id| !selected.contains(id))
        {
            return Err("native_command_required_pack_missing");
        }
        let root = source::read_pack_blob(&set.release, &mut fetch)?;
        let program = Self::from_integrity_bound_packs_catalog(
            &root,
            &set.release.sha256,
            &selected,
            budget,
            fetch,
            catalog,
        )?;
        if program.program_digest != expected_program {
            return Err("native_command_program_binding_mismatch");
        }
        Ok(program)
    }
}
