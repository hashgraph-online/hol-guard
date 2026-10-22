//! Bind legacy controls to authenticated predecessor metadata, never old IR.

use super::{tampered, Res, REFUSED};
use guard_command::native_command_program::source::{lookup_pack, read_pack_blob, PackObjectRef};
use guard_command::native_command_program::{digest_value, PackAdmissionBudget};
use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

struct Metadata<'a> {
    directory: &'a Path,
    blob_limit: usize,
}

impl Metadata<'_> {
    fn fetch(&mut self, digest: &str) -> Result<Vec<u8>, &'static str> {
        if digest.len() != 64
            || !digest
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err(REFUSED);
        }
        let bytes = guard_secure_fs::read_bounded(
            &self
                .directory
                .join("objects")
                .join(format!("{digest}.json")),
            65536,
        )
        .map_err(|_| REFUSED)?
        .bytes;
        Ok(bytes)
    }

    fn blob(&mut self, reference: &Value) -> Res<Vec<u8>> {
        let reference: PackObjectRef =
            serde_json::from_value(reference.clone()).map_err(|_| tampered(REFUSED))?;
        if reference.expanded_length > self.blob_limit {
            return Err(tampered(REFUSED));
        }
        read_pack_blob(&reference, &mut |digest| self.fetch(digest)).map_err(|_| tampered(REFUSED))
    }

    fn json(&mut self, reference: &Value) -> Res<Value> {
        crate::strict_json_value(&self.blob(reference)?).map_err(|_| tampered(REFUSED))
    }
}

pub(super) fn validate_predecessor(
    snapshot: &Map<String, Value>,
    expected: &Value,
    opened: &Value,
    catalog: &str,
    directory: &Path,
) -> Res<()> {
    validate_predecessor_with_limits(
        snapshot,
        expected,
        opened,
        catalog,
        directory,
        PackAdmissionBudget::resident(),
    )
}

fn validate_predecessor_with_limits(
    snapshot: &Map<String, Value>,
    expected: &Value,
    opened: &Value,
    catalog: &str,
    directory: &Path,
    mut limits: PackAdmissionBudget,
) -> Res<()> {
    // A present null, malformed binding or explicit mismatch is never legacy.
    if let Some(binding) = snapshot.get("command_pack_record_digest") {
        return if binding.is_string() && binding == expected {
            Ok(())
        } else {
            Err(tampered(REFUSED))
        };
    }
    // The caller has authenticated the signed snapshot and exact SQL activation,
    // then record.open has authenticated the activation and its cached inventories.
    // Its catalog is the missing link: an unrelated valid activation cannot stand
    // in for the catalog the user's signed control snapshot actually authorized.
    let previous = &opened["value"];
    if previous["catalog_digest"].as_str() != Some(catalog) {
        return Err(tampered(REFUSED));
    }
    let program = previous["program_digest"]
        .as_str()
        .filter(|v| {
            v.len() == 64
                && v.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        })
        .ok_or_else(|| tampered(REFUSED))?;
    let mut metadata = Metadata {
        directory,
        // These are the immutable-object format bounds, independent of the
        // aggregate program admission budget. read_pack_blob also enforces it.
        blob_limit: 8 * 1024 * 1024,
    };
    let set_bytes = guard_secure_fs::read_bounded(
        &directory.join("sets").join(format!("{program}.json")),
        65536,
    )
    .map_err(|_| tampered(REFUSED))?
    .bytes;
    let set = crate::strict_json_value(&set_bytes).map_err(|_| tampered(REFUSED))?;
    if set.as_object().is_none_or(|v| v.len() != 4)
        || set["schema"] != "guard.command-pack-cache.v1"
        || set["selection"] != previous["selection"]
        || set["selected_count"] != previous["selected_count"]
    {
        return Err(tampered(REFUSED));
    }
    let publication = metadata.json(&previous["distribution"])?;
    let root = &publication["policy"]["root"];
    let root_bytes = metadata.blob(&set["release"])?;
    if set["release"]["sha256"].as_str()
        != Some(
            hex::encode(Sha256::digest(
                guard_policy_snapshot::canonical_json_bytes(root).map_err(|_| tampered(REFUSED))?,
            ))
            .as_str(),
        )
        || crate::strict_json_value(&root_bytes).map_err(|_| tampered(REFUSED))? != *root
        || root["schema"] != "guard.command-pack-release.v1"
        || root["engine"] != previous["engine"]
    {
        return Err(tampered(REFUSED));
    }
    let count = root["extensions"]
        .as_u64()
        .filter(|n| *n > 0 && *n <= limits.packs as u64)
        .ok_or_else(|| tampered(REFUSED))? as usize;
    let index: PackObjectRef =
        serde_json::from_value(root["index"].clone()).map_err(|_| tampered(REFUSED))?;
    let selected = opened["selected"]
        .as_array()
        .filter(|ids| !ids.is_empty() && ids.len() <= count)
        .ok_or_else(|| tampered(REFUSED))?;
    let mut identities = Vec::with_capacity(selected.len());
    let mut last = "";
    for id in selected {
        let id = id
            .as_str()
            .filter(|id| *id > last)
            .ok_or_else(|| tampered(REFUSED))?;
        last = id;
        let reference = lookup_pack(&index, count, id, &mut |digest| metadata.fetch(digest))
            .map_err(|_| tampered(REFUSED))?
            .ok_or_else(|| tampered(REFUSED))?;
        let manifest = metadata.json(&json!(reference))?;
        if manifest["schema"] != "guard.command-policy-pack.v1"
            || manifest["extension_id"] != id
            || manifest["engine"] != previous["engine"]
        {
            return Err(tampered(REFUSED));
        }
        // Read only hash-bound metadata. Old nodes are not admitted or executed:
        // a new engine must never treat its predecessor's IR as its own IR.
        let pack = metadata.json(&manifest["program"])?;
        // Match ordinary admission's accounting dimension: only canonical
        // program bytes spend program_bytes. Publication/index/manifest/catalog
        // IO is bounded by its own object/blob/inventory format limits instead.
        let canonical_program =
            guard_policy_snapshot::canonical_json_bytes(&pack).map_err(|_| tampered(REFUSED))?;
        limits.program_bytes = limits
            .program_bytes
            .checked_sub(canonical_program.len())
            .ok_or_else(|| tampered(REFUSED))?;
        let catalog_bytes = metadata.blob(&manifest["catalog"])?;
        let catalog_value =
            crate::strict_json_value(&catalog_bytes).map_err(|_| tampered(REFUSED))?;
        let canonical_catalog = guard_policy_snapshot::canonical_json_bytes(&catalog_value)
            .map_err(|_| tampered(REFUSED))?;
        if pack["program_digest"] != manifest["program_digest"]
            || pack["trust_digest"] != manifest["trust_digest"]
            || pack["catalog_digest"].as_str()
                != Some(hex::encode(Sha256::digest(&canonical_catalog)).as_str())
        {
            return Err(tampered(REFUSED));
        }
        identities.push(json!({"extension":id,"program":pack["program_digest"],
            "catalog":pack["catalog_digest"],"trust":pack["trust_digest"]}));
    }
    let digests = [
        (
            "program_digest",
            digest_value(
                b"hol-guard.active-command-program.v1\0",
                &json!({"engine":previous["engine"],"packs":identities}),
            ),
        ),
        (
            "catalog_digest",
            digest_value(b"hol-guard.active-command-catalog.v1\0", &identities),
        ),
        (
            "trust_digest",
            digest_value(b"hol-guard.active-command-trust.v1\0", &identities),
        ),
    ];
    for (field, digest) in digests {
        if previous[field].as_str() != Some(digest.map_err(|_| tampered(REFUSED))?.as_str()) {
            return Err(tampered(REFUSED));
        }
    }
    Ok(())
}

#[cfg(test)]
#[path = "installed_upgrade_legacy_tests.rs"]
mod tests;
