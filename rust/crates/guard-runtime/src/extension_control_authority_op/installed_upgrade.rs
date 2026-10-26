//! An installed release may replace policy compiled by an older engine, but
//! cannot use that migration to change the user's controls or pack selection.
use super::layers::{layers_from_json, layers_from_values, layers_to_values};
use super::records::{
    canonical, field, query_row, row_text, tampered, verify_record, Res, Row, SNAPSHOT_PURPOSE,
};
use super::{Ctx, Read, ReadMode, View, PROTECTED};
use guard_command::extension_control::ControlLayerKind;
use guard_command::native_command_program::{NativeCommandProgram, PackAdmissionBudget};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::path::Path;

const REFUSED: &str = "installed command pack upgrade is not authorized";
const MANAGED: &str = "managed policy changed before installed upgrade";

#[path = "installed_upgrade_legacy.rs"]
mod legacy;

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn open(value: &Value, key: &[u8], directory: &Path) -> Res<Value> {
    let result = crate::pack_lifecycle::evaluate(&json!({
        "kind":"record", "operation":"open", "purpose":"activation",
        "key":hex::encode(key), "directory":directory,
        "record":value["record"], "digest":value["digest"], "mac":value["mac"],
    }))
    .map_err(|_| tampered(REFUSED))?;
    if !result["fault"].is_null() || !result["selected"].is_array() {
        return Err(tampered(REFUSED));
    }
    Ok(result)
}

impl Ctx<'_> {
    /// The managed policy the candidate was prepared against must still be the
    /// one the authority serves. The caller used to recompute this view and
    /// compare it before handing the migration over; the resident derives it
    /// from the same authenticated state instead.
    fn managed_policy_unchanged(&self, evidence: &Value, catalog_digest: &str) -> Res<()> {
        let expected = &evidence["managed"];
        let Read::View(view) = self.read(
            catalog_digest,
            ReadMode {
                migration: false,
                allow_migration: false,
            },
        )?
        else {
            return Err(tampered(MANAGED));
        };
        if view.health != PROTECTED {
            return Err(tampered(MANAGED));
        }
        let composed = self.compose_managed(view, None)?;
        let Some(composed) = composed.get("view") else {
            return Err(tampered(MANAGED));
        };
        let composed = View::from_value(Some(composed))?;
        let managed: Vec<_> = composed
            .layers
            .iter()
            .filter(|layer| layer.kind == ControlLayerKind::SignedCloud)
            .cloned()
            .collect();
        if json!(composed.managed_revision) != expected["revision"]
            || layers_to_values(&managed)
                != layers_to_values(&layers_from_values(&expected["layers"])?)
        {
            return Err(tampered(MANAGED));
        }
        Ok(())
    }

    pub(super) fn installed_upgrade_digest(&self, source: &Row) -> Res<Option<String>> {
        let migration = self
            .request
            .catalog_migration
            .as_ref()
            .ok_or_else(|| tampered(REFUSED))?;
        let Some(evidence) = &migration.installed_upgrade else {
            return Ok(None);
        };
        let key = self.require_key()?;
        let payload = verify_record(
            &row_text(source, "snapshot_json")?,
            &row_text(source, "snapshot_digest")?,
            &row_text(source, "snapshot_mac")?,
            key,
            SNAPSHOT_PURPOSE,
        )?;
        let stored_layers = row_text(source, "layers_json")?;
        let stored_catalog = row_text(source, "catalog_digest")?;
        if field(&payload, "layers_json").as_str() != Some(stored_layers.as_str())
            || field(&payload, "catalog_digest").as_str() != Some(stored_catalog.as_str())
        {
            return Err(tampered(REFUSED));
        }
        self.managed_policy_unchanged(evidence, &stored_catalog)?;
        let mut retained = layers_from_json(&stored_layers)?;
        let target = self.catalog_digest()?;
        for layer in &mut retained {
            layer.catalog_digest = target.to_owned();
        }
        let requested_layers = layers_from_values(&migration.layers)?;
        if layers_to_values(&retained) != layers_to_values(&requested_layers) {
            return Err(tampered("installed command pack upgrade changed controls"));
        }
        let current = query_row(self.connection,
            "select record_json, record_digest, record_mac from extension_command_pack_activation where singleton=1", [],
        )?.ok_or_else(|| tampered(REFUSED))?;
        for (wire, column) in [
            ("record", "record_json"),
            ("digest", "record_digest"),
            ("mac", "record_mac"),
        ] {
            if evidence["previous"][wire] != row_text(&current, column)? {
                return Err(tampered(REFUSED));
            }
        }
        let policy_key = crate::policy_store::read_verifier_key(
            &Path::new(&self.request.guard_home).join("native-runtime"),
        )
        .map_err(|_| tampered(REFUSED))?;
        let directory = Path::new(&self.request.guard_home).join("native-runtime/command-packs");
        let previous_open = open(&evidence["previous"], &policy_key, &directory)?;
        let candidate_open = open(&evidence["candidate"], &policy_key, &directory)?;
        legacy::validate_predecessor(
            &payload,
            &evidence["previous"]["digest"],
            &previous_open,
            &stored_catalog,
            &directory,
        )?;
        if previous_open["selected"] != candidate_open["selected"] {
            return Err(tampered("installed command pack upgrade changed selection"));
        }
        let previous = &previous_open["value"];
        let candidate = &candidate_open["value"];
        let installed = crate::pack_lifecycle::evaluate(&json!({"kind":"installed",
            "runtime_manifest":evidence["release"]["runtime_manifest"],
            "compiler_manifest":evidence["release"]["compiler_manifest"],
            "release_data":evidence["release"]["release_data"]}))
        .map_err(|_| tampered(REFUSED))?;
        let floor = crate::pack_lifecycle::evaluate(
            &json!({"kind":"transition","key":hex::encode(policy_key),
            "floor":evidence["floor"],"candidate":installed,"ancestry":null}),
        )
        .map_err(|_| tampered(REFUSED))?;
        if floor["record"] != evidence["next_floor"]
            || previous["engine"] == installed["engine"]
            || candidate["authority_profile"] != "installed"
            || candidate["engine"] != installed["engine"]
            || candidate["source_sha"] != installed["source"]
            || candidate["root_digest"] != installed["root"]
            || candidate["catalog_digest"] != target
            || candidate["previous_digest"] != evidence["previous"]["digest"]
            || candidate["revision"].as_u64()
                != previous["revision"].as_u64().and_then(|v| v.checked_add(1))
        {
            return Err(tampered(REFUSED));
        }
        let digest = candidate["program_digest"]
            .as_str()
            .ok_or_else(|| tampered(REFUSED))?;
        let program = NativeCommandProgram::from_pack_cache(
            &directory,
            digest,
            PackAdmissionBudget::resident(),
        )
        .map_err(|_| tampered(REFUSED))?;
        let release: Value = serde_json::from_str(
            evidence["release"]["release_data"]
                .as_str()
                .ok_or_else(|| tampered(REFUSED))?,
        )
        .map_err(|_| tampered(REFUSED))?;
        let set_bytes = guard_secure_fs::read_bounded(
            &directory.join("sets").join(format!("{digest}.json")),
            65536,
        )
        .map_err(|_| tampered(REFUSED))?
        .bytes;
        let set: Value = serde_json::from_slice(&set_bytes).map_err(|_| tampered(REFUSED))?;
        if set["release"]["sha256"] != hash(canonical(&release["policy"]["root"])?.as_bytes())
            || program.catalog_digest != candidate["catalog_digest"]
            || program.trust_digest != candidate["trust_digest"]
            || candidate["distribution"]["sha256"] != installed["root"]
        {
            return Err(tampered(REFUSED));
        }
        Ok(Some(
            evidence["candidate"]["digest"]
                .as_str()
                .ok_or_else(|| tampered(REFUSED))?
                .to_owned(),
        ))
    }
}
