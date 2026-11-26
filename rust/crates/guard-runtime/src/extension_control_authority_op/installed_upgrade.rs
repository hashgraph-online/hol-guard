//! An installed release may replace policy compiled by an older engine, but
//! cannot use that migration to change the user's controls or pack selection.
//! The one addition it may make is a pack the installed release turns on by
//! default and the previous release did not.
use super::layers::{layers_from_json, layers_from_values, layers_to_values};
use super::records::{
    canonical, field, query_row, row_text, tampered, verify_record, Fault, Res, Row,
    SNAPSHOT_PURPOSE,
};
use super::{Ctx, Read, ReadMode, View, PROTECTED};
use guard_command::extension_control::ControlLayerKind;
use guard_command::native_command_program::{NativeCommandProgram, PackAdmissionBudget};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::Path;

const REFUSED: &str = "installed command pack upgrade is not authorized";
const MANAGED: &str = "managed policy changed before installed upgrade";

#[path = "installed_upgrade_legacy.rs"]
mod legacy;

/// Every refusal keeps the one prefix callers match on and names the check
/// that failed, so a refused migration says which binding moved.
fn refused(cause: &str) -> Fault {
    tampered(&format!("{REFUSED}: {cause}"))
}

/// A lifecycle answer's reason is carried only when it is a plain phrase, so
/// no path or record content reaches the daemon log through it.
fn lifecycle_reason(result: &Value) -> Option<&str> {
    let reason = result["reason"].as_str()?;
    let plain = !reason.is_empty()
        && reason.len() <= 120
        && reason
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b" _.:-".contains(&b));
    plain.then_some(reason)
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

/// The default packs an installed upgrade is judged against: those of the
/// installed release and those of the release the previous activation used.
struct Defaults {
    installed: BTreeSet<String>,
    previous: BTreeSet<String>,
}

/// The upgrade keeps every pack the user's selection held. It may add only a
/// pack the authenticated installed release turns on by default and the
/// previous release did not, such as a new core protection. A default the
/// previous release already had and the selection lacks is one the user
/// turned off, so the upgrade never turns it back on. It never drops a pack
/// or adds any other.
fn selection_kept(
    previous: &Value,
    candidate: &Value,
    defaults: impl FnOnce() -> Res<Defaults>,
) -> Res<()> {
    let changed = || tampered("installed command pack upgrade changed selection");
    let ids = |value: &Value| -> Option<BTreeSet<String>> {
        value
            .as_array()?
            .iter()
            .map(|id| id.as_str().map(str::to_owned))
            .collect()
    };
    let (Some(previous), Some(candidate)) = (ids(previous), ids(candidate)) else {
        return Err(changed());
    };
    if !previous.is_subset(&candidate) {
        return Err(changed());
    }
    if previous.len() == candidate.len() {
        return Ok(());
    }
    let defaults = defaults().map_err(|_| changed())?;
    if candidate
        .difference(&previous)
        .all(|id| defaults.installed.contains(id) && !defaults.previous.contains(id))
    {
        Ok(())
    } else {
        Err(changed())
    }
}

fn open(role: &str, value: &Value, key: &[u8], directory: &Path) -> Res<Value> {
    let result = crate::pack_lifecycle::evaluate(&json!({
        "kind":"record", "operation":"open", "purpose":"activation",
        "key":hex::encode(key), "directory":directory,
        "record":value["record"], "digest":value["digest"], "mac":value["mac"],
    }))
    .map_err(|_| refused(&format!("{role} activation could not be opened")))?;
    if let Some(fault) = result["fault"].as_str() {
        let fault = if fault == "tampered" {
            "tampered"
        } else {
            "refused"
        };
        return Err(refused(&match lifecycle_reason(&result) {
            Some(reason) => format!("{role} activation {fault} ({reason})"),
            None => format!("{role} activation {fault}"),
        }));
    }
    if !result["fault"].is_null() || !result["selected"].is_array() {
        return Err(refused(&format!("{role} activation has no selection")));
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
            .ok_or_else(|| refused("no catalog migration"))?;
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
            return Err(refused("control snapshot does not match its row"));
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
        )?.ok_or_else(|| refused("command pack activation missing"))?;
        for (wire, column) in [
            ("record", "record_json"),
            ("digest", "record_digest"),
            ("mac", "record_mac"),
        ] {
            if evidence["previous"][wire] != row_text(&current, column)? {
                return Err(refused(&format!(
                    "command pack activation changed since preparation ({wire})"
                )));
            }
        }
        let policy_key = crate::policy_store::read_verifier_key(
            &Path::new(&self.request.guard_home).join("native-runtime"),
        )
        .map_err(|_| refused("policy verifier key unavailable"))?;
        let directory = Path::new(&self.request.guard_home).join("native-runtime/command-packs");
        let previous_open = open("previous", &evidence["previous"], &policy_key, &directory)?;
        let candidate_open = open("candidate", &evidence["candidate"], &policy_key, &directory)?;
        legacy::validate_predecessor(
            &payload,
            &evidence["previous"]["digest"],
            &previous_open,
            &stored_catalog,
            &directory,
        )?;
        let previous = &previous_open["value"];
        let candidate = &candidate_open["value"];
        let installed = crate::pack_lifecycle::evaluate(&json!({"kind":"installed",
            "runtime_manifest":evidence["release"]["runtime_manifest"],
            "compiler_manifest":evidence["release"]["compiler_manifest"],
            "release_data":evidence["release"]["release_data"]}))
        .map_err(|_| refused("installed release could not be identified"))?;
        let floor = crate::pack_lifecycle::evaluate(
            &json!({"kind":"transition","key":hex::encode(policy_key),
            "floor":evidence["floor"],"candidate":installed,"ancestry":null}),
        )
        .map_err(|_| refused("release floor transition refused"))?;
        let checks = [
            (
                floor["record"] != evidence["next_floor"],
                "release floor moved",
            ),
            (
                previous["engine"] == installed["engine"],
                "previous activation already uses the installed engine",
            ),
            (
                candidate["authority_profile"] != "installed",
                "candidate is not an installed activation",
            ),
            (
                candidate["engine"] != installed["engine"],
                "candidate engine is not the installed engine",
            ),
            (
                candidate["source_sha"] != installed["source"],
                "candidate source is not the installed release",
            ),
            (
                candidate["root_digest"] != installed["root"],
                "candidate root is not the installed release",
            ),
            (
                candidate["catalog_digest"] != target,
                "candidate catalog is not the target catalog",
            ),
            (
                candidate["previous_digest"] != evidence["previous"]["digest"],
                "candidate does not follow the previous activation",
            ),
            (
                candidate["revision"].as_u64()
                    != previous["revision"].as_u64().and_then(|v| v.checked_add(1)),
                "candidate revision does not follow the previous activation",
            ),
        ];
        if let Some((_, cause)) = checks.iter().find(|(failed, _)| *failed) {
            return Err(refused(cause));
        }
        let digest = candidate["program_digest"]
            .as_str()
            .ok_or_else(|| refused("candidate has no program digest"))?;
        let program = NativeCommandProgram::from_pack_cache(
            &directory,
            digest,
            PackAdmissionBudget::resident(),
        )
        .map_err(|_| refused("candidate program is not in the pack cache"))?;
        let release: Value = serde_json::from_str(
            evidence["release"]["release_data"]
                .as_str()
                .ok_or_else(|| refused("installed release data missing"))?,
        )
        .map_err(|_| refused("installed release data malformed"))?;
        let set_bytes = guard_secure_fs::read_bounded(
            &directory.join("sets").join(format!("{digest}.json")),
            65536,
        )
        .map_err(|_| refused("candidate pack set unreadable"))?
        .bytes;
        let set: Value = serde_json::from_slice(&set_bytes)
            .map_err(|_| refused("candidate pack set malformed"))?;
        let checks = [
            (
                set["release"]["sha256"] != hash(canonical(&release["policy"]["root"])?.as_bytes()),
                "candidate pack set is not the installed release",
            ),
            (
                program.catalog_digest != candidate["catalog_digest"],
                "candidate program catalog differs",
            ),
            (
                program.trust_digest != candidate["trust_digest"],
                "candidate program trust differs",
            ),
            (
                candidate["distribution"]["sha256"] != installed["root"],
                "candidate distribution is not the installed release",
            ),
        ];
        if let Some((_, cause)) = checks.iter().find(|(failed, _)| *failed) {
            return Err(refused(cause));
        }
        selection_kept(
            &previous_open["selected"],
            &candidate_open["selected"],
            || {
                let defaults = |release: &Value| {
                    crate::pack_preparation::release_default_ids(&directory, release)
                        .map_err(|_| refused("release default packs unreadable"))
                };
                let publication = legacy::previous_publication(previous, &directory)?;
                Ok(Defaults {
                    installed: defaults(&release)?,
                    previous: defaults(&publication)?,
                })
            },
        )?;
        Ok(Some(
            evidence["candidate"]["digest"]
                .as_str()
                .ok_or_else(|| refused("candidate has no digest"))?
                .to_owned(),
        ))
    }
}

#[cfg(test)]
mod selection_tests {
    use super::*;

    fn ids(values: &[&str]) -> BTreeSet<String> {
        values.iter().map(|id| (*id).to_owned()).collect()
    }

    fn defaults(installed: &[&str], previous: &[&str]) -> impl FnOnce() -> Res<Defaults> {
        let defaults = Defaults {
            installed: ids(installed),
            previous: ids(previous),
        };
        move || Ok(defaults)
    }

    fn unread() -> Res<Defaults> {
        Err(refused("release default packs unreadable"))
    }

    #[test]
    fn an_unchanged_selection_is_kept() {
        let selection = json!(["command.alpha", "command.beta"]);
        assert!(selection_kept(&selection, &selection, unread).is_ok());
    }

    #[test]
    fn a_dropped_pack_is_refused() {
        let previous = json!(["command.alpha", "command.beta"]);
        let candidate = json!(["command.alpha"]);
        let all = ["command.alpha", "command.beta"];
        assert!(selection_kept(&previous, &candidate, defaults(&all, &[])).is_err());
    }

    #[test]
    fn a_pack_the_release_does_not_default_is_refused() {
        let previous = json!(["command.alpha"]);
        let candidate = json!(["command.alpha", "command.beta"]);
        assert!(selection_kept(&previous, &candidate, defaults(&["command.alpha"], &[])).is_err());
    }

    #[test]
    fn a_newly_shipped_default_is_added() {
        let previous = json!(["command.alpha"]);
        let candidate = json!(["command.alpha", "command.beta"]);
        let installed = ["command.alpha", "command.beta"];
        let kept = selection_kept(
            &previous,
            &candidate,
            defaults(&installed, &["command.alpha"]),
        );
        assert!(kept.is_ok());
    }

    #[test]
    fn a_default_the_user_turned_off_stays_off() {
        // command.beta was already a default, so its absence is the user's choice.
        let previous = json!(["command.alpha"]);
        let candidate = json!(["command.alpha", "command.beta"]);
        let both = ["command.alpha", "command.beta"];
        assert!(selection_kept(&previous, &candidate, defaults(&both, &both)).is_err());
    }

    #[test]
    fn unreadable_default_metadata_is_refused() {
        let previous = json!(["command.alpha"]);
        let candidate = json!(["command.alpha", "command.beta"]);
        assert!(selection_kept(&previous, &candidate, unread).is_err());
    }
}
