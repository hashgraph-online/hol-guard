//! Trusted catalog manifests and the rebinding of authenticated controls when
//! the built-in catalog changes.

use guard_command::extension_control::{
    expand_legacy_dns_layers, ExtensionControl, ExtensionControlLayer,
};
use rusqlite::params;
use serde_json::{json, Value};

use super::layers::{
    layers_to_values, manifest_sha256, preserve_migrated, same_layers, validate_layers, Manifest,
};
use super::records::{
    degraded, fields_match, query_row, row_text, tampered, verify_record, Res,
    CATALOG_MANIFEST_PURPOSE,
};
use super::{Ctx, Read, ReadMode, View, PROTECTED};

/// The `migrate_catalog` action: commit `layers` under `catalog_digest` as the
/// revision after `previous`, retiring `retired_targets`.
pub(super) fn migrate_action(
    previous: &View,
    catalog_digest: &str,
    layers: &[ExtensionControlLayer],
    retired_targets: &[String],
) -> Value {
    json!({
        "action": "migrate_catalog",
        "previous_revision": previous.revision,
        "previous_catalog_digest": previous.catalog_digest,
        "catalog_digest": catalog_digest,
        "layers": layers_to_values(layers),
        "retired_targets": retired_targets,
    })
}

impl Ctx<'_> {
    /// `_load_catalog_manifest`.
    pub(super) fn load_manifest(&self, catalog_digest: &str) -> Res<Option<Manifest>> {
        let Some(row) = query_row(
            self.connection,
            "select * from extension_control_catalog_manifest where catalog_digest = ?",
            params![catalog_digest],
        )?
        else {
            return Ok(None);
        };
        let payload = verify_record(
            &row_text(&row, "record_json")?,
            &row_text(&row, "record_digest")?,
            &row_text(&row, "record_mac")?,
            self.require_key()?,
            CATALOG_MANIFEST_PURPOSE,
        )?;
        let manifest_json = row_text(&row, "manifest_json")?;
        if !fields_match(
            &payload,
            &[
                ("catalog_digest", Some(json!(catalog_digest))),
                ("manifest_json", Some(json!(manifest_json))),
                ("recorded_at", Some(json!(row_text(&row, "recorded_at")?))),
            ],
        ) {
            return Err(tampered(
                "extension control catalog manifest field mismatch",
            ));
        }
        let value = serde_json::from_str::<Value>(&manifest_json)
            .map_err(|_| degraded("invalid extension control catalog manifest json"))?;
        let Value::Object(entries) = value else {
            return Err(tampered("invalid extension control catalog manifest"));
        };
        entries
            .into_iter()
            .map(|(name, fingerprint)| match fingerprint {
                Value::String(fingerprint) => Ok((name, fingerprint)),
                _ => Err(tampered("invalid extension control catalog manifest")),
            })
            .collect::<Res<Manifest>>()
            .map(Some)
    }

    /// `_rebound_catalog_layers`: `previous`'s controls restamped for
    /// `catalog_digest`, without the targets the new catalog retired.
    pub(super) fn rebound_catalog_layers(
        &self,
        previous: &View,
        catalog_digest: &str,
        current_manifest: &Manifest,
    ) -> Res<(Vec<ExtensionControlLayer>, Vec<String>)> {
        let previous_manifest = self
            .load_manifest(&previous.catalog_digest)?
            .unwrap_or_default();
        let expanded = expand_legacy_dns_layers(&previous.layers);
        let keep = |control: &ExtensionControl| {
            preserve_migrated(control, &previous_manifest, current_manifest)
        };
        let mut retired_targets: Vec<String> = expanded
            .iter()
            .flat_map(|layer| layer.controls.iter())
            .filter(|control| !keep(control))
            .map(|control| control.target.target_id.clone())
            .collect();
        retired_targets.sort();
        let layers: Vec<ExtensionControlLayer> = expanded
            .into_iter()
            .map(|layer| ExtensionControlLayer {
                catalog_digest: catalog_digest.to_owned(),
                controls: layer
                    .controls
                    .iter()
                    .filter(|control| keep(control))
                    .cloned()
                    .collect(),
                ..layer
            })
            .collect();
        validate_layers(&layers, catalog_digest)?;
        Ok((layers, retired_targets))
    }

    /// `_sync_trusted_catalog_manifest` for a protected `view`: compare the
    /// recorded manifest of the requested catalog with the current one.
    ///
    /// Answers the view to serve and `stale`, the recorded manifest the caller
    /// replaces once managed controls are composed, or an action.
    pub(super) fn sync_manifest(&self, view: View) -> Res<Value> {
        if view.health != PROTECTED {
            return Err(tampered(
                "extension control catalog manifest sync requires protected authority",
            ));
        }
        let catalog_digest = self.catalog_digest()?;
        let allow_migration = self.request.allow_migration;
        let unchanged = |view: &View| Ok(json!({ "view": view.to_value(), "stale": null }));
        let existing = query_row(
            self.connection,
            "select 1 from extension_control_catalog_manifest where catalog_digest = ?",
            params![catalog_digest],
        )?;
        if existing.is_none() {
            // A read-only caller holds the shared lock, so recording the first
            // manifest is the next writer's job.
            return Ok(json!({
                "view": view.to_value(),
                "stale": null,
                "manifest_write": if allow_migration { json!("insert") } else { Value::Null },
            }));
        }
        let persisted = self
            .load_manifest(catalog_digest)?
            .ok_or_else(|| tampered("extension control catalog manifest conflict"))?;
        let current = match (
            self.current_manifest(),
            self.request.current_manifest_sha256.as_deref(),
        ) {
            (Some(current), _) => current,
            (None, Some(sha256)) if manifest_sha256(&persisted)? == sha256 => {
                return unchanged(&view)
            }
            (None, _) => return Ok(json!({ "need": "current_manifest" })),
        };
        if persisted == *current {
            return unchanged(&view);
        }
        // The same catalog digest can still carry a newer trusted contract
        // fingerprint after a package update.
        let rebound: Vec<ExtensionControlLayer> = view
            .layers
            .iter()
            .map(|layer| ExtensionControlLayer {
                catalog_digest: view.catalog_digest.clone(),
                controls: layer
                    .controls
                    .iter()
                    .filter(|control| preserve_migrated(control, &persisted, current))
                    .cloned()
                    .collect(),
                ..layer.clone()
            })
            .collect();
        let stale = json!(persisted);
        if same_layers(&rebound, &view.layers) {
            return Ok(json!({ "view": view.to_value(), "stale": stale }));
        }
        if !allow_migration {
            let view = View {
                layers: rebound,
                ..view
            };
            return Ok(json!({ "view": view.to_value(), "stale": stale }));
        }
        let (layers, retired_targets) =
            self.rebound_catalog_layers(&view, catalog_digest, current)?;
        let mut action = migrate_action(&view, catalog_digest, &layers, &retired_targets);
        action["stale"] = stale;
        Ok(json!({ "action": action }))
    }

    /// `read`, then `sync_manifest` and `compose_managed` on the view it
    /// settles on, in one round trip. A read that owes writer work answers as
    /// `read` does. A sync that owes a manifest write or a migration answers
    /// with the base view alone, and the caller finishes with the separate ops.
    pub(super) fn read_composed(&self, mode: ReadMode) -> Res<Value> {
        let base = match self.read(self.catalog_digest()?, mode)? {
            Read::View(view) => view,
            other => return Ok(other.into_value()),
        };
        let mut view = base.clone();
        let mut stale: Option<Manifest> = None;
        if base.health == PROTECTED {
            let synced = self.sync_manifest(base.clone())?;
            if synced.get("need").is_some() {
                return Ok(synced);
            }
            let settled = synced.get("action").is_none()
                && matches!(synced.get("manifest_write"), None | Some(Value::Null));
            let Some(synced_view) = synced.get("view").filter(|_| settled) else {
                return Ok(json!({ "view": base.to_value() }));
            };
            view = View::from_value(Some(synced_view))?;
            stale = match synced.get("stale") {
                None | Some(Value::Null) => None,
                Some(value) => Some(
                    serde_json::from_value(value.clone())
                        .map_err(|_| tampered("invalid extension control catalog manifest"))?,
                ),
            };
        }
        let composed = self.compose_managed(view, stale.as_ref())?;
        let Some(composed_view) = composed.get("view") else {
            return Ok(composed);
        };
        Ok(json!({
            "view": base.to_value(),
            "composed": composed_view,
            "stale": stale,
        }))
    }
}
