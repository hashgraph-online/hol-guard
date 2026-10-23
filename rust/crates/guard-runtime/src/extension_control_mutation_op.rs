//! `ExtensionControl` mutation checks — what a local extension-control draft may
//! change before it is previewed or committed.
//!
//! Pure: every query is answered from the request alone. Three questions are
//! asked of a draft:
//!
//! - `mutation_bounds`: does it stay within the layer and control counts one
//!   authority holds. Asked before any work that depends on the draft.
//! - `mutation_validate`: may it proceed against the catalog the caller serves.
//!   Extension targets are named by their canonical id (an alias resolves to
//!   its extension), the mutation and every layer must name the served catalog,
//!   every target must be known, and the managed layer and the controls the
//!   catalog fixes must stay as they are.
//! - `mutability_validate`: the last of those checks alone, against the catalog
//!   a prepared mutation carries.
//!
//! A refusal describes the draft, so it is a normal `ok` reply carrying its
//! reason; an `error` reply means the request itself could not be read.

use std::collections::{HashMap, HashSet};

use guard_command::extension_control::MAX_CONTROL_LAYERS;
use guard_contracts::{
    ExtensionControlMutationExtensionV1, ExtensionControlMutationOverlayV1,
    ExtensionControlMutationRegistryV1, ExtensionControlPayloadV1, NativeExtensionControlLayerV1,
    NativeExtensionControlV1, EXTENSION_CONTROL_MUTATION_CATALOG_CONFLICT,
    EXTENSION_CONTROL_MUTATION_CONTROL_LIMIT, EXTENSION_CONTROL_MUTATION_DUPLICATE_TARGET,
    EXTENSION_CONTROL_MUTATION_IMMUTABLE_EXTENSION,
    EXTENSION_CONTROL_MUTATION_IMMUTABLE_PERMISSION, EXTENSION_CONTROL_MUTATION_INVALID,
    EXTENSION_CONTROL_MUTATION_LAYER_CONTROL_LIMIT, EXTENSION_CONTROL_MUTATION_LAYER_LIMIT,
    EXTENSION_CONTROL_MUTATION_MANAGED_LAYER, EXTENSION_CONTROL_MUTATION_UNKNOWN_EXTENSION,
    EXTENSION_CONTROL_MUTATION_UNKNOWN_PERMISSION,
};

use crate::extension_control_op::{normalize, typed_layers};

/// Most controls one layer holds; the resolver's own bound.
const MAX_CONTROLS_PER_LAYER: usize = 512;
const MAX_CONTROLS_TOTAL: usize = MAX_CONTROL_LAYERS * MAX_CONTROLS_PER_LAYER;
const EXTENSION: &str = "extension";
const LOCAL_ADMIN: &str = "local-admin";
const SIGNED_CLOUD: &str = "signed-cloud";
const REGISTRY_INVALID: &str = "native_extension_control_registry_invalid";

/// The answer to `mutation_bounds`.
pub(crate) fn bounds(layers: &[NativeExtensionControlLayerV1]) -> ExtensionControlPayloadV1 {
    ExtensionControlPayloadV1::MutationBounds {
        refusal: limit_refusal(layers).map(str::to_owned),
    }
}

/// The answer to `mutation_validate`.
pub(crate) fn validate(
    registry: &ExtensionControlMutationRegistryV1,
    catalog_digest: &str,
    requested_catalog_digest: &str,
    current_layers: &[NativeExtensionControlLayerV1],
    layers: &[NativeExtensionControlLayerV1],
) -> Result<ExtensionControlPayloadV1, String> {
    let targets = MutationTargets::new(registry)?;
    // The current layers are the runtime's own; a runtime that cannot be read
    // is a broken request. The draft's layers are the caller's input, so a
    // draft that is not a set of layers is refused as one.
    typed_layers(current_layers)?;
    if typed_layers(layers).is_err() {
        return Ok(refused(EXTENSION_CONTROL_MUTATION_INVALID));
    }
    if let Some(reason) = limit_refusal(layers) {
        return Ok(refused(reason));
    }
    let canonical = match canonicalize(&targets, layers) {
        Ok(canonical) => canonical,
        Err(reason) => return Ok(refused(reason)),
    };
    // A target the catalog names by an id that is no longer a valid target
    // cannot be a control.
    if typed_layers(&canonical).is_err() {
        return Ok(refused(EXTENSION_CONTROL_MUTATION_INVALID));
    }
    if requested_catalog_digest != catalog_digest
        || canonical
            .iter()
            .any(|layer| layer.catalog_digest != catalog_digest)
    {
        return Ok(refused(EXTENSION_CONTROL_MUTATION_CATALOG_CONFLICT));
    }
    if let Some(reason) = unknown_target_refusal(&targets, &canonical) {
        return Ok(refused(reason));
    }
    if let Some(reason) = immutable_refusal(&targets, current_layers, &canonical) {
        return Ok(refused(reason));
    }
    Ok(validated(None, canonical))
}

/// The answer to `mutability_validate`.
pub(crate) fn mutability(
    registry: &ExtensionControlMutationRegistryV1,
    current_layers: &[NativeExtensionControlLayerV1],
    layers: &[NativeExtensionControlLayerV1],
) -> Result<ExtensionControlPayloadV1, String> {
    let targets = MutationTargets::new(registry)?;
    typed_layers(current_layers)?;
    typed_layers(layers)?;
    Ok(ExtensionControlPayloadV1::MutabilityValidate {
        refusal: immutable_refusal(&targets, current_layers, layers).map(str::to_owned),
    })
}

fn validated(
    refusal: Option<&str>,
    layers: Vec<NativeExtensionControlLayerV1>,
) -> ExtensionControlPayloadV1 {
    ExtensionControlPayloadV1::MutationValidate {
        refusal: refusal.map(str::to_owned),
        layers,
    }
}

fn refused(reason: &str) -> ExtensionControlPayloadV1 {
    validated(Some(reason), Vec::new())
}

/// The first bound the layers break, checked from the coarsest down.
fn limit_refusal(layers: &[NativeExtensionControlLayerV1]) -> Option<&'static str> {
    if layers.len() > MAX_CONTROL_LAYERS {
        return Some(EXTENSION_CONTROL_MUTATION_LAYER_LIMIT);
    }
    if layers
        .iter()
        .any(|layer| layer.controls.len() > MAX_CONTROLS_PER_LAYER)
    {
        return Some(EXTENSION_CONTROL_MUTATION_LAYER_CONTROL_LIMIT);
    }
    let total: usize = layers.iter().map(|layer| layer.controls.len()).sum();
    (total > MAX_CONTROLS_TOTAL).then_some(EXTENSION_CONTROL_MUTATION_CONTROL_LIMIT)
}

/// The layers with every extension target named by its canonical id. A target
/// the catalog does not know is refused; so is a layer that holds two controls
/// for one target once its aliases are resolved.
fn canonicalize(
    targets: &MutationTargets<'_>,
    layers: &[NativeExtensionControlLayerV1],
) -> Result<Vec<NativeExtensionControlLayerV1>, &'static str> {
    let mut canonical = Vec::with_capacity(layers.len());
    for layer in layers {
        let mut seen: HashSet<(String, String)> = HashSet::with_capacity(layer.controls.len());
        let mut controls = Vec::with_capacity(layer.controls.len());
        for control in &layer.controls {
            let mut control = control.clone();
            if control.target_kind == EXTENSION {
                let extension = targets
                    .extension(&control.target_id)
                    .ok_or(EXTENSION_CONTROL_MUTATION_UNKNOWN_EXTENSION)?;
                control.target_id = extension.extension_id.to_owned();
            }
            if !seen.insert((control.target_kind.clone(), control.target_id.clone())) {
                return Err(EXTENSION_CONTROL_MUTATION_DUPLICATE_TARGET);
            }
            controls.push(control);
        }
        canonical.push(NativeExtensionControlLayerV1 {
            schema_version: layer.schema_version.clone(),
            kind: layer.kind.clone(),
            catalog_digest: layer.catalog_digest.clone(),
            global_lockdown: layer.global_lockdown,
            controls,
        });
    }
    Ok(canonical)
}

/// The first control, in layer order, that names a target the catalog does not
/// know.
fn unknown_target_refusal(
    targets: &MutationTargets<'_>,
    layers: &[NativeExtensionControlLayerV1],
) -> Option<&'static str> {
    layers
        .iter()
        .flat_map(|layer| layer.controls.iter())
        .find_map(|control| {
            if control.target_kind == EXTENSION {
                targets
                    .extension(&control.target_id)
                    .is_none()
                    .then_some(EXTENSION_CONTROL_MUTATION_UNKNOWN_EXTENSION)
            } else {
                targets
                    .permission(&control.target_id)
                    .is_none()
                    .then_some(EXTENSION_CONTROL_MUTATION_UNKNOWN_PERMISSION)
            }
        })
}

/// Why `layers` may not replace `current_layers`, if they may not.
///
/// The managed layer must be exactly the current one. A local control of a
/// required extension, or of a permission the catalog fixes, may be neither
/// created nor changed. One the current layers already hold is kept as it is,
/// and dropping it is always allowed: that restores the canonical behaviour.
fn immutable_refusal(
    targets: &MutationTargets<'_>,
    current_layers: &[NativeExtensionControlLayerV1],
    layers: &[NativeExtensionControlLayerV1],
) -> Option<&'static str> {
    if managed_layers(layers) != managed_layers(current_layers) {
        return Some(EXTENSION_CONTROL_MUTATION_MANAGED_LAYER);
    }
    let current_local = local_controls(current_layers);
    for control in local_controls(layers) {
        let (immutable, reason) = if control.target_kind == EXTENSION {
            (
                targets
                    .extension(&control.target_id)
                    .is_some_and(|extension| extension.required),
                EXTENSION_CONTROL_MUTATION_IMMUTABLE_EXTENSION,
            )
        } else {
            (
                targets
                    .permission(&control.target_id)
                    .is_some_and(|configurable| !configurable),
                EXTENSION_CONTROL_MUTATION_IMMUTABLE_PERMISSION,
            )
        };
        let unchanged = current_local.iter().any(|current| {
            current.target_kind == control.target_kind
                && current.target_id == control.target_id
                && current.state == control.state
        });
        if immutable && !unchanged {
            return Some(reason);
        }
    }
    None
}

fn managed_layers(layers: &[NativeExtensionControlLayerV1]) -> Vec<&NativeExtensionControlLayerV1> {
    layers
        .iter()
        .filter(|layer| layer.kind == SIGNED_CLOUD)
        .collect()
}

/// The controls of the first local layer; a draft holds at most one.
fn local_controls(layers: &[NativeExtensionControlLayerV1]) -> &[NativeExtensionControlV1] {
    layers
        .iter()
        .find(|layer| layer.kind == LOCAL_ADMIN)
        .map(|layer| layer.controls.as_slice())
        .unwrap_or(&[])
}

/// An extension the mutation may target.
struct KnownExtension<'a> {
    extension_id: &'a str,
    required: bool,
}

/// The target projection a mutation runs against, indexed as the Python
/// catalog and its request-local overlay were: the catalog resolves an
/// extension through its normalized id or an alias (alias keys as listed) and a
/// permission through its normalized id; the overlay is consulted afterwards, by
/// exact id, and its aliases are not honored.
struct MutationTargets<'a> {
    extensions: HashMap<&'a str, &'a ExtensionControlMutationExtensionV1>,
    aliases: HashMap<&'a str, &'a str>,
    /// Permission id to whether it is configurable.
    permissions: HashMap<&'a str, bool>,
    overlay_extensions: HashMap<&'a str, &'a ExtensionControlMutationOverlayV1>,
    /// The first overlay extension to list a permission decides it.
    overlay_permissions: HashMap<&'a str, bool>,
}

impl<'a> MutationTargets<'a> {
    fn new(registry: &'a ExtensionControlMutationRegistryV1) -> Result<Self, String> {
        let invalid = || REGISTRY_INVALID.to_owned();
        let mut extensions = HashMap::with_capacity(registry.extensions.len());
        let mut aliases = HashMap::new();
        for extension in &registry.extensions {
            if extensions
                .insert(extension.extension_id.as_str(), extension)
                .is_some()
            {
                return Err(invalid());
            }
            for alias in &extension.aliases {
                aliases.insert(alias.as_str(), extension.extension_id.as_str());
            }
        }
        let mut permissions = HashMap::with_capacity(registry.permissions.len());
        for permission in &registry.permissions {
            if permissions
                .insert(permission.permission_id.as_str(), permission.configurable)
                .is_some()
            {
                return Err(invalid());
            }
        }
        let mut overlay_extensions = HashMap::with_capacity(registry.overlay.len());
        let mut overlay_permissions = HashMap::new();
        for overlay in &registry.overlay {
            if overlay_extensions
                .insert(overlay.extension_id.as_str(), overlay)
                .is_some()
            {
                return Err(invalid());
            }
            for permission in &overlay.permissions {
                overlay_permissions
                    .entry(permission.permission_id.as_str())
                    .or_insert(permission.configurable);
            }
        }
        Ok(Self {
            extensions,
            aliases,
            permissions,
            overlay_extensions,
            overlay_permissions,
        })
    }

    fn extension(&self, extension_id: &str) -> Option<KnownExtension<'a>> {
        let normalized = normalize(extension_id);
        let key = self
            .aliases
            .get(normalized.as_str())
            .copied()
            .unwrap_or(normalized.as_str());
        if let Some(extension) = self.extensions.get(key).copied() {
            return Some(KnownExtension {
                extension_id: extension.extension_id.as_str(),
                required: extension.required,
            });
        }
        self.overlay_extensions
            .get(extension_id)
            .copied()
            .map(|overlay| KnownExtension {
                extension_id: overlay.extension_id.as_str(),
                required: overlay.required,
            })
    }

    /// Whether the permission is configurable, or `None` when it is unknown.
    fn permission(&self, permission_id: &str) -> Option<bool> {
        self.permissions
            .get(normalize(permission_id).as_str())
            .copied()
            .or_else(|| self.overlay_permissions.get(permission_id).copied())
    }
}

#[cfg(test)]
#[path = "extension_control_mutation_op_tests.rs"]
mod tests;
