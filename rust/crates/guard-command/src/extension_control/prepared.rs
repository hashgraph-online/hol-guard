//! The resolver split by what each part depends on.
//!
//! Composition, validation of the layers against the catalog and the set of
//! disabled targets depend only on the layers, the catalog and the surface:
//! [`PreparedControls`] does them once. The dependency closure depends only on
//! the ids asked about and the catalog: [`ControlClosure`] holds it, so a
//! caller that asks about many ids against many layer sets resolves each id's
//! closure once.
//!
//! `resolve_extension_controls` is `PreparedControls::new(..).resolve(..)`, so
//! a caller that reuses a preparation and its closures (the extension-control
//! preview) answers exactly as command evaluation does.

use std::collections::BTreeSet;

use super::{
    compose_control_layers, expand_legacy_dns_layers, extension_closure,
    has_explicit_enabled_permission, permission_closure, resolution, validate_layer_targets,
    ComposedExtensionControls, ControlRegistry, ControlResolution, ControlResolverFailure,
    ControlState, ControlSurface, ControlTargetKind, ExtensionControlLayer, ResolverFailureCode,
    MAX_CONTROLS_PER_LAYER, MAX_CONTROL_LAYERS, MAX_INPUT_TEXT_LENGTH, MAX_OBSERVATIONS,
    MAX_RESOLUTION_IDS, TRUSTED_LOCKDOWN_SURFACES,
};

const LOCKDOWN_REASON: &str = "control.global-lockdown";
const DISABLED_EXTENSION_REASON: &str = "control.disabled-extension";
const DISABLED_PERMISSION_REASON: &str = "control.disabled-permission";

/// Whether the ids asked about exceed the resolver's input limits.
fn ids_over_limit(extension_ids: &[String], permission_ids: &[String]) -> bool {
    extension_ids.len() > MAX_RESOLUTION_IDS
        || permission_ids.len() > MAX_RESOLUTION_IDS
        || extension_ids
            .iter()
            .chain(permission_ids.iter())
            .any(|value| value.len() > MAX_INPUT_TEXT_LENGTH)
}

fn observations_over_limit(observations: &[String]) -> bool {
    observations.len() > MAX_OBSERVATIONS
        || observations
            .iter()
            .any(|value| value.len() > MAX_INPUT_TEXT_LENGTH)
}

/// The extensions and permissions asking about some ids pulls in: the ids
/// themselves, what they depend on or imply, and the extension owning each
/// permission reached. Unknown ids are failures, not members.
#[derive(Debug, Clone, Default)]
pub struct ControlClosure {
    extensions: BTreeSet<String>,
    permissions: BTreeSet<String>,
    failures: BTreeSet<ControlResolverFailure>,
    over_limit: bool,
}

impl ControlClosure {
    /// The closure of the ids against the catalog. Ids beyond the resolver's
    /// input limits are not walked; the closure records that they are over.
    pub fn of(
        registry: &dyn ControlRegistry,
        extension_ids: &[String],
        permission_ids: &[String],
    ) -> Self {
        if ids_over_limit(extension_ids, permission_ids) {
            return Self {
                over_limit: true,
                ..Self::default()
            };
        }
        let mut failures: BTreeSet<ControlResolverFailure> = BTreeSet::new();
        let mut extensions = extension_closure(registry, extension_ids, &mut failures);
        let permissions = permission_closure(registry, permission_ids, &mut failures);
        // Expand each resolved permission's owning extension into the extension set.
        for permission_id in &permissions {
            if let Some(permission) = registry.permission(permission_id) {
                extensions.extend(extension_closure(
                    registry,
                    &[permission.extension_id],
                    &mut failures,
                ));
            }
        }
        Self {
            extensions,
            permissions,
            failures,
            over_limit: false,
        }
    }

    /// How many entries a comparison against this closure walks.
    pub fn size(&self) -> usize {
        self.extensions.len() + self.permissions.len() + 1
    }
}

/// What is true of a set of layers on a surface against a catalog, whatever
/// ids are asked about.
pub struct PreparedControls<'r> {
    registry: Option<&'r dyn ControlRegistry>,
    surface: ControlSurface,
    composed: ComposedExtensionControls,
    /// Failures of composition and of the authority; every answer carries them.
    base_failures: BTreeSet<ControlResolverFailure>,
    /// Failures of the layers against the catalog. Empty when there is no
    /// catalog or the layers exceed the limits, which answer first.
    layer_failures: BTreeSet<ControlResolverFailure>,
    layers_over_limit: bool,
    disabled_extensions: BTreeSet<String>,
    disabled_permissions: BTreeSet<String>,
}

impl<'r> PreparedControls<'r> {
    /// `registry` is `None` to model `CATALOG_UNAVAILABLE`.
    pub fn new(
        layers: &[ExtensionControlLayer],
        registry: Option<&'r dyn ControlRegistry>,
        surface: ControlSurface,
        authority_failure: Option<ResolverFailureCode>,
    ) -> Self {
        // `islice(layers, MAX_CONTROL_LAYERS + 1)` — bound before expansion.
        let layer_slice: Vec<ExtensionControlLayer> = layers
            .iter()
            .take(MAX_CONTROL_LAYERS + 1)
            .cloned()
            .collect();
        let layer_values = expand_legacy_dns_layers(&layer_slice);
        let composed = compose_control_layers(&layer_values);
        let mut base_failures: BTreeSet<ControlResolverFailure> =
            composed.failures.iter().copied().collect();
        if let Some(failure) =
            authority_failure.filter(|_| surface != ControlSurface::TrustedLocalProof)
        {
            base_failures.insert(ControlResolverFailure::new(failure, None));
        }
        let layers_over_limit = layer_values.len() > MAX_CONTROL_LAYERS
            || layer_values
                .iter()
                .any(|layer| layer.controls.len() > MAX_CONTROLS_PER_LAYER);

        let mut layer_failures: BTreeSet<ControlResolverFailure> = BTreeSet::new();
        if let Some(catalog) = registry.filter(|_| !layers_over_limit) {
            for layer in &layer_values {
                if layer.catalog_digest != catalog.catalog_digest() {
                    layer_failures.insert(ControlResolverFailure::new(
                        ResolverFailureCode::CatalogDigestMismatch,
                        Some(layer.kind),
                    ));
                }
                validate_layer_targets(layer, catalog, &mut layer_failures);
            }
        }

        let disabled = |kind: ControlTargetKind| -> BTreeSet<String> {
            composed
                .controls
                .iter()
                .filter(|control| control.target.kind == kind)
                .filter(|control| control.state == ControlState::Disabled)
                .map(|control| control.target.target_id.clone())
                .collect()
        };
        let disabled_extensions = disabled(ControlTargetKind::Extension);
        let disabled_permissions = disabled(ControlTargetKind::Permission);

        Self {
            registry,
            surface,
            composed,
            base_failures,
            layer_failures,
            layers_over_limit,
            disabled_extensions,
            disabled_permissions,
        }
    }

    /// Whether asking about a closure is blocked: any failure, a global
    /// lockdown on a surface that does not trust it, or a disabled extension
    /// or permission in the closure.
    pub fn blocked_by(&self, closure: &ControlClosure) -> bool {
        if self.layers_over_limit || self.registry.is_none() || closure.over_limit {
            return true;
        }
        !self.base_failures.is_empty()
            || !self.layer_failures.is_empty()
            || !closure.failures.is_empty()
            || self.block_reason(closure).is_some()
    }

    /// Why a failure-free question is blocked, if it is.
    fn block_reason(&self, closure: &ControlClosure) -> Option<&'static str> {
        if self.composed.global_lockdown && !TRUSTED_LOCKDOWN_SURFACES.contains(&self.surface) {
            return Some(LOCKDOWN_REASON);
        }
        if closure
            .extensions
            .iter()
            .any(|id| self.disabled_extensions.contains(id))
        {
            return Some(DISABLED_EXTENSION_REASON);
        }
        if closure
            .permissions
            .iter()
            .any(|id| self.disabled_permissions.contains(id))
        {
            return Some(DISABLED_PERMISSION_REASON);
        }
        None
    }

    /// `resolve_extension_controls` (:69-146) for these layers.
    pub fn resolve(
        self,
        extension_ids: &[String],
        permission_ids: &[String],
        observations: &[String],
    ) -> ControlResolution {
        let mut failures = self.base_failures.clone();

        if self.layers_over_limit
            || ids_over_limit(extension_ids, permission_ids)
            || observations_over_limit(observations)
        {
            failures.insert(ControlResolverFailure::new(
                ResolverFailureCode::InputLimitExceeded,
                None,
            ));
            let truncated: Vec<String> = observations
                .iter()
                .take(MAX_OBSERVATIONS)
                .cloned()
                .collect();
            return resolution(self.composed, failures, truncated, None);
        }

        // `type(surface) is not ControlSurface` is unrepresentable in Rust (typed
        // enum); Python's guard is a runtime isinstance check — no-op here.
        let Some(registry) = self.registry else {
            failures.insert(ControlResolverFailure::new(
                ResolverFailureCode::CatalogUnavailable,
                None,
            ));
            return resolution(self.composed, failures, observations.to_vec(), None);
        };

        failures.extend(self.layer_failures.iter().copied());
        let closure = ControlClosure::of(registry, extension_ids, permission_ids);
        failures.extend(closure.failures.iter().copied());
        if !failures.is_empty() {
            return resolution(self.composed, failures, observations.to_vec(), None);
        }
        if let Some(reason) = self.block_reason(&closure) {
            return resolution(self.composed, failures, observations.to_vec(), Some(reason));
        }
        let mut explicitly_enabled_permission_ids: Vec<String> = permission_ids
            .iter()
            .filter(|id| has_explicit_enabled_permission(&self.composed, id))
            .cloned()
            .collect();
        explicitly_enabled_permission_ids.sort();
        ControlResolution {
            composed: self.composed,
            blocked: false,
            factors: Vec::new(),
            failures: Vec::new(),
            observations: observations.to_vec(),
            explicitly_enabled_permission_ids,
        }
    }
}
