//! Fail-closed composition and resolution of command-extension controls.
//!
//! Byte-parity port of `extension_control_contract.py` (control types +
//! `ResolverFailureCode`), `command_dns_control_migration.py` (legacy
//! aggregate-DNS expansion), and `extension_control_resolver.py`
//! (`compose_control_layers` + `resolve_extension_controls`).
//!
//! Catalog access is abstracted behind [`ControlRegistry`]; the resident
//! implements it over the native command program/catalog so this module stays
//! IO-free and pure.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::LazyLock;

use regex::Regex;
use serde::{Deserialize, Serialize};

use super::effect_decision::{DecisionBasis, DecisionFactor, DecisionFactorSource, GuardAction};

/// `CONTROL_SCHEMA_VERSION` (extension_control_contract.py:12).
pub const CONTROL_SCHEMA_VERSION: &str = "1.0.0";

// Limits (extension_control_limits.py + extension_control_resolver.py:36-40).
/// `MAX_CONTROL_LAYERS` = len(ControlLayerKind) = 2.
pub const MAX_CONTROL_LAYERS: usize = 2;
/// `_MAX_CONTROLS_PER_LAYER` (resolver).
const MAX_CONTROLS_PER_LAYER: usize = 512;
/// `_MAX_RESOLUTION_IDS` (resolver).
const MAX_RESOLUTION_IDS: usize = 1024;
/// `_MAX_OBSERVATIONS` (resolver).
const MAX_OBSERVATIONS: usize = 2048;
/// `_MAX_INPUT_TEXT_LENGTH` (resolver).
const MAX_INPUT_TEXT_LENGTH: usize = 256;

const FAILURE_REASON: &str = "control.resolver-failure";

static SHA256: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\A[0-9a-f]{64}\z").unwrap());
static TARGET_ID: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"\Acommand\.[a-z0-9]+(?:[.-][a-z0-9]+)*\z").unwrap());

/// `ControlLayerKind` (contract:20).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlLayerKind {
    LocalAdmin,
    SignedCloud,
}

impl ControlLayerKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LocalAdmin => "local-admin",
            Self::SignedCloud => "signed-cloud",
        }
    }
}

/// `ControlTargetKind` (contract:25).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlTargetKind {
    Extension,
    Permission,
}

impl ControlTargetKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Extension => "extension",
            Self::Permission => "permission",
        }
    }
}

/// `ControlState` (contract:30).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlState {
    Enabled,
    Disabled,
}

impl ControlState {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Enabled => "enabled",
            Self::Disabled => "disabled",
        }
    }
}

/// `ControlSurface` (contract:35).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlSurface {
    CommandEvaluation,
    TrustedLocalRecovery,
    TrustedLocalProof,
}

impl ControlSurface {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::CommandEvaluation => "command-evaluation",
            Self::TrustedLocalRecovery => "trusted-local-recovery",
            Self::TrustedLocalProof => "trusted-local-proof",
        }
    }
}

/// `_TRUSTED_LOCKDOWN_SURFACES` (resolver:35).
const TRUSTED_LOCKDOWN_SURFACES: &[ControlSurface] = &[
    ControlSurface::TrustedLocalRecovery,
    ControlSurface::TrustedLocalProof,
];

/// `ResolverFailureCode` (contract:45-56).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ResolverFailureCode {
    AuthorityTampered,
    AuthorityUnavailable,
    UnsupportedControlSchema,
    DuplicateLayerKind,
    DuplicateTargetInLayer,
    CatalogDigestMismatch,
    UnknownExtensionTarget,
    UnknownPermissionTarget,
    InvalidControlSurface,
    InvalidObservationBinding,
    CatalogUnavailable,
    InputLimitExceeded,
    NonCanonicalTarget,
    ManagedPolicyUnavailable,
    ManagedPolicyNotYetValid,
    ManagedPolicyExpired,
    ManagedPolicyRevoked,
    ManagedPolicyRollback,
}

impl ResolverFailureCode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AuthorityTampered => "authority-tampered",
            Self::AuthorityUnavailable => "authority-unavailable",
            Self::UnsupportedControlSchema => "unsupported-control-schema",
            Self::DuplicateLayerKind => "duplicate-layer-kind",
            Self::DuplicateTargetInLayer => "duplicate-target-in-layer",
            Self::CatalogDigestMismatch => "catalog-digest-mismatch",
            Self::UnknownExtensionTarget => "unknown-extension-target",
            Self::UnknownPermissionTarget => "unknown-permission-target",
            Self::InvalidControlSurface => "invalid-control-surface",
            Self::InvalidObservationBinding => "invalid-observation-binding",
            Self::CatalogUnavailable => "catalog-unavailable",
            Self::InputLimitExceeded => "input-limit-exceeded",
            Self::NonCanonicalTarget => "non-canonical-target",
            Self::ManagedPolicyUnavailable => "managed-policy-unavailable",
            Self::ManagedPolicyNotYetValid => "managed-policy-not-yet-valid",
            Self::ManagedPolicyExpired => "managed-policy-expired",
            Self::ManagedPolicyRevoked => "managed-policy-revoked",
            Self::ManagedPolicyRollback => "managed-policy-rollback",
        }
    }
}

/// `ControlTarget` (contract:62, order=True → kind then target_id).
///
/// `Ord` derives field-order: `kind` then `target_id`, matching Python's
/// dataclass ordering (`ControlTargetKind` enum order Extension<Permission
/// because Python sorts on the enum's `_sort_order_`... actually Python orders
/// str-Enum by value: "extension"<"permission"; kebab-case matches).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct ControlTarget {
    pub kind: ControlTargetKind,
    pub target_id: String,
}

impl ControlTarget {
    /// `__post_init__` (contract:65-78) — validate kind/target/shape.
    pub fn new(kind: ControlTargetKind, target_id: String) -> Result<Self, &'static str> {
        if !TARGET_ID.is_match(&target_id) {
            return Err("target_id must be a canonical command catalog ID");
        }
        let has_permission = target_id.contains(".permission.");
        match kind {
            ControlTargetKind::Permission if !has_permission => {
                return Err("permission targets must contain a permission segment")
            }
            ControlTargetKind::Extension if has_permission => {
                return Err("extension targets cannot contain a permission segment")
            }
            _ => {}
        }
        Ok(Self { kind, target_id })
    }

    /// Unchecked constructor for already-validated catalog IDs (e.g. produced
    /// by the DNS migration / internal closures where the target came from the
    /// registry). Used where Python would rely on `__post_init__` but the value
    /// is already canonical.
    fn trusted(kind: ControlTargetKind, target_id: String) -> Self {
        Self { kind, target_id }
    }
}

/// `ExtensionControl` (contract:80).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ExtensionControl {
    pub target: ControlTarget,
    pub state: ControlState,
}

/// `ExtensionControlLayer` (contract:90).
#[derive(Debug, Clone)]
pub struct ExtensionControlLayer {
    pub schema_version: String,
    pub kind: ControlLayerKind,
    pub catalog_digest: String,
    pub global_lockdown: bool,
    pub controls: Vec<ExtensionControl>,
}

impl ExtensionControlLayer {
    /// `__post_init__` (contract:94-110) — schema/kind/digest/controls checks.
    pub fn validate(&self) -> Result<(), &'static str> {
        if self.schema_version != CONTROL_SCHEMA_VERSION {
            return Err("unsupported control schema version");
        }
        if !SHA256.is_match(&self.catalog_digest) {
            return Err("catalog_digest must be a lowercase SHA-256 digest");
        }
        Ok(())
    }
}

/// `ControlResolverFailure` (contract:114, order=True → code then layer_kind).
///
/// `layer_kind: Option<None>` sorts before `Some(..)` in both Python (None <
/// value via dataclass order where None is a sentinel) and Rust `Option` Ord.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct ControlResolverFailure {
    pub code: ResolverFailureCode,
    pub layer_kind: Option<ControlLayerKind>,
}

impl ControlResolverFailure {
    pub const fn new(code: ResolverFailureCode, layer_kind: Option<ControlLayerKind>) -> Self {
        Self { code, layer_kind }
    }
}

/// `ComposedExtensionControls` (contract:125).
#[derive(Debug, Clone)]
pub struct ComposedExtensionControls {
    pub global_lockdown: bool,
    pub controls: Vec<ExtensionControl>,
    pub failures: Vec<ControlResolverFailure>,
}

impl ComposedExtensionControls {
    /// `state_for` (contract:131-137): ENABLED default.
    pub fn state_for(&self, kind: ControlTargetKind, target_id: &str) -> ControlState {
        self.controls
            .iter()
            .find(|c| c.target.kind == kind && c.target.target_id == target_id)
            .map(|c| c.state)
            .unwrap_or(ControlState::Enabled)
    }
}

/// `ControlResolution` (contract:138).
#[derive(Debug, Clone)]
pub struct ControlResolution {
    pub composed: ComposedExtensionControls,
    pub blocked: bool,
    pub factors: Vec<DecisionFactor>,
    pub failures: Vec<ControlResolverFailure>,
    pub observations: Vec<String>,
    pub explicitly_enabled_permission_ids: Vec<String>,
}

/// Minimal catalog surface the resolver needs from the command registry.
///
/// Mirrors `CommandSafetyExtensionRegistry` methods used by the resolver:
/// `.get(extension_id)`, `.permission(permission_id)`, `.catalog_digest`,
/// `.permission_for_rule_id(rule_id)`. The resident supplies the impl over the
/// native catalog; this keeps the resolver pure.
pub trait ControlRegistry {
    /// `registry.catalog_digest`.
    fn catalog_digest(&self) -> &str;
    /// `registry.get(extension_id)` → `(extension_id, dependencies, required)`
    /// or `None` if unknown. Returns the canonical extension_id (may differ
    /// from the query if non-canonical).
    fn extension(&self, extension_id: &str) -> Option<RegistryExtension>;
    /// `registry.permission(permission_id)` → permission record or `None`.
    fn permission(&self, permission_id: &str) -> Option<RegistryPermission>;
    /// `registry.permission_for_rule_id(rule_id)` → owning permission_id.
    fn permission_for_rule_id(&self, rule_id: &str) -> Option<String>;
}

/// Projection of a catalog `CommandSafetyExtension` used by the resolver.
pub struct RegistryExtension {
    /// Canonical extension_id (may differ from the looked-up key).
    pub extension_id: String,
    pub dependencies: Vec<String>,
}

/// Projection of a catalog `CommandPermission`.
pub struct RegistryPermission {
    pub permission_id: String,
    /// `extension_id` that owns this permission.
    pub extension_id: String,
    pub dependencies: Vec<String>,
    pub implied_permissions: Vec<String>,
}

// ---------------------------------------------------------------------------
// DNS migration (command_dns_control_migration.py)
// ---------------------------------------------------------------------------

const LEGACY_DNS_EXTENSION_ID: &str = "command.dns";
const LEGACY_DNS_PERMISSION_ID: &str = "command.dns.permission.delete";
const DNS_PROVIDER_EXTENSION_IDS: &[&str] =
    &["command.dns.aws", "command.dns.gcp", "command.dns.azure"];
const DNS_ZONE_PERMISSION_IDS: &[&str] = &[
    "command.dns.aws.permission.zone-deletion",
    "command.dns.gcp.permission.zone-deletion",
    "command.dns.azure.permission.public-zone-deletion",
];

/// `expand_legacy_dns_target` (:35-46).
fn expand_legacy_dns_target(target: &ControlTarget) -> Vec<ControlTarget> {
    match target.kind {
        ControlTargetKind::Extension if target.target_id == LEGACY_DNS_EXTENSION_ID => {
            DNS_PROVIDER_EXTENSION_IDS
                .iter()
                .map(|id| ControlTarget::trusted(ControlTargetKind::Extension, (*id).to_owned()))
                .collect()
        }
        ControlTargetKind::Permission if target.target_id == LEGACY_DNS_PERMISSION_ID => {
            DNS_ZONE_PERMISSION_IDS
                .iter()
                .map(|id| ControlTarget::trusted(ControlTargetKind::Permission, (*id).to_owned()))
                .collect()
        }
        _ => vec![target.clone()],
    }
}

/// `expand_legacy_dns_layers` (:49-79).
///
/// Expansion-induced collisions merge with disable dominance; duplicate
/// original targets stay duplicated (as `extras`) so composition fails closed.
pub fn expand_legacy_dns_layers(layers: &[ExtensionControlLayer]) -> Vec<ExtensionControlLayer> {
    layers
        .iter()
        .map(|layer| {
            let mut merged: BTreeMap<ControlTarget, ControlState> = BTreeMap::new();
            let mut order: Vec<ControlTarget> = Vec::new();
            let mut extras: Vec<ExtensionControl> = Vec::new();
            let mut seen_originals: BTreeSet<ControlTarget> = BTreeSet::new();
            for control in &layer.controls {
                let expanded_targets = expand_legacy_dns_target(&control.target);
                if seen_originals.contains(&control.target) {
                    extras.extend(expanded_targets.into_iter().map(|target| ExtensionControl {
                        target,
                        state: control.state,
                    }));
                    continue;
                }
                seen_originals.insert(control.target.clone());
                for target in expanded_targets {
                    match merged.get(&target) {
                        None => {
                            order.push(target.clone());
                            merged.insert(target, control.state);
                        }
                        Some(prev)
                            if *prev == ControlState::Disabled
                                || control.state == ControlState::Disabled =>
                        {
                            merged.insert(target, ControlState::Disabled);
                        }
                        _ => {}
                    }
                }
            }
            let mut expanded: Vec<ExtensionControl> = order
                .into_iter()
                .map(|target| ExtensionControl {
                    state: merged[&target],
                    target,
                })
                .collect();
            expanded.extend(extras);
            ExtensionControlLayer {
                schema_version: layer.schema_version.clone(),
                kind: layer.kind,
                catalog_digest: layer.catalog_digest.clone(),
                global_lockdown: layer.global_lockdown,
                controls: expanded,
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// Composition + resolution (extension_control_resolver.py)
// ---------------------------------------------------------------------------

/// `compose_control_layers` (:43-66): disable-dominant, deterministic output.
pub fn compose_control_layers(layers: &[ExtensionControlLayer]) -> ComposedExtensionControls {
    let mut states: BTreeMap<ControlTarget, ControlState> = BTreeMap::new();
    let mut seen_layer_kinds: BTreeSet<ControlLayerKind> = BTreeSet::new();
    let mut failures: BTreeSet<ControlResolverFailure> = BTreeSet::new();
    let mut lockdown = false;
    for layer in layers {
        if seen_layer_kinds.contains(&layer.kind) {
            failures.insert(ControlResolverFailure::new(
                ResolverFailureCode::DuplicateLayerKind,
                Some(layer.kind),
            ));
        }
        seen_layer_kinds.insert(layer.kind);
        lockdown = lockdown || layer.global_lockdown;
        let mut seen_targets: BTreeSet<&ControlTarget> = BTreeSet::new();
        for control in &layer.controls {
            if seen_targets.contains(&control.target) {
                failures.insert(ControlResolverFailure::new(
                    ResolverFailureCode::DuplicateTargetInLayer,
                    Some(layer.kind),
                ));
                continue;
            }
            seen_targets.insert(&control.target);
            let previous = states.get(&control.target).copied();
            if previous == Some(ControlState::Disabled) || control.state == ControlState::Disabled {
                states.insert(control.target.clone(), ControlState::Disabled);
            } else {
                states.insert(control.target.clone(), ControlState::Enabled);
            }
        }
    }
    let controls = states
        .iter()
        .map(|(target, state)| ExtensionControl {
            target: target.clone(),
            state: *state,
        })
        .collect();
    ComposedExtensionControls {
        global_lockdown: lockdown,
        controls,
        failures: failures.into_iter().collect(),
    }
}

fn has_explicit_enabled_permission(
    composed: &ComposedExtensionControls,
    permission_id: &str,
) -> bool {
    composed.controls.iter().any(|c| {
        c.target.kind == ControlTargetKind::Permission
            && c.target.target_id == permission_id
            && c.state == ControlState::Enabled
    })
}

fn validate_layer_targets(
    layer: &ExtensionControlLayer,
    registry: &dyn ControlRegistry,
    failures: &mut BTreeSet<ControlResolverFailure>,
) {
    for control in &layer.controls {
        match control.target.kind {
            ControlTargetKind::Extension => match registry.extension(&control.target.target_id) {
                None => {
                    failures.insert(ControlResolverFailure::new(
                        ResolverFailureCode::UnknownExtensionTarget,
                        Some(layer.kind),
                    ));
                }
                Some(ext) if ext.extension_id != control.target.target_id => {
                    failures.insert(ControlResolverFailure::new(
                        ResolverFailureCode::NonCanonicalTarget,
                        Some(layer.kind),
                    ));
                }
                _ => {}
            },
            ControlTargetKind::Permission => {
                if registry.permission(&control.target.target_id).is_none() {
                    failures.insert(ControlResolverFailure::new(
                        ResolverFailureCode::UnknownPermissionTarget,
                        Some(layer.kind),
                    ));
                }
            }
        }
    }
}

fn extension_closure(
    registry: &dyn ControlRegistry,
    extension_ids: &[String],
    failures: &mut BTreeSet<ControlResolverFailure>,
) -> BTreeSet<String> {
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<String> = extension_ids.to_vec();
    while let Some(extension_id) = pending.pop() {
        match registry.extension(&extension_id) {
            None => {
                failures.insert(ControlResolverFailure::new(
                    ResolverFailureCode::UnknownExtensionTarget,
                    None,
                ));
            }
            Some(ext) => {
                if resolved.contains(&ext.extension_id) {
                    continue;
                }
                resolved.insert(ext.extension_id.clone());
                pending.extend(ext.dependencies);
            }
        }
    }
    resolved
}

fn permission_closure(
    registry: &dyn ControlRegistry,
    permission_ids: &[String],
    failures: &mut BTreeSet<ControlResolverFailure>,
) -> BTreeSet<String> {
    let mut resolved: BTreeSet<String> = BTreeSet::new();
    let mut pending: Vec<String> = permission_ids.to_vec();
    while let Some(permission_id) = pending.pop() {
        match registry.permission(&permission_id) {
            None => {
                failures.insert(ControlResolverFailure::new(
                    ResolverFailureCode::UnknownPermissionTarget,
                    None,
                ));
            }
            Some(perm) => {
                if resolved.contains(&perm.permission_id) {
                    continue;
                }
                resolved.insert(perm.permission_id.clone());
                pending.extend(perm.dependencies);
                pending.extend(perm.implied_permissions);
            }
        }
    }
    resolved
}

fn resolution(
    composed: ComposedExtensionControls,
    failures: BTreeSet<ControlResolverFailure>,
    observations: Vec<String>,
    reason: Option<&str>,
) -> ControlResolution {
    let ordered_failures: Vec<ControlResolverFailure> = failures.into_iter().collect();
    let reason_code = if !ordered_failures.is_empty() {
        Some(FAILURE_REASON)
    } else {
        reason
    };
    match reason_code {
        None => ControlResolution {
            composed,
            blocked: false,
            factors: Vec::new(),
            failures: ordered_failures,
            observations,
            explicitly_enabled_permission_ids: Vec::new(),
        },
        Some(code) => {
            let factor = DecisionFactor {
                source: DecisionFactorSource::Control,
                reason_code: code.to_owned(),
                basis: DecisionBasis {
                    action_floor: GuardAction::Block,
                    proof_route: None,
                },
                segment_ref: None,
                operation_ref: None,
                producer_ref: Some("control:resolver".to_owned()),
                evidence_digest: None,
                assessment: None,
                proof: None,
            };
            ControlResolution {
                composed,
                blocked: true,
                factors: vec![factor],
                failures: ordered_failures,
                observations,
                explicitly_enabled_permission_ids: Vec::new(),
            }
        }
    }
}

/// `resolve_extension_controls` (:69-146).
///
/// `authority_failure` mirrors the Python kwarg; `registry` is `None` to model
/// `CATALOG_UNAVAILABLE` (Python `isinstance` check).
#[allow(clippy::too_many_arguments)]
pub fn resolve_extension_controls(
    layers: &[ExtensionControlLayer],
    registry: Option<&dyn ControlRegistry>,
    extension_ids: &[String],
    permission_ids: &[String],
    surface: ControlSurface,
    observations: &[String],
    authority_failure: Option<ResolverFailureCode>,
) -> ControlResolution {
    // `islice(layers, MAX_CONTROL_LAYERS + 1)` — bound before expansion.
    let layer_slice: Vec<ExtensionControlLayer> = layers
        .iter()
        .take(MAX_CONTROL_LAYERS + 1)
        .cloned()
        .collect();
    let layer_values = expand_legacy_dns_layers(&layer_slice);
    let composed = compose_control_layers(&layer_values);
    let mut failures: BTreeSet<ControlResolverFailure> =
        composed.failures.iter().copied().collect();

    if let Some(failure) =
        authority_failure.filter(|_| surface != ControlSurface::TrustedLocalProof)
    {
        failures.insert(ControlResolverFailure::new(failure, None));
    }

    let input_limit_exceeded = layer_values.len() > MAX_CONTROL_LAYERS
        || layer_values
            .iter()
            .any(|l| l.controls.len() > MAX_CONTROLS_PER_LAYER)
        || extension_ids.len() > MAX_RESOLUTION_IDS
        || permission_ids.len() > MAX_RESOLUTION_IDS
        || observations.len() > MAX_OBSERVATIONS
        || extension_ids
            .iter()
            .chain(permission_ids.iter())
            .chain(observations.iter())
            .any(|v| v.len() > MAX_INPUT_TEXT_LENGTH);

    if input_limit_exceeded {
        failures.insert(ControlResolverFailure::new(
            ResolverFailureCode::InputLimitExceeded,
            None,
        ));
        let truncated: Vec<String> = observations
            .iter()
            .take(MAX_OBSERVATIONS)
            .cloned()
            .collect();
        return resolution(composed, failures, truncated, None);
    }

    // `type(surface) is not ControlSurface` is unrepresentable in Rust (typed
    // enum); Python's guard is a runtime isinstance check — no-op here.
    let registry = match registry {
        None => {
            failures.insert(ControlResolverFailure::new(
                ResolverFailureCode::CatalogUnavailable,
                None,
            ));
            return resolution(composed, failures, observations.to_vec(), None);
        }
        Some(r) => r,
    };

    for layer in &layer_values {
        if layer.catalog_digest != registry.catalog_digest() {
            failures.insert(ControlResolverFailure::new(
                ResolverFailureCode::CatalogDigestMismatch,
                Some(layer.kind),
            ));
        }
        validate_layer_targets(layer, registry, &mut failures);
    }

    let mut expanded_extensions = extension_closure(registry, extension_ids, &mut failures);
    let expanded_permissions = permission_closure(registry, permission_ids, &mut failures);
    // Expand each resolved permission's owning extension into the extension set.
    for permission_id in expanded_permissions.clone() {
        if let Some(permission) = registry.permission(&permission_id) {
            expanded_extensions.extend(extension_closure(
                registry,
                &[permission.extension_id],
                &mut failures,
            ));
        }
    }

    if !failures.is_empty() {
        return resolution(composed, failures, observations.to_vec(), None);
    }
    if composed.global_lockdown && !TRUSTED_LOCKDOWN_SURFACES.contains(&surface) {
        return resolution(
            composed,
            failures,
            observations.to_vec(),
            Some("control.global-lockdown"),
        );
    }
    if expanded_extensions
        .iter()
        .any(|id| composed.state_for(ControlTargetKind::Extension, id) == ControlState::Disabled)
    {
        return resolution(
            composed,
            failures,
            observations.to_vec(),
            Some("control.disabled-extension"),
        );
    }
    if expanded_permissions
        .iter()
        .any(|id| composed.state_for(ControlTargetKind::Permission, id) == ControlState::Disabled)
    {
        return resolution(
            composed,
            failures,
            observations.to_vec(),
            Some("control.disabled-permission"),
        );
    }
    let explicitly_enabled_permission_ids: Vec<String> = permission_ids
        .iter()
        .filter(|id| has_explicit_enabled_permission(&composed, id))
        .cloned()
        .collect();
    let mut sorted_enabled = explicitly_enabled_permission_ids;
    sorted_enabled.sort();
    ControlResolution {
        composed,
        blocked: false,
        factors: Vec::new(),
        failures: Vec::new(),
        observations: observations.to_vec(),
        explicitly_enabled_permission_ids: sorted_enabled,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;

    fn sha() -> String {
        "a".repeat(64)
    }

    fn target(kind: ControlTargetKind, id: &str) -> ControlTarget {
        ControlTarget::new(kind, id.to_owned()).unwrap()
    }

    fn layer(kind: ControlLayerKind, controls: Vec<ExtensionControl>) -> ExtensionControlLayer {
        ExtensionControlLayer {
            schema_version: CONTROL_SCHEMA_VERSION.to_owned(),
            kind,
            catalog_digest: sha(),
            global_lockdown: false,
            controls,
        }
    }

    fn ext_control(id: &str, state: ControlState) -> ExtensionControl {
        ExtensionControl {
            target: target(ControlTargetKind::Extension, id),
            state,
        }
    }

    #[allow(dead_code)]
    fn perm_control(id: &str, state: ControlState) -> ExtensionControl {
        ExtensionControl {
            target: target(ControlTargetKind::Permission, id),
            state,
        }
    }

    struct FakeRegistry {
        digest: String,
        extensions: HashMap<String, RegistryExtension>,
        permissions: HashMap<String, RegistryPermission>,
    }

    impl ControlRegistry for FakeRegistry {
        fn catalog_digest(&self) -> &str {
            &self.digest
        }
        fn extension(&self, id: &str) -> Option<RegistryExtension> {
            self.extensions.get(id).map(|e| RegistryExtension {
                extension_id: e.extension_id.clone(),
                dependencies: e.dependencies.clone(),
            })
        }
        fn permission(&self, id: &str) -> Option<RegistryPermission> {
            self.permissions.get(id).map(|p| RegistryPermission {
                permission_id: p.permission_id.clone(),
                extension_id: p.extension_id.clone(),
                dependencies: p.dependencies.clone(),
                implied_permissions: p.implied_permissions.clone(),
            })
        }
        fn permission_for_rule_id(&self, _r: &str) -> Option<String> {
            None
        }
    }

    fn registry() -> FakeRegistry {
        let mut extensions = HashMap::new();
        for id in ["command.dns.aws", "command.dns.gcp", "command.dns.azure"] {
            extensions.insert(
                id.to_owned(),
                RegistryExtension {
                    extension_id: id.to_owned(),
                    dependencies: vec![],
                },
            );
        }
        let mut permissions = HashMap::new();
        permissions.insert(
            "command.dns.aws.permission.zone-deletion".to_owned(),
            RegistryPermission {
                permission_id: "command.dns.aws.permission.zone-deletion".to_owned(),
                extension_id: "command.dns.aws".to_owned(),
                dependencies: vec![],
                implied_permissions: vec![],
            },
        );
        FakeRegistry {
            digest: sha(),
            extensions,
            permissions,
        }
    }

    #[test]
    fn target_id_validation() {
        assert!(ControlTarget::new(ControlTargetKind::Extension, "command.dns.aws".into()).is_ok());
        // permission kind requires `.permission.` segment
        assert!(
            ControlTarget::new(ControlTargetKind::Permission, "command.dns.aws".into()).is_err()
        );
        assert!(ControlTarget::new(
            ControlTargetKind::Permission,
            "command.dns.aws.permission.zone-deletion".into()
        )
        .is_ok());
        // extension kind cannot contain `.permission.`
        assert!(ControlTarget::new(
            ControlTargetKind::Extension,
            "command.dns.aws.permission.zone-deletion".into()
        )
        .is_err());
    }

    #[test]
    fn compose_disable_dominates_across_layers() {
        let local = layer(
            ControlLayerKind::LocalAdmin,
            vec![ext_control("command.dns.aws", ControlState::Disabled)],
        );
        let cloud = layer(
            ControlLayerKind::SignedCloud,
            vec![ext_control("command.dns.aws", ControlState::Enabled)],
        );
        let composed = compose_control_layers(&[local, cloud]);
        // disabled dominates.
        assert_eq!(
            composed.state_for(ControlTargetKind::Extension, "command.dns.aws"),
            ControlState::Disabled
        );
        // No duplicate failures for distinct kinds.
        assert!(composed.failures.is_empty());
    }

    #[test]
    fn compose_duplicate_layer_kind_fails() {
        let a = layer(ControlLayerKind::LocalAdmin, vec![]);
        let b = layer(ControlLayerKind::LocalAdmin, vec![]);
        let composed = compose_control_layers(&[a, b]);
        assert!(composed
            .failures
            .iter()
            .any(|f| f.code == ResolverFailureCode::DuplicateLayerKind));
    }

    #[test]
    fn legacy_dns_extension_expands() {
        let layer = layer(
            ControlLayerKind::LocalAdmin,
            vec![ext_control(LEGACY_DNS_EXTENSION_ID, ControlState::Disabled)],
        );
        let out = expand_legacy_dns_layers(&[layer]);
        let ids: Vec<_> = out[0]
            .controls
            .iter()
            .map(|c| c.target.target_id.as_str())
            .collect();
        // Python preserves expansion order aws→gcp→azure (insertion order into
        // the `order` list, not sorted).
        assert_eq!(
            ids,
            vec!["command.dns.aws", "command.dns.gcp", "command.dns.azure"]
        );
        assert!(out[0]
            .controls
            .iter()
            .all(|c| c.state == ControlState::Disabled));
    }

    #[test]
    fn resolve_disabled_extension_blocks() {
        let reg = registry();
        let layer = layer(
            ControlLayerKind::LocalAdmin,
            vec![ext_control("command.dns.aws", ControlState::Disabled)],
        );
        let res = resolve_extension_controls(
            &[layer],
            Some(&reg),
            &["command.dns.aws".to_owned()],
            &[],
            ControlSurface::CommandEvaluation,
            &[],
            None,
        );
        assert!(res.blocked);
        assert_eq!(res.factors[0].reason_code, "control.disabled-extension");
        assert_eq!(res.factors[0].basis.action_floor, GuardAction::Block);
    }

    #[test]
    fn resolve_lockdown_blocks_command_surface() {
        let mut layer = layer(ControlLayerKind::LocalAdmin, vec![]);
        layer.global_lockdown = true;
        let reg = registry();
        let res = resolve_extension_controls(
            &[layer],
            Some(&reg),
            &[],
            &[],
            ControlSurface::CommandEvaluation,
            &[],
            None,
        );
        assert!(res.blocked);
        assert_eq!(res.factors[0].reason_code, "control.global-lockdown");
    }

    #[test]
    fn resolve_lockdown_allowed_on_trusted_surface() {
        let mut layer = layer(ControlLayerKind::LocalAdmin, vec![]);
        layer.global_lockdown = true;
        let reg = registry();
        let res = resolve_extension_controls(
            &[layer],
            Some(&reg),
            &[],
            &[],
            ControlSurface::TrustedLocalProof,
            &[],
            None,
        );
        assert!(!res.blocked);
    }

    #[test]
    fn resolve_catalog_digest_mismatch_fails() {
        let mut reg = registry();
        reg.digest = "b".repeat(64);
        let layer = layer(ControlLayerKind::LocalAdmin, vec![]);
        let res = resolve_extension_controls(
            &[layer],
            Some(&reg),
            &[],
            &[],
            ControlSurface::CommandEvaluation,
            &[],
            None,
        );
        assert!(res.blocked);
        assert_eq!(res.factors[0].reason_code, FAILURE_REASON);
        assert!(res
            .failures
            .iter()
            .any(|f| f.code == ResolverFailureCode::CatalogDigestMismatch));
    }

    #[test]
    fn resolve_unknown_permission_fails() {
        let reg = registry();
        let res = resolve_extension_controls(
            &[],
            Some(&reg),
            &[],
            &["command.unknown.permission.x".to_owned()],
            ControlSurface::CommandEvaluation,
            &[],
            None,
        );
        assert!(res.blocked);
        assert!(res
            .failures
            .iter()
            .any(|f| f.code == ResolverFailureCode::UnknownPermissionTarget));
    }

    #[test]
    fn resolve_no_registry_fails_closed() {
        let res = resolve_extension_controls(
            &[],
            None,
            &[],
            &[],
            ControlSurface::CommandEvaluation,
            &[],
            None,
        );
        assert!(res.blocked);
        assert!(res
            .failures
            .iter()
            .any(|f| f.code == ResolverFailureCode::CatalogUnavailable));
    }
}
