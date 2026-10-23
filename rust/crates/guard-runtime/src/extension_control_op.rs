//! `ExtensionControl` — resident op for extension-control composition and resolution.
//!
//! Pure: every query is answered from the request alone. Resolution runs the
//! same resolver the command-evaluation path uses, against a registry the
//! request carries, so a candidate or authored catalog resolves exactly like
//! the packaged one. A rejected request is a bound `error` reply carrying its
//! specific code, never a default verdict.

use std::collections::HashMap;

use guard_command::command_evaluation_controls::control_layers_from_wire_unbounded;
use guard_command::extension_control::{
    compose_control_layers, resolve_extension_controls, ComposedExtensionControls,
    ControlLayerKind, ControlRegistry, ControlResolverFailure, ControlSurface,
    ExtensionControlLayer, RegistryExtension, RegistryPermission, ResolverFailureCode,
};
use guard_command::extension_trust::extension_is_active_for_class;
use guard_contracts::{
    runtime_snapshot_digest, validate_snapshot_layers, ExtensionControlComposedControlV1,
    ExtensionControlComposedV1, ExtensionControlFailureV1, ExtensionControlItemResultV1,
    ExtensionControlItemV1, ExtensionControlPayloadV1, ExtensionControlQueryV1,
    ExtensionControlRegistryExtensionV1, ExtensionControlRegistryPermissionV1,
    ExtensionControlRegistryV1, ExtensionControlRequestV1, ExtensionControlResultV1,
    ExtensionControlScenarioResultV1, ExtensionControlScenarioV1, NativeExtensionControlLayerV1,
    RuntimeSnapshot, EXTENSION_CONTROL_MAX_BYTES, EXTENSION_CONTROL_REQUEST_SCHEMA,
    EXTENSION_CONTROL_RESULT_SCHEMA,
};
use serde_json::Value;

use crate::extension_control_proof::{enrollment_digest, mutation_digest, Mutation};
use crate::package_authority_op::request_digest_with_limit;

/// Most scenarios and items one request resolves, bounding both the work and
/// the reply, which the transport caps at 2 MiB.
const MAX_SCENARIOS: usize = 64;
const MAX_ITEMS: usize = 4_096;
/// The request asks for more work than one reply may cost.
pub(crate) const TOO_MANY_ITEMS: &str = "native_extension_control_too_many_items";
/// The answer does not fit the transport's reply cap; it is refused whole,
/// never cut, because a cut answer would be reviewed and approved as complete.
pub(crate) const REPLY_TOO_LARGE: &str = "native_extension_control_reply_too_large";
const TRUST_CLASSES: [&str; 3] = ["first-party", "trusted-library", "external"];
const AUTHORITY_HEALTH: [&str; 6] = [
    "unenrolled",
    "protected",
    "degraded-unacknowledged",
    "degraded-acknowledged",
    "tampered",
    "recovery-required",
];

pub(crate) fn evaluate_extension_control_request(
    request: &ExtensionControlRequestV1,
) -> Result<Vec<u8>, String> {
    // Bound the complete canonical request before any decision work; an
    // oversized request has no digest to bind.
    let request_sha256 = request_digest_with_limit(request, EXTENSION_CONTROL_MAX_BYTES)
        .map_err(|_| "native_extension_control_too_large".to_owned())?;
    encode_outcome(request, &request_sha256, decide(request))
}

/// The reply for an outcome. An answer that does not fit the transport's reply
/// cap is the refusal `REPLY_TOO_LARGE`, so the transport never meets one.
pub(crate) fn encode_outcome(
    request: &ExtensionControlRequestV1,
    request_sha256: &str,
    outcome: Result<ExtensionControlPayloadV1, String>,
) -> Result<Vec<u8>, String> {
    match encode_result(request, request_sha256, outcome) {
        Err(reason) if reason == "native_response_too_large" => {
            encode_result(request, request_sha256, Err(REPLY_TOO_LARGE.to_owned()))
        }
        other => other,
    }
}

fn encode_result(
    request: &ExtensionControlRequestV1,
    request_sha256: &str,
    outcome: Result<ExtensionControlPayloadV1, String>,
) -> Result<Vec<u8>, String> {
    let (status, code, payload) = match outcome {
        Ok(payload) => ("ok", "ok".to_owned(), Some(payload)),
        Err(code) => ("error", code, None),
    };
    crate::encode_response(&ExtensionControlResultV1 {
        schema: EXTENSION_CONTROL_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256: request_sha256.to_owned(),
        status: status.to_owned(),
        code,
        payload,
    })
}

fn decide(request: &ExtensionControlRequestV1) -> Result<ExtensionControlPayloadV1, String> {
    if request.schema != EXTENSION_CONTROL_REQUEST_SCHEMA {
        return Err("native_extension_control_schema_mismatch".to_owned());
    }
    match &request.query {
        ExtensionControlQueryV1::Compose { layers } => {
            let layers = typed_layers(layers)?;
            Ok(ExtensionControlPayloadV1::Compose {
                composed: composed_wire(&compose_control_layers(&layers)),
            })
        }
        ExtensionControlQueryV1::Resolve {
            registry,
            scenarios,
        } => {
            let items: usize = scenarios.iter().map(|scenario| scenario.items.len()).sum();
            if scenarios.len() > MAX_SCENARIOS || items > MAX_ITEMS {
                return Err(TOO_MANY_ITEMS.to_owned());
            }
            let registry = RequestRegistry::new(registry)?;
            let scenarios = scenarios
                .iter()
                .map(|scenario| resolve_scenario(&registry, scenario))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(ExtensionControlPayloadV1::Resolve { scenarios })
        }
        ExtensionControlQueryV1::SnapshotDigest {
            catalog_digest,
            health,
            revision,
            managed_revision,
            layers,
        } => {
            if !AUTHORITY_HEALTH.contains(&health.as_str()) {
                return Err("native_extension_control_snapshot_invalid".to_owned());
            }
            typed_layers(layers)?;
            // Only a snapshot the resident would bind gets a digest.
            validate_snapshot_layers(catalog_digest, layers)
                .map_err(|_| "native_extension_control_snapshot_invalid".to_owned())?;
            let digest = runtime_snapshot_digest(&RuntimeSnapshot {
                catalog_digest,
                health,
                revision: *revision,
                managed_revision: *managed_revision,
                layers,
                active_security_digest: None,
            })
            .map_err(|_| "native_extension_control_snapshot_invalid".to_owned())?;
            Ok(ExtensionControlPayloadV1::SnapshotDigest { digest })
        }
        ExtensionControlQueryV1::MutationDigest {
            previous_revision,
            catalog_digest,
            layers,
            actor_id,
            idempotency_key,
            nonce,
        } => {
            let layers = typed_layers(layers)?;
            let digest = mutation_digest(&Mutation {
                previous_revision: *previous_revision,
                catalog_digest,
                layers: &layers,
                actor_id,
                idempotency_key,
                nonce,
            })?;
            Ok(ExtensionControlPayloadV1::MutationDigest { digest })
        }
        ExtensionControlQueryV1::EnrollmentDigest {
            catalog_digest,
            actor_id,
            nonce,
        } => Ok(ExtensionControlPayloadV1::EnrollmentDigest {
            digest: enrollment_digest(catalog_digest, actor_id, nonce)?,
        }),
        ExtensionControlQueryV1::Preview {
            registry,
            current_layers,
            proposed_layers,
        } => Ok(ExtensionControlPayloadV1::Preview {
            preview: crate::extension_control_preview_op::semantic_preview(
                registry,
                current_layers,
                proposed_layers,
            )?,
        }),
        ExtensionControlQueryV1::MutationBounds { layers } => {
            Ok(crate::extension_control_mutation_op::bounds(layers))
        }
        ExtensionControlQueryV1::MutationValidate {
            registry,
            catalog_digest,
            requested_catalog_digest,
            current_layers,
            layers,
        } => crate::extension_control_mutation_op::validate(
            registry,
            catalog_digest,
            requested_catalog_digest,
            current_layers,
            layers,
        ),
        ExtensionControlQueryV1::MutabilityValidate {
            registry,
            current_layers,
            layers,
        } => crate::extension_control_mutation_op::mutability(registry, current_layers, layers),
        ExtensionControlQueryV1::RequestDigest {
            previous_revision,
            catalog_digest,
            layers,
            actor_id,
            idempotency_key,
            nonce,
        } => crate::extension_control_prepared_op::request_digest([
            ("previous_revision", &**previous_revision),
            ("catalog_digest", &**catalog_digest),
            ("layers", &**layers),
            ("actor_id", &**actor_id),
            ("idempotency_key", &**idempotency_key),
            ("nonce", &**nonce),
        ]),
        ExtensionControlQueryV1::CandidateNonce {
            nonce,
            activation_digest,
            lifecycle_before,
            lifecycle_after,
            security_digest,
        } => crate::extension_control_prepared_op::candidate_nonce(
            nonce,
            activation_digest,
            lifecycle_before,
            lifecycle_after,
            security_digest.as_deref(),
        ),
        ExtensionControlQueryV1::PreviewEventTargets {
            registry,
            current_layers,
            proposed_layers,
        } => crate::extension_control_prepared_op::event_targets(
            registry,
            current_layers,
            proposed_layers,
        ),
    }
}

pub(crate) fn typed_layers(
    layers: &[NativeExtensionControlLayerV1],
) -> Result<Vec<ExtensionControlLayer>, String> {
    control_layers_from_wire_unbounded(layers)
        .map_err(|_| "native_extension_control_layer_invalid".to_owned())
}

fn resolve_scenario(
    registry: &RequestRegistry<'_>,
    scenario: &ExtensionControlScenarioV1,
) -> Result<ExtensionControlScenarioResultV1, String> {
    let layers = typed_layers(&scenario.layers)?;
    let surface: ControlSurface = parse_enum(&scenario.surface)
        .ok_or_else(|| "native_extension_control_surface_invalid".to_owned())?;
    let authority_failure: Option<ResolverFailureCode> = match &scenario.authority_failure {
        None => None,
        Some(code) => Some(
            parse_enum(code)
                .ok_or_else(|| "native_extension_control_authority_failure_invalid".to_owned())?,
        ),
    };
    let results = scenario
        .items
        .iter()
        .map(|item| resolve_item(registry, &layers, surface, authority_failure, item))
        .collect::<Result<Vec<_>, _>>()?;
    Ok(ExtensionControlScenarioResultV1 {
        global_lockdown: compose_control_layers(&layers).global_lockdown,
        results,
    })
}

fn resolve_item(
    registry: &RequestRegistry<'_>,
    layers: &[ExtensionControlLayer],
    surface: ControlSurface,
    authority_failure: Option<ResolverFailureCode>,
    item: &ExtensionControlItemV1,
) -> Result<ExtensionControlItemResultV1, String> {
    let resolution = resolve_extension_controls(
        layers,
        Some(registry),
        &item.extension_ids,
        &item.permission_ids,
        surface,
        &[],
        authority_failure,
    );
    let active = item
        .active_extension_id
        .as_deref()
        .map(|extension_id| is_active(registry, layers, extension_id))
        .transpose()?;
    Ok(ExtensionControlItemResultV1 {
        blocked: resolution.blocked,
        factor_reason_codes: resolution
            .factors
            .iter()
            .map(|factor| factor.reason_code.clone())
            .collect(),
        failures: failures_wire(&resolution.failures),
        explicitly_enabled_permission_ids: resolution.explicitly_enabled_permission_ids,
        active,
    })
}

/// An owner the registry does not know is never active. An owner whose trust
/// class the request left out cannot be answered, so the request is refused.
/// The controls name canonical ids, so an owner asked about by alias or in
/// another case is judged by the canonical id the registry resolved it to.
fn is_active(
    registry: &RequestRegistry<'_>,
    layers: &[ExtensionControlLayer],
    extension_id: &str,
) -> Result<bool, String> {
    let Some(extension) = registry.lookup(extension_id) else {
        return Ok(false);
    };
    let trust_class = extension
        .trust_class
        .as_deref()
        .ok_or_else(|| "native_extension_control_trust_class_missing".to_owned())?;
    Ok(extension_is_active_for_class(
        trust_class,
        &extension.extension_id,
        extension.required,
        layers,
    ))
}

fn parse_enum<T: serde::de::DeserializeOwned>(value: &str) -> Option<T> {
    serde_json::from_value(Value::String(value.to_owned())).ok()
}

/// Failures ordered by the string values of their code and layer kind, the
/// order the Python resolver sorted by; the Rust enums sort by declaration.
fn failures_wire(failures: &[ControlResolverFailure]) -> Vec<ExtensionControlFailureV1> {
    let mut ordered = failures.to_vec();
    ordered.sort_by_key(|failure| {
        (
            failure.code.as_str(),
            failure.layer_kind.map(ControlLayerKind::as_str),
        )
    });
    ordered
        .into_iter()
        .map(|failure| ExtensionControlFailureV1 {
            code: failure.code.as_str().to_owned(),
            layer_kind: failure.layer_kind.map(|kind| kind.as_str().to_owned()),
        })
        .collect()
}

fn composed_wire(composed: &ComposedExtensionControls) -> ExtensionControlComposedV1 {
    ExtensionControlComposedV1 {
        global_lockdown: composed.global_lockdown,
        controls: composed
            .controls
            .iter()
            .map(|control| ExtensionControlComposedControlV1 {
                target_kind: control.target.kind.as_str().to_owned(),
                target_id: control.target.target_id.clone(),
                state: control.state.as_str().to_owned(),
            })
            .collect(),
        failures: failures_wire(&composed.failures),
    }
}

/// Lookup normalization of the Python catalog the request projects.
pub(crate) fn normalize(value: &str) -> String {
    value.trim().to_lowercase()
}

/// The registry projection a request carries, indexed as the Python catalog
/// indexes it: an extension resolves through its normalized id or an alias
/// (alias keys are taken as listed), a permission through its normalized id.
pub(crate) struct RequestRegistry<'a> {
    catalog_digest: &'a str,
    extensions: HashMap<&'a str, &'a ExtensionControlRegistryExtensionV1>,
    aliases: HashMap<&'a str, &'a str>,
    permissions: HashMap<&'a str, &'a ExtensionControlRegistryPermissionV1>,
}

impl<'a> RequestRegistry<'a> {
    pub(crate) fn new(registry: &'a ExtensionControlRegistryV1) -> Result<Self, String> {
        let invalid = || "native_extension_control_registry_invalid".to_owned();
        let mut extensions = HashMap::with_capacity(registry.extensions.len());
        let mut aliases = HashMap::new();
        for extension in &registry.extensions {
            let unknown_class = extension
                .trust_class
                .as_deref()
                .is_some_and(|class| !TRUST_CLASSES.contains(&class));
            if unknown_class
                || extensions
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
                .insert(permission.permission_id.as_str(), permission)
                .is_some()
            {
                return Err(invalid());
            }
        }
        Ok(Self {
            catalog_digest: &registry.catalog_digest,
            extensions,
            aliases,
            permissions,
        })
    }

    pub(crate) fn lookup(
        &self,
        extension_id: &str,
    ) -> Option<&'a ExtensionControlRegistryExtensionV1> {
        let normalized = normalize(extension_id);
        let key = self
            .aliases
            .get(normalized.as_str())
            .copied()
            .unwrap_or(normalized.as_str());
        self.extensions.get(key).copied()
    }
}

impl ControlRegistry for RequestRegistry<'_> {
    fn catalog_digest(&self) -> &str {
        self.catalog_digest
    }

    fn extension(&self, extension_id: &str) -> Option<RegistryExtension> {
        self.lookup(extension_id)
            .map(|extension| RegistryExtension {
                extension_id: extension.extension_id.clone(),
                dependencies: extension.dependencies.clone(),
            })
    }

    fn permission(&self, permission_id: &str) -> Option<RegistryPermission> {
        self.permissions
            .get(normalize(permission_id).as_str())
            .map(|permission| RegistryPermission {
                permission_id: permission.permission_id.clone(),
                extension_id: permission.extension_id.clone(),
                dependencies: permission.dependencies.clone(),
                implied_permissions: permission.implied_permissions.clone(),
            })
    }

    /// The resolver never asks; rule ownership is not part of the projection.
    fn permission_for_rule_id(&self, _rule_id: &str) -> Option<String> {
        None
    }
}

#[cfg(test)]
#[path = "extension_control_op_tests.rs"]
mod tests;
