//! `ExtensionControl` — wire contract for the resident extension-control op.
//!
//! The op composes control layers and resolves effective control state for
//! catalog identities. It is pure (no IO, no SQLite): the request carries the
//! control layers and, for resolution, a projection of the registry the caller
//! resolves against, so a candidate or authored registry resolves exactly like
//! the packaged one. A rejected request is a bound `error` reply with its
//! specific code, never a default verdict.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::{
    ExtensionControlEventTargetV1, ExtensionControlMutationRegistryV1,
    ExtensionControlPreviewRegistryV1, ExtensionControlSemanticPreviewV1,
    NativeExtensionControlLayerV1,
};

/// Schema discriminator for the request.
pub const EXTENSION_CONTROL_REQUEST_SCHEMA: &str = "guard-extension-control-request.v1";
/// Schema discriminator for the result.
pub const EXTENSION_CONTROL_RESULT_SCHEMA: &str = "guard-extension-control-result.v1";
/// Capability advertised by the runtime when this operation is available.
pub const EXTENSION_CONTROL_FEATURE: &str = "extension-control-v1";

/// Largest canonical request serialization the op will accept.
pub const EXTENSION_CONTROL_MAX_BYTES: usize = 4 * 1024 * 1024;

/// One extension of the registry the caller resolves against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlRegistryExtensionV1 {
    pub extension_id: String,
    /// Alternate ids that resolve to this extension, exactly as the catalog
    /// lists them (lookups normalize the queried id, not the alias).
    pub aliases: Vec<String>,
    pub dependencies: Vec<String>,
    pub required: bool,
    /// `first-party`, `trusted-library` or `external`. Required only when an
    /// item asks whether this extension is active; null otherwise.
    pub trust_class: Option<String>,
}

/// One permission of the registry the caller resolves against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlRegistryPermissionV1 {
    pub permission_id: String,
    pub extension_id: String,
    pub dependencies: Vec<String>,
    pub implied_permissions: Vec<String>,
}

/// The registry projection a resolution runs against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlRegistryV1 {
    pub catalog_digest: String,
    pub extensions: Vec<ExtensionControlRegistryExtensionV1>,
    pub permissions: Vec<ExtensionControlRegistryPermissionV1>,
}

/// One resolution asked against a scenario's layers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlItemV1 {
    pub extension_ids: Vec<String>,
    pub permission_ids: Vec<String>,
    /// When set, the result also reports whether this extension is active for
    /// the scenario's layers (`extension_is_active`).
    pub active_extension_id: Option<String>,
}

/// One set of layers resolved against the shared registry.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlScenarioV1 {
    pub layers: Vec<NativeExtensionControlLayerV1>,
    /// `command-evaluation`, `trusted-local-recovery` or `trusted-local-proof`.
    pub surface: String,
    /// A `ResolverFailureCode` value recorded as a failure, when the caller
    /// could not read the authority behind the layers.
    pub authority_failure: Option<String>,
    pub items: Vec<ExtensionControlItemV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionControlQueryV1 {
    /// Compose layers with disable dominance.
    Compose {
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// Resolve every scenario's items against one registry.
    Resolve {
        registry: ExtensionControlRegistryV1,
        scenarios: Vec<ExtensionControlScenarioV1>,
    },
    /// The digest that identifies the runtime snapshot of one authority view.
    SnapshotDigest {
        catalog_digest: String,
        health: String,
        revision: u64,
        managed_revision: u64,
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// The digest a commit proof binds: replacing the layers at
    /// `previous_revision` with `layers`, for this actor and request.
    MutationDigest {
        previous_revision: i64,
        catalog_digest: String,
        layers: Vec<NativeExtensionControlLayerV1>,
        actor_id: String,
        idempotency_key: String,
        nonce: String,
    },
    /// The digest a first-enrollment proof binds.
    EnrollmentDigest {
        catalog_digest: String,
        actor_id: String,
        nonce: String,
    },
    /// The semantic preview of replacing `current_layers` with `proposed_layers`.
    Preview {
        registry: ExtensionControlPreviewRegistryV1,
        current_layers: Vec<NativeExtensionControlLayerV1>,
        proposed_layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// Whether `layers` stay within the input bounds of one mutation. Asked
    /// before any work that depends on the layers, so an oversized draft is
    /// refused cheaply.
    MutationBounds {
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// Whether a mutation may proceed, and its layers with every extension
    /// target named by its canonical id. `catalog_digest` is the catalog the
    /// caller serves; the mutation must name it, and so must every layer.
    MutationValidate {
        registry: ExtensionControlMutationRegistryV1,
        catalog_digest: String,
        requested_catalog_digest: String,
        current_layers: Vec<NativeExtensionControlLayerV1>,
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// Whether `layers` leave the managed layer and every immutable control of
    /// `current_layers` as they are, against a registry the mutation was
    /// prepared with.
    MutabilityValidate {
        registry: ExtensionControlMutationRegistryV1,
        current_layers: Vec<NativeExtensionControlLayerV1>,
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// The digest that identifies one apply request: the fields below are
    /// exactly the ones that make two requests the same request. They are
    /// hashed as the caller sent them (`null` for a missing field), because the
    /// request is not yet known to be well formed.
    ///
    /// The fields are boxed so the arbitrary-shape values do not set the size of
    /// every query.
    RequestDigest {
        previous_revision: Box<Value>,
        catalog_digest: Box<Value>,
        layers: Box<Value>,
        actor_id: Box<Value>,
        idempotency_key: Box<Value>,
        nonce: Box<Value>,
    },
    /// The nonce a prepared candidate's mutation is proven under: the caller's
    /// nonce bound to the identities of the activation records staged for it,
    /// so a proof cannot be reused with other records.
    CandidateNonce {
        nonce: String,
        activation_digest: String,
        lifecycle_before: String,
        lifecycle_after: String,
        security_digest: Option<String>,
    },
    /// The audit projection of the semantic preview of replacing
    /// `current_layers` with `proposed_layers`: one entry per changed target,
    /// without the target's id.
    PreviewEventTargets {
        registry: ExtensionControlPreviewRegistryV1,
        current_layers: Vec<NativeExtensionControlLayerV1>,
        proposed_layers: Vec<NativeExtensionControlLayerV1>,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlRequestV1 {
    pub schema: String,
    /// Optional caller correlation id; echoed back in the result.
    #[serde(default)]
    pub request_id: String,
    pub query: ExtensionControlQueryV1,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlFailureV1 {
    pub code: String,
    pub layer_kind: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlComposedControlV1 {
    pub target_kind: String,
    pub target_id: String,
    pub state: String,
}

/// The composition of a scenario's layers.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlComposedV1 {
    pub global_lockdown: bool,
    pub controls: Vec<ExtensionControlComposedControlV1>,
    /// Sorted by code then layer kind, by their string values.
    pub failures: Vec<ExtensionControlFailureV1>,
}

/// The effective state of one item.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlItemResultV1 {
    pub blocked: bool,
    /// Reason codes of the control factors that blocked the item.
    pub factor_reason_codes: Vec<String>,
    /// Sorted by code then layer kind, by their string values.
    pub failures: Vec<ExtensionControlFailureV1>,
    pub explicitly_enabled_permission_ids: Vec<String>,
    /// Present exactly when the item named an `active_extension_id`.
    pub active: Option<bool>,
}

/// One scenario's answer: whether its composition holds a global lockdown,
/// and the answer to each of its items in request order. The full composition
/// is a `compose` query, not part of every scenario, to keep replies small.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlScenarioResultV1 {
    pub global_lockdown: bool,
    pub results: Vec<ExtensionControlItemResultV1>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum ExtensionControlPayloadV1 {
    Compose {
        composed: ExtensionControlComposedV1,
    },
    Resolve {
        scenarios: Vec<ExtensionControlScenarioResultV1>,
    },
    SnapshotDigest {
        digest: String,
    },
    MutationDigest {
        digest: String,
    },
    EnrollmentDigest {
        digest: String,
    },
    Preview {
        preview: ExtensionControlSemanticPreviewV1,
    },
    /// The answer to `mutation_bounds`: null when the layers are inside every
    /// limit, otherwise the limit reason.
    MutationBounds {
        refusal: Option<String>,
    },
    /// The answer to `mutation_validate`.
    MutationValidate {
        /// Null when the mutation is accepted, otherwise the reason it is
        /// refused (one of the `EXTENSION_CONTROL_MUTATION_*` reasons).
        refusal: Option<String>,
        /// The validated mutation's layers, extension targets canonical. Empty
        /// when the mutation is refused.
        layers: Vec<NativeExtensionControlLayerV1>,
    },
    /// The answer to `mutability_validate`: null when the draft may proceed,
    /// otherwise the immutability reason.
    MutabilityValidate {
        refusal: Option<String>,
    },
    /// The answer to `request_digest`: lowercase hex SHA-256.
    RequestDigest {
        digest: String,
    },
    /// The answer to `candidate_nonce`: lowercase hex SHA-256.
    CandidateNonce {
        nonce: String,
    },
    /// The answer to `preview_event_targets`, bounded by
    /// `EXTENSION_CONTROL_MAX_EVENT_TARGETS`.
    PreviewEventTargets {
        targets: Vec<ExtensionControlEventTargetV1>,
    },
}

/// A mutation exceeds the layer count of one authority.
pub const EXTENSION_CONTROL_MUTATION_LAYER_LIMIT: &str = "layer_limit_exceeded";
/// One layer of a mutation holds more controls than a layer may.
pub const EXTENSION_CONTROL_MUTATION_LAYER_CONTROL_LIMIT: &str = "layer_control_limit_exceeded";
/// A mutation holds more controls than one authority may.
pub const EXTENSION_CONTROL_MUTATION_CONTROL_LIMIT: &str = "control_limit_exceeded";
/// A control targets an extension the catalog does not know.
pub const EXTENSION_CONTROL_MUTATION_UNKNOWN_EXTENSION: &str = "unknown_extension";
/// A control targets a permission the catalog does not know.
pub const EXTENSION_CONTROL_MUTATION_UNKNOWN_PERMISSION: &str = "unknown_permission";
/// A layer holds two controls for one target, once its aliases are resolved.
pub const EXTENSION_CONTROL_MUTATION_DUPLICATE_TARGET: &str = "duplicate_control_target";
/// The mutation or one of its layers is bound to another catalog.
pub const EXTENSION_CONTROL_MUTATION_CATALOG_CONFLICT: &str = "catalog_conflict";
/// The mutation adds, changes or drops a managed-layer control.
pub const EXTENSION_CONTROL_MUTATION_MANAGED_LAYER: &str = "managed_layer_mutation";
/// The mutation creates or changes a control of a required extension.
pub const EXTENSION_CONTROL_MUTATION_IMMUTABLE_EXTENSION: &str = "immutable_extension";
/// The mutation creates or changes a control of a permission the catalog fixes.
pub const EXTENSION_CONTROL_MUTATION_IMMUTABLE_PERMISSION: &str = "immutable_permission";
/// The mutation's layers are not valid once their targets are canonical.
pub const EXTENSION_CONTROL_MUTATION_INVALID: &str = "invalid_mutation";

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlResultV1 {
    pub schema: String,
    pub request_id: String,
    /// SHA-256 of the canonical request, binding the result to its request.
    pub request_sha256: String,
    /// `ok` or `error`.
    pub status: String,
    /// `ok`, or one of the `native_extension_control_*` failure codes.
    pub code: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub payload: Option<ExtensionControlPayloadV1>,
}
