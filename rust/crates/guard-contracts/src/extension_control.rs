//! `ExtensionControl` — wire contract for the resident extension-control op.
//!
//! The op composes control layers and resolves effective control state for
//! catalog identities. It is pure (no IO, no SQLite): the request carries the
//! control layers and, for resolution, a projection of the registry the caller
//! resolves against, so a candidate or authored registry resolves exactly like
//! the packaged one. A rejected request is a bound `error` reply with its
//! specific code, never a default verdict.

use serde::{Deserialize, Serialize};

use crate::NativeExtensionControlLayerV1;

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
}

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
