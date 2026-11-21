//! `ExtensionControl` mutation queries — wire contract for the checks a local
//! extension-control mutation passes before it is previewed or committed.
//!
//! The caller parses the layers it was handed and the resident decides whether
//! the mutation may proceed: the input bounds, the canonical identity of every
//! extension target, the catalog the mutation is bound to, the targets the
//! catalog knows, and the controls a local draft may not touch (the managed
//! layer, a required extension, a permission the catalog fixes). A refusal is a
//! normal `ok` reply carrying its reason, because it describes the mutation;
//! only a request the resident cannot read is an `error` reply.

use serde::{Deserialize, Serialize};

/// One extension of the catalog a mutation resolves its targets against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlMutationExtensionV1 {
    pub extension_id: String,
    /// Alternate ids that resolve to this extension, exactly as listed.
    pub aliases: Vec<String>,
    /// A required extension cannot be given a local control.
    pub required: bool,
}

/// One permission of the catalog a mutation resolves its targets against.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlMutationPermissionV1 {
    pub permission_id: String,
    /// A permission that is not configurable cannot be given a local control.
    pub configurable: bool,
}

/// An extension known only from authenticated metadata fetched for this
/// request. It is consulted after the catalog and by its exact id; its aliases
/// are not honored.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlMutationOverlayV1 {
    pub extension_id: String,
    pub required: bool,
    pub permissions: Vec<ExtensionControlMutationPermissionV1>,
}

/// The target projection a mutation runs against: the catalog, then the
/// request-local overlay. The catalog wins wherever both name a target.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct ExtensionControlMutationRegistryV1 {
    pub extensions: Vec<ExtensionControlMutationExtensionV1>,
    pub permissions: Vec<ExtensionControlMutationPermissionV1>,
    pub overlay: Vec<ExtensionControlMutationOverlayV1>,
}
