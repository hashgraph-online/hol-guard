//! Admitted cloud action bindings.
//!
//! A binding is the reviewed meaning of one hosted action: which adapter runs
//! it, what effect it has, which argument names its resource and which
//! restrictions the hosting target must enforce. The evaluator loads one
//! binding set at startup. Requests name an action; they never supply its
//! effect, digests or required restrictions, so a caller cannot give an
//! unknown action the meaning of a known one.

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::cloud_action_canonical::{canonical_bytes, domain_digest, parse_strict};

pub const BINDING_SET_SCHEMA: &str = "guard.cloud-action-binding-set.v1";
pub const BINDING_SCHEMA: &str = "guard.cloud-action-binding.v1";
pub const MAX_BINDINGS: usize = 4096;
const EXECUTION_IDENTITY_DOMAIN: &str = "guard.cloud-action-execution-identity.v1";
const BINDING_SET_DOMAIN: &str = "guard.cloud-action-binding-set.v1";

/// What a hosted action does to the provider.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ActionEffect {
    Read,
    Write,
    Destructive,
    Admin,
}

/// A restriction the hosting target can enforce for an action.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum TargetCapability {
    /// Requests go only to the binding's provider origin, re-checked per connection.
    EgressPinned,
    /// The named resource is checked against the connection's allowed resources.
    ResourceAllowlist,
    /// The adapter forwards a stable idempotency key to the provider.
    ProviderIdempotency,
    /// Results are size-bounded before they reach the caller.
    BoundedOutput,
    /// No filesystem access from the adapter.
    NoFilesystem,
    /// No subprocess launch from the adapter.
    NoSubprocess,
}

impl TargetCapability {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::EgressPinned => "egress-pinned",
            Self::ResourceAllowlist => "resource-allowlist",
            Self::ProviderIdempotency => "provider-idempotency",
            Self::BoundedOutput => "bounded-output",
            Self::NoFilesystem => "no-filesystem",
            Self::NoSubprocess => "no-subprocess",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AdapterKind {
    NativeConnector,
    RemoteMcp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingAdapter {
    pub kind: AdapterKind,
    pub identity: String,
    pub provider: String,
    pub input_schema: Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingRemoteMcp {
    pub url: String,
    pub tool_name: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BindingResource {
    pub kind: String,
    /// Top-level argument whose string value names the resource.
    pub argument: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CloudActionBinding {
    pub schema: String,
    pub action_id: String,
    pub adapter: BindingAdapter,
    pub effect: ActionEffect,
    pub resource: Option<BindingResource>,
    pub remote_mcp: Option<BindingRemoteMcp>,
    pub required_capabilities: BTreeSet<TargetCapability>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BindingSetDocument {
    schema: String,
    bindings: Vec<Value>,
}

/// One admitted binding with its derived identity.
#[derive(Debug, Clone)]
pub struct AdmittedBinding {
    pub binding: CloudActionBinding,
    pub execution_identity_digest: String,
}

#[derive(Debug, Clone)]
pub struct BindingSet {
    pub digest: String,
    bindings: BTreeMap<String, AdmittedBinding>,
}

impl BindingSet {
    pub fn get(&self, action_id: &str) -> Option<&AdmittedBinding> {
        self.bindings.get(action_id)
    }

    pub fn len(&self) -> usize {
        self.bindings.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bindings.is_empty()
    }
}

/// Load a binding set document. Any invalid binding rejects the whole set:
/// a partially admitted set would silently drop restrictions.
pub fn load_binding_set(bytes: &[u8]) -> Result<BindingSet, &'static str> {
    let document = parse_strict(bytes).map_err(|_| "binding_set_malformed")?;
    let canonical = canonical_bytes(&document).map_err(|_| "binding_set_malformed")?;
    let document: BindingSetDocument =
        serde_json::from_value(document).map_err(|_| "binding_set_malformed")?;
    if document.schema != BINDING_SET_SCHEMA {
        return Err("binding_set_unsupported_version");
    }
    if document.bindings.len() > MAX_BINDINGS {
        return Err("binding_set_limit");
    }
    let mut bindings = BTreeMap::new();
    for raw in document.bindings {
        let admitted = admit_binding(raw)?;
        let action_id = admitted.binding.action_id.clone();
        if bindings.insert(action_id, admitted).is_some() {
            return Err("binding_duplicate_action");
        }
    }
    Ok(BindingSet {
        digest: domain_digest(BINDING_SET_DOMAIN, &[&canonical]),
        bindings,
    })
}

fn admit_binding(raw: Value) -> Result<AdmittedBinding, &'static str> {
    let canonical = canonical_bytes(&raw).map_err(|_| "binding_malformed")?;
    let binding: CloudActionBinding =
        serde_json::from_value(raw).map_err(|_| "binding_malformed")?;
    if binding.schema != BINDING_SCHEMA {
        return Err("binding_unsupported_version");
    }
    if !valid_action_id(&binding.action_id)
        || !valid_label(&binding.adapter.identity)
        || !valid_label(&binding.adapter.provider)
        || !binding.adapter.input_schema.is_object()
    {
        return Err("binding_malformed");
    }
    if let Some(resource) = &binding.resource {
        if !valid_label(&resource.kind) || !valid_label(&resource.argument) {
            return Err("binding_malformed");
        }
    }
    match (binding.adapter.kind, &binding.remote_mcp) {
        (AdapterKind::RemoteMcp, Some(remote)) => {
            if !remote.url.starts_with("https://") || remote.tool_name.trim().is_empty() {
                return Err("binding_malformed");
            }
        }
        (AdapterKind::NativeConnector, None) => {}
        _ => return Err("binding_malformed"),
    }
    // Every hosted target must at least pin egress and bound output.
    for floor in [
        TargetCapability::EgressPinned,
        TargetCapability::BoundedOutput,
    ] {
        if !binding.required_capabilities.contains(&floor) {
            return Err("binding_missing_required_capability");
        }
    }
    Ok(AdmittedBinding {
        execution_identity_digest: domain_digest(EXECUTION_IDENTITY_DOMAIN, &[&canonical]),
        binding,
    })
}

/// `<provider>.<segment>[.<segment>...]`, lowercase ASCII, digits, `_` and `-`.
pub fn valid_action_id(value: &str) -> bool {
    let segments: Vec<&str> = value.split('.').collect();
    value.len() <= 128 && segments.len() >= 2 && segments.iter().all(|s| valid_segment(s))
}

fn valid_segment(segment: &str) -> bool {
    !segment.is_empty()
        && segment.as_bytes()[0].is_ascii_lowercase()
        && segment
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-')
}

/// A short printable identifier with no whitespace or control characters.
pub fn valid_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 256
        && value
            .bytes()
            .all(|b| b.is_ascii_graphic() && b != b'"' && b != b'\\')
}
