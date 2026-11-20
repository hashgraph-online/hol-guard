//! Version-checked reader for compiled cloud action binding artifacts.
//!
//! Hosted evaluation loads the artifact the offline compiler wrote beside the
//! program. The reader admits exactly the formats this build can interpret:
//! one schema and the compiler versions listed in
//! [`SUPPORTED_ARTIFACT_COMPILER_VERSIONS`]. Anything older or newer is an
//! explicit `cloud_binding_artifact_unsupported_version`, never a best-effort
//! read, because a field this build does not understand may be the one that
//! restricts an action.
//!
//! Every digest is recomputed and every action is re-checked against the same
//! rules the compiler applied, so a hand-edited or truncated artifact fails
//! instead of loading with weaker meaning.

use super::cloud_binding::{
    CloudSupport, BINDING_ARTIFACT_COMPILER_VERSION, BINDING_ARTIFACT_DOMAIN,
    BINDING_ARTIFACT_SCHEMA, BINDING_MEANING_DOMAIN, EXECUTABLE_FLOOR, MAX_BINDINGS_PER_EXTENSION,
};
use super::{catalog, json, mcp};
use crate::cloud_action_binding::{
    valid_action_id, valid_label, ActionEffect, TargetCapability, MAX_BINDINGS,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

/// Compiler versions whose artifacts this build reads.
pub const SUPPORTED_ARTIFACT_COMPILER_VERSIONS: &[u64] = &[BINDING_ARTIFACT_COMPILER_VERSION];
/// Largest artifact file a reader accepts.
pub const MAX_ARTIFACT_BYTES: usize = json::MAX_SOURCE_BYTES;

/// What a reader supports, for compatibility checks before loading.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingArtifactCompatibility {
    pub schema: &'static str,
    pub compiler_versions: &'static [u64],
    pub max_actions: usize,
}

pub fn binding_artifact_compatibility() -> BindingArtifactCompatibility {
    BindingArtifactCompatibility {
        schema: BINDING_ARTIFACT_SCHEMA,
        compiler_versions: SUPPORTED_ARTIFACT_COMPILER_VERSIONS,
        max_actions: MAX_BINDINGS,
    }
}

/// Identity of one admitted artifact.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct BindingArtifactMetadata {
    pub schema: String,
    pub compiler_version: u64,
    pub program_digest: String,
    pub artifact_digest: String,
    pub action_count: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "kebab-case", deny_unknown_fields)]
pub enum ArtifactTarget {
    CommandPermission {
        permission_id: String,
    },
    McpTool {
        tool: String,
        endpoint: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactResource {
    pub kind: String,
    pub argument: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactAction {
    pub action_id: String,
    pub extension_id: String,
    pub target: ArtifactTarget,
    pub effect: ActionEffect,
    pub resource: Option<ArtifactResource>,
    pub required_capabilities: BTreeSet<TargetCapability>,
    pub cloud_support: CloudSupport,
    pub binding_digest: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ArtifactDocument {
    schema: String,
    compiler_version: u64,
    program_digest: String,
    actions: Vec<Value>,
    artifact_digest: String,
}

/// An admitted binding artifact.
#[derive(Debug, Clone)]
pub struct BindingArtifact {
    pub metadata: BindingArtifactMetadata,
    actions: BTreeMap<String, ArtifactAction>,
}

impl BindingArtifact {
    pub fn get(&self, action_id: &str) -> Option<&ArtifactAction> {
        self.actions.get(action_id)
    }

    pub fn actions(&self) -> impl Iterator<Item = &ArtifactAction> {
        self.actions.values()
    }

    /// Refuse an artifact compiled against a different program than the one loaded.
    pub fn require_program(&self, program_digest: &str) -> Result<(), &'static str> {
        if self.metadata.program_digest == program_digest {
            Ok(())
        } else {
            Err("cloud_binding_artifact_program_mismatch")
        }
    }
}

/// Read a compiled binding artifact. Any invalid action rejects the whole
/// artifact: a partially admitted set would silently drop restrictions.
pub fn read_binding_artifact(bytes: &[u8]) -> Result<BindingArtifact, &'static str> {
    if bytes.len() > MAX_ARTIFACT_BYTES {
        return Err("cloud_binding_artifact_limit");
    }
    // The bounded decoder also refuses any array longer than MAX_BINDINGS.
    let value = json::decode(bytes).map_err(|_| "cloud_binding_artifact_malformed")?;
    // The version decides how the rest is read, so check it before the shape.
    match value["schema"].as_str() {
        Some(BINDING_ARTIFACT_SCHEMA) => {}
        Some(_) => return Err("cloud_binding_artifact_unsupported_version"),
        None => return Err("cloud_binding_artifact_malformed"),
    }
    match value["compiler_version"].as_u64() {
        Some(version) if SUPPORTED_ARTIFACT_COMPILER_VERSIONS.contains(&version) => {}
        Some(_) => return Err("cloud_binding_artifact_unsupported_version"),
        None => return Err("cloud_binding_artifact_malformed"),
    }
    let mut unsigned = value.clone();
    unsigned
        .as_object_mut()
        .and_then(|object| object.remove("artifact_digest"));
    let document: ArtifactDocument =
        serde_json::from_value(value).map_err(|_| "cloud_binding_artifact_malformed")?;
    if !valid_digest(&document.program_digest) || !valid_digest(&document.artifact_digest) {
        return Err("cloud_binding_artifact_malformed");
    }
    if catalog::digest(BINDING_ARTIFACT_DOMAIN, &unsigned)? != document.artifact_digest {
        return Err("cloud_binding_artifact_digest_mismatch");
    }
    // The compiler writes an artifact only for at least one contribution, and
    // never more actions for one extension than a contribution may declare.
    if document.actions.is_empty() {
        return Err("cloud_binding_artifact_malformed");
    }
    let mut actions = BTreeMap::new();
    let mut per_extension: BTreeMap<String, usize> = BTreeMap::new();
    let mut previous: Option<String> = None;
    for raw in document.actions {
        let action = admit_action(raw)?;
        let count = per_extension
            .entry(action.extension_id.clone())
            .or_default();
        *count += 1;
        if *count > MAX_BINDINGS_PER_EXTENSION {
            return Err("cloud_binding_artifact_limit");
        }
        // The compiler writes actions strictly ascending; any other order is not its output.
        if previous
            .as_deref()
            .is_some_and(|last| last >= action.action_id.as_str())
        {
            return Err("cloud_binding_artifact_order_invalid");
        }
        previous = Some(action.action_id.clone());
        actions.insert(action.action_id.clone(), action);
    }
    Ok(BindingArtifact {
        metadata: BindingArtifactMetadata {
            schema: document.schema,
            compiler_version: document.compiler_version,
            program_digest: document.program_digest,
            artifact_digest: document.artifact_digest,
            action_count: actions.len(),
        },
        actions,
    })
}

fn admit_action(raw: Value) -> Result<ArtifactAction, &'static str> {
    let action: ArtifactAction =
        serde_json::from_value(raw.clone()).map_err(|_| "cloud_binding_artifact_malformed")?;
    // A typed read that drops or coerces anything is not the compiler's output.
    if serde_json::to_value(&action).ok().as_ref() != Some(&raw) {
        return Err("cloud_binding_artifact_malformed");
    }
    let target_valid = match &action.target {
        ArtifactTarget::CommandPermission { permission_id } => {
            valid_label(permission_id) && action.cloud_support == CloudSupport::PortablePolicy
        }
        ArtifactTarget::McpTool { tool, endpoint } => {
            valid_label(tool)
                && match endpoint {
                    // Only the compiler's canonical form of an admitted remote endpoint.
                    Some(endpoint) => mcp::canonical_endpoint(endpoint)
                        .is_ok_and(|canonical| canonical == *endpoint),
                    None => action.cloud_support == CloudSupport::PortablePolicy,
                }
        }
    };
    if !valid_action_id(&action.action_id)
        || !valid_label(&action.extension_id)
        || !target_valid
        || !valid_digest(&action.binding_digest)
        || action.resource.as_ref().is_some_and(|resource| {
            !valid_label(&resource.kind) || !valid_label(&resource.argument)
        })
    {
        return Err("cloud_binding_artifact_malformed");
    }
    if action.cloud_support == CloudSupport::CloudExecutable
        && !EXECUTABLE_FLOOR
            .iter()
            .all(|floor| action.required_capabilities.contains(floor))
    {
        return Err("cloud_binding_artifact_missing_required_capability");
    }
    let mut meaning = raw;
    meaning
        .as_object_mut()
        .and_then(|object| object.remove("binding_digest"));
    if catalog::digest(BINDING_MEANING_DOMAIN, &meaning)? != action.binding_digest {
        return Err("cloud_binding_artifact_digest_mismatch");
    }
    Ok(action)
}

fn valid_digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

#[cfg(test)]
#[path = "native_command_source_cloud_binding_artifact_tests.rs"]
mod tests;
