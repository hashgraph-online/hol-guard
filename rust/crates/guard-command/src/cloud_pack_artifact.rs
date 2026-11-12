//! Compiled cloud action pack artifacts.
//!
//! An artifact is the validated pack with its fixtures stripped, plus three
//! digests a host pins: the pack it was compiled from, the facts program (each
//! action's fact derivation, which is what a decision depends on), and the
//! artifact as a whole. Loading recomputes all three and validates the pack
//! again, so a host never trusts a digest it did not check.

use crate::cloud_action_canonical::{canonical_bytes, domain_digest, parse_strict};
use crate::cloud_pack::{CloudActionPack, PackError, MAX_PACK_BYTES};
use crate::cloud_pack_validate::{validate, validate_compiled};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

pub const ARTIFACT_SCHEMA: &str = "guard.cloud-action-pack-artifact.v1";
/// Bumped whenever compilation would turn the same pack into a different artifact.
pub const COMPILER_VERSION: &str = "cloud-pack-compiler.1";
const PACK_DOMAIN: &str = "guard.cloud-action-pack.v1";
const FACTS_PROGRAM_DOMAIN: &str = "guard.cloud-action-pack-facts-program.v1";
const ARTIFACT_DOMAIN: &str = "guard.cloud-action-pack-artifact.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct PackArtifact {
    pub schema: String,
    pub compiler_version: String,
    pub provider_id: String,
    pub pack_digest: String,
    pub facts_program_digest: String,
    pub artifact_digest: String,
    pub pack: CloudActionPack,
}

fn canonical(value: &Value) -> Result<Vec<u8>, PackError> {
    canonical_bytes(value).map_err(|_| PackError::new("cloud_pack_not_canonical", ""))
}

fn stripped(pack: &CloudActionPack) -> CloudActionPack {
    let mut pack = pack.clone();
    for action in &mut pack.actions {
        action.fixtures.clear();
    }
    pack
}

fn to_value<T: Serialize>(value: &T) -> Result<Value, PackError> {
    serde_json::to_value(value).map_err(|_| PackError::new("cloud_pack_not_canonical", ""))
}

/// The digest of a fixture-free pack.
pub fn pack_digest(pack: &CloudActionPack) -> Result<String, PackError> {
    let bytes = canonical(&to_value(&stripped(pack))?)?;
    Ok(domain_digest(PACK_DOMAIN, &[&bytes]))
}

/// The digest of every action's fact derivation, in action-id order.
pub fn facts_program_digest(pack: &CloudActionPack) -> Result<String, PackError> {
    let mut actions: Vec<_> = pack.actions.iter().collect();
    actions.sort_by(|left, right| left.action_id.cmp(&right.action_id));
    let program: Vec<Value> = actions
        .iter()
        .map(|action| {
            Ok(json!({
                "actionId": action.action_id,
                "facts": to_value(&action.facts)?,
                "effect": to_value(&action.safety.effect)?,
            }))
        })
        .collect::<Result<_, PackError>>()?;
    let bytes = canonical(&Value::Array(program))?;
    Ok(domain_digest(FACTS_PROGRAM_DOMAIN, &[&bytes]))
}

fn artifact_digest(artifact: &PackArtifact) -> Result<String, PackError> {
    let mut value = to_value(artifact)?;
    if let Some(object) = value.as_object_mut() {
        object.remove("artifactDigest");
    }
    let bytes = canonical(&value)?;
    Ok(domain_digest(ARTIFACT_DOMAIN, &[&bytes]))
}

/// Compile a source pack. The pack must validate and every fixture must pass.
pub fn compile(pack: &CloudActionPack) -> Result<PackArtifact, PackError> {
    validate(pack)?;
    if !crate::cloud_pack_fixtures::run(pack).passed {
        return Err(PackError::new("cloud_pack_fixtures_failed", ""));
    }
    let compiled = stripped(pack);
    let mut artifact = PackArtifact {
        schema: ARTIFACT_SCHEMA.to_string(),
        compiler_version: COMPILER_VERSION.to_string(),
        provider_id: compiled.provider.id.clone(),
        pack_digest: pack_digest(&compiled)?,
        facts_program_digest: facts_program_digest(&compiled)?,
        artifact_digest: String::new(),
        pack: compiled,
    };
    artifact.artifact_digest = artifact_digest(&artifact)?;
    Ok(artifact)
}

/// Load an artifact, recomputing every digest and validating the pack again.
pub fn load(bytes: &[u8]) -> Result<PackArtifact, PackError> {
    if bytes.len() > MAX_PACK_BYTES {
        return Err(PackError::new("cloud_pack_too_large", ""));
    }
    let value = parse_strict(bytes).map_err(|_| PackError::new("cloud_pack_json_invalid", ""))?;
    load_value(value)
}

/// [`load`] for an artifact that was already parsed strictly.
pub fn load_value(value: Value) -> Result<PackArtifact, PackError> {
    crate::cloud_pack::within_limit(&value)?;
    let artifact: PackArtifact = serde_json::from_value(value)
        .map_err(|_| PackError::new("cloud_pack_artifact_invalid", ""))?;
    if artifact.schema != ARTIFACT_SCHEMA {
        return Err(PackError::new(
            "cloud_pack_artifact_schema_unsupported",
            "/schema",
        ));
    }
    if artifact.compiler_version != COMPILER_VERSION {
        return Err(PackError::new(
            "cloud_pack_compiler_unsupported",
            "/compilerVersion",
        ));
    }
    validate_compiled(&artifact.pack)?;
    let checks = [
        (
            artifact.provider_id == artifact.pack.provider.id,
            "/providerId",
        ),
        (
            artifact.pack_digest == pack_digest(&artifact.pack)?,
            "/packDigest",
        ),
        (
            artifact.facts_program_digest == facts_program_digest(&artifact.pack)?,
            "/factsProgramDigest",
        ),
        (
            artifact.artifact_digest == artifact_digest(&artifact)?,
            "/artifactDigest",
        ),
    ];
    if let Some((_, pointer)) = checks.iter().find(|(ok, _)| !ok) {
        return Err(PackError::new(
            "cloud_pack_artifact_digest_mismatch",
            *pointer,
        ));
    }
    Ok(artifact)
}
