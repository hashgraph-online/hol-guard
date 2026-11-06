//! Artifact JSON shapes shared by the AIBOM discovery rules. Every artifact is
//! the wire form of a `GuardArtifact` (private runtime metadata never crosses).

use std::path::Path;

use serde_json::{json, Map, Value};
use sha2::{Digest, Sha256};

use super::aibom_paths::{file_content_hash, file_name_string};

pub(crate) fn guard_artifact(
    artifact_id: String,
    name: String,
    harness: &str,
    artifact_type: &str,
    source_scope: &str,
    config_path: &Path,
    metadata: Map<String, Value>,
) -> Value {
    json!({
        "artifact_id": artifact_id,
        "name": name,
        "harness": harness,
        "artifact_type": artifact_type,
        "source_scope": source_scope,
        "config_path": config_path.to_string_lossy(),
        "command": null,
        "args": [],
        "url": null,
        "transport": null,
        "publisher": null,
        "metadata": metadata,
    })
}

/// `version_info_metadata(...)["versionInfo"]` for content-hashed artifacts.
pub(crate) fn content_version_info(content_hash: &str, version_label: &str) -> Value {
    json!({
        "versionLabel": version_label,
        "hashBasis": "content",
        "contentHash": content_hash,
        "changedFields": [],
    })
}

pub(crate) fn sha256_hex(text: &str) -> String {
    hex::encode(Sha256::digest(text.as_bytes()))
}

/// `_instruction_artifact`.
pub(crate) struct Instruction<'a> {
    pub(crate) harness: &'a str,
    pub(crate) path: &'a Path,
    pub(crate) role: &'a str,
    pub(crate) display_name: Option<String>,
    pub(crate) artifact_name: Option<String>,
    pub(crate) artifact_id: Option<String>,
}

pub(crate) fn instruction_artifact(spec: Instruction<'_>) -> Value {
    let file_name = file_name_string(spec.path);
    let digest = file_content_hash(spec.path)
        .filter(|digest| !digest.is_empty())
        .unwrap_or_else(|| sha256_hex(&file_name));
    let content_hash = format!("sha256:{digest}");
    let name = spec.display_name.unwrap_or(file_name);
    let suffix = spec.artifact_name.unwrap_or_else(|| name.clone());
    let artifact_id = spec.artifact_id.unwrap_or_else(|| {
        format!(
            "{}:project:instruction:{}:{suffix}",
            spec.harness, spec.role
        )
    });
    let mut metadata = Map::new();
    metadata.insert("instructionRole".to_owned(), json!(spec.role));
    metadata.insert("content_hash".to_owned(), json!(content_hash));
    metadata.insert(
        "versionInfo".to_owned(),
        content_version_info(&content_hash, &name),
    );
    guard_artifact(
        artifact_id,
        name,
        spec.harness,
        "instruction",
        "project",
        spec.path,
        metadata,
    )
}
