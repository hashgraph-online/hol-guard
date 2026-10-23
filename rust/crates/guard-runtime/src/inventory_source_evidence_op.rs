//! `InventorySourceEvidence` - resident op reading an inventory item's source
//! of truth off the filesystem.
//!
//! Two readings used to happen in the caller assembling a snapshot: the
//! content hash of a skill's or an instruction's primary document, and, for a
//! config path that is a symlink, where that link leads. Both decide what the
//! snapshot records about an item, both walk paths the user did not write, and
//! both are only sound while they stay inside the roots the caller names. The
//! resident does that walking so the bound and the reading live together.
//!
//! The answer also carries the artifact's item kind. The caller needs it
//! before it has any metadata to classify - it names the source link and
//! decides which enrichment an artifact gets - and this is the first thing it
//! asks the resident about an artifact, so the mapping rides back here rather
//! than being kept a second time in the caller.
//!
//! For an overlay it carries the instruction role of the configured path as
//! well. The discovery walk already reads that role from the same grammar, so
//! deriving it again in the caller is how the role a snapshot records and the
//! role discovery assigned come apart.
//!
//! The entries ride in one request: a snapshot covers every artifact a
//! detection found, and asking per artifact would put the resident on the
//! critical path of an inventory a few hundred times over.

use std::ffi::OsStr;
use std::path::{Path, PathBuf};

use guard_command::inventory_item_metadata::{item_kind, safe_roots_for_inspection};
use guard_contracts::{
    InventorySourceEvidenceEntryV1, InventorySourceEvidenceRequestV1,
    InventorySourceEvidenceResultV1, INVENTORY_SOURCE_EVIDENCE_MAX_BYTES,
    INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES, INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA,
    INVENTORY_SOURCE_EVIDENCE_RESULT_SCHEMA,
};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::aibom_paths::{instruction_role_for_path, is_symlink, py_path, resolves_within_root};
use crate::aibom_symlink::{
    inspect_aibom_source_path, path_has_symlink_component, source_of_truth_metadata_from_inspection,
};
use crate::package_authority_op::request_digest_with_limit;
use crate::workspace_inventory_files::expanduser;

/// The suffixes an instruction document is read from.
const INSTRUCTION_SUFFIXES: [&str; 2] = ["md", "mdc"];

pub(crate) fn evaluate_inventory_source_evidence_request(
    request: &InventorySourceEvidenceRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 = request_digest_with_limit(request, INVENTORY_SOURCE_EVIDENCE_MAX_BYTES)
        .map_err(|_| "native_inventory_source_evidence_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&InventorySourceEvidenceResultV1 {
        schema: INVENTORY_SOURCE_EVIDENCE_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &InventorySourceEvidenceRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != INVENTORY_SOURCE_EVIDENCE_REQUEST_SCHEMA {
        return Some("native_inventory_source_evidence_schema_mismatch");
    }
    // Every safe root and every redacted path is spelled against the home
    // directory, so an absent one would leave the walk unbounded.
    if request.home_dir.trim().is_empty() {
        return Some("native_inventory_source_evidence_home_required");
    }
    if request.entries.len() > INVENTORY_SOURCE_EVIDENCE_MAX_ENTRIES {
        return Some("native_inventory_source_evidence_too_many_entries");
    }
    None
}

/// One answer per requested entry, in the request's order.
pub(crate) fn evaluate_request(request: &InventorySourceEvidenceRequestV1) -> Value {
    let home_dir = py_path(&request.home_dir);
    let workspace_dir = request
        .workspace_dir
        .as_deref()
        .filter(|value| !value.is_empty())
        .map(py_path);
    let safe_roots = safe_roots_for_inspection(&home_dir, workspace_dir.as_deref());
    let evidence: Vec<Value> = request
        .entries
        .iter()
        .map(|entry| {
            json!({
                "item_kind": item_kind(&entry.artifact_type),
                "instruction_role": overlay_instruction_role(entry),
                "source_of_truth": source_of_truth(
                    entry,
                    request,
                    &safe_roots,
                    &home_dir,
                    workspace_dir.as_deref(),
                ),
                "primary_content_hash": primary_artifact_content_hash(
                    entry,
                    &home_dir,
                    workspace_dir.as_deref(),
                ),
            })
        })
        .collect();
    json!({ "evidence": evidence })
}

/// The `instructionRole` an overlay's configured path stands for.
///
/// Only an overlay has one: it is the artifact kind whose config path is the
/// instruction document itself. The path is read as written, the way the
/// discovery walk reads it, so a role never depends on where the scan ran:
/// `configured_path` is what the harness configured, and the caller sends it
/// whenever it had to anchor a relative path to reach the filesystem.
fn overlay_instruction_role(entry: &InventorySourceEvidenceEntryV1) -> Option<&'static str> {
    if item_kind(&entry.artifact_type) != "overlay" {
        return None;
    }
    let config_path = entry
        .configured_path
        .as_deref()
        .or(entry.config_path.as_deref())
        .filter(|value| !value.is_empty())?;
    instruction_role_for_path(&py_path(config_path))
}

/// `_apply_source_of_truth_metadata`, as the `sourceOfTruth` value alone: a
/// config path that is not a symlink leaves the item's metadata as it was.
fn source_of_truth(
    entry: &InventorySourceEvidenceEntryV1,
    request: &InventorySourceEvidenceRequestV1,
    safe_roots: &[PathBuf],
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> Option<Value> {
    if !request.include_symlinks {
        return None;
    }
    let config_path = entry
        .config_path
        .as_deref()
        .filter(|value| !value.is_empty())?;
    // Deliberately not expanded: the Python source inspects the configured
    // path as written and expands only for the primary document hash.
    let path = py_path(config_path);
    if !is_symlink(&path) {
        return None;
    }
    let inspection = inspect_aibom_source_path(
        &path,
        safe_roots,
        home_dir,
        workspace_dir,
        request.follow_unsafe_symlinks,
    );
    let fingerprint: String = inspection.source_fingerprint.chars().take(24).collect();
    let source_link_id = format!(
        "{}:{}:{fingerprint}",
        entry.harness,
        item_kind(&entry.artifact_type)
    );
    Some(source_of_truth_metadata_from_inspection(
        &inspection,
        &source_link_id,
    ))
}

/// `_primary_artifact_content_hash`: the fingerprint of the artifact's own
/// document, and nothing standing in for it. A skill's hash covers the
/// `SKILL.md` of a named skill directory under a `skills` root the caller
/// owns; an instruction's covers a markdown file inside the workspace. Any
/// other artifact type has no primary document, and a path reached through a
/// symlink is refused rather than read.
fn primary_artifact_content_hash(
    entry: &InventorySourceEvidenceEntryV1,
    home_dir: &Path,
    workspace_dir: Option<&Path>,
) -> Option<String> {
    let config_path = entry
        .config_path
        .as_deref()
        .filter(|value| !value.trim().is_empty())?;
    let path = py_path(&expanduser(config_path).to_string_lossy());
    let allowed_roots: Vec<PathBuf> = match entry.artifact_type.as_str() {
        "skill" => {
            if path.file_name() != Some(OsStr::new("SKILL.md")) {
                return None;
            }
            let skills_root = path
                .ancestors()
                .skip(1)
                .find(|parent| {
                    parent
                        .file_name()
                        .is_some_and(|name| name.to_string_lossy().to_lowercase() == "skills")
                })?
                .to_path_buf();
            let relative = path.strip_prefix(&skills_root).ok()?;
            // `skills/SKILL.md` names no skill: the document has to sit inside
            // a directory the skill is identified by.
            if relative.components().count() < 2 {
                return None;
            }
            [Some(home_dir), workspace_dir]
                .into_iter()
                .flatten()
                .find(|root| resolves_within_root(root, &skills_root, true))?;
            vec![skills_root]
        }
        "instruction" => {
            let workspace = workspace_dir?;
            let suffix = path
                .extension()
                .map(|value| value.to_string_lossy().to_lowercase())?;
            if !INSTRUCTION_SUFFIXES.contains(&suffix.as_str()) {
                return None;
            }
            vec![workspace.to_path_buf()]
        }
        _ => return None,
    };
    let allowed_root = allowed_roots
        .iter()
        .find(|root| resolves_within_root(root.as_path(), &path, true))?;
    if path_has_symlink_component(&path, allowed_root) {
        return None;
    }
    let digest = stream_sha256(&path)?;
    Some(format!("sha256:{digest}"))
}

/// The whole file's SHA-256, read in bounded chunks; `None` when it cannot be
/// read, as the Python source's `OSError` branch returns.
fn stream_sha256(path: &Path) -> Option<String> {
    use std::io::Read;

    let mut file = std::fs::File::open(path).ok()?;
    let mut digest = Sha256::new();
    let mut chunk = [0_u8; 65_536];
    loop {
        match file.read(&mut chunk) {
            Ok(0) => break,
            Ok(count) => digest.update(&chunk[..count]),
            Err(_) => return None,
        }
    }
    Some(hex::encode(digest.finalize()))
}

#[cfg(test)]
#[path = "inventory_source_evidence_op_tests.rs"]
mod tests;
