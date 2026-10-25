//! `InventoryItemClassification` - resident op deciding what an inventory
//! item is.
//!
//! The readings used to run in the caller assembling a snapshot: an item's
//! kind, the capabilities it declares, its risk level, the hash that
//! identifies its content, and which evidence keys a skill may keep. Each one
//! is a protection decision made from metadata Guard scanned, and a second
//! implementation of the rules is a second answer Guard can give about the
//! same artifact. `guard_command::inventory_item_metadata` owns the grammar
//! and `testdata/inventory_item_metadata_parity.json` pins it, so the caller
//! asks for the answers rather than deriving them.
//!
//! The whole artifact set rides in one request: a snapshot covers every
//! artifact a detection found, and asking per artifact would put the resident
//! on the critical path of an inventory a few hundred times over.
//!
//! The metadata changes come back as key edits, not as a rewritten object.
//! The caller's metadata is an insertion-ordered dict it then publishes, and
//! handing back a map would reorder every export for no change in content.

use guard_command::inventory_fingerprints::{fingerprint_mapping, stable_snapshot_value};
use guard_command::inventory_item_metadata::{
    bind_skill_document_evidence, capabilities_for_artifact,
    discard_unverified_skill_directory_hash, item_kind, resolve_item_content_hash, risk_level,
    validated_complete_skill_directory_hash,
};
use guard_contracts::{
    InventoryItemClassificationEntryV1, InventoryItemClassificationRequestV1,
    InventoryItemClassificationResultV1, INVENTORY_ITEM_CLASSIFICATION_MAX_BYTES,
    INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES, INVENTORY_ITEM_CLASSIFICATION_REQUEST_SCHEMA,
    INVENTORY_ITEM_CLASSIFICATION_RESULT_SCHEMA,
};
use serde_json::{json, Map, Value};

use crate::package_authority_op::request_digest_with_limit;

pub(crate) fn evaluate_inventory_item_classification_request(
    request: &InventoryItemClassificationRequestV1,
) -> Result<Vec<u8>, String> {
    let request_sha256 =
        request_digest_with_limit(request, INVENTORY_ITEM_CLASSIFICATION_MAX_BYTES)
            .map_err(|_| "native_inventory_item_classification_too_large".to_owned())?;
    let (status, code, payload) = match refusal(request) {
        Some(code) => ("error", code, None),
        None => ("ok", "ok", Some(evaluate_request(request))),
    };
    crate::encode_response(&InventoryItemClassificationResultV1 {
        schema: INVENTORY_ITEM_CLASSIFICATION_RESULT_SCHEMA.to_owned(),
        request_id: request.request_id.clone(),
        request_sha256,
        status: status.to_owned(),
        code: code.to_owned(),
        payload,
    })
}

/// The conditions the op refuses rather than answers.
fn refusal(request: &InventoryItemClassificationRequestV1) -> Option<&'static str> {
    // A request naming another contract is not this op's to answer: the field
    // is the sender's own statement of which request shape it built.
    if request.schema != INVENTORY_ITEM_CLASSIFICATION_REQUEST_SCHEMA {
        return Some("native_inventory_item_classification_schema_mismatch");
    }
    if request.entries.len() > INVENTORY_ITEM_CLASSIFICATION_MAX_ENTRIES {
        return Some("native_inventory_item_classification_too_many_entries");
    }
    None
}

/// One answer per requested entry, in the request's order.
pub(crate) fn evaluate_request(request: &InventoryItemClassificationRequestV1) -> Value {
    let items: Vec<Value> = request.entries.iter().map(classify).collect();
    json!({ "items": items })
}

/// The six readings of one artifact, in the order `_item_from_artifact` made
/// them: the evidence a skill may keep is settled before anything is derived
/// from the metadata, so the kind, hash, capabilities and risk level all read
/// the same evidence the snapshot will publish.
fn classify(entry: &InventoryItemClassificationEntryV1) -> Value {
    let primary_content_hash = entry
        .primary_content_hash
        .as_deref()
        .filter(|value| !value.is_empty());
    let classified = if entry.artifact_type == "skill" {
        let bound = bind_skill_document_evidence(&entry.metadata, primary_content_hash);
        discard_unverified_skill_directory_hash(&bound)
    } else {
        entry.metadata.clone()
    };
    let semantic_text = fingerprint_mapping(&json!({
        "artifact_id": entry.artifact_id,
        "artifact_type": entry.artifact_type,
        "name": entry.name,
        "metadata": stable_snapshot_value(&Value::Object(classified.clone())),
    }));
    let content_hash = match entry.artifact_type.as_str() {
        "skill" => validated_complete_skill_directory_hash(&classified)
            .or_else(|| primary_content_hash.map(ToOwned::to_owned))
            .unwrap_or(semantic_text),
        "instruction" => primary_content_hash
            .map(ToOwned::to_owned)
            .unwrap_or(semantic_text),
        _ => resolve_item_content_hash(&classified, &semantic_text),
    };
    let (removals, updates) = metadata_edits(&entry.metadata, &classified);
    json!({
        "item_kind": item_kind(&entry.artifact_type),
        "metadata_removals": removals,
        "metadata_updates": updates,
        "content_hash": content_hash,
        "capability_categories": capabilities_for_artifact(&entry.artifact_type, &classified),
        "risk_level": risk_level(&classified),
    })
}

/// The difference between the metadata the caller sent and the metadata the
/// readings were made against, as the keys to drop and the keys to write.
///
/// Applying these to the caller's own mapping leaves every untouched key where
/// it already was, which is what keeps a snapshot's exported key order stable
/// across a release that changes nothing about an item.
fn metadata_edits(
    before: &Map<String, Value>,
    after: &Map<String, Value>,
) -> (Vec<String>, Map<String, Value>) {
    let removals: Vec<String> = before
        .keys()
        .filter(|key| !after.contains_key(key.as_str()))
        .cloned()
        .collect();
    let updates: Map<String, Value> = after
        .iter()
        .filter(|(key, value)| before.get(key.as_str()) != Some(value))
        .map(|(key, value)| (key.clone(), value.clone()))
        .collect();
    (removals, updates)
}

#[cfg(test)]
#[path = "inventory_item_classification_op_tests.rs"]
mod tests;
