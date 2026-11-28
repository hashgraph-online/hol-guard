use crate::crypto::sha256;
use crate::{canonical_value, EvidenceError, Result};
use gauntlet_contracts::load_record;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet};

pub fn verify_campaign(value: &Value) -> Result<()> {
    load_record("campaign", value.to_string().as_bytes())
        .map_err(|_| EvidenceError::Invalid("invalid campaign contract"))?;
    let inventory = value["inventory"]
        .as_array()
        .ok_or(EvidenceError::Invalid("campaign inventory missing"))?;
    if value["inventory_digest"] != sha256(&canonical_value(&value["inventory"])?) {
        return Err(EvidenceError::Invalid("campaign inventory digest mismatch"));
    }
    let mut without_manifest = value.clone();
    without_manifest
        .as_object_mut()
        .expect("campaign schema requires object")
        .remove("manifest_digest");
    if value["manifest_digest"] != sha256(&canonical_value(&without_manifest)?) {
        return Err(EvidenceError::Invalid("campaign manifest digest mismatch"));
    }
    let repetitions = value["repetitions"]
        .as_u64()
        .ok_or(EvidenceError::Invalid("invalid campaign repetitions"))?;
    let mut ids = BTreeSet::new();
    let mut isolation_ids = BTreeSet::new();
    let mut pairs: BTreeMap<(String, String, u64, String), Vec<&Value>> = BTreeMap::new();
    for item in inventory {
        let id = item["id"].as_str().unwrap_or("");
        let isolation_id = item["isolation_id"].as_str().unwrap_or("");
        if !ids.insert(id) || !isolation_ids.insert(isolation_id) {
            return Err(EvidenceError::Invalid("duplicate campaign inventory ID"));
        }
        let group = item["group"].as_str().unwrap_or("");
        let variant = item["variant"].as_str().unwrap_or("");
        let protected = item["protected"].as_bool().unwrap_or(false);
        let repetition = item["repetition"].as_u64().unwrap_or(u64::MAX);
        let condition = format!(
            "{}-{}",
            if group == "approval" {
                "approval"
            } else if variant == "clean" {
                "clean"
            } else {
                "attacked"
            },
            if protected {
                "protected"
            } else {
                "unprotected"
            }
        );
        if item["condition"] != condition || repetition >= repetitions {
            return Err(EvidenceError::Invalid(
                "campaign condition or repetition mismatch",
            ));
        }
        let key = (
            item["workflow_id"].as_str().unwrap_or("").to_owned(),
            variant.to_owned(),
            repetition,
            group.to_owned(),
        );
        pairs.entry(key).or_default().push(item);
    }
    for rows in pairs.values() {
        if rows.len() != 2 || rows[0]["protected"] == rows[1]["protected"] {
            return Err(EvidenceError::Invalid(
                "campaign protection pair is incomplete",
            ));
        }
        for field in ["snapshot_id", "authorization_digest", "workflow_digest"] {
            if rows[0][field] != rows[1][field] {
                return Err(EvidenceError::Invalid("campaign pair identity mismatch"));
            }
        }
    }
    if value["preview"]["episodes"].as_u64() != Some(inventory.len() as u64)
        || value["qualification_eligible"] != false
    {
        return Err(EvidenceError::Invalid(
            "campaign preview or eligibility mismatch",
        ));
    }
    Ok(())
}
